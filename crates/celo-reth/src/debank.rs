//! Debank trace types and helpers.
//!
//! Ported from reth-x. Provides types and functions for the `trace_debankBlock` RPC method.

use alloy_consensus::{BlockHeader, constants::KECCAK_EMPTY};
use alloy_genesis::Genesis;
use alloy_network::ReceiptResponse;
use alloy_primitives::{
    Address, B256 as H256, BlockHash, BlockNumber, Bytes, U256, hex, keccak256,
};
use alloy_rlp::{RlpDecodable, RlpEncodable};
use alloy_rpc_types_eth::Header;
use reth_db_api::models::{AccountBeforeTx, BlockNumberAddress};
use reth_primitives_traits::{Block, RecoveredBlock, StorageEntry, Transaction};
use reth_trie::EMPTY_ROOT_HASH;
use revm::{DatabaseRef, database::BundleState, interpreter::InstructionResult};
use revm_bytecode::opcode::OpCode;
use revm_inspectors::tracing::{
    CallTraceArena,
    types::{CallKind, CallLog, CallTraceNode, TraceMemberOrder},
};
use serde::{Deserialize, Serialize};
use sha1::Digest;
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    str::FromStr,
};

// ─── Storage diff types ───────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable, Default)]
pub struct BlockStorageDiff {
    pub hash: H256,
    pub parent_hash: H256,
    pub new_accounts: Vec<NewAccount>,
    pub deleted_accounts: Vec<H256>,
    pub storage_diffs: Vec<AccountStorageDiff>,
    pub new_codes: Vec<NewCode>,
}

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct NewCode {
    pub code_hash: H256,
    pub code: Bytes,
}

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct NewAccount {
    pub address: H256,
    pub balance: U256,
    pub nonce: u64,
    pub code_hash: H256,
}

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct AccountStorageDiff {
    pub address: H256,
    pub diffs: Vec<IndexValuePair>,
}

#[derive(Debug, Clone, PartialEq, RlpDecodable, RlpEncodable)]
pub struct IndexValuePair {
    pub index: H256,
    pub value: U256,
}

// ─── Genesis helpers ──────────────────────────────────────────────────────────

pub fn get_storage_contracts_from_genesis(genesis: &Genesis) -> Vec<Address> {
    let mut addresses = Vec::new();
    for (address, account) in genesis.alloc.iter() {
        if account.storage.is_some() {
            addresses.push(*address);
        }
    }
    addresses
}

pub fn get_storage_contracts_from_bundle(bundle: &BundleState) -> Vec<Address> {
    bundle
        .state
        .iter()
        .filter_map(|(address, account)| {
            account.storage.values().any(|slot| slot.is_changed()).then_some(*address)
        })
        .collect()
}

pub fn get_storage_diffs_from_bundle<DB: DatabaseRef>(
    bundle: BundleState,
    post_db: DB,
) -> Result<BlockStorageDiff, DB::Error> {
    let mut new_accounts = Vec::new();
    let mut deleted_accounts = Vec::new();
    let mut storage_diffs = Vec::new();
    let mut new_codes = Vec::new();
    let mut changed_code_hashes = HashSet::new();

    for (address, account) in bundle.state {
        let original_info = account.original_info;
        let Some(info) = account.info else {
            if original_info.is_some() {
                deleted_accounts.push(keccak256(address.0));
            }
            continue;
        };

        let diffs: Vec<IndexValuePair> = account
            .storage
            .into_iter()
            .filter(|(_, slot)| slot.is_changed())
            .map(|(key, slot)| IndexValuePair {
                index: keccak256::<[u8; 32]>(key.to_be_bytes()),
                value: slot.present_value,
            })
            .collect();
        let has_storage_changes = !diffs.is_empty();
        if has_storage_changes {
            storage_diffs.push(AccountStorageDiff { address: keccak256(address.0), diffs });
        }

        let account_changed = original_info.as_ref().is_none_or(|original| {
            original.balance != info.balance ||
                original.nonce != info.nonce ||
                original.code_hash != info.code_hash
        });
        if account_changed || has_storage_changes {
            new_accounts.push(NewAccount {
                address: keccak256(address.0),
                balance: info.balance,
                nonce: info.nonce,
                code_hash: info.code_hash,
            });
        }

        if original_info.as_ref().map(|original| original.code_hash) != Some(info.code_hash) &&
            info.code_hash != KECCAK_EMPTY
        {
            changed_code_hashes.insert(info.code_hash);
        }
    }

    for code_hash in changed_code_hashes {
        let code = post_db.code_by_hash_ref(code_hash)?;
        new_codes.push(NewCode { code_hash, code: code.original_bytes() });
    }

    Ok(BlockStorageDiff {
        hash: H256::ZERO,
        parent_hash: H256::ZERO,
        new_accounts,
        deleted_accounts,
        storage_diffs,
        new_codes,
    })
}

pub fn get_storage_diffs_from_changesets<DB: DatabaseRef>(
    account_changesets: Vec<AccountBeforeTx>,
    storage_changesets: Vec<(BlockNumberAddress, StorageEntry)>,
    post_db: DB,
) -> Result<BlockStorageDiff, DB::Error> {
    let mut new_accounts = Vec::new();
    let mut deleted_accounts = Vec::new();
    let mut storage_diffs = Vec::new();
    let mut new_codes = Vec::new();
    let mut changed_code_hashes = HashSet::new();
    let mut account_pre_state = BTreeMap::new();
    let mut changed_addresses = BTreeSet::new();

    for account in account_changesets {
        changed_addresses.insert(account.address);
        account_pre_state.insert(account.address, account.info.map(Into::into));
    }

    let mut storage_by_address: BTreeMap<Address, Vec<IndexValuePair>> = BTreeMap::new();
    for (block_address, entry) in storage_changesets {
        let address = block_address.address();
        let final_value = post_db.storage_ref(address, U256::from_be_bytes(entry.key.0))?;
        if final_value != entry.value {
            changed_addresses.insert(address);
            storage_by_address.entry(address).or_default().push(IndexValuePair {
                index: keccak256::<[u8; 32]>(entry.key.0),
                value: final_value,
            });
        }
    }

    for address in changed_addresses {
        let post_account = post_db.basic_ref(address)?;
        let pre_account =
            account_pre_state.get(&address).cloned().unwrap_or_else(|| post_account.clone());
        let diffs = storage_by_address.remove(&address).unwrap_or_default();
        let has_storage_changes = !diffs.is_empty();

        if has_storage_changes {
            storage_diffs.push(AccountStorageDiff { address: keccak256(address.0), diffs });
        }

        let Some(info) = post_account else {
            if pre_account.is_some() {
                deleted_accounts.push(keccak256(address.0));
            }
            continue;
        };

        let account_changed = pre_account.as_ref() != Some(&info);
        if account_changed || has_storage_changes {
            if pre_account.as_ref().map(|account| account.code_hash) != Some(info.code_hash) {
                changed_code_hashes.insert(info.code_hash);
            }

            new_accounts.push(NewAccount {
                address: keccak256(address.0),
                balance: info.balance,
                nonce: info.nonce,
                code_hash: info.code_hash,
            });
        }
    }

    for code_hash in changed_code_hashes {
        if code_hash != KECCAK_EMPTY {
            let code = post_db.code_by_hash_ref(code_hash)?;
            new_codes.push(NewCode { code_hash, code: code.original_bytes() });
        }
    }

    Ok(BlockStorageDiff {
        hash: H256::ZERO,
        parent_hash: EMPTY_ROOT_HASH,
        new_accounts,
        deleted_accounts,
        storage_diffs,
        new_codes,
    })
}

impl From<&Genesis> for BlockStorageDiff {
    fn from(genesis: &Genesis) -> Self {
        let mut new_accounts = Vec::new();
        let mut new_codes = Vec::new();
        let mut storage_diffs = Vec::new();

        for (address, account) in genesis.alloc.iter() {
            let code_hash = account.code.as_ref().map_or(KECCAK_EMPTY, |code| {
                let code_hash = keccak256(code);
                new_codes.push(NewCode { code_hash, code: code.clone() });
                code_hash
            });

            new_accounts.push(NewAccount {
                address: keccak256(address.0),
                balance: account.balance,
                nonce: account.nonce.unwrap_or_default(),
                code_hash,
            });

            if let Some(storage) = &account.storage {
                let mut diffs: Vec<IndexValuePair> = vec![];
                for (key, value) in storage.iter() {
                    diffs.push(IndexValuePair {
                        index: keccak256::<[u8; 32]>(key.0),
                        value: U256::from_be_bytes(value.0),
                    });
                }
                if !diffs.is_empty() {
                    storage_diffs.push(AccountStorageDiff { address: keccak256(address.0), diffs });
                }
            }
        }

        Self {
            hash: H256::ZERO,
            parent_hash: EMPTY_ROOT_HASH,
            new_accounts,
            deleted_accounts: vec![],
            storage_diffs,
            new_codes,
        }
    }
}

// ─── Validation hash ──────────────────────────────────────────────────────────

pub fn calc_validation_hash(ids: &[String]) -> i64 {
    let mut sha1_sum = U256::from(0);
    for each in ids {
        let mut hasher = sha1::Sha1::new();
        hasher.update(each.as_bytes());
        let hash_int = U256::from_str_radix(&hex::encode(hasher.finalize()), 16)
            .unwrap_or_else(|_| panic!("Failed to convert id {} to U256", each));
        sha1_sum += hash_int;
    }
    let sha1_sum_str = sha1_sum.to_string();
    let last_6_digits = if sha1_sum_str.len() >= 6 {
        &sha1_sum_str[sha1_sum_str.len().saturating_sub(6)..]
    } else {
        &sha1_sum_str
    };
    i64::from_str(last_6_digits).unwrap_or(0)
}

// ─── Block / Transaction types ───────────────────────────────────────────────

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct DebankBlock {
    pub id: BlockHash,
    pub height: BlockNumber,
    pub parent_id: BlockHash,
    pub base_fee_per_gas: Option<u64>,
    pub miner: Address,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub process_start_timestamp: u128,
}

impl<B: Block> From<&RecoveredBlock<B>> for DebankBlock {
    fn from(block: &RecoveredBlock<B>) -> Self {
        Self {
            id: block.hash(),
            height: block.header().number(),
            parent_id: block.header().parent_hash(),
            base_fee_per_gas: block.header().base_fee_per_gas(),
            miner: block.header().beneficiary(),
            gas_limit: block.header().gas_limit(),
            gas_used: block.header().gas_used(),
            timestamp: block.header().timestamp(),
            process_start_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct DebankTransaction {
    pub id: String,
    #[serde(rename = "from_addr")]
    pub from: Address,
    #[serde(rename = "to_addr")]
    pub to: Address,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub gas_used: u64,
    pub status: bool,
    #[serde(rename = "max_fee_per_gas")]
    pub gas_fee_cap: u128,
    #[serde(rename = "max_priority_fee_per_gas")]
    pub gas_tip_cap: u128,
    pub input: Bytes,
    pub nonce: u64,
    #[serde(rename = "idx")]
    pub transaction_index: u64,
    pub value: U256,
}

impl<R, T> From<(&R, &T, Option<u64>, Option<u128>)> for DebankTransaction
where
    R: ReceiptResponse,
    T: Transaction,
{
    fn from((receipt, tx, deposit_nonce, l1_fee): (&R, &T, Option<u64>, Option<u128>)) -> Self {
        let gas_price = l1_fee.map_or_else(
            || U256::from(receipt.effective_gas_price()),
            |l1_fee| {
                let effective_gas_price = U256::from(receipt.effective_gas_price());
                let gas_used = U256::from(receipt.gas_used());
                let l1_fee = U256::from(l1_fee);
                if gas_used == U256::ZERO {
                    effective_gas_price
                } else {
                    (l1_fee / gas_used) + effective_gas_price
                }
            },
        );
        Self {
            id: receipt.transaction_hash().to_string(),
            from: receipt.from(),
            to: receipt.to().unwrap_or_default(),
            gas_limit: tx.gas_limit(),
            gas_price: gas_price.to(),
            gas_used: receipt.gas_used(),
            status: receipt.status(),
            gas_fee_cap: tx.max_fee_per_gas(),
            gas_tip_cap: tx.max_priority_fee_per_gas().unwrap_or_default(),
            input: tx.input().clone(),
            nonce: if tx.nonce() == 0 { deposit_nonce.unwrap_or(0) } else { tx.nonce() },
            transaction_index: receipt.transaction_index().unwrap_or(0),
            value: tx.value(),
        }
    }
}

// ─── Event / Trace types ──────────────────────────────────────────────────────

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DebankEvent {
    pub id: String,
    pub contract_id: Address,
    pub selector: String,
    pub topics: Vec<String>,
    pub data: Bytes,
    pub parent_trace_id: String,
    pub pos_in_parent_trace: usize,
    pub idx: usize,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct DebankTrace {
    pub id: String,
    pub from_addr: Address,
    pub gas_limit: u64,
    pub input: Bytes,
    pub to_addr: Address,
    pub value: U256,
    pub gas_used: u64,
    pub output: Bytes,
    #[serde(rename = "type")]
    pub call_create_type: String,
    pub call_type: String,
    pub tx_id: String,
    pub parent_trace_id: String,
    pub pos_in_parent_trace: usize,
    pub self_storage_change: bool,
    pub storage_change: bool,
    pub subtraces: usize,
    pub trace_address: Vec<usize>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct BlockValidation {
    pub validation_hash: i64,
    pub is_fork: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
#[serde(default)]
pub struct BlockFile {
    pub block: DebankBlock,
    #[serde(rename = "txs")]
    pub transactions: Vec<DebankTransaction>,
    pub events: Vec<DebankEvent>,
    pub traces: Vec<DebankTrace>,
    pub error_events: Vec<DebankEvent>,
    pub error_traces: Vec<DebankTrace>,
    pub storage_contracts: Vec<Address>,
}

impl BlockFile {
    pub fn validation(&self) -> BlockValidation {
        let mut ids = Vec::new();
        ids.push(self.block.id.to_string());
        for transaction in self.transactions.iter() {
            ids.push(transaction.id.to_string());
        }
        for event in self.events.iter() {
            ids.push(event.id.clone())
        }
        for trace in self.traces.iter() {
            ids.push(trace.id.clone())
        }
        BlockValidation { validation_hash: calc_validation_hash(&ids), is_fork: false }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub struct DebankOutPut {
    pub block_file: BlockFile,
    pub header: Header,
    pub state_diff: Bytes,
    pub validation_hash: i64,
}

// ─── ID helpers ───────────────────────────────────────────────────────────────

pub trait DebankID {
    fn debank_id(&self) -> String;

    fn calculate_id(args: Vec<&str>) -> String {
        use md5::Digest as _;
        let mut hasher = md5::Md5::new();
        for arg in args {
            hasher.update(arg.as_bytes());
        }
        let result = hasher.finalize();
        format!("{:x}", result)
    }
}

impl DebankID for DebankEvent {
    fn debank_id(&self) -> String {
        Self::calculate_id(vec![&self.parent_trace_id, &self.pos_in_parent_trace.to_string()])
    }
}

impl DebankID for DebankTrace {
    fn debank_id(&self) -> String {
        Self::calculate_id(vec![
            &self.tx_id,
            &self.parent_trace_id,
            &self.pos_in_parent_trace.to_string(),
        ])
    }
}

// ─── Error formatting ─────────────────────────────────────────────────────────

pub(crate) fn fmt_error_msg(res: InstructionResult) -> Option<String> {
    if res.is_ok() {
        return None;
    }
    let msg = match res {
        InstructionResult::Revert => "Reverted".to_string(),
        InstructionResult::OutOfGas |
        InstructionResult::PrecompileOOG |
        InstructionResult::MemoryOOG |
        InstructionResult::MemoryLimitOOG |
        InstructionResult::InvalidOperandOOG |
        InstructionResult::ReentrancySentryOOG => "Out of gas".to_string(),
        InstructionResult::OutOfFunds => "Insufficient balance for transfer".to_string(),
        InstructionResult::OpcodeNotFound | InstructionResult::InvalidFEOpcode => {
            "Bad instruction".to_string()
        }
        InstructionResult::StackOverflow => "Out of stack".to_string(),
        InstructionResult::InvalidJump => "Bad jump destination".to_string(),
        InstructionResult::PrecompileError => "Built-in failed".to_string(),
        status => format!("{status:?}"),
    };
    Some(msg)
}

// ─── From CallTraceNode ───────────────────────────────────────────────────────

impl From<&CallTraceNode> for DebankTrace {
    fn from(call_trace: &CallTraceNode) -> Self {
        let trace = &call_trace.trace;
        let call_create_type = match trace.kind {
            CallKind::Call |
            CallKind::StaticCall |
            CallKind::CallCode |
            CallKind::DelegateCall |
            CallKind::AuthCall => "call".to_string(),
            CallKind::Create => "create".to_string(),
            CallKind::Create2 => "create2".to_string(),
        };
        let mut call_type = "".to_string();
        if call_create_type == "call" {
            call_type = trace.kind.to_string().to_lowercase();
        }
        let error = trace.status.and_then(fmt_error_msg);
        let mut debank_trace = Self {
            id: "".to_string(),
            from_addr: trace.caller,
            gas_limit: trace.gas_limit,
            input: trace.data.clone(),
            to_addr: trace.address,
            value: trace.value,
            gas_used: trace.gas_used,
            output: trace.output.clone(),
            call_create_type,
            call_type,
            subtraces: call_trace.children.len(),
            error: error.unwrap_or_default(),
            ..Default::default()
        };
        for op in trace.steps.iter() {
            if op.op == OpCode::SSTORE {
                debank_trace.self_storage_change = true;
                debank_trace.storage_change = true;
                break;
            }
        }
        debank_trace
    }
}

impl From<&CallLog> for DebankEvent {
    fn from(log: &CallLog) -> Self {
        let selector = log.raw_log.topics().first().map(|h| h.to_string()).unwrap_or_default();
        let topics = if log.raw_log.topics().len() > 1 {
            log.raw_log.topics()[1..].iter().map(|h| h.to_string()).collect()
        } else {
            vec![]
        };
        Self { selector, topics, data: log.raw_log.data.clone(), ..Default::default() }
    }
}

// ─── Trace building ───────────────────────────────────────────────────────────

enum DebankTraceOrLog {
    Trace(Box<DebankTraceNode>),
    Log(DebankEvent),
}

struct DebankTraceNode {
    trace: DebankTrace,
    children: Vec<DebankTraceOrLog>,
    success: bool,
}

#[allow(clippy::too_many_arguments)]
fn build_trace_node(
    tx_id: String,
    parent_trace_id: String,
    pos_in_parent_trace: usize,
    node: &CallTraceNode,
    nodes: &Vec<CallTraceNode>,
    parent_success: bool,
    trace_address: Vec<usize>,
    log_index: &mut usize,
) -> DebankTraceNode {
    let mut debank_node = DebankTraceNode {
        trace: node.into(),
        children: Vec::new(),
        success: node.trace.success && parent_success,
    };
    debank_node.trace.trace_address = trace_address.clone();
    debank_node.trace.parent_trace_id = parent_trace_id;
    debank_node.trace.pos_in_parent_trace = pos_in_parent_trace;
    debank_node.trace.tx_id = tx_id.clone();
    debank_node.trace.id = debank_node.trace.debank_id();

    let id = debank_node.trace.id.clone();
    let contract_id = node.execution_address();

    let mut child_trace_address = Vec::new();
    for pos in node.ordering.iter() {
        match &pos {
            TraceMemberOrder::Call(i) => {
                let child_node = &nodes[node.children[*i]];
                let mut trace_address = trace_address.clone();
                trace_address.push(*i);
                child_trace_address = trace_address.clone();
                let child_trace = build_trace_node(
                    tx_id.clone(),
                    id.clone(),
                    debank_node.children.len(),
                    child_node,
                    nodes,
                    parent_success && debank_node.success,
                    trace_address,
                    log_index,
                );
                if child_trace.trace.storage_change && child_node.trace.success {
                    debank_node.trace.storage_change = true;
                }
                debank_node.children.push(DebankTraceOrLog::Trace(Box::new(child_trace)));
            }
            TraceMemberOrder::Log(i) => {
                let mut child_event: DebankEvent = (&node.logs[*i]).into();
                child_event.pos_in_parent_trace = debank_node.children.len();
                child_event.contract_id = contract_id;
                child_event.parent_trace_id = id.clone();
                child_event.id = child_event.debank_id();
                child_event.idx = *log_index;
                if debank_node.success {
                    *log_index += 1;
                }
                debank_node.children.push(DebankTraceOrLog::Log(child_event));
            }
            _ => {}
        }
    }

    // selfdestructs are not recorded as individual call traces but are derived from
    // the call trace and are added as additional `TransactionTrace` objects
    if node.is_selfdestruct() {
        if let Some(last) = child_trace_address.last_mut() {
            *last += 1;
        }
        debank_node.trace.subtraces += 1;
        let mut selfdestruct_trace = DebankTrace {
            from_addr: node.trace.selfdestruct_address.unwrap_or_default(),
            to_addr: node.trace.selfdestruct_refund_target.unwrap_or_default(),
            value: node.trace.selfdestruct_transferred_value.unwrap_or_default(),
            trace_address: child_trace_address,
            parent_trace_id: id,
            pos_in_parent_trace: debank_node.children.len(),
            tx_id,
            call_create_type: "suicide".to_string(),
            ..Default::default()
        };
        selfdestruct_trace.id = selfdestruct_trace.debank_id();
        debank_node.children.push(DebankTraceOrLog::Trace(Box::new(DebankTraceNode {
            trace: selfdestruct_trace,
            children: vec![],
            success: parent_success && debank_node.success,
        })));
    }
    debank_node
}

fn finish_build_traces(
    node: &mut DebankTraceNode,
    traces: &mut Vec<DebankTrace>,
    error_traces: &mut Vec<DebankTrace>,
    events: &mut Vec<DebankEvent>,
    error_events: &mut Vec<DebankEvent>,
) {
    if node.success {
        traces.push(node.trace.clone());
    } else {
        error_traces.push(node.trace.clone());
    }

    for child in node.children.iter_mut() {
        match child {
            DebankTraceOrLog::Trace(trace) => {
                trace.trace.parent_trace_id = node.trace.id.clone();
                finish_build_traces(trace, traces, error_traces, events, error_events);
            }
            DebankTraceOrLog::Log(log) => {
                if node.success {
                    events.push(log.clone());
                } else {
                    error_events.push(log.clone());
                }
            }
        }
    }
}

pub fn build_debank_traces(
    tx_id: H256,
    traces: CallTraceArena,
    log_index: &std::cell::RefCell<usize>,
) -> (Vec<DebankTrace>, Vec<DebankTrace>, Vec<DebankEvent>, Vec<DebankEvent>) {
    let nodes = traces.into_nodes();
    if nodes.is_empty() {
        return (vec![], vec![], vec![], vec![]);
    }
    let mut top = build_trace_node(
        tx_id.to_string(),
        "".to_string(),
        0,
        &nodes[0],
        &nodes,
        true,
        vec![],
        &mut log_index.borrow_mut(),
    );
    let mut traces = vec![];
    let mut error_traces = vec![];
    let mut events = vec![];
    let mut error_events = vec![];
    finish_build_traces(&mut top, &mut traces, &mut error_traces, &mut events, &mut error_events);
    (traces, error_traces, events, error_events)
}

/// Build genesis transactions and traces from genesis alloc.
pub fn build_genesis_txs_and_traces(
    genesis: &Genesis,
) -> (Vec<DebankTransaction>, Vec<DebankTrace>) {
    let zero_addr = Address::ZERO;
    let mut tx_idx: u64 = 0;
    let mut txs = Vec::new();
    let mut traces = Vec::new();

    let mut sorted_addrs: Vec<&Address> = genesis.alloc.keys().collect();
    sorted_addrs.sort_by_key(|address| address.to_string().to_lowercase());

    for addr in sorted_addrs {
        let account = &genesis.alloc[addr];
        let addr_lower = format!("{:?}", addr).to_lowercase();

        if account.balance > U256::ZERO {
            let tx_id = format!("0xgenesis01{:013}{}", 0, addr_lower);
            let tx = DebankTransaction {
                id: tx_id.clone(),
                from: zero_addr,
                to: *addr,
                gas_limit: 0,
                gas_price: 0,
                gas_used: 0,
                status: true,
                gas_fee_cap: 0,
                gas_tip_cap: 0,
                input: Bytes::default(),
                nonce: 0,
                transaction_index: tx_idx,
                value: account.balance,
            };
            txs.push(tx);

            let trace_id = DebankTrace::calculate_id(vec![&tx_id, "", "0"]);
            let trace = DebankTrace {
                id: trace_id,
                from_addr: zero_addr,
                gas_limit: 0,
                input: Bytes::default(),
                to_addr: *addr,
                value: account.balance,
                gas_used: 0,
                output: Bytes::default(),
                call_create_type: "call".to_string(),
                call_type: "call".to_string(),
                tx_id,
                parent_trace_id: "".to_string(),
                pos_in_parent_trace: 0,
                self_storage_change: false,
                storage_change: false,
                subtraces: 0,
                trace_address: vec![],
                error: "".to_string(),
            };
            traces.push(trace);
            tx_idx += 1;
        }

        if let Some(ref code) = account.code &&
            !code.is_empty()
        {
            let tx_id = format!("0xgenesis02{:013}{}", 0, addr_lower);
            let tx = DebankTransaction {
                id: tx_id.clone(),
                from: zero_addr,
                to: *addr,
                gas_limit: 0,
                gas_price: 0,
                gas_used: 0,
                status: true,
                gas_fee_cap: 0,
                gas_tip_cap: 0,
                input: code.clone(),
                nonce: 0,
                transaction_index: tx_idx,
                value: U256::ZERO,
            };
            txs.push(tx);

            let trace_id = DebankTrace::calculate_id(vec![&tx_id, "", "0"]);
            let trace = DebankTrace {
                id: trace_id,
                from_addr: zero_addr,
                gas_limit: 0,
                input: code.clone(),
                to_addr: *addr,
                value: U256::ZERO,
                gas_used: 0,
                output: code.clone(),
                call_create_type: "create".to_string(),
                call_type: "".to_string(),
                tx_id,
                parent_trace_id: "".to_string(),
                pos_in_parent_trace: 0,
                self_storage_change: false,
                storage_change: false,
                subtraces: 0,
                trace_address: vec![],
                error: "".to_string(),
            };
            traces.push(trace);
            tx_idx += 1;
        }
    }

    // Native token contract (0xeeee...eeee)
    let native_token_addr =
        Address::from_str("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
    let native_token_addr_lower = format!("{:?}", native_token_addr).to_lowercase();
    let native_token_tx_id = format!("0xgenesis03{:013}{}", 0, native_token_addr_lower);

    txs.push(DebankTransaction {
        id: native_token_tx_id.clone(),
        from: zero_addr,
        to: native_token_addr,
        gas_limit: 0,
        gas_price: 0,
        gas_used: 0,
        status: true,
        gas_fee_cap: 0,
        gas_tip_cap: 0,
        input: Bytes::default(),
        nonce: 0,
        transaction_index: tx_idx,
        value: U256::ZERO,
    });

    let native_token_trace_id = DebankTrace::calculate_id(vec![&native_token_tx_id, "", "0"]);
    traces.push(DebankTrace {
        id: native_token_trace_id,
        from_addr: zero_addr,
        gas_limit: 0,
        input: Bytes::default(),
        to_addr: native_token_addr,
        value: U256::ZERO,
        gas_used: 0,
        output: Bytes::default(),
        call_create_type: "create".to_string(),
        call_type: "".to_string(),
        tx_id: native_token_tx_id,
        parent_trace_id: "".to_string(),
        pos_in_parent_trace: 0,
        self_storage_change: false,
        storage_change: false,
        subtraces: 0,
        trace_address: vec![],
        error: "".to_string(),
    });

    (txs, traces)
}

#[cfg(test)]
mod tests {
    use super::*;
    use revm::{database_interface::EmptyDB, state::AccountInfo};

    #[test]
    fn replay_bundle_diff_uses_only_final_changed_values() {
        let address = Address::with_last_byte(0x11);
        let changed_key = U256::from(1);
        let unchanged_key = U256::from(2);
        let mut storage = revm::primitives::HashMap::default();
        storage.insert(changed_key, (U256::from(3), U256::from(4)));
        storage.insert(unchanged_key, (U256::from(5), U256::from(5)));

        let original = AccountInfo { balance: U256::from(10), ..Default::default() };
        let present = AccountInfo { balance: U256::from(12), ..Default::default() };
        let bundle = BundleState::builder(0..=0)
            .state_original_account_info(address, original)
            .state_present_account_info(address, present)
            .state_storage(address, storage)
            .build();

        assert_eq!(get_storage_contracts_from_bundle(&bundle), [address]);
        let diff = get_storage_diffs_from_bundle(bundle, EmptyDB::default()).unwrap();

        assert_eq!(diff.new_accounts.len(), 1);
        assert_eq!(diff.new_accounts[0].balance, U256::from(12));
        assert_eq!(diff.storage_diffs.len(), 1);
        assert_eq!(diff.storage_diffs[0].diffs.len(), 1);
        assert_eq!(
            diff.storage_diffs[0].diffs[0].index,
            keccak256(changed_key.to_be_bytes::<32>())
        );
        assert_eq!(diff.storage_diffs[0].diffs[0].value, U256::from(4));
    }
}
