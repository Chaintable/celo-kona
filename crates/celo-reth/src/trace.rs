use crate::{
    debank::{
        BlockFile, BlockStorageDiff, DebankBlock, DebankEvent, DebankID, DebankOutPut, DebankTrace,
        DebankTransaction, build_debank_traces, build_genesis_txs_and_traces,
        get_storage_contracts_from_bundle, get_storage_contracts_from_genesis,
        get_storage_diffs_from_bundle,
    },
    primitives::CeloPrimitives,
};
use alloy_celo_evm::{CeloEvmFactory, cip64_storage::Cip64Storage};
use alloy_consensus::{BlockHeader, transaction::TxHashRef};
use alloy_eips::BlockId;
use alloy_evm::evm::EvmFactoryExt;
use alloy_rpc_types_eth::Header;
use async_trait::async_trait;
use celo_alloy_consensus::CeloTxEnvelope;
use celo_alloy_rpc_types::CeloTransactionReceipt;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use reth_chainspec::{ChainSpecProvider, EthChainSpec};
use reth_evm::ConfigureEvm;
use reth_primitives_traits::RecoveredBlock;
use reth_revm::{database::StateProviderDatabase, db::State};
use reth_rpc_eth_api::{
    EthApiTypes, FromEthApiError, RpcNodeCore, RpcTypes,
    helpers::{EthBlocks, LoadReceipt, TraceExt},
};
use reth_rpc_eth_types::{EthApiError, cache::db::StateCacheDb};
use revm::{context_interface::Block, database::states::bundle_state::BundleRetention};
use revm_bytecode::opcode::OpCode;
use revm_inspectors::tracing::{OpcodeFilter, TracingInspector, TracingInspectorConfig};
use std::collections::HashMap;

/// Adds per-transaction CIP-64 metadata capture to the EVM factory used by this trace replay.
pub trait CeloTraceEvmFactory: Clone {
    fn with_trace_cip64_storage(self, storage: Cip64Storage) -> Self;
}

impl CeloTraceEvmFactory for CeloEvmFactory {
    fn with_trace_cip64_storage(self, storage: Cip64Storage) -> Self {
        self.with_cip64_trace_storage(storage)
    }
}

#[rpc(server, namespace = "trace")]
pub trait CeloDebankTraceApi {
    #[method(name = "debankBlock")]
    async fn debank_block(&self, block_id: BlockId) -> RpcResult<DebankOutPut>;
}

#[derive(Debug)]
pub struct CeloDebankTraceApiImpl<Eth> {
    eth: Eth,
}

impl<Eth> CeloDebankTraceApiImpl<Eth> {
    pub const fn new(eth: Eth) -> Self {
        Self { eth }
    }
}

fn get_deposit_nonce(receipt: &CeloTransactionReceipt) -> Option<u64> {
    receipt.inner.inner.deposit_nonce()
}

fn get_l1_fee(receipt: &CeloTransactionReceipt, tx: &CeloTxEnvelope) -> Option<u128> {
    // A non-native CIP-64 receipt reports effective_gas_price in fee-currency units, while
    // l1_fee remains native-denominated. Do not mix the two units in DebankTransaction.gas_price.
    if let CeloTxEnvelope::Cip64(signed) = tx &&
        signed
            .tx()
            .fee_currency
            .is_some_and(|fee_currency| fee_currency != alloy_primitives::Address::ZERO)
    {
        return None;
    }
    receipt.l1_block_info.l1_fee
}

#[async_trait]
impl<Eth> CeloDebankTraceApiServer for CeloDebankTraceApiImpl<Eth>
where
    Eth: TraceExt + EthBlocks + LoadReceipt + 'static,
    Eth: RpcNodeCore<Primitives = CeloPrimitives>,
    <Eth as EthApiTypes>::NetworkTypes: RpcTypes<Receipt = CeloTransactionReceipt>,
    <Eth as RpcNodeCore>::Provider: ChainSpecProvider<ChainSpec: EthChainSpec>,
    reth_evm::EvmFactoryFor<Eth::Evm>: CeloTraceEvmFactory,
{
    async fn debank_block(&self, block_id: BlockId) -> RpcResult<DebankOutPut> {
        Ok(self.trace_debank_block_inner(block_id).await.map_err(Into::into)?)
    }
}

impl<Eth> CeloDebankTraceApiImpl<Eth>
where
    Eth: TraceExt + EthBlocks + LoadReceipt + 'static,
    Eth: RpcNodeCore<Primitives = CeloPrimitives>,
    <Eth as EthApiTypes>::NetworkTypes: RpcTypes<Receipt = CeloTransactionReceipt>,
    <Eth as RpcNodeCore>::Provider: ChainSpecProvider<ChainSpec: EthChainSpec>,
    reth_evm::EvmFactoryFor<Eth::Evm>: CeloTraceEvmFactory,
{
    async fn trace_debank_block_inner(
        &self,
        block_id: BlockId,
    ) -> Result<DebankOutPut, Eth::Error> {
        let eth = &self.eth;

        let block = eth.recovered_block(block_id).await?;
        let Some(block) = block else {
            return Err(EthApiError::HeaderNotFound(block_id).into());
        };

        let debank_block: DebankBlock = block.as_ref().into();
        let debank_header = build_rpc_header(&block);

        if block.number() == 0 {
            let chain_spec = reth_rpc_eth_api::RpcNodeCore::provider(eth).chain_spec();
            let genesis = chain_spec.genesis();
            let mut state_diff: BlockStorageDiff = genesis.into();
            state_diff.hash = block.state_root();
            let (transactions, traces) = build_genesis_txs_and_traces(genesis);
            let block_file = BlockFile {
                block: debank_block,
                transactions,
                traces,
                storage_contracts: get_storage_contracts_from_genesis(genesis),
                ..Default::default()
            };
            let validation_hash = block_file.validation().validation_hash;
            return Ok(DebankOutPut {
                block_file,
                header: debank_header,
                state_diff: alloy_rlp::encode(state_diff).into(),
                validation_hash,
            });
        }

        let resolved_block_id = block.hash().into();
        let receipts: Option<Vec<CeloTransactionReceipt>> =
            eth.block_receipts(resolved_block_id).await?;
        let Some(receipts) = receipts else {
            return Err(EthApiError::HeaderNotFound(block_id).into());
        };

        let transactions = &block.body().transactions;
        if receipts.len() != transactions.len() {
            return Err(EthApiError::EvmCustom(format!(
                "transaction/receipt count mismatch for block {}: {} transactions, {} receipts",
                block.hash(),
                transactions.len(),
                receipts.len()
            ))
            .into());
        }

        let mut debank_txs: Vec<DebankTransaction> = Vec::with_capacity(transactions.len());
        for (tx, receipt) in transactions.iter().zip(&receipts) {
            let deposit_nonce = get_deposit_nonce(receipt);
            let l1_fee = get_l1_fee(receipt, tx);
            debank_txs.push(DebankTransaction::from((receipt, tx, deposit_nonce, l1_fee)));
        }

        let parent_block = eth.recovered_block(block.parent_hash().into()).await?;
        let Some(parent_block) = parent_block else {
            return Err(EthApiError::HeaderNotFound(block_id).into());
        };

        let mut block_file =
            BlockFile { block: debank_block, transactions: debank_txs, ..Default::default() };

        if transactions.is_empty() && parent_block.state_root() == block.state_root() {
            let state_diff = BlockStorageDiff {
                hash: block.state_root(),
                parent_hash: parent_block.state_root(),
                ..Default::default()
            };
            let validation_hash = block_file.validation().validation_hash;
            return Ok(DebankOutPut {
                block_file,
                header: debank_header,
                state_diff: alloy_rlp::encode(state_diff).into(),
                validation_hash,
            });
        }

        let (mut trace_results, mut state_diff, change_addresses) =
            trace_all_block(eth, resolved_block_id).await?;

        if trace_results.len() != transactions.len() {
            return Err(EthApiError::EvmCustom(format!(
                "transaction/trace count mismatch for block {}: {} transactions, {} traces",
                block.hash(),
                transactions.len(),
                trace_results.len()
            ))
            .into());
        }

        let mut canonical_log_cursor = 0usize;
        for (((entry, split), receipt), tx) in
            trace_results.iter_mut().zip(&receipts).zip(transactions.iter())
        {
            let receipt_logs = receipt.inner.inner.logs();
            let canonical_start = receipt_logs
                .first()
                .and_then(|log| log.log_index)
                .map_or(canonical_log_cursor, |index| index as usize);
            let hidden_storage_change = is_non_native_cip64(tx);
            if hidden_storage_change && split.is_none() {
                return Err(EthApiError::EvmCustom(format!(
                    "missing CIP-64 trace metadata for transaction {}",
                    tx.tx_hash()
                ))
                .into());
            }
            reconcile_receipt_events(
                entry,
                receipt_logs,
                hidden_storage_change,
                canonical_start,
                *split,
            )
            .map_err(|err| EthApiError::EvmCustom(format!("{}: {err}", tx.tx_hash())))?;
            if let Some(last_log) = receipt_logs.last() {
                canonical_log_cursor = last_log
                    .log_index
                    .map_or(canonical_start + receipt_logs.len(), |index| index as usize + 1);
            }
        }

        for ((trace, error_trace, event, error_event), _) in trace_results.drain(..) {
            block_file.traces.extend(trace);
            block_file.error_traces.extend(error_trace);
            block_file.events.extend(event);
            block_file.error_events.extend(error_event);
        }
        state_diff.hash = block.state_root();
        state_diff.parent_hash = parent_block.state_root();
        block_file.storage_contracts = change_addresses;
        let validation_hash = block_file.validation().validation_hash;

        Ok(DebankOutPut {
            block_file,
            header: debank_header,
            state_diff: alloy_rlp::encode(state_diff).into(),
            validation_hash,
        })
    }
}

fn build_rpc_header<B>(block: &RecoveredBlock<B>) -> Header
where
    B: reth_primitives_traits::Block,
{
    Header {
        inner: alloy_consensus::Header {
            parent_hash: block.header().parent_hash(),
            ommers_hash: block.header().ommers_hash(),
            beneficiary: block.header().beneficiary(),
            state_root: block.header().state_root(),
            transactions_root: block.header().transactions_root(),
            receipts_root: block.header().receipts_root(),
            logs_bloom: block.header().logs_bloom(),
            difficulty: block.header().difficulty(),
            number: block.header().number(),
            gas_limit: block.header().gas_limit(),
            gas_used: block.header().gas_used(),
            timestamp: block.header().timestamp(),
            extra_data: block.header().extra_data().clone(),
            mix_hash: block.header().mix_hash().unwrap_or_default(),
            nonce: block.header().nonce().unwrap_or_default(),
            base_fee_per_gas: block.header().base_fee_per_gas(),
            withdrawals_root: block.header().withdrawals_root(),
            blob_gas_used: block.header().blob_gas_used(),
            excess_blob_gas: block.header().excess_blob_gas(),
            parent_beacon_block_root: block.header().parent_beacon_block_root(),
            requests_hash: block.header().requests_hash(),
            block_access_list_hash: block.header().block_access_list_hash(),
            slot_number: None,
        },
        hash: block.hash(),
        total_difficulty: None,
        size: None,
    }
}

type TraceEntry = (Vec<DebankTrace>, Vec<DebankTrace>, Vec<DebankEvent>, Vec<DebankEvent>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Cip64LogSplit {
    pre: usize,
    post: usize,
}

type TraceResult = (TraceEntry, Option<Cip64LogSplit>);

fn is_non_native_cip64(tx: &CeloTxEnvelope) -> bool {
    matches!(
        tx,
        CeloTxEnvelope::Cip64(signed)
            if signed
                .tx()
                .fee_currency
                .is_some_and(|fee_currency| fee_currency != alloy_primitives::Address::ZERO)
    )
}

fn event_matches_log(event: &DebankEvent, log: &alloy_rpc_types_eth::Log) -> bool {
    event.contract_id == log.address() &&
        event.selector == log.topic0().map(ToString::to_string).unwrap_or_default() &&
        event.topics == log.topics()[1..].iter().map(ToString::to_string).collect::<Vec<_>>() &&
        event.data == log.data().data
}

/// Reconciles inspector events with canonical receipt logs.
///
/// Celo's CIP-64 debit/credit hooks execute as uninspected system calls. Their logs are included
/// in the canonical receipt but are absent from `TracingInspector`, so synthesize only the
/// missing events and attach them to the transaction's root trace. Receipt indexes also repair
/// the insertion index of reverted events, including transactions after a CIP-64 transaction.
fn reconcile_receipt_events(
    entry: &mut TraceEntry,
    receipt_logs: &[alloy_rpc_types_eth::Log],
    hidden_storage_change: bool,
    canonical_log_start: usize,
    split: Option<Cip64LogSplit>,
) -> Result<(), String> {
    let root =
        entry.0.iter_mut().chain(entry.1.iter_mut()).find(|trace| trace.trace_address.is_empty());
    let Some(root) = root else { return Ok(()) };

    if hidden_storage_change {
        root.storage_change = true;
    }
    let root_id = root.id.clone();

    let (main_start, main_end) = if let Some(split) = split {
        let Some(main_end) = receipt_logs.len().checked_sub(split.post) else {
            return Err(format!(
                "invalid CIP-64 receipt split: {} logs, {} pre, {} post",
                receipt_logs.len(),
                split.pre,
                split.post
            ));
        };
        if split.pre > main_end {
            return Err(format!(
                "invalid CIP-64 receipt split: {} logs, {} pre, {} post",
                receipt_logs.len(),
                split.pre,
                split.post
            ));
        }
        (split.pre, main_end)
    } else {
        (0, receipt_logs.len())
    };
    let main_logs = &receipt_logs[main_start..main_end];
    if main_logs.len() != entry.2.len() {
        return Err(format!(
            "inspector/receipt main-log count mismatch: {} inspector logs, {} receipt logs",
            entry.2.len(),
            main_logs.len()
        ));
    }

    let mut success_boundaries = Vec::with_capacity(entry.2.len());
    for (offset, (event, log)) in entry.2.iter_mut().zip(main_logs).enumerate() {
        if !event_matches_log(event, log) {
            return Err(format!("inspector/receipt log mismatch at main-log offset {offset}"));
        }
        let receipt_index = main_start + offset;
        let original_index = event.idx;
        let canonical_index =
            log.log_index.map_or(canonical_log_start + receipt_index, |index| index as usize);
        event.idx = canonical_index;
        success_boundaries.push((original_index, canonical_index));
    }
    success_boundaries.sort_unstable_by_key(|(original_index, _)| *original_index);

    for event in &mut entry.3 {
        event.idx = success_boundaries
            .iter()
            .find(|(original_index, _)| *original_index >= event.idx)
            .map(|(_, canonical_index)| *canonical_index)
            .or_else(|| {
                success_boundaries
                    .last()
                    .map(|(_, canonical_index)| canonical_index.saturating_add(1))
            })
            .unwrap_or(canonical_log_start + main_start);
    }

    if !hidden_storage_change {
        entry.2.sort_by_key(|event| event.idx);
        return Ok(());
    }

    // Debit-hook logs precede main execution. Reserve their exact number of positions at the
    // beginning of the root and recursively re-key the shifted main trace subtree.
    if main_start != 0 {
        shift_root_children(entry, &root_id, main_start);
    }

    let (traces, error_traces, events, error_events) = entry;
    let mut next_position = traces
        .iter()
        .chain(error_traces.iter())
        .filter(|trace| trace.parent_trace_id == root_id)
        .map(|trace| trace.pos_in_parent_trace)
        .chain(
            events
                .iter()
                .chain(error_events.iter())
                .filter(|event| event.parent_trace_id == root_id)
                .map(|event| event.pos_in_parent_trace),
        )
        .max()
        .map_or(0, |position| position + 1);

    for (position, log_index) in (0..main_start).enumerate() {
        let log = &receipt_logs[log_index];
        let mut event =
            receipt_log_to_event(log, root_id.clone(), position, canonical_log_start + log_index);
        event.id = event.debank_id();
        events.push(event);
    }

    for (log_index, log) in receipt_logs.iter().enumerate().skip(main_end) {
        let mut event = receipt_log_to_event(
            log,
            root_id.clone(),
            next_position,
            canonical_log_start + log_index,
        );
        event.id = event.debank_id();
        events.push(event);
        next_position += 1;
    }

    events.sort_by_key(|event| event.idx);
    Ok(())
}

fn receipt_log_to_event(
    log: &alloy_rpc_types_eth::Log,
    parent_trace_id: String,
    pos_in_parent_trace: usize,
    fallback_index: usize,
) -> DebankEvent {
    DebankEvent {
        contract_id: log.address(),
        selector: log.topic0().map(ToString::to_string).unwrap_or_default(),
        topics: log.topics()[1..].iter().map(ToString::to_string).collect(),
        data: log.data().data.clone(),
        parent_trace_id,
        pos_in_parent_trace,
        idx: log.log_index.map_or(fallback_index, |index| index as usize),
        ..Default::default()
    }
}

fn shift_root_children(entry: &mut TraceEntry, root_id: &str, shift: usize) {
    let (traces, error_traces, events, error_events) = entry;
    let mut changed_ids = HashMap::<String, String>::new();

    for trace in traces.iter_mut().chain(error_traces.iter_mut()) {
        let old_id = trace.id.clone();
        let mut changed = false;
        if trace.parent_trace_id == root_id {
            trace.pos_in_parent_trace += shift;
            changed = true;
        } else if let Some(parent_id) = changed_ids.get(&trace.parent_trace_id) {
            trace.parent_trace_id.clone_from(parent_id);
            changed = true;
        }
        if changed {
            trace.id = trace.debank_id();
            changed_ids.insert(old_id, trace.id.clone());
        }
    }

    for event in events.iter_mut().chain(error_events.iter_mut()) {
        let mut changed = false;
        if event.parent_trace_id == root_id {
            event.pos_in_parent_trace += shift;
            changed = true;
        } else if let Some(parent_id) = changed_ids.get(&event.parent_trace_id) {
            event.parent_trace_id.clone_from(parent_id);
            changed = true;
        }
        if changed {
            event.id = event.debank_id();
        }
    }
}

async fn trace_all_block<Eth>(
    eth: &Eth,
    block_id: BlockId,
) -> Result<(Vec<TraceResult>, BlockStorageDiff, Vec<alloy_primitives::Address>), Eth::Error>
where
    Eth: TraceExt + RpcNodeCore + 'static,
    Eth::Error: FromEthApiError,
    reth_evm::BlockEnvFor<Eth::Evm>: Block,
    reth_evm::EvmFactoryFor<Eth::Evm>: CeloTraceEvmFactory,
{
    use reth_rpc_eth_types::cache::db::StateProviderTraitObjWrapper;

    let block = eth.recovered_block(block_id);
    let ((evm_env, _), block) = futures::try_join!(eth.evm_env_at(block_id), block)?;

    let Some(block) = block else {
        return Err(EthApiError::EvmCustom(format!("cannot find block {block_id}")).into());
    };

    let parent_hash = block.parent_hash();

    eth.spawn_blocking_io_fut(move |this| async move {
        let block_hash = block.hash();
        let block_number: u64 = evm_env.block_env.number().saturating_to();
        let base_fee = evm_env.block_env.basefee();

        let post_state = this.state_at_block_id(block_hash.into()).await?;
        let exec_state = this.state_at_block_id(parent_hash.into()).await?;

        let mut db: StateCacheDb = State::builder()
            .with_database(StateProviderDatabase::new(StateProviderTraitObjWrapper(exec_state)))
            .with_bundle_update()
            .build();

        this.apply_pre_execution_changes(&block, &mut db)?;

        let log_index_cell = std::cell::RefCell::new(0usize);
        let mut idx = 0u64;

        let mut trace_cfg = TracingInspectorConfig::default_parity()
            .set_steps(true)
            .set_record_logs(true)
            .set_exclude_precompile_calls(false);
        trace_cfg.record_opcodes_filter = Some(OpcodeFilter::new().enabled(OpCode::SSTORE));

        let trace_cip64_storage = Cip64Storage::default();
        let trace_factory = this
            .evm_config()
            .evm_factory()
            .clone()
            .with_trace_cip64_storage(trace_cip64_storage.clone());
        let results: Vec<TraceResult> = trace_factory
            .create_tracer(&mut db, evm_env, TracingInspector::new(trace_cfg))
            .try_trace_many(block.transactions_recovered(), |mut ctx| {
                use alloy_rpc_types_eth::TransactionInfo;
                let tx_info = TransactionInfo {
                    hash: Some(*ctx.tx.tx_hash()),
                    index: Some(idx),
                    block_hash: Some(block_hash),
                    block_number: Some(block_number),
                    base_fee: Some(base_fee),
                    block_timestamp: Some(block.timestamp()),
                };
                idx += 1;
                let traces = build_debank_traces(
                    tx_info.hash.unwrap(),
                    ctx.take_inspector().into_traces(),
                    &log_index_cell,
                );
                let split =
                    trace_cip64_storage.pop_cip64_receipt_data().map(|data| Cip64LogSplit {
                        pre: data.cip64_info.logs_pre.len(),
                        post: data.cip64_info.logs_post.len(),
                    });
                Ok::<_, Eth::Error>((traces, split))
            })
            .commit_last_tx()
            .collect::<Result<_, _>>()?;

        db.merge_transitions(BundleRetention::PlainState);
        let bundle = db.take_bundle();
        let change_addresses = get_storage_contracts_from_bundle(&bundle);
        let storage_diff = get_storage_diffs_from_bundle(
            bundle,
            StateProviderDatabase::new(StateProviderTraitObjWrapper(post_state)),
        )
        .map_err(|err| {
            Eth::Error::from_eth_err(EthApiError::EvmCustom(format!(
                "failed to build state diff from replayed block: {err}"
            )))
        })?;
        Ok((results, storage_diff, change_addresses))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, B256, Bytes, LogData};

    fn rpc_log(
        address: Address,
        selector: B256,
        data: &[u8],
        log_index: u64,
    ) -> alloy_rpc_types_eth::Log {
        alloy_rpc_types_eth::Log {
            inner: alloy_primitives::Log {
                address,
                data: LogData::new_unchecked(vec![selector], Bytes::copy_from_slice(data)),
            },
            log_index: Some(log_index),
            ..Default::default()
        }
    }

    #[test]
    fn reconcile_receipt_events_adds_hidden_cip64_logs_once() {
        let root_id = "root".to_string();
        let root = DebankTrace { id: root_id.clone(), trace_address: vec![], ..Default::default() };

        let pre = rpc_log(Address::with_last_byte(1), B256::with_last_byte(1), b"pre", 5);
        let main = rpc_log(Address::with_last_byte(2), B256::with_last_byte(2), b"main", 6);
        let post = rpc_log(Address::with_last_byte(3), B256::with_last_byte(3), b"post", 7);

        let mut main_event = DebankEvent {
            contract_id: main.address(),
            selector: main.topic0().unwrap().to_string(),
            data: main.data().data.clone(),
            parent_trace_id: root_id,
            pos_in_parent_trace: 0,
            ..Default::default()
        };
        main_event.id = main_event.debank_id();

        let mut entry = (vec![root], vec![], vec![main_event], vec![]);
        reconcile_receipt_events(
            &mut entry,
            &[pre, main, post],
            true,
            5,
            Some(Cip64LogSplit { pre: 1, post: 1 }),
        )
        .unwrap();

        assert_eq!(entry.2.len(), 3);
        assert_eq!(entry.2.iter().map(|event| event.idx).collect::<Vec<_>>(), [5, 6, 7]);
        assert_eq!(
            entry.2.iter().map(|event| event.pos_in_parent_trace).collect::<Vec<_>>(),
            [0, 1, 2]
        );
        assert_eq!(
            entry.2.iter().filter(|event| event.contract_id == Address::with_last_byte(2)).count(),
            1
        );
        assert!(entry.0[0].storage_change);
    }

    #[test]
    fn reconcile_receipt_events_offsets_later_reverted_events() {
        let root_id = "failed-root".to_string();
        let root = DebankTrace { id: root_id.clone(), trace_address: vec![], ..Default::default() };
        let mut error_event = DebankEvent {
            parent_trace_id: root_id,
            // The inspector saw one successful main log in the preceding transaction.
            idx: 1,
            ..Default::default()
        };
        error_event.id = error_event.debank_id();

        let mut entry = (vec![], vec![root], vec![], vec![error_event]);
        // The preceding CIP-64 receipt contained three canonical logs (pre/main/post), so this
        // transaction's first reverted event belongs at canonical insertion index 3.
        reconcile_receipt_events(&mut entry, &[], false, 3, None).unwrap();

        assert_eq!(entry.3[0].idx, 3);
    }

    #[test]
    fn reconcile_receipt_events_rekeys_shifted_trace_subtree() {
        let root_id = "root".to_string();
        let root = DebankTrace { id: root_id.clone(), trace_address: vec![], ..Default::default() };
        let mut child = DebankTrace {
            tx_id: "tx".to_string(),
            parent_trace_id: root_id,
            pos_in_parent_trace: 0,
            trace_address: vec![0],
            ..Default::default()
        };
        child.id = child.debank_id();
        let old_child_id = child.id.clone();
        let mut grandchild = DebankTrace {
            tx_id: "tx".to_string(),
            parent_trace_id: child.id.clone(),
            pos_in_parent_trace: 0,
            trace_address: vec![0, 0],
            ..Default::default()
        };
        grandchild.id = grandchild.debank_id();
        let old_grandchild_id = grandchild.id.clone();

        let pre = rpc_log(Address::with_last_byte(1), B256::with_last_byte(1), b"pre", 0);
        let main = rpc_log(Address::with_last_byte(2), B256::with_last_byte(2), b"main", 1);
        let post = rpc_log(Address::with_last_byte(3), B256::with_last_byte(3), b"post", 2);
        let mut main_event = DebankEvent {
            contract_id: main.address(),
            selector: main.topic0().unwrap().to_string(),
            data: main.data().data.clone(),
            parent_trace_id: grandchild.id.clone(),
            pos_in_parent_trace: 0,
            ..Default::default()
        };
        main_event.id = main_event.debank_id();

        let mut entry = (vec![root, child, grandchild], vec![], vec![main_event], vec![]);
        reconcile_receipt_events(
            &mut entry,
            &[pre, main, post],
            true,
            0,
            Some(Cip64LogSplit { pre: 1, post: 1 }),
        )
        .unwrap();

        assert_eq!(entry.0[1].pos_in_parent_trace, 1);
        assert_ne!(entry.0[1].id, old_child_id);
        assert_eq!(entry.0[2].parent_trace_id, entry.0[1].id);
        assert_ne!(entry.0[2].id, old_grandchild_id);
        let main_event =
            entry.2.iter().find(|event| event.contract_id == Address::with_last_byte(2)).unwrap();
        assert_eq!(main_event.parent_trace_id, entry.0[2].id);
    }

    #[test]
    fn reconcile_receipt_events_places_cip64_error_between_fee_logs() {
        let root_id = "failed-root".to_string();
        let root = DebankTrace { id: root_id.clone(), trace_address: vec![], ..Default::default() };
        let mut error_event =
            DebankEvent { parent_trace_id: root_id, pos_in_parent_trace: 0, ..Default::default() };
        error_event.id = error_event.debank_id();
        let pre = rpc_log(Address::with_last_byte(1), B256::with_last_byte(1), b"pre", 5);
        let post = rpc_log(Address::with_last_byte(2), B256::with_last_byte(2), b"post", 6);

        let mut entry = (vec![], vec![root], vec![], vec![error_event]);
        reconcile_receipt_events(
            &mut entry,
            &[pre, post],
            true,
            5,
            Some(Cip64LogSplit { pre: 1, post: 1 }),
        )
        .unwrap();

        assert_eq!(entry.3[0].idx, 6);
        assert_eq!(entry.3[0].pos_in_parent_trace, 1);
        assert_eq!(
            entry.2.iter().map(|event| event.pos_in_parent_trace).collect::<Vec<_>>(),
            [0, 2]
        );
    }

    #[test]
    fn reconcile_receipt_events_uses_split_for_duplicate_logs() {
        let root_id = "root".to_string();
        let root = DebankTrace { id: root_id.clone(), trace_address: vec![], ..Default::default() };
        let duplicate = rpc_log(Address::with_last_byte(1), B256::with_last_byte(1), b"same", 0);
        let mut main = duplicate.clone();
        main.log_index = Some(1);
        let post = rpc_log(Address::with_last_byte(2), B256::with_last_byte(2), b"post", 2);
        let mut main_event = DebankEvent {
            contract_id: main.address(),
            selector: main.topic0().unwrap().to_string(),
            data: main.data().data.clone(),
            parent_trace_id: root_id,
            ..Default::default()
        };
        main_event.id = main_event.debank_id();

        let mut entry = (vec![root], vec![], vec![main_event], vec![]);
        reconcile_receipt_events(
            &mut entry,
            &[duplicate, main, post],
            true,
            0,
            Some(Cip64LogSplit { pre: 1, post: 1 }),
        )
        .unwrap();

        let main_event = entry
            .2
            .iter()
            .find(|event| event.contract_id == Address::with_last_byte(1) && event.idx == 1)
            .unwrap();
        assert_eq!(main_event.pos_in_parent_trace, 1);
    }
}
