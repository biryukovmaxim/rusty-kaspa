use kaspa_consensus_core::acceptance_data::{AcceptanceData, AcceptedTxEntry, MergesetBlockAcceptanceData};

use crate::{RpcAcceptanceData, RpcAcceptedTxEntry, RpcCompactTransaction, RpcMergesetBlockAcceptanceData, RpcTransaction};

impl From<&AcceptedTxEntry> for RpcAcceptedTxEntry {
    fn from(item: &AcceptedTxEntry) -> Self {
        Self {
            transaction_id: item.transaction_id.clone(),
            index_within_block: item.index_within_block,
            compact_transaction: None,
            raw_transaction: None,
        }
    }
}

impl From<&MergesetBlockAcceptanceData> for RpcMergesetBlockAcceptanceData {
    fn from(item: &MergesetBlockAcceptanceData) -> Self {
        Self {
            merged_block_hash: item.block_hash.clone(),
            accepted_transaction_entries: item.accepted_transaction_entry.iter().map(RpcAcceptedTxEntry::from).collect(),
        }
    }
}

impl From<(Hash, &AcceptanceData)> for RpcAcceptanceData {
    fn from(item: (Hash, &AcceptanceData)) -> Self {
        Self {
            accepting_blue_score: item.1.accepting_blue_score,
            mergeset_block_acceptance_data: item.1.mergeset.iter().map(RpcMergesetBlockAcceptanceData::from).collect()
        }
    }
}