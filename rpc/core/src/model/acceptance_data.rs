use super::{RpcAddress, RpcHash, RpcSubnetworkId, RpcTransaction, RpcTransactionId, RpcTransactionIndexType, RpcTransactionPayload};


#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAcceptedTxEntry {
    pub transaction_id: RpcTransactionId,
    pub index_within_block: RpcTransactionIndexType,
    pub compact_transaction: Option<RpcAcceptedTxEntryVerbsoseData>,
    pub raw_transaction: Option<RpcTransaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcMergesetBlockAcceptanceData {
    pub merged_block_hash: RpcHash,
    pub accepted_transaction_entries: Option<Vec<RpcAcceptedTxEntry>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAcceptanceData {
    pub accepting_blue_score: u64,
    pub mergeset_block_acceptance_data: Vec<RpcMergesetBlockAcceptanceData>,
}
