use super::tx::RpcCompactTransactionHeaderVerbosity;

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAcceptedTxEntry {
    pub include_transaction_id: bool,
    pub include_index_within_block: bool,
    pub include_compact_transaction: Option<RpcCompactTransactionHeaderVerbosity>,
    pub include_raw_transaction: Option<RpcTransaction>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcMergesetBlockAcceptanceData {
    pub include_merged_block_hash: RpcHash,
    pub include_accepted_transaction_entries: Vec<RpcAcceptedTxEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcAcceptanceData {
    pub include_accepting_chain_block: RpcHash,
    pub include_accepting_blue_score: u64,
    pub include_mergeset_block_acceptance_data: Vec<RpcMergesetBlockAcceptanceData>,
}
