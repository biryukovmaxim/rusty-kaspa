use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcCompactTransactionHeaderVerbosity {
    pub include_version: bool,
    pub include_subnetwork_id: bool,
    pub include_payload: bool,
    pub include_mass: bool,

}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcCompactTransactionVerbosity {
    pub include_compact_header: Option<RpcCompactTransactionHeaderVerbosity>,
    pub include_input_addresses: bool,
    pub include_input_amounts: bool,
    pub include_output_addresses: bool,
    pub include_output_amounts: bool,
}