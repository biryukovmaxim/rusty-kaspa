pub struct RpcCompactTransactionVerbosity{
    include_header: Option<RpcCompactTransactionHeaderVerbosity>,
    include_inputs: bool,
    include_outputs: bool, 
}

pub struct RpcCompactTransactionHeaderVerbosity{
    include_payload: bool
}