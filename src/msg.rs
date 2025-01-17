use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, CustomMsg, Uint256};

#[cw_serde]
pub struct InstantiateMsg {
    pub retry_delay: u64,
    pub job_id: String,
    pub creator: String,
    pub signers: Vec<String>,
}

#[cw_serde]
pub enum ExecuteMsg {
    ReceiveFromBridgeUsdc {
        message: String,
        signature: String,
        receiver: String,
    },
    ReceiveFromBridgeOther {
        message: String,
        signature: String,
        receiver: String,
        ctoken: String,
        dex: String,
        payload: String,
    },
    SetPaloma {},
    UpdateCompass {
        new_compass: String,
    },
    UpdateBlueprint {
        new_blueprint: String,
    },
    UpdateRefundWallet {
        new_refund_wallet: String,
    },
    UpdateGasFee {
        new_gas_fee: Uint256,
    },
    UpdateServiceFeeCollector {
        new_service_fee_collector: String,
    },
    UpdateServiceFee {
        new_service_fee: Uint256,
    },
}

#[cw_serde]
#[derive(Eq)]
pub struct Metadata {
    pub creator: String,
    pub signers: Vec<String>,
}

/// Message struct for cross-chain calls.
#[cw_serde]
pub struct PalomaMsg {
    /// The ID of the paloma scheduled job to run.
    pub job_id: String,
    /// The payload, ABI encoded for the target chain.
    pub payload: Binary,
    /// Metadata
    pub metadata: Metadata,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    // GetCount returns the current count as a json-encoded number
    #[returns(GetJobIdResponse)]
    GetJobId {},
}

// We define a custom struct for each query response
#[cw_serde]
pub struct GetJobIdResponse {
    pub job_id: String,
}

impl CustomMsg for PalomaMsg {}
