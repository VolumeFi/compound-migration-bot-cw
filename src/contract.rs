#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, StdResult,
};
use cw2::set_contract_version;

use crate::error::ContractError;
use crate::msg::{ExecuteMsg, GetJobIdResponse, InstantiateMsg, Metadata, PalomaMsg, QueryMsg};
use crate::state::{State, STATE};
use cosmwasm_std::CosmosMsg;
use ethabi::{Contract, Function, Param, ParamType, StateMutability, Token, Uint};
use std::collections::BTreeMap;
use std::str::FromStr;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:llammalend-leverage-cw";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<Empty>, ContractError> {
    let state = State {
        retry_delay: msg.retry_delay,
        job_id: msg.job_id.clone(),
        owner: info.sender.clone(),
        metadata: Metadata {
            creator: msg.creator,
            signers: msg.signers,
        },
    };
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    STATE.save(deps.storage, &state)?;
    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("job_id", msg.job_id))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<PalomaMsg>, ContractError> {
    match msg {
        ExecuteMsg::ReceiveFromBridgeUsdc {
            message,
            signature,
            receiver,
        } => execute::receive_from_bridge_usdc(deps, env, info, message, signature, receiver),
        ExecuteMsg::ReceiveFromBridgeOther {
            message,
            signature,
            receiver,
            ctoken,
            dex,
            payload,
        } => execute::receive_from_bridge_other(
            deps, env, info, message, signature, receiver, ctoken, dex, payload,
        ),
        ExecuteMsg::SetPaloma {} => execute::set_paloma(deps, info),
        ExecuteMsg::UpdateCompass { new_compass } => {
            execute::update_compass(deps, info, new_compass)
        }
        ExecuteMsg::UpdateBlueprint { new_blueprint } => {
            execute::update_blueprint(deps, info, new_blueprint)
        }
        ExecuteMsg::UpdateRefundWallet { new_refund_wallet } => {
            execute::update_refund_wallet(deps, info, new_refund_wallet)
        }
        ExecuteMsg::UpdateGasFee { new_gas_fee } => {
            execute::update_gas_fee(deps, info, new_gas_fee)
        }
        ExecuteMsg::UpdateServiceFeeCollector {
            new_service_fee_collector,
        } => execute::update_service_fee_collector(deps, info, new_service_fee_collector),
        ExecuteMsg::UpdateServiceFee { new_service_fee } => {
            execute::update_service_fee(deps, info, new_service_fee)
        }
    }
}

pub mod execute {
    use super::*;
    use crate::state::WITHDRAW_TIMESTAMP;
    use crate::ContractError::{AllPending, Unauthorized};
    use cosmwasm_std::Uint256;
    use ethabi::Address;

    #[allow(clippy::too_many_arguments)]
    pub fn receive_from_bridge_usdc(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        message: String,
        signature: String,
        receiver: String,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "receive_from_bridge_usdc".to_string(),
                vec![Function {
                    name: "receive_from_bridge_usdc".to_string(),
                    inputs: vec![
                        Param {
                            name: "message".to_string(),
                            kind: ParamType::Bytes,
                            internal_type: None,
                        },
                        Param {
                            name: "signature".to_string(),
                            kind: ParamType::Bytes,
                            internal_type: None,
                        },
                        Param {
                            name: "receiver".to_string(),
                            kind: ParamType::Address,
                            internal_type: None,
                        },
                    ],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };
        let mut tokens: Vec<Token> = vec![];
        let retry_delay: u64 = state.retry_delay;
        if let Some(timestamp) =
            WITHDRAW_TIMESTAMP.may_load(deps.storage, (message.clone(), signature.clone()))?
        {
            if timestamp.plus_seconds(retry_delay).lt(&env.block.time) {
                tokens.push(Token::Bytes(hex::decode(message.clone()).unwrap()));
                tokens.push(Token::Bytes(hex::decode(signature.clone()).unwrap()));
                tokens.push(Token::Address(
                    Address::from_str(receiver.as_str()).unwrap(),
                ));
                WITHDRAW_TIMESTAMP.save(deps.storage, (message, signature), &env.block.time)?;
            }
        } else {
            tokens.push(Token::Bytes(hex::decode(message.clone()).unwrap()));
            tokens.push(Token::Bytes(hex::decode(signature.clone()).unwrap()));
            tokens.push(Token::Address(
                Address::from_str(receiver.as_str()).unwrap(),
            ));
            WITHDRAW_TIMESTAMP.save(deps.storage, (message, signature), &env.block.time)?;
        }
        if tokens.is_empty() {
            Err(AllPending {})
        } else {
            Ok(Response::new()
                .add_message(CosmosMsg::Custom(PalomaMsg {
                    job_id: state.job_id,
                    payload: Binary::new(
                        contract
                            .function("receive_from_bridge_usdc")
                            .unwrap()
                            .encode_input(tokens.as_slice())
                            .unwrap(),
                    ),
                    metadata: state.metadata,
                }))
                .add_attribute("action", "receive_from_bridge_usdc"))
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn receive_from_bridge_other(
        deps: DepsMut,
        env: Env,
        info: MessageInfo,
        message: String,
        signature: String,
        receiver: String,
        ctoken: String,
        dex: String,
        payload: String,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "receive_from_bridge_other".to_string(),
                vec![Function {
                    name: "receive_from_bridge_other".to_string(),
                    inputs: vec![
                        Param {
                            name: "message".to_string(),
                            kind: ParamType::Bytes,
                            internal_type: None,
                        },
                        Param {
                            name: "signature".to_string(),
                            kind: ParamType::Bytes,
                            internal_type: None,
                        },
                        Param {
                            name: "receiver".to_string(),
                            kind: ParamType::Address,
                            internal_type: None,
                        },
                        Param {
                            name: "ctoken".to_string(),
                            kind: ParamType::Address,
                            internal_type: None,
                        },
                        Param {
                            name: "dex".to_string(),
                            kind: ParamType::Address,
                            internal_type: None,
                        },
                        Param {
                            name: "payload".to_string(),
                            kind: ParamType::Bytes,
                            internal_type: None,
                        },
                    ],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };
        let mut tokens: Vec<Token> = vec![];
        let retry_delay: u64 = state.retry_delay;
        if let Some(timestamp) =
            WITHDRAW_TIMESTAMP.may_load(deps.storage, (message.clone(), signature.clone()))?
        {
            if timestamp.plus_seconds(retry_delay).lt(&env.block.time) {
                tokens.push(Token::Bytes(hex::decode(message.clone()).unwrap()));
                tokens.push(Token::Bytes(hex::decode(signature.clone()).unwrap()));
                tokens.push(Token::Address(
                    Address::from_str(receiver.as_str()).unwrap(),
                ));
                tokens.push(Token::Address(Address::from_str(ctoken.as_str()).unwrap()));
                tokens.push(Token::Address(Address::from_str(dex.as_str()).unwrap()));
                tokens.push(Token::Bytes(hex::decode(payload.clone()).unwrap()));
                WITHDRAW_TIMESTAMP.save(deps.storage, (message, signature), &env.block.time)?;
            }
        } else {
            tokens.push(Token::Bytes(hex::decode(message.clone()).unwrap()));
            tokens.push(Token::Bytes(hex::decode(signature.clone()).unwrap()));
            tokens.push(Token::Address(
                Address::from_str(receiver.as_str()).unwrap(),
            ));
            tokens.push(Token::Address(Address::from_str(ctoken.as_str()).unwrap()));
            tokens.push(Token::Address(Address::from_str(dex.as_str()).unwrap()));
            tokens.push(Token::Bytes(hex::decode(payload.clone()).unwrap()));
            WITHDRAW_TIMESTAMP.save(deps.storage, (message, signature), &env.block.time)?;
        }
        if tokens.is_empty() {
            Err(AllPending {})
        } else {
            Ok(Response::new()
                .add_message(CosmosMsg::Custom(PalomaMsg {
                    job_id: state.job_id,
                    payload: Binary::new(
                        contract
                            .function("receive_from_bridge_other")
                            .unwrap()
                            .encode_input(tokens.as_slice())
                            .unwrap(),
                    ),
                    metadata: state.metadata,
                }))
                .add_attribute("action", "receive_from_bridge_other"))
        }
    }

    pub fn set_paloma(
        deps: DepsMut,
        info: MessageInfo,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "set_paloma".to_string(),
                vec![Function {
                    name: "set_paloma".to_string(),
                    inputs: vec![],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };
        Ok(Response::new()
            .add_message(CosmosMsg::Custom(PalomaMsg {
                job_id: state.job_id,
                payload: Binary::new(
                    contract
                        .function("set_paloma")
                        .unwrap()
                        .encode_input(&[])
                        .unwrap(),
                ),
                metadata: state.metadata,
            }))
            .add_attribute("action", "set_paloma"))
    }

    pub fn update_compass(
        deps: DepsMut,
        info: MessageInfo,
        new_compass: String,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        let new_compass_address: Address = Address::from_str(new_compass.as_str()).unwrap();
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "update_compass".to_string(),
                vec![Function {
                    name: "update_compass".to_string(),
                    inputs: vec![Param {
                        name: "new_compass".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    }],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };

        Ok(Response::new()
            .add_message(CosmosMsg::Custom(PalomaMsg {
                job_id: state.job_id,
                payload: Binary::new(
                    contract
                        .function("update_compass")
                        .unwrap()
                        .encode_input(&[Token::Address(new_compass_address)])
                        .unwrap(),
                ),
                metadata: state.metadata,
            }))
            .add_attribute("action", "update_compass"))
    }

    pub fn update_blueprint(
        deps: DepsMut,
        info: MessageInfo,
        new_blueprint: String,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        let new_blueprint_address: Address = Address::from_str(new_blueprint.as_str()).unwrap();
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "update_blueprint".to_string(),
                vec![Function {
                    name: "update_blueprint".to_string(),
                    inputs: vec![Param {
                        name: "new_compass".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    }],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };

        Ok(Response::new()
            .add_message(CosmosMsg::Custom(PalomaMsg {
                job_id: state.job_id,
                payload: Binary::new(
                    contract
                        .function("update_blueprint")
                        .unwrap()
                        .encode_input(&[Token::Address(new_blueprint_address)])
                        .unwrap(),
                ),
                metadata: state.metadata,
            }))
            .add_attribute("action", "update_blueprint"))
    }

    pub fn update_refund_wallet(
        deps: DepsMut,
        info: MessageInfo,
        new_compass: String,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        let update_refund_wallet_address: Address =
            Address::from_str(new_compass.as_str()).unwrap();
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "update_refund_wallet".to_string(),
                vec![Function {
                    name: "update_refund_wallet".to_string(),
                    inputs: vec![Param {
                        name: "new_compass".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    }],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };

        Ok(Response::new()
            .add_message(CosmosMsg::Custom(PalomaMsg {
                job_id: state.job_id,
                payload: Binary::new(
                    contract
                        .function("update_refund_wallet")
                        .unwrap()
                        .encode_input(&[Token::Address(update_refund_wallet_address)])
                        .unwrap(),
                ),
                metadata: state.metadata,
            }))
            .add_attribute("action", "update_refund_wallet"))
    }

    pub fn update_gas_fee(
        deps: DepsMut,
        info: MessageInfo,
        new_gas_fee: Uint256,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "update_gas_fee".to_string(),
                vec![Function {
                    name: "update_gas_fee".to_string(),
                    inputs: vec![Param {
                        name: "new_gas_fee".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    }],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };

        Ok(Response::new()
            .add_message(CosmosMsg::Custom(PalomaMsg {
                job_id: state.job_id,
                payload: Binary::new(
                    contract
                        .function("update_gas_fee")
                        .unwrap()
                        .encode_input(&[Token::Uint(Uint::from_big_endian(
                            &new_gas_fee.to_be_bytes(),
                        ))])
                        .unwrap(),
                ),
                metadata: state.metadata,
            }))
            .add_attribute("action", "update_gas_fee"))
    }

    pub fn update_service_fee_collector(
        deps: DepsMut,
        info: MessageInfo,
        new_service_fee_collector: String,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        let new_service_fee_collector_address: Address =
            Address::from_str(new_service_fee_collector.as_str()).unwrap();
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "update_service_fee_collector".to_string(),
                vec![Function {
                    name: "update_service_fee_collector".to_string(),
                    inputs: vec![Param {
                        name: "new_service_fee_collector".to_string(),
                        kind: ParamType::Address,
                        internal_type: None,
                    }],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };

        Ok(Response::new()
            .add_message(CosmosMsg::Custom(PalomaMsg {
                job_id: state.job_id,
                payload: Binary::new(
                    contract
                        .function("update_service_fee_collector")
                        .unwrap()
                        .encode_input(&[Token::Address(new_service_fee_collector_address)])
                        .unwrap(),
                ),
                metadata: state.metadata,
            }))
            .add_attribute("action", "update_service_fee_collector"))
    }

    pub fn update_service_fee(
        deps: DepsMut,
        info: MessageInfo,
        new_service_fee: Uint256,
    ) -> Result<Response<PalomaMsg>, ContractError> {
        let state = STATE.load(deps.storage)?;
        if state.owner != info.sender {
            return Err(Unauthorized {});
        }
        #[allow(deprecated)]
        let contract: Contract = Contract {
            constructor: None,
            functions: BTreeMap::from_iter(vec![(
                "update_service_fee".to_string(),
                vec![Function {
                    name: "update_service_fee".to_string(),
                    inputs: vec![Param {
                        name: "new_service_fee".to_string(),
                        kind: ParamType::Uint(256),
                        internal_type: None,
                    }],
                    outputs: Vec::new(),
                    constant: None,
                    state_mutability: StateMutability::NonPayable,
                }],
            )]),
            events: BTreeMap::new(),
            errors: BTreeMap::new(),
            receive: false,
            fallback: false,
        };

        Ok(Response::new()
            .add_message(CosmosMsg::Custom(PalomaMsg {
                job_id: state.job_id,
                payload: Binary::new(
                    contract
                        .function("update_service_fee")
                        .unwrap()
                        .encode_input(&[Token::Uint(Uint::from_big_endian(
                            &new_service_fee.to_be_bytes(),
                        ))])
                        .unwrap(),
                ),
                metadata: state.metadata,
            }))
            .add_attribute("action", "update_service_fee"))
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetJobId {} => to_json_binary(&query::get_job_id(deps)?),
    }
}

pub mod query {
    use super::*;

    pub fn get_job_id(deps: Deps) -> StdResult<GetJobIdResponse> {
        let state = STATE.load(deps.storage)?;
        Ok(GetJobIdResponse {
            job_id: state.job_id,
        })
    }
}

#[cfg(test)]
mod test {
    use crate::contract::{execute, instantiate, query};
    use crate::msg::{ExecuteMsg, GetJobIdResponse, InstantiateMsg, PalomaMsg, QueryMsg};
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{from_json, Addr, Binary, CosmosMsg, Uint256};
    use std::str::FromStr;

    #[test]
    fn initialization() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetJobId {}).unwrap();
        let value: GetJobIdResponse = from_json(&res).unwrap();
        assert_eq!("job".to_string(), value.job_id);
    }

    #[test]
    fn receive_from_bridge_usdc() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::ReceiveFromBridgeUsdc {
            message: "6d657373616765".to_string(),
            signature: "7369676e6174757265".to_string(),
            receiver: "0x0123456789abcdef0123456789abcdef01234567".to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                                  job_id: _, payload, metadata: _
                              }) => assert_eq!(Binary::new(hex::decode("12e4321f000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000123456789abcdef0123456789abcdef0123456700000000000000000000000000000000000000000000000000000000000000076d6573736167650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000097369676e61747572650000000000000000000000000000000000000000000000").unwrap()), payload, "Not same"),
            _ => panic!("Error")
        }
    }

    #[test]
    fn receive_from_bridge_other() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::ReceiveFromBridgeOther {
            message: "6d657373616765".to_string(),
            signature: "7369676e6174757265".to_string(),
            receiver: "0x0123456789abcdef0123456789abcdef01234567".to_string(),
            ctoken: "0x123456789abcdef0123456789abcdef012345678".to_string(),
            dex: "0x23456789abcdef0123456789abcdef0123456789".to_string(),
            payload: "7061796c6f6164".to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                                  job_id: _, payload, metadata: _
                              }) => assert_eq!(Binary::new(hex::decode("9d025b3400000000000000000000000000000000000000000000000000000000000000c000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000123456789abcdef0123456789abcdef01234567000000000000000000000000123456789abcdef0123456789abcdef01234567800000000000000000000000023456789abcdef0123456789abcdef0123456789000000000000000000000000000000000000000000000000000000000000014000000000000000000000000000000000000000000000000000000000000000076d6573736167650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000097369676e6174757265000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000077061796c6f616400000000000000000000000000000000000000000000000000").unwrap()), payload, "Not same"),
            _ => panic!("Error")
        }
    }

    #[test]
    fn set_paloma() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::SetPaloma {};
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                job_id: _,
                payload,
                metadata: _,
            }) => assert_eq!(
                Binary::new(hex::decode("23fde8e2").unwrap()),
                payload,
                "Not same"
            ),
            _ => panic!("Error"),
        }
    }

    #[test]
    fn update_compass() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::UpdateCompass {
            new_compass: "0x0123456789abcdef0123456789abcdef01234567".to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                job_id: _,
                payload,
                metadata: _,
            }) => assert_eq!(
                Binary::new(
                    hex::decode(
                        "6974af690000000000000000000000000123456789abcdef0123456789abcdef01234567"
                    )
                    .unwrap()
                ),
                payload,
                "Not same"
            ),
            _ => panic!("Error"),
        }
    }

    #[test]
    fn update_blueprint() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::UpdateBlueprint {
            new_blueprint: "0x0123456789abcdef0123456789abcdef01234567".to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                job_id: _,
                payload,
                metadata: _,
            }) => assert_eq!(
                Binary::new(
                    hex::decode(
                        "7361564a0000000000000000000000000123456789abcdef0123456789abcdef01234567"
                    )
                    .unwrap()
                ),
                payload,
                "Not same"
            ),
            _ => panic!("Error"),
        }
    }

    #[test]
    fn update_refund_wallet() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::UpdateRefundWallet {
            new_refund_wallet: "0x0123456789abcdef0123456789abcdef01234567".to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                job_id: _,
                payload,
                metadata: _,
            }) => assert_eq!(
                Binary::new(
                    hex::decode(
                        "c98856aa0000000000000000000000000123456789abcdef0123456789abcdef01234567"
                    )
                    .unwrap()
                ),
                payload,
                "Not same"
            ),
            _ => panic!("Error"),
        }
    }

    #[test]
    fn update_gas_fee() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::UpdateGasFee {
            new_gas_fee: Uint256::from_str("100").unwrap(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                job_id: _,
                payload,
                metadata: _,
            }) => assert_eq!(
                Binary::new(
                    hex::decode(
                        "6e9bc3f60000000000000000000000000000000000000000000000000000000000000064"
                    )
                    .unwrap()
                ),
                payload,
                "Not same"
            ),
            _ => panic!("Error"),
        }
    }

    #[test]
    fn update_service_fee_collector() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::UpdateServiceFeeCollector {
            new_service_fee_collector: "0x0123456789abcdef0123456789abcdef01234567".to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                job_id: _,
                payload,
                metadata: _,
            }) => assert_eq!(
                Binary::new(
                    hex::decode(
                        "30e59cbc0000000000000000000000000123456789abcdef0123456789abcdef01234567"
                    )
                    .unwrap()
                ),
                payload,
                "Not same"
            ),
            _ => panic!("Error"),
        }
    }

    #[test]
    fn update_service_fee() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg {
            retry_delay: 30,
            job_id: "job".to_string(),
            creator: "creator".to_string(),
            signers: vec!["creator".to_string()],
        };
        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        let info = message_info(&Addr::unchecked("sender".to_string()), &[]);

        let msg = ExecuteMsg::UpdateServiceFee {
            new_service_fee: Uint256::from_str("100").unwrap(),
        };
        let res = execute(deps.as_mut(), mock_env(), info, msg).unwrap();
        match res.messages[0].clone().msg {
            CosmosMsg::Custom(PalomaMsg {
                job_id: _,
                payload,
                metadata: _,
            }) => assert_eq!(
                Binary::new(
                    hex::decode(
                        "c4ec2ff10000000000000000000000000000000000000000000000000000000000000064"
                    )
                    .unwrap()
                ),
                payload,
                "Not same"
            ),
            _ => panic!("Error"),
        }
    }
}
