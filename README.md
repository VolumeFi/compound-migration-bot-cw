# Compound Migration Bot CosmWasm smart contract

This is a CosmWasm smart contract to manage Compound Migration Bot smart contract on EVM chain written in Vyper.

Each target chain, will need it's own deployed instance of this contract.

Each contract sends a paloma transaction to Vyper contract via Compass to mint Compound asset from bridged USDC or swapped underlying asset.

## ExecuteMsg

### ReceiveFromBridgeUsdc

Run `receive_from_bridge_usdc` function on Vyper smart contract.

| Key       | Type   | Description                                                           |
|-----------|--------|-----------------------------------------------------------------------|
| message   | String | USDC bridge message bytes data                                        |
| signature | String | USDC bridge signature bytes data                                      |
| receiver  | String | Receiver EVM address. It should be same as the token migrator address |

### ReceiveFromBridgeUsdc

Run `receive_from_bridge_usdc` function on Vyper smart contract.

| Key       | Type   | Description                                                           |
|-----------|--------|-----------------------------------------------------------------------|
| message   | String | USDC bridge message bytes data                                        |
| signature | String | USDC bridge signature bytes data                                      |
| receiver  | String | Receiver EVM address. It should be same as the token migrator address |
| ctoken    | String | cToken address to be migrated                                         |
| dex       | String | dex address to exchange USDC into asset                               |
| payload   | String | payload data to exchange USDC into asset                              |

### SetPaloma

Run `set_paloma` function on Vyper smart contract to register this contract address data in the Vyper contract.

| Key | Type | Description |
|-----|------|-------------|
| -   | -    | -           |

### Update*

Run `update_*` function on Vyper smart contract to register this contract address data in the Vyper contract.

| Key | Type | Description |
|-----|------|-------------|
| -   | -    | -           |

## QueryMsg

### GetJobId

Get `job_id` of Paloma message to run `multiple_withdraw` function on a Vyper smart contract.

| Key | Type | Description |
|-----|------|-------------|
| -   | -    | -           |

#### Response

| Key    | Type   | Description      |
|--------|--------|------------------|
| job_id | String | Job Id on Paloma |

