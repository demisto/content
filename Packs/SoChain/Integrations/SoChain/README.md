On-chain data for Bitcoin, Litecoin, Dogecoin and Zcash addresses and transactions from SoChain, including address poisoning checks.
This integration was integrated and tested with version 3 of the SoChain API.

## Networks

Every command takes BTC, LTC, DOGE, ZEC and their testnets (BTCTEST is Bitcoin testnet4). When an address command gets no `network`, it uses the first of BTC, LTC, DOGE and ZEC on which the address is valid. A `bitcoin:`, `litecoin:`, `dogecoin:` or `zcash:` prefix on an address also selects the network. Zcash data covers transparent addresses.

## API key and limits

Lookups work without an API key, up to 2,500 a day per IP. A key from SoChain raises the limit: a free account gets 75,000 requests a month, and paid plans start at $35 a month. The key is sent in the `API-KEY` header. See the integration's setup instructions for how to get one.

## Configure SoChain in Cortex

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Server URL | The SoChain API v3 base URL. | True |
| API Key | Optional. Without a key, lookups are limited to 2,500 a day per IP. Get a key at <https://sochain.com/dashboard>. | False |
| Use system proxy settings | Runs the integration's requests through the system proxy. | False |
| Trust any certificate (not secure) | Skips SSL certificate checks on requests to the server URL. Use only for testing. | False |
| Source Reliability | Reliability of the source providing the intelligence data. | False |

## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### crypto

***
Enriches cryptocurrency addresses (BTC, LTC, DOGE, ZEC) with their activity and the address poisoning check. SoChain does not give verdicts: the DBot score is always 0 (Unknown), and its message says whether look-alike addresses were found.

#### Reputation

SoChain gives on-chain facts, not verdicts, so `crypto` never returns a malicious verdict: the DBot score is always 0 (Unknown). The score's message says whether look-alike addresses sent the address dust (address poisoning), which marks the address as a target, not as a bad actor. An address that is not valid, or has no transactions, gets "No results found."

#### Base Command

`crypto`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| crypto | A comma-separated list of addresses. A "bitcoin:", "litecoin:", "dogecoin:" or "zcash:" prefix selects the network. | Required |
| network | The network. If not given, the first of BTC, LTC, DOGE and ZEC on which the address is valid is used. Possible values are: BTC, LTC, DOGE, ZEC, BTCTEST, LTCTEST, DOGETEST, ZECTEST. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | String | The indicator that was tested. |
| DBotScore.Type | String | The indicator type. |
| DBotScore.Vendor | String | The vendor used to calculate the score. |
| DBotScore.Score | Number | The actual score. |
| DBotScore.Reliability | String | Reliability of the source providing the intelligence data. |
| DBotScore.Message | String | What SoChain found: whether address poisoning look-alikes sent the address dust, or No results found. |
| Cryptocurrency.Address | String | The cryptocurrency address. |
| Cryptocurrency.AddressType | String | The cryptocurrency type, e.g. bitcoin. |
| SoChain.Address.Address | String | The address. |
| SoChain.Address.Network | String | The network \(BTC, LTC, DOGE, ZEC or a testnet\). |
| SoChain.Address.TxsSent | Number | Transactions in which the address sent coins. |
| SoChain.Address.TxsReceived | Number | Transactions in which the address received coins. |
| SoChain.Address.TxsTotal | Number | Every transaction the address appears in, each counted once. |
| SoChain.Address.ConfirmedBalance | String | The confirmed balance, in coins \(a decimal string\). |
| SoChain.Address.UnconfirmedBalance | String | The unconfirmed balance change, in coins \(a decimal string\). |
| SoChain.Address.ConfirmedReceived | String | Everything received in confirmed transactions, in coins \(a decimal string\). |
| SoChain.Address.FirstActiveHeight | Number | The block height of the address's first transaction. |
| SoChain.Address.FirstActiveTime | Date | The time of the block of the address's first transaction \(UTC, ISO 8601, e.g., 2011-05-13T21:04:05Z\). |
| SoChain.Address.LastActiveHeight | Number | The block height of the address's latest transaction. |
| SoChain.Address.LastActiveTime | Date | The time of the block of the address's latest transaction \(UTC, ISO 8601, e.g., 2011-05-13T21:04:05Z\). |
| SoChain.Address.Poisoning.Address | String | The address checked. |
| SoChain.Address.Poisoning.Network | String | The network. |
| SoChain.Address.Poisoning.Building | Boolean | True while the check is still catching up on the network's history. |
| SoChain.Address.Poisoning.LookalikesFound | Boolean | True if look-alike addresses sent the address dust. |
| SoChain.Address.Poisoning.Findings.Sender | String | The look-alike address that sent the dust. |
| SoChain.Address.Poisoning.Findings.Imitates | String | The real address the look-alike copies. |
| SoChain.Address.Poisoning.Findings.Amount | String | The dust amount, in coins. |
| SoChain.Address.Poisoning.Findings.DustTxid | String | The transaction that sent the dust. |
| SoChain.Address.Poisoning.Findings.RealTxid | String | The real transaction with the imitated address. |
| SoChain.Address.Poisoning.Findings.RealHeight | Number | The block height of the real transaction. |
| SoChain.Address.Poisoning.Findings.RealAmount | String | The amount of the real transaction, in coins. |
| SoChain.Address.Poisoning.Findings.ReceiverPaid | Boolean | True if the address later paid a look-alike. |
| SoChain.Address.Poisoning.Findings.SharedPrefix | Number | The number of leading characters the look-alike shares with the real address. |
| SoChain.Address.Poisoning.Findings.SharedSuffix | Number | The number of trailing characters the look-alike shares with the real address. |
| SoChain.Address.Poisoning.Findings.SenderKind | String | The kind of sender \(new or dust_bot\). |
| SoChain.Address.Poisoning.Findings.SenderTxs | Number | The number of transactions of the sender. |
| SoChain.Address.Poisoning.Findings.Height | Number | The block height of the dust transaction \(empty while unconfirmed\). |
| SoChain.Address.Poisoning.Findings.Confirmed | Boolean | True if the dust transaction is confirmed. |

#### Command example

```!crypto crypto="bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"```

#### Context Example

```json
{
    "Cryptocurrency": {
        "Address": "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "AddressType": "bitcoin"
    },
    "DBotScore": {
        "Indicator": "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        "Message": "No address poisoning look-alikes found.",
        "Reliability": "C - Fairly reliable",
        "Score": 0,
        "Type": "cryptocurrency",
        "Vendor": "SoChain"
    },
    "SoChain": {
        "Address": {
            "Address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "ConfirmedBalance": "57.69113627",
            "ConfirmedReceived": "57.69113627",
            "FirstActiveHeight": 123723,
            "FirstActiveTime": "2011-05-13T21:04:05Z",
            "LastActiveHeight": 973657,
            "LastActiveTime": "2026-10-29T07:39:59Z",
            "Network": "BTC",
            "Poisoning": {
                "Address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
                "Building": false,
                "Findings": [],
                "LookalikesFound": false,
                "Network": "BTC"
            },
            "TxsReceived": 67173,
            "TxsSent": 0,
            "TxsTotal": 67173,
            "UnconfirmedBalance": "0.00003672"
        }
    }
}
```

#### Human Readable Output

>### SoChain: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (BTC)
>
>|Address|Network|TxsSent|TxsReceived|TxsTotal|ConfirmedBalance|UnconfirmedBalance|ConfirmedReceived|FirstActiveHeight|FirstActiveTime|LastActiveHeight|LastActiveTime|AddressPoisoning|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa | BTC | 0 | 67173 | 67173 | 57.69113627 | 0.00003672 | 57.69113627 | 123723 | 2011-05-13T21:04:05Z | 973657 | 2026-10-29T07:39:59Z | No address poisoning look-alikes found. |

### sochain-address-summary

***
Gets an address's transaction counts, balances, total received, and first and last activity.

#### Base Command

`sochain-address-summary`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | The address. | Required |
| network | The network. If not given, the first of BTC, LTC, DOGE and ZEC on which the address is valid is used. Possible values are: BTC, LTC, DOGE, ZEC, BTCTEST, LTCTEST, DOGETEST, ZECTEST. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SoChain.Address.Address | String | The address. |
| SoChain.Address.Network | String | The network \(BTC, LTC, DOGE, ZEC or a testnet\). |
| SoChain.Address.TxsSent | Number | Transactions in which the address sent coins. |
| SoChain.Address.TxsReceived | Number | Transactions in which the address received coins. |
| SoChain.Address.TxsTotal | Number | Every transaction the address appears in, each counted once. |
| SoChain.Address.ConfirmedBalance | String | The confirmed balance, in coins \(a decimal string\). |
| SoChain.Address.UnconfirmedBalance | String | The unconfirmed balance change, in coins \(a decimal string\). |
| SoChain.Address.ConfirmedReceived | String | Everything received in confirmed transactions, in coins \(a decimal string\). |
| SoChain.Address.FirstActiveHeight | Number | The block height of the address's first transaction. |
| SoChain.Address.FirstActiveTime | Date | The time of the block of the address's first transaction \(UTC, ISO 8601, e.g., 2011-05-13T21:04:05Z\). |
| SoChain.Address.LastActiveHeight | Number | The block height of the address's latest transaction. |
| SoChain.Address.LastActiveTime | Date | The time of the block of the address's latest transaction \(UTC, ISO 8601, e.g., 2011-05-13T21:04:05Z\). |

#### Command example

```!sochain-address-summary address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"```

#### Context Example

```json
{
    "SoChain": {
        "Address": {
            "Address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "ConfirmedBalance": "57.69113627",
            "ConfirmedReceived": "57.69113627",
            "FirstActiveHeight": 123723,
            "FirstActiveTime": "2011-05-13T21:04:05Z",
            "LastActiveHeight": 973657,
            "LastActiveTime": "2026-10-29T07:39:59Z",
            "Network": "BTC",
            "TxsReceived": 67173,
            "TxsSent": 0,
            "TxsTotal": 67173,
            "UnconfirmedBalance": "0.00003672"
        }
    }
}
```

#### Human Readable Output

>### SoChain address summary: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (BTC)
>
>|Address|Network|TxsSent|TxsReceived|TxsTotal|ConfirmedBalance|UnconfirmedBalance|ConfirmedReceived|FirstActiveHeight|FirstActiveTime|LastActiveHeight|LastActiveTime|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa | BTC | 0 | 67173 | 67173 | 57.69113627 | 0.00003672 | 57.69113627 | 123723 | 2011-05-13T21:04:05Z | 973657 | 2026-10-29T07:39:59Z |

### sochain-transaction

***
Gets a transaction with its confirmations, fee, and every input and output.

#### Base Command

`sochain-transaction`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| txid | The transaction ID. | Required |
| network | The network. Possible values are: BTC, LTC, DOGE, ZEC, BTCTEST, LTCTEST, DOGETEST, ZECTEST. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SoChain.Transaction.Hash | String | The transaction ID. |
| SoChain.Transaction.Network | String | The network. |
| SoChain.Transaction.Confirmations | Number | The number of confirmations. |
| SoChain.Transaction.BlockHash | String | The hash of the block containing the transaction. |
| SoChain.Transaction.BlockHeight | Number | The height of the block containing the transaction. |
| SoChain.Transaction.Time | Date | The transaction time \(UTC, ISO 8601, e.g., 2011-05-13T21:04:05Z\). |
| SoChain.Transaction.Size | Number | The size in bytes. |
| SoChain.Transaction.Vsize | Number | The virtual size in vbytes. |
| SoChain.Transaction.Fee | String | The fee, in coins. |
| SoChain.Transaction.InputsCount | Number | The number of inputs. |
| SoChain.Transaction.OutputsCount | Number | The number of outputs. |
| SoChain.Transaction.InputsValue | String | The total value of the inputs, in coins. |
| SoChain.Transaction.OutputsValue | String | The total value of the outputs, in coins. |
| SoChain.Transaction.Inputs.Index | Number | The input index. |
| SoChain.Transaction.Inputs.Address | String | The address spending the input. |
| SoChain.Transaction.Inputs.Value | String | The input value, in coins. |
| SoChain.Transaction.Outputs.Index | Number | The output index. |
| SoChain.Transaction.Outputs.Address | String | The address receiving the output. |
| SoChain.Transaction.Outputs.Value | String | The output value, in coins. |
| SoChain.Transaction.Outputs.Type | String | The output script type. |
| SoChain.Transaction.Outputs.Spent | Boolean | True if the output has been spent. |

#### Command example

```!sochain-transaction txid="597bafa25fcbb081467bdeb030a42bf441dbfcc054bdcfad31a829d7db5d931f" network="BTC"```

#### Context Example

```json
{
    "SoChain": {
        "Transaction": {
            "BlockHash": "0000000000000000000717afe429887e2967094d6e17c2b22b54cf0e33debb69",
            "BlockHeight": 769781,
            "Confirmations": 203970,
            "Fee": "0.00090000",
            "Hash": "597bafa25fcbb081467bdeb030a42bf441dbfcc054bdcfad31a829d7db5d931f",
            "Inputs": [
                {
                    "Address": "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
                    "Index": 0,
                    "Value": "0.66579765"
                }
            ],
            "InputsCount": 1,
            "InputsValue": "0.66579765",
            "Network": "BTC",
            "Outputs": [
                {
                    "Address": "39KPyDkWXeEE9UXkSNPXkv5tbgqZfxHhqv",
                    "Index": 0,
                    "Spent": true,
                    "Type": "scripthash",
                    "Value": "0.15526090"
                },
                {
                    "Address": "bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej",
                    "Index": 1,
                    "Spent": true,
                    "Type": "witness_v0_scripthash",
                    "Value": "0.50963675"
                }
            ],
            "OutputsCount": 2,
            "OutputsValue": "0.66489765",
            "Size": 380,
            "Time": "2022-12-31T22:23:07Z",
            "Vsize": 190
        }
    }
}
```

#### Human Readable Output

>### SoChain transaction 597bafa25fcbb081467bdeb030a42bf441dbfcc054bdcfad31a829d7db5d931f (BTC)
>
>|Hash|Network|Confirmations|BlockHash|BlockHeight|Time|Size|Vsize|Fee|InputsCount|OutputsCount|InputsValue|OutputsValue|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| 597bafa25fcbb081467bdeb030a42bf441dbfcc054bdcfad31a829d7db5d931f | BTC | 203970 | 0000000000000000000717afe429887e2967094d6e17c2b22b54cf0e33debb69 | 769781 | 2022-12-31T22:23:07Z | 380 | 190 | 0.00090000 | 1 | 2 | 0.66579765 | 0.66489765 |
>
>### Inputs
>
>|Index|Address|Value|
>|---|---|---|
>| 0 | bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej | 0.66579765 |
>
>### Outputs
>
>|Index|Address|Value|Type|Spent|
>|---|---|---|---|---|
>| 0 | 39KPyDkWXeEE9UXkSNPXkv5tbgqZfxHhqv | 0.15526090 | scripthash | true |
>| 1 | bc1qwqdg6squsna38e46795at95yu9atm8azzmyvckulcc7kytlcckxswvvzej | 0.50963675 | witness_v0_scripthash | true |

### sochain-address-counterparties

***
Lists who an address paid and was paid by lately (payments of a significant amount, newest first).

#### Base Command

`sochain-address-counterparties`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | The address. | Required |
| network | The network. If not given, the first of BTC, LTC, DOGE and ZEC on which the address is valid is used. Possible values are: BTC, LTC, DOGE, ZEC, BTCTEST, LTCTEST, DOGETEST, ZECTEST. | Optional |
| limit | The number of rows to return, newest first (1 to 100). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SoChain.Counterparties.Address | String | The address. |
| SoChain.Counterparties.Network | String | The network. |
| SoChain.Counterparties.WindowBlocks | Number | The number of recent blocks the list covers. |
| SoChain.Counterparties.FromHeight | Number | The first block height the list covers. |
| SoChain.Counterparties.Building | Boolean | True while the data is still catching up on the network's history. |
| SoChain.Counterparties.Counterparties.Address | String | The counterparty address. |
| SoChain.Counterparties.Counterparties.Direction | String | sent \(the address paid it\) or received \(the address was paid by it\). |
| SoChain.Counterparties.Counterparties.Amount | String | The amount, in coins. |
| SoChain.Counterparties.Counterparties.Txid | String | The transaction ID. |
| SoChain.Counterparties.Counterparties.Height | Number | The block height. |

#### Command example

```!sochain-address-counterparties address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" network="BTC" limit="3"```

#### Context Example

```json
{
    "SoChain": {
        "Counterparties": {
            "Address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "Building": false,
            "Counterparties": [
                {
                    "Address": "bc1qdux37a0pzr44lrhc8vm44uellvplgyh7g73epq",
                    "Amount": "0.06774527",
                    "Direction": "received",
                    "Height": 971286,
                    "Txid": "f1363d1f8ceb5753aa5f9f5fee1a9c605545be2d167ae89c44103c04d2b80731"
                },
                {
                    "Address": "bc1qq2mvrp4g3ugd424dw4xv53rgsf8szkrv853jrc",
                    "Amount": "0.06871954",
                    "Direction": "received",
                    "Height": 969861,
                    "Txid": "412eb99d45ac2d77c34240f17197ca202385adec870a6ef9be5870f579ab34fb"
                }
            ],
            "FromHeight": 969431,
            "Network": "BTC",
            "WindowBlocks": 4320
        }
    }
}
```

#### Human Readable Output

>### SoChain counterparties of 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (BTC), from block 969431
>
>|Address|Direction|Amount|Txid|Height|
>|---|---|---|---|---|
>| bc1qdux37a0pzr44lrhc8vm44uellvplgyh7g73epq | received | 0.06774527 | f1363d1f8ceb5753aa5f9f5fee1a9c605545be2d167ae89c44103c04d2b80731 | 971286 |
>| bc1qq2mvrp4g3ugd424dw4xv53rgsf8szkrv853jrc | received | 0.06871954 | 412eb99d45ac2d77c34240f17197ca202385adec870a6ef9be5870f579ab34fb | 969861 |

### sochain-address-poisoning

***
Checks whether an address was targeted by address poisoning, that is look-alike addresses that sent it dust, imitating an address it really paid or was paid by.

#### Base Command

`sochain-address-poisoning`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| address | The address. | Required |
| network | The network. If not given, the first of BTC, LTC, DOGE and ZEC on which the address is valid is used. Possible values are: BTC, LTC, DOGE, ZEC, BTCTEST, LTCTEST, DOGETEST, ZECTEST. | Optional |
| limit | The number of rows to return, newest first (1 to 100). | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SoChain.AddressPoisoning.Address | String | The address checked. |
| SoChain.AddressPoisoning.Network | String | The network. |
| SoChain.AddressPoisoning.Building | Boolean | True while the check is still catching up on the network's history. |
| SoChain.AddressPoisoning.LookalikesFound | Boolean | True if look-alike addresses sent the address dust. |
| SoChain.AddressPoisoning.Findings.Sender | String | The look-alike address that sent the dust. |
| SoChain.AddressPoisoning.Findings.Imitates | String | The real address the look-alike copies. |
| SoChain.AddressPoisoning.Findings.Amount | String | The dust amount, in coins. |
| SoChain.AddressPoisoning.Findings.DustTxid | String | The transaction that sent the dust. |
| SoChain.AddressPoisoning.Findings.RealTxid | String | The real transaction with the imitated address. |
| SoChain.AddressPoisoning.Findings.RealHeight | Number | The block height of the real transaction. |
| SoChain.AddressPoisoning.Findings.RealAmount | String | The amount of the real transaction, in coins. |
| SoChain.AddressPoisoning.Findings.ReceiverPaid | Boolean | True if the address later paid a look-alike. |
| SoChain.AddressPoisoning.Findings.SharedPrefix | Number | The number of leading characters the look-alike shares with the real address. |
| SoChain.AddressPoisoning.Findings.SharedSuffix | Number | The number of trailing characters the look-alike shares with the real address. |
| SoChain.AddressPoisoning.Findings.SenderKind | String | The kind of sender \(new or dust_bot\). |
| SoChain.AddressPoisoning.Findings.SenderTxs | Number | The number of transactions of the sender. |
| SoChain.AddressPoisoning.Findings.Height | Number | The block height of the dust transaction \(empty while unconfirmed\). |
| SoChain.AddressPoisoning.Findings.Confirmed | Boolean | True if the dust transaction is confirmed. |

#### Command example

```!sochain-address-poisoning address="1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" network="BTC"```

#### Context Example

```json
{
    "SoChain": {
        "AddressPoisoning": {
            "Address": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
            "Building": false,
            "Findings": [],
            "LookalikesFound": false,
            "Network": "BTC"
        }
    }
}
```

#### Human Readable Output

>### SoChain address poisoning check: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa (BTC)
>
>No address poisoning look-alikes found.
