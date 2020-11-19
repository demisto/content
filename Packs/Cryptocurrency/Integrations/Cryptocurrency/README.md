## Configure Cryptocurrency on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.

2. Search for Cryptocurrency.

3. Click **Add instance** to create and configure a new integration instance.

4. Click **Test** to validate the URLs, token, and connection.

## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### crypto
***
Return Cryptocurrency reputation.


#### Base Command

`crypto`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| crypto | List of cryptocurrency addresses. | Optional | 
| address_type | The cryptocurrency address type, if known. e.g. 'bitcoin' | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| DBotScore.Indicator | string | The indicator that was tested. | 
| DBotScore.Score | number | The actual score. | 
| DBotScore.Type | string | The indicator type. | 
| DBotScore.Vendor | string | The vendor used to calculate the score. | 
| Cryptocurrency.Address | string | The cryptocurrency address. | 
| Cryptocurrency.AddressType | string | The cryptocurrency type. e.g. 'bitcoin'. | 


#### Command Example
```!crypto crypto=bitcoin-1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i```

#### Context Example
```json
{
    "Cryptocurrency": {
        "Address": "bitcoin-1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        "AddressType": "bitcoin"
    },
    "DBotScore": {
        "Indicator": "bitcoin-1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        "Score": 2,
        "Type": "cryptocurrency",
        "Vendor": "Cryptocurrency"
    }
}
```
#### Command Example
```!crypto crypto=1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i address_type=bitcoin```

#### Context Example
```json
{
    "Cryptocurrency": {
        "Address": "bitcoin-1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        "AddressType": "bitcoin"
    },
    "DBotScore": {
        "Indicator": "bitcoin-1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i",
        "Score": 2,
        "Type": "cryptocurrency",
        "Vendor": "Cryptocurrency"
    }
}
```
#### Human Readable Output
>Cryptocurrency reputation for address bitcoin-1AGNa15ZQXAZUgFiqJ2i7Z2DPU2J6hW62i was set to Suspicious.
