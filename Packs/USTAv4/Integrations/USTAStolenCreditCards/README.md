This integration offers organizations the ability to track stolen credit card data across the web, providing comprehensive insight into compromised card information sourced from underground markets, dark web forums, and other malicious platforms.

## Configure USTA Stolen Credit Cards on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for USTA Stolen Credit Cards.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Your server URL |  | True |
    | API Key | The API Key to use for connection | True |
    | Fetch incidents by status |  | False |
    | Trust any certificate (not secure) |  | False |
    | Use system proxy settings |  | False |
    | Fetch incidents |  | False |
    | First Fetch Time | The time range to consider for the initial data fetch. Warning: Fetching a large time range may cause performance issues\! | True |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### usta-scc-search

***
Search for stolen credit card number

#### Base Command

`usta-scc-search`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| card_number | Credit card number to search. | Required | 
| page_size | Number of vendors that should appear on each page. Each page of data will have at most this many vendors. | Optional | 
| page | 1-indexed page number to get a particular page of results. | Optional | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| USTA.StolenCreditCards.id | Number | The ticket ID of the alert | 
| USTA.StolenCreditCards.card_number | String | The stolen credit card number | 
| USTA.StolenCreditCards.expire | String | The expiration date of the stolen credit card | 
| USTA.StolenCreditCards.created | String | The creation date of the stolen credit card | 

### Command Example

```!usta-scc-search card_number=133713371337 page=1 page_size=1```

### Context Example

```json
{
    "USTA" : {
        "StolenCreditCards": {
            "id": 133737,
            "card_number": "133713371337",
            "expire": "06/31",
            "created": "2024-11-19T07:42:01.388163Z"
        }
    }
}
```
