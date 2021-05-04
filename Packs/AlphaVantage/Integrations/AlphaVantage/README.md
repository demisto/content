This is an API to get stock prices etc
## Configure AlphaVantage on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for AlphaVantage.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | API Key | True |
    | Fetch incidents | False |
    | Incident type | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### alphavantage-stock-data-get
***
Gets data for a stock


#### Base Command

`alphavantage-stock-data-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| symbol | Symbol or Ticker of stock. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlphaVantage.StockData.symbol | String | Stock symbol | 
| AlphaVantage.StockData.open | String | Open price | 
| AlphaVantage.StockData.high | String | Day high price | 
| AlphaVantage.StockData.low | String | Day low price | 
| AlphaVantage.StockData.price | String | Last price recorded | 
| AlphaVantage.StockData.volume | String | Trade volume | 
| AlphaVantage.StockData.latest trading day | Date | Last trade day date | 
| AlphaVantage.StockData.previous close | String | Last day close price | 
| AlphaVantage.StockData.change | String | Change since last close | 
| AlphaVantage.StockData.change percent | String | Change since last close in % | 


#### Command Example
```!alphavantage-stock-data-get symbol=PANW```

#### Context Example
```json
{
    "AlphaVantage": {
        "StockData": {
            "change": "5.9900",
            "change percent": "1.8599%",
            "high": "332.7650",
            "latest trading day": "2021-04-01",
            "low": "325.8500",
            "open": "327.0000",
            "previous close": "322.0600",
            "price": "328.0500",
            "symbol": "PANW",
            "volume": "995632"
        }
    }
}
```

#### Human Readable Output

>### Results
>|change|change percent|high|latest trading day|low|open|previous close|price|symbol|volume|
>|---|---|---|---|---|---|---|---|---|---|
>| 5.9900 | 1.8599% | 332.7650 | 2021-04-01 | 325.8500 | 327.0000 | 322.0600 | 328.0500 | PANW | 995632 |


### alphavantage-stock-history-get
***
Gets historical data for a stock


#### Base Command

`alphavantage-stock-history-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| symbol | Symbols of stocksto fetch. | Required | 
| interval | Time interval between two data points. Possible values are: 1min, 5min, 15min, 30min, 60min. Default is 60min. | Optional | 
| output_size | Amount of data return. Possible values are: compact, full. Default is compact. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| AlphaVantage.StockHistory.Information | String | Info about each time series | 
| AlphaVantage.StockHistory.Interval | String | Time interval between two data samples | 
| AlphaVantage.StockHistory.Last Refreshed | String | Last time the API  data was refreshed | 
| AlphaVantage.StockHistory.Output Size | String | Amount of data. Either last 100 samples or as much as possible | 
| AlphaVantage.StockHistory.Symbol | String | Stock symbol | 
| AlphaVantage.StockHistory.Time Series | Unknown | List of all stock data samples | 


#### Command Example
```!alphavantage-stock-history-get symbol=PANW interval=5min output_size=compact```

#### Context Example
```json
{
    "AlphaVantage": {
        "StockHistory": {
            "Information": "Intraday (5min) open, high, low, close prices and volume",
            "Interval": "5min",
            "Last Refreshed": "2021-04-01 16:05:00",
            "Output Size": "Compact",
            "Symbol": "PANW",
            "Time Series": {
                "2021-03-31 14:45:00": {
                    "close": "324.1500",
                    "high": "324.4400",
                    "low": "323.4800",
                    "open": "324.2000",
                    "volume": "14877"
                },
                "2021-03-31 14:50:00": {
                    "close": "324.1300",
                    "high": "324.6900",
                    "low": "324.0800",
                    "open": "324.3850",
                    "volume": "7734"
                },
                "2021-03-31 14:55:00": {
                    "close": "324.4750",
                    "high": "324.4750",
                    "low": "323.7500",
                    "open": "323.9740",
                    "volume": "5611"
                },
                "2021-03-31 15:00:00": {
                    "close": "324.0300",
                    "high": "324.7500",
                    "low": "324.0300",
                    "open": "324.4800",
                    "volume": "7327"
                },
                "2021-03-31 15:05:00": {
                    "close": "325.0200",
                    "high": "325.0200",
                    "low": "324.3800",
                    "open": "324.3800",
                    "volume": "5967"
                },
                "2021-03-31 15:10:00": {
                    "close": "324.8600",
                    "high": "325.2500",
                    "low": "324.6000",
                    "open": "325.2500",
                    "volume": "5504"
                },
                "2021-03-31 15:15:00": {
                    "close": "324.8300",
                    "high": "325.1390",
                    "low": "324.6200",
                    "open": "324.6600",
                    "volume": "8099"
                },
                "2021-03-31 15:20:00": {
                    "close": "324.4100",
                    "high": "325.3150",
                    "low": "324.4100",
                    "open": "324.8500",
                    "volume": "12790"
                },
                "2021-03-31 15:25:00": {
                    "close": "323.8200",
                    "high": "324.7200",
                    "low": "323.8200",
                    "open": "324.3500",
                    "volume": "9676"
                },
                "2021-03-31 15:30:00": {
                    "close": "323.8900",
                    "high": "324.0000",
                    "low": "323.5700",
                    "open": "323.6400",
                    "volume": "16436"
                },
                "2021-03-31 15:35:00": {
                    "close": "324.1800",
                    "high": "324.3200",
                    "low": "323.4650",
                    "open": "323.8500",
                    "volume": "17200"
                },
                "2021-03-31 15:40:00": {
                    "close": "324.1800",
                    "high": "324.3850",
                    "low": "323.9150",
                    "open": "324.0200",
                    "volume": "18491"
                },
                "2021-03-31 15:45:00": {
                    "close": "324.9700",
                    "high": "325.1900",
                    "low": "324.0800",
                    "open": "324.2000",
                    "volume": "17295"
                },
                "2021-03-31 15:50:00": {
                    "close": "324.1700",
                    "high": "325.0000",
                    "low": "324.0000",
                    "open": "325.0000",
                    "volume": "12737"
                },
                "2021-03-31 15:55:00": {
                    "close": "323.0800",
                    "high": "324.4300",
                    "low": "322.9500",
                    "open": "324.0500",
                    "volume": "21790"
                },
                "2021-03-31 16:00:00": {
                    "close": "322.3000",
                    "high": "323.0900",
                    "low": "322.0600",
                    "open": "323.0300",
                    "volume": "75705"
                },
                "2021-03-31 16:05:00": {
                    "close": "322.0600",
                    "high": "322.0600",
                    "low": "322.0600",
                    "open": "322.0600",
                    "volume": "24212"
                },
                "2021-03-31 16:15:00": {
                    "close": "322.0600",
                    "high": "322.0600",
                    "low": "322.0600",
                    "open": "322.0600",
                    "volume": "8400"
                },
                "2021-03-31 16:25:00": {
                    "close": "322.0600",
                    "high": "322.0600",
                    "low": "322.0600",
                    "open": "322.0600",
                    "volume": "8400"
                },
                "2021-04-01 09:05:00": {
                    "close": "322.0600",
                    "high": "322.0600",
                    "low": "322.0600",
                    "open": "322.0600",
                    "volume": "2564"
                },
                "2021-04-01 09:30:00": {
                    "close": "327.5400",
                    "high": "327.5400",
                    "low": "327.0600",
                    "open": "327.0600",
                    "volume": "415"
                },
                "2021-04-01 09:35:00": {
                    "close": "330.7000",
                    "high": "330.9200",
                    "low": "327.0000",
                    "open": "327.0000",
                    "volume": "41300"
                },
                "2021-04-01 09:40:00": {
                    "close": "329.3700",
                    "high": "332.7650",
                    "low": "329.0000",
                    "open": "330.9900",
                    "volume": "17485"
                },
                "2021-04-01 09:45:00": {
                    "close": "329.2500",
                    "high": "330.2900",
                    "low": "329.0700",
                    "open": "329.3100",
                    "volume": "16405"
                },
                "2021-04-01 09:50:00": {
                    "close": "330.7800",
                    "high": "330.8000",
                    "low": "329.3400",
                    "open": "329.7350",
                    "volume": "7280"
                },
                "2021-04-01 09:55:00": {
                    "close": "330.5500",
                    "high": "331.0300",
                    "low": "330.0500",
                    "open": "330.4400",
                    "volume": "7345"
                },
                "2021-04-01 10:00:00": {
                    "close": "331.4200",
                    "high": "331.9900",
                    "low": "330.9000",
                    "open": "330.9200",
                    "volume": "13618"
                },
                "2021-04-01 10:05:00": {
                    "close": "329.4100",
                    "high": "332.0500",
                    "low": "329.4100",
                    "open": "331.7400",
                    "volume": "44828"
                },
                "2021-04-01 10:10:00": {
                    "close": "329.5100",
                    "high": "330.1799",
                    "low": "328.9784",
                    "open": "329.3200",
                    "volume": "22289"
                },
                "2021-04-01 10:15:00": {
                    "close": "329.7500",
                    "high": "329.8700",
                    "low": "328.8400",
                    "open": "329.7500",
                    "volume": "21910"
                },
                "2021-04-01 10:20:00": {
                    "close": "329.8800",
                    "high": "329.8800",
                    "low": "328.4100",
                    "open": "329.8200",
                    "volume": "6477"
                },
                "2021-04-01 10:25:00": {
                    "close": "329.2800",
                    "high": "329.9400",
                    "low": "328.6400",
                    "open": "329.5800",
                    "volume": "5200"
                },
                "2021-04-01 10:30:00": {
                    "close": "329.8350",
                    "high": "330.0800",
                    "low": "329.0700",
                    "open": "329.3900",
                    "volume": "11445"
                },
                "2021-04-01 10:35:00": {
                    "close": "329.7950",
                    "high": "330.5500",
                    "low": "329.4600",
                    "open": "330.1300",
                    "volume": "8154"
                },
                "2021-04-01 10:40:00": {
                    "close": "329.3300",
                    "high": "330.1100",
                    "low": "329.3300",
                    "open": "330.1000",
                    "volume": "8729"
                },
                "2021-04-01 10:45:00": {
                    "close": "330.5400",
                    "high": "330.7000",
                    "low": "329.2700",
                    "open": "329.2700",
                    "volume": "8210"
                },
                "2021-04-01 10:50:00": {
                    "close": "330.0800",
                    "high": "330.4700",
                    "low": "329.9800",
                    "open": "330.3450",
                    "volume": "6976"
                },
                "2021-04-01 10:55:00": {
                    "close": "329.9000",
                    "high": "330.4800",
                    "low": "329.9000",
                    "open": "330.1800",
                    "volume": "6522"
                },
                "2021-04-01 11:00:00": {
                    "close": "329.9400",
                    "high": "329.9500",
                    "low": "329.2150",
                    "open": "329.8100",
                    "volume": "10622"
                },
                "2021-04-01 11:05:00": {
                    "close": "330.3000",
                    "high": "330.3700",
                    "low": "329.4800",
                    "open": "329.9300",
                    "volume": "6394"
                },
                "2021-04-01 11:10:00": {
                    "close": "328.3300",
                    "high": "330.0700",
                    "low": "328.3300",
                    "open": "330.0700",
                    "volume": "7340"
                },
                "2021-04-01 11:15:00": {
                    "close": "328.1500",
                    "high": "328.4350",
                    "low": "327.8600",
                    "open": "328.1900",
                    "volume": "10997"
                },
                "2021-04-01 11:20:00": {
                    "close": "326.8909",
                    "high": "327.9200",
                    "low": "326.7000",
                    "open": "327.8300",
                    "volume": "13479"
                },
                "2021-04-01 11:25:00": {
                    "close": "327.7300",
                    "high": "328.1200",
                    "low": "326.9500",
                    "open": "326.9500",
                    "volume": "7789"
                },
                "2021-04-01 11:30:00": {
                    "close": "328.8300",
                    "high": "328.8700",
                    "low": "327.4600",
                    "open": "327.4600",
                    "volume": "9577"
                },
                "2021-04-01 11:35:00": {
                    "close": "329.4800",
                    "high": "329.5800",
                    "low": "329.1300",
                    "open": "329.1300",
                    "volume": "9107"
                },
                "2021-04-01 11:40:00": {
                    "close": "328.3748",
                    "high": "329.4600",
                    "low": "328.3748",
                    "open": "329.4600",
                    "volume": "13143"
                },
                "2021-04-01 11:45:00": {
                    "close": "327.5600",
                    "high": "328.4600",
                    "low": "327.3800",
                    "open": "328.4600",
                    "volume": "19241"
                },
                "2021-04-01 11:50:00": {
                    "close": "328.8784",
                    "high": "328.9200",
                    "low": "327.6050",
                    "open": "327.6700",
                    "volume": "6235"
                },
                "2021-04-01 11:55:00": {
                    "close": "328.9200",
                    "high": "329.2350",
                    "low": "328.7100",
                    "open": "328.9000",
                    "volume": "9322"
                },
                "2021-04-01 12:00:00": {
                    "close": "328.0800",
                    "high": "329.0800",
                    "low": "328.0800",
                    "open": "328.9550",
                    "volume": "7043"
                },
                "2021-04-01 12:05:00": {
                    "close": "328.3300",
                    "high": "328.6800",
                    "low": "328.0600",
                    "open": "328.2500",
                    "volume": "7816"
                },
                "2021-04-01 12:10:00": {
                    "close": "328.7408",
                    "high": "328.9650",
                    "low": "328.5100",
                    "open": "328.5300",
                    "volume": "8472"
                },
                "2021-04-01 12:15:00": {
                    "close": "327.9900",
                    "high": "328.5800",
                    "low": "327.7800",
                    "open": "328.4300",
                    "volume": "6726"
                },
                "2021-04-01 12:20:00": {
                    "close": "328.6100",
                    "high": "328.6900",
                    "low": "327.7600",
                    "open": "327.8650",
                    "volume": "7855"
                },
                "2021-04-01 12:25:00": {
                    "close": "327.5400",
                    "high": "328.4750",
                    "low": "327.4900",
                    "open": "328.4750",
                    "volume": "7528"
                },
                "2021-04-01 12:30:00": {
                    "close": "328.3200",
                    "high": "328.3200",
                    "low": "327.4300",
                    "open": "327.6200",
                    "volume": "6316"
                },
                "2021-04-01 12:35:00": {
                    "close": "328.0100",
                    "high": "328.7700",
                    "low": "328.0100",
                    "open": "328.7700",
                    "volume": "7293"
                },
                "2021-04-01 12:40:00": {
                    "close": "327.2200",
                    "high": "327.7800",
                    "low": "326.9600",
                    "open": "327.7800",
                    "volume": "9155"
                },
                "2021-04-01 12:45:00": {
                    "close": "328.4200",
                    "high": "328.4800",
                    "low": "327.2200",
                    "open": "327.2700",
                    "volume": "36983"
                },
                "2021-04-01 12:50:00": {
                    "close": "327.7300",
                    "high": "328.8100",
                    "low": "327.7300",
                    "open": "328.4620",
                    "volume": "9833"
                },
                "2021-04-01 12:55:00": {
                    "close": "327.6400",
                    "high": "327.8200",
                    "low": "327.3900",
                    "open": "327.3900",
                    "volume": "6860"
                },
                "2021-04-01 13:00:00": {
                    "close": "327.9100",
                    "high": "328.2000",
                    "low": "327.7200",
                    "open": "327.7200",
                    "volume": "7487"
                },
                "2021-04-01 13:05:00": {
                    "close": "327.8300",
                    "high": "328.5100",
                    "low": "327.8100",
                    "open": "328.1900",
                    "volume": "11032"
                },
                "2021-04-01 13:10:00": {
                    "close": "327.0400",
                    "high": "327.7950",
                    "low": "327.0400",
                    "open": "327.7950",
                    "volume": "6693"
                },
                "2021-04-01 13:15:00": {
                    "close": "327.1800",
                    "high": "327.4250",
                    "low": "326.7500",
                    "open": "327.0300",
                    "volume": "8645"
                },
                "2021-04-01 13:20:00": {
                    "close": "326.3250",
                    "high": "327.3750",
                    "low": "326.3200",
                    "open": "327.3750",
                    "volume": "8253"
                },
                "2021-04-01 13:25:00": {
                    "close": "326.8500",
                    "high": "326.9200",
                    "low": "326.2400",
                    "open": "326.4700",
                    "volume": "5543"
                },
                "2021-04-01 13:30:00": {
                    "close": "327.0150",
                    "high": "327.1700",
                    "low": "326.8000",
                    "open": "326.8800",
                    "volume": "7837"
                },
                "2021-04-01 13:35:00": {
                    "close": "327.6350",
                    "high": "327.6500",
                    "low": "326.8300",
                    "open": "326.9800",
                    "volume": "9763"
                },
                "2021-04-01 13:40:00": {
                    "close": "328.3700",
                    "high": "328.4000",
                    "low": "327.4600",
                    "open": "327.4600",
                    "volume": "13188"
                },
                "2021-04-01 13:45:00": {
                    "close": "326.9350",
                    "high": "328.1900",
                    "low": "326.9350",
                    "open": "328.1500",
                    "volume": "10697"
                },
                "2021-04-01 13:50:00": {
                    "close": "326.6050",
                    "high": "327.0700",
                    "low": "326.3600",
                    "open": "327.0700",
                    "volume": "7741"
                },
                "2021-04-01 13:55:00": {
                    "close": "326.8300",
                    "high": "326.8850",
                    "low": "326.5300",
                    "open": "326.6700",
                    "volume": "7592"
                },
                "2021-04-01 14:00:00": {
                    "close": "326.2700",
                    "high": "326.9700",
                    "low": "326.2700",
                    "open": "326.8350",
                    "volume": "6317"
                },
                "2021-04-01 14:05:00": {
                    "close": "326.4200",
                    "high": "326.5300",
                    "low": "326.2100",
                    "open": "326.4000",
                    "volume": "7903"
                },
                "2021-04-01 14:10:00": {
                    "close": "326.2600",
                    "high": "326.7250",
                    "low": "325.8500",
                    "open": "326.3300",
                    "volume": "19968"
                },
                "2021-04-01 14:15:00": {
                    "close": "327.4900",
                    "high": "327.4900",
                    "low": "326.3000",
                    "open": "326.3000",
                    "volume": "8419"
                },
                "2021-04-01 14:20:00": {
                    "close": "326.7900",
                    "high": "327.3300",
                    "low": "326.5600",
                    "open": "327.3300",
                    "volume": "9085"
                },
                "2021-04-01 14:25:00": {
                    "close": "327.3500",
                    "high": "327.4900",
                    "low": "326.7300",
                    "open": "326.8000",
                    "volume": "8359"
                },
                "2021-04-01 14:30:00": {
                    "close": "326.8400",
                    "high": "327.2300",
                    "low": "326.6800",
                    "open": "327.2300",
                    "volume": "8482"
                },
                "2021-04-01 14:35:00": {
                    "close": "326.9300",
                    "high": "327.1300",
                    "low": "326.8300",
                    "open": "326.9600",
                    "volume": "7836"
                },
                "2021-04-01 14:40:00": {
                    "close": "326.8200",
                    "high": "327.0200",
                    "low": "326.4250",
                    "open": "326.9495",
                    "volume": "12190"
                },
                "2021-04-01 14:45:00": {
                    "close": "326.8100",
                    "high": "326.8700",
                    "low": "326.6200",
                    "open": "326.6950",
                    "volume": "2254"
                },
                "2021-04-01 14:50:00": {
                    "close": "327.0800",
                    "high": "327.2300",
                    "low": "326.3300",
                    "open": "326.8200",
                    "volume": "13308"
                },
                "2021-04-01 14:55:00": {
                    "close": "327.1700",
                    "high": "327.3300",
                    "low": "326.9700",
                    "open": "327.1100",
                    "volume": "9227"
                },
                "2021-04-01 15:00:00": {
                    "close": "327.2650",
                    "high": "327.8700",
                    "low": "327.1800",
                    "open": "327.1900",
                    "volume": "12801"
                },
                "2021-04-01 15:05:00": {
                    "close": "326.6100",
                    "high": "327.3700",
                    "low": "326.4200",
                    "open": "327.2600",
                    "volume": "15935"
                },
                "2021-04-01 15:10:00": {
                    "close": "326.9200",
                    "high": "327.0900",
                    "low": "326.5000",
                    "open": "326.5000",
                    "volume": "23641"
                },
                "2021-04-01 15:15:00": {
                    "close": "326.1700",
                    "high": "326.8500",
                    "low": "326.1700",
                    "open": "326.8400",
                    "volume": "11739"
                },
                "2021-04-01 15:20:00": {
                    "close": "326.8700",
                    "high": "326.9400",
                    "low": "326.1700",
                    "open": "326.1700",
                    "volume": "11382"
                },
                "2021-04-01 15:25:00": {
                    "close": "326.8000",
                    "high": "327.0000",
                    "low": "326.5800",
                    "open": "327.0000",
                    "volume": "9400"
                },
                "2021-04-01 15:30:00": {
                    "close": "327.1000",
                    "high": "327.1100",
                    "low": "326.7913",
                    "open": "326.9500",
                    "volume": "9949"
                },
                "2021-04-01 15:35:00": {
                    "close": "327.0300",
                    "high": "327.4700",
                    "low": "327.0200",
                    "open": "327.1000",
                    "volume": "12255"
                },
                "2021-04-01 15:40:00": {
                    "close": "326.8400",
                    "high": "327.0400",
                    "low": "326.3700",
                    "open": "327.0400",
                    "volume": "16750"
                },
                "2021-04-01 15:45:00": {
                    "close": "326.5900",
                    "high": "326.8500",
                    "low": "326.3000",
                    "open": "326.7900",
                    "volume": "16489"
                },
                "2021-04-01 15:50:00": {
                    "close": "327.0800",
                    "high": "327.3900",
                    "low": "326.5800",
                    "open": "326.6050",
                    "volume": "14594"
                },
                "2021-04-01 15:55:00": {
                    "close": "326.9000",
                    "high": "327.6100",
                    "low": "326.8800",
                    "open": "327.0800",
                    "volume": "25794"
                },
                "2021-04-01 16:00:00": {
                    "close": "328.2700",
                    "high": "328.2800",
                    "low": "326.9100",
                    "open": "326.9100",
                    "volume": "50395"
                },
                "2021-04-01 16:05:00": {
                    "close": "328.0500",
                    "high": "328.0500",
                    "low": "328.0500",
                    "open": "328.0500",
                    "volume": "2197"
                }
            },
            "Time Zone": "US/Eastern"
        }
    }
}
```

#### Human Readable Output

>### Stock History (Interval: 5min)
>|2021-03-31 14:45:00|2021-03-31 14:50:00|2021-03-31 14:55:00|2021-03-31 15:00:00|2021-03-31 15:05:00|2021-03-31 15:10:00|2021-03-31 15:15:00|2021-03-31 15:20:00|2021-03-31 15:25:00|2021-03-31 15:30:00|2021-03-31 15:35:00|2021-03-31 15:40:00|2021-03-31 15:45:00|2021-03-31 15:50:00|2021-03-31 15:55:00|2021-03-31 16:00:00|2021-03-31 16:05:00|2021-03-31 16:15:00|2021-03-31 16:25:00|2021-04-01 09:05:00|2021-04-01 09:30:00|2021-04-01 09:35:00|2021-04-01 09:40:00|2021-04-01 09:45:00|2021-04-01 09:50:00|2021-04-01 09:55:00|2021-04-01 10:00:00|2021-04-01 10:05:00|2021-04-01 10:10:00|2021-04-01 10:15:00|2021-04-01 10:20:00|2021-04-01 10:25:00|2021-04-01 10:30:00|2021-04-01 10:35:00|2021-04-01 10:40:00|2021-04-01 10:45:00|2021-04-01 10:50:00|2021-04-01 10:55:00|2021-04-01 11:00:00|2021-04-01 11:05:00|2021-04-01 11:10:00|2021-04-01 11:15:00|2021-04-01 11:20:00|2021-04-01 11:25:00|2021-04-01 11:30:00|2021-04-01 11:35:00|2021-04-01 11:40:00|2021-04-01 11:45:00|2021-04-01 11:50:00|2021-04-01 11:55:00|2021-04-01 12:00:00|2021-04-01 12:05:00|2021-04-01 12:10:00|2021-04-01 12:15:00|2021-04-01 12:20:00|2021-04-01 12:25:00|2021-04-01 12:30:00|2021-04-01 12:35:00|2021-04-01 12:40:00|2021-04-01 12:45:00|2021-04-01 12:50:00|2021-04-01 12:55:00|2021-04-01 13:00:00|2021-04-01 13:05:00|2021-04-01 13:10:00|2021-04-01 13:15:00|2021-04-01 13:20:00|2021-04-01 13:25:00|2021-04-01 13:30:00|2021-04-01 13:35:00|2021-04-01 13:40:00|2021-04-01 13:45:00|2021-04-01 13:50:00|2021-04-01 13:55:00|2021-04-01 14:00:00|2021-04-01 14:05:00|2021-04-01 14:10:00|2021-04-01 14:15:00|2021-04-01 14:20:00|2021-04-01 14:25:00|2021-04-01 14:30:00|2021-04-01 14:35:00|2021-04-01 14:40:00|2021-04-01 14:45:00|2021-04-01 14:50:00|2021-04-01 14:55:00|2021-04-01 15:00:00|2021-04-01 15:05:00|2021-04-01 15:10:00|2021-04-01 15:15:00|2021-04-01 15:20:00|2021-04-01 15:25:00|2021-04-01 15:30:00|2021-04-01 15:35:00|2021-04-01 15:40:00|2021-04-01 15:45:00|2021-04-01 15:50:00|2021-04-01 15:55:00|2021-04-01 16:00:00|2021-04-01 16:05:00|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| open: 324.2000<br/>high: 324.4400<br/>low: 323.4800<br/>close: 324.1500<br/>volume: 14877 | open: 324.3850<br/>high: 324.6900<br/>low: 324.0800<br/>close: 324.1300<br/>volume: 7734 | open: 323.9740<br/>high: 324.4750<br/>low: 323.7500<br/>close: 324.4750<br/>volume: 5611 | open: 324.4800<br/>high: 324.7500<br/>low: 324.0300<br/>close: 324.0300<br/>volume: 7327 | open: 324.3800<br/>high: 325.0200<br/>low: 324.3800<br/>close: 325.0200<br/>volume: 5967 | open: 325.2500<br/>high: 325.2500<br/>low: 324.6000<br/>close: 324.8600<br/>volume: 5504 | open: 324.6600<br/>high: 325.1390<br/>low: 324.6200<br/>close: 324.8300<br/>volume: 8099 | open: 324.8500<br/>high: 325.3150<br/>low: 324.4100<br/>close: 324.4100<br/>volume: 12790 | open: 324.3500<br/>high: 324.7200<br/>low: 323.8200<br/>close: 323.8200<br/>volume: 9676 | open: 323.6400<br/>high: 324.0000<br/>low: 323.5700<br/>close: 323.8900<br/>volume: 16436 | open: 323.8500<br/>high: 324.3200<br/>low: 323.4650<br/>close: 324.1800<br/>volume: 17200 | open: 324.0200<br/>high: 324.3850<br/>low: 323.9150<br/>close: 324.1800<br/>volume: 18491 | open: 324.2000<br/>high: 325.1900<br/>low: 324.0800<br/>close: 324.9700<br/>volume: 17295 | open: 325.0000<br/>high: 325.0000<br/>low: 324.0000<br/>close: 324.1700<br/>volume: 12737 | open: 324.0500<br/>high: 324.4300<br/>low: 322.9500<br/>close: 323.0800<br/>volume: 21790 | open: 323.0300<br/>high: 323.0900<br/>low: 322.0600<br/>close: 322.3000<br/>volume: 75705 | open: 322.0600<br/>high: 322.0600<br/>low: 322.0600<br/>close: 322.0600<br/>volume: 24212 | open: 322.0600<br/>high: 322.0600<br/>low: 322.0600<br/>close: 322.0600<br/>volume: 8400 | open: 322.0600<br/>high: 322.0600<br/>low: 322.0600<br/>close: 322.0600<br/>volume: 8400 | open: 322.0600<br/>high: 322.0600<br/>low: 322.0600<br/>close: 322.0600<br/>volume: 2564 | open: 327.0600<br/>high: 327.5400<br/>low: 327.0600<br/>close: 327.5400<br/>volume: 415 | open: 327.0000<br/>high: 330.9200<br/>low: 327.0000<br/>close: 330.7000<br/>volume: 41300 | open: 330.9900<br/>high: 332.7650<br/>low: 329.0000<br/>close: 329.3700<br/>volume: 17485 | open: 329.3100<br/>high: 330.2900<br/>low: 329.0700<br/>close: 329.2500<br/>volume: 16405 | open: 329.7350<br/>high: 330.8000<br/>low: 329.3400<br/>close: 330.7800<br/>volume: 7280 | open: 330.4400<br/>high: 331.0300<br/>low: 330.0500<br/>close: 330.5500<br/>volume: 7345 | open: 330.9200<br/>high: 331.9900<br/>low: 330.9000<br/>close: 331.4200<br/>volume: 13618 | open: 331.7400<br/>high: 332.0500<br/>low: 329.4100<br/>close: 329.4100<br/>volume: 44828 | open: 329.3200<br/>high: 330.1799<br/>low: 328.9784<br/>close: 329.5100<br/>volume: 22289 | open: 329.7500<br/>high: 329.8700<br/>low: 328.8400<br/>close: 329.7500<br/>volume: 21910 | open: 329.8200<br/>high: 329.8800<br/>low: 328.4100<br/>close: 329.8800<br/>volume: 6477 | open: 329.5800<br/>high: 329.9400<br/>low: 328.6400<br/>close: 329.2800<br/>volume: 5200 | open: 329.3900<br/>high: 330.0800<br/>low: 329.0700<br/>close: 329.8350<br/>volume: 11445 | open: 330.1300<br/>high: 330.5500<br/>low: 329.4600<br/>close: 329.7950<br/>volume: 8154 | open: 330.1000<br/>high: 330.1100<br/>low: 329.3300<br/>close: 329.3300<br/>volume: 8729 | open: 329.2700<br/>high: 330.7000<br/>low: 329.2700<br/>close: 330.5400<br/>volume: 8210 | open: 330.3450<br/>high: 330.4700<br/>low: 329.9800<br/>close: 330.0800<br/>volume: 6976 | open: 330.1800<br/>high: 330.4800<br/>low: 329.9000<br/>close: 329.9000<br/>volume: 6522 | open: 329.8100<br/>high: 329.9500<br/>low: 329.2150<br/>close: 329.9400<br/>volume: 10622 | open: 329.9300<br/>high: 330.3700<br/>low: 329.4800<br/>close: 330.3000<br/>volume: 6394 | open: 330.0700<br/>high: 330.0700<br/>low: 328.3300<br/>close: 328.3300<br/>volume: 7340 | open: 328.1900<br/>high: 328.4350<br/>low: 327.8600<br/>close: 328.1500<br/>volume: 10997 | open: 327.8300<br/>high: 327.9200<br/>low: 326.7000<br/>close: 326.8909<br/>volume: 13479 | open: 326.9500<br/>high: 328.1200<br/>low: 326.9500<br/>close: 327.7300<br/>volume: 7789 | open: 327.4600<br/>high: 328.8700<br/>low: 327.4600<br/>close: 328.8300<br/>volume: 9577 | open: 329.1300<br/>high: 329.5800<br/>low: 329.1300<br/>close: 329.4800<br/>volume: 9107 | open: 329.4600<br/>high: 329.4600<br/>low: 328.3748<br/>close: 328.3748<br/>volume: 13143 | open: 328.4600<br/>high: 328.4600<br/>low: 327.3800<br/>close: 327.5600<br/>volume: 19241 | open: 327.6700<br/>high: 328.9200<br/>low: 327.6050<br/>close: 328.8784<br/>volume: 6235 | open: 328.9000<br/>high: 329.2350<br/>low: 328.7100<br/>close: 328.9200<br/>volume: 9322 | open: 328.9550<br/>high: 329.0800<br/>low: 328.0800<br/>close: 328.0800<br/>volume: 7043 | open: 328.2500<br/>high: 328.6800<br/>low: 328.0600<br/>close: 328.3300<br/>volume: 7816 | open: 328.5300<br/>high: 328.9650<br/>low: 328.5100<br/>close: 328.7408<br/>volume: 8472 | open: 328.4300<br/>high: 328.5800<br/>low: 327.7800<br/>close: 327.9900<br/>volume: 6726 | open: 327.8650<br/>high: 328.6900<br/>low: 327.7600<br/>close: 328.6100<br/>volume: 7855 | open: 328.4750<br/>high: 328.4750<br/>low: 327.4900<br/>close: 327.5400<br/>volume: 7528 | open: 327.6200<br/>high: 328.3200<br/>low: 327.4300<br/>close: 328.3200<br/>volume: 6316 | open: 328.7700<br/>high: 328.7700<br/>low: 328.0100<br/>close: 328.0100<br/>volume: 7293 | open: 327.7800<br/>high: 327.7800<br/>low: 326.9600<br/>close: 327.2200<br/>volume: 9155 | open: 327.2700<br/>high: 328.4800<br/>low: 327.2200<br/>close: 328.4200<br/>volume: 36983 | open: 328.4620<br/>high: 328.8100<br/>low: 327.7300<br/>close: 327.7300<br/>volume: 9833 | open: 327.3900<br/>high: 327.8200<br/>low: 327.3900<br/>close: 327.6400<br/>volume: 6860 | open: 327.7200<br/>high: 328.2000<br/>low: 327.7200<br/>close: 327.9100<br/>volume: 7487 | open: 328.1900<br/>high: 328.5100<br/>low: 327.8100<br/>close: 327.8300<br/>volume: 11032 | open: 327.7950<br/>high: 327.7950<br/>low: 327.0400<br/>close: 327.0400<br/>volume: 6693 | open: 327.0300<br/>high: 327.4250<br/>low: 326.7500<br/>close: 327.1800<br/>volume: 8645 | open: 327.3750<br/>high: 327.3750<br/>low: 326.3200<br/>close: 326.3250<br/>volume: 8253 | open: 326.4700<br/>high: 326.9200<br/>low: 326.2400<br/>close: 326.8500<br/>volume: 5543 | open: 326.8800<br/>high: 327.1700<br/>low: 326.8000<br/>close: 327.0150<br/>volume: 7837 | open: 326.9800<br/>high: 327.6500<br/>low: 326.8300<br/>close: 327.6350<br/>volume: 9763 | open: 327.4600<br/>high: 328.4000<br/>low: 327.4600<br/>close: 328.3700<br/>volume: 13188 | open: 328.1500<br/>high: 328.1900<br/>low: 326.9350<br/>close: 326.9350<br/>volume: 10697 | open: 327.0700<br/>high: 327.0700<br/>low: 326.3600<br/>close: 326.6050<br/>volume: 7741 | open: 326.6700<br/>high: 326.8850<br/>low: 326.5300<br/>close: 326.8300<br/>volume: 7592 | open: 326.8350<br/>high: 326.9700<br/>low: 326.2700<br/>close: 326.2700<br/>volume: 6317 | open: 326.4000<br/>high: 326.5300<br/>low: 326.2100<br/>close: 326.4200<br/>volume: 7903 | open: 326.3300<br/>high: 326.7250<br/>low: 325.8500<br/>close: 326.2600<br/>volume: 19968 | open: 326.3000<br/>high: 327.4900<br/>low: 326.3000<br/>close: 327.4900<br/>volume: 8419 | open: 327.3300<br/>high: 327.3300<br/>low: 326.5600<br/>close: 326.7900<br/>volume: 9085 | open: 326.8000<br/>high: 327.4900<br/>low: 326.7300<br/>close: 327.3500<br/>volume: 8359 | open: 327.2300<br/>high: 327.2300<br/>low: 326.6800<br/>close: 326.8400<br/>volume: 8482 | open: 326.9600<br/>high: 327.1300<br/>low: 326.8300<br/>close: 326.9300<br/>volume: 7836 | open: 326.9495<br/>high: 327.0200<br/>low: 326.4250<br/>close: 326.8200<br/>volume: 12190 | open: 326.6950<br/>high: 326.8700<br/>low: 326.6200<br/>close: 326.8100<br/>volume: 2254 | open: 326.8200<br/>high: 327.2300<br/>low: 326.3300<br/>close: 327.0800<br/>volume: 13308 | open: 327.1100<br/>high: 327.3300<br/>low: 326.9700<br/>close: 327.1700<br/>volume: 9227 | open: 327.1900<br/>high: 327.8700<br/>low: 327.1800<br/>close: 327.2650<br/>volume: 12801 | open: 327.2600<br/>high: 327.3700<br/>low: 326.4200<br/>close: 326.6100<br/>volume: 15935 | open: 326.5000<br/>high: 327.0900<br/>low: 326.5000<br/>close: 326.9200<br/>volume: 23641 | open: 326.8400<br/>high: 326.8500<br/>low: 326.1700<br/>close: 326.1700<br/>volume: 11739 | open: 326.1700<br/>high: 326.9400<br/>low: 326.1700<br/>close: 326.8700<br/>volume: 11382 | open: 327.0000<br/>high: 327.0000<br/>low: 326.5800<br/>close: 326.8000<br/>volume: 9400 | open: 326.9500<br/>high: 327.1100<br/>low: 326.7913<br/>close: 327.1000<br/>volume: 9949 | open: 327.1000<br/>high: 327.4700<br/>low: 327.0200<br/>close: 327.0300<br/>volume: 12255 | open: 327.0400<br/>high: 327.0400<br/>low: 326.3700<br/>close: 326.8400<br/>volume: 16750 | open: 326.7900<br/>high: 326.8500<br/>low: 326.3000<br/>close: 326.5900<br/>volume: 16489 | open: 326.6050<br/>high: 327.3900<br/>low: 326.5800<br/>close: 327.0800<br/>volume: 14594 | open: 327.0800<br/>high: 327.6100<br/>low: 326.8800<br/>close: 326.9000<br/>volume: 25794 | open: 326.9100<br/>high: 328.2800<br/>low: 326.9100<br/>close: 328.2700<br/>volume: 50395 | open: 328.0500<br/>high: 328.0500<br/>low: 328.0500<br/>close: 328.0500<br/>volume: 2197 |

