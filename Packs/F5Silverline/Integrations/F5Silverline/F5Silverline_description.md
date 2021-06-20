## F5 Silverline

To configure an instance of F5 Silverline, you need to obtain the following information.

* Server URL
* API Key

## Get your API Key
1. In F5 Silverline portal, go to **Config** > **API Tokens** .
2. If you already have an API key you can find it there.
3. If you do not have an API Key, generate one by clicking **Add**.

## Fetching F5 Silverline Alerts

As the F5 Silverline API does not support fetch incidents for now, we retrieve alerts via a log collector.   
In order to fetch alerts, follow the instructions [here](https://github.com/demisto/content/raw/master/Packs/F5Silverline/Integrations/F5Silverline/README.md#fetch-f5-silverline-alerts)