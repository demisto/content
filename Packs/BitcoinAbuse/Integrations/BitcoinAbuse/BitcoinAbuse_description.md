
Use the integration to fetch Bitcoin Cryptocurrency Address indicators from BitcoinAbuse.com, a public database of bitcoin addresses used by hackers and criminals.

#### Get Your API Key
In order to use Bitcoin Abuse service, you need to get your API key.
The API key is free and can be achieved by doing the following:
1. Navigate to https://www.bitcoinabuse.com and click on "Register" on top right corner of your screen.
2. Fill in your details (Name, Email, Password, etc...)
3. After your account have been set, go to Settings, and click on "API" section.
4. Give your API token a name, and click on "Create", and a screen containing your generated API key
will appear.
   
#### Fetching indicators
When configuring an integration instance, you will be required to enter the first fetch parameter which will set the timeframe to pull Indicators in the first fetch, Two options are available:

- 30 Days - Indicators recorded in the last 30 days (updates every Sunday between 2am-3am UTC.)
- Forever - All recorded indicators (updates every 15th of the month between 2am-3am UTC.)

Each fetch after the initial fetch will return indicators reported on the previous day (updates once a day between 2am-3am UTC). Therefore, fetching more than once a day will not have any effect.
