
Use the Bitcoin Abuse integration to access a public database of bitcoin addresses used by scammers, hackers, and criminals.

#### Fetching indicators
When configuring an integration instance, you will be required to enter the first fetch parameter which will set the timeframe to pull Indicators in the first fetch, Two options are available:

- 30 Days - Indicators recorded in the last 30 days (updates every Sunday between 2am-3am UTC.)
- Forever - All recorded indicators (updates every 15th of the month between 2am-3am UTC.)

Each fetch after the initial fetch will return indicators reported on the previous day (updates once a day between 2am-3am UTC). Therefore, fetching more than once a day will not have any effect.
