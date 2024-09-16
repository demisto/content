# Humio integration
## Obtaining an API key
Go to https://your-humio/settings and copy the API token. Example [https://cloud.humio.com/settings](https://cloud.humio.com/settings)

## Important note regarding `humio-query`
This command can potentially contain unlimited amounts of data, which XSOAR does not like, it is a good idea to include a `head(50)` to the end of any query that otherwise may be unbounded / non-aggregate queries. A sign that you are receiving too much data is that the command is executed but no results are returned for a long time.

## Fetch incidents
The parameters used for fetch-incidents are only used if you want to use the fetch incidents feature. It is recommended to use alerts and notifiers in Humio to send this data to XSOAR via a webhook notifier instead. You can read more about the supported time-formats for backfilling [here](https://docs.humio.com/api/using-the-search-api-with-humio/#time-specification)