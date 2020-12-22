Use the Bitcoin Abuse integration to access a public database of bitcoin addresses used by scammers, hackers, and criminals.

Fetching indicators from Bitcoin Abuse has 3 available options:
- Forever (holds all data from beginning of time to current, updated monthly every 15th of month)
- 30 Days (holds all data from last month, updated weekly every sunday)
- 1 Day (holds all data from last day, updated daily).

All updates occur between 2am-3am UTC.

## Initial Fetch
After you configure an integration instance, you will be required to enter the first fetch window, when 2 options are available:

in order to bring as much data as possible in the first fetch, whenever Forever is selected, we
download Forever CSV file and merge it with 30 Days CSV file to avoid missing as much data as possible.

restrictions will be that any data from sunday (after 30 Days file update) to the day of the first fetch
will not be fetched


### Fetch Indicators after initial fetch
* Each fetch will be done by Bitcoin Abuse option of 1 day.
* The default configuration for fetching interval will be 1 day, as been mentioned above the update of their CSV file happens once per day, so fetching more than once a day will not have any effect.
