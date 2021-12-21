## Known Limitations:
* Sort can drop search results.
* Search is limited to 100 results.
* Time range searches are limited to full days (e.g. after:2020-10-10).
* Max page size is 10 (i.e. to get 100 results we need to send 10 requests with start=11, start=21...)

## TODO:
* Search should match fetch-incidents.
* finish fetch-incidents:
  * Download file.
  * Manage time ranges.
  * Manage de-dups.
