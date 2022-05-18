## Notes
1. It is highly recommended to not create multiple instances of the same indicator type, even when fetching both from fusion and connectApi. Creating multiple instances with same indicator type will lead to duplicate indicators being fetched which can cause performance issues for the server.
2. Recommended interval for fetching indicators according to Recorded Future documentation:

| **Indicator Type** | **Recommended Fetch Interval**
| --- | --- |
| IP | 1 Hour. |
| Domain | 2 Hours. |
| Hash | 1 Day. |
| URL | 2 Hours. |
| Vulnerability | 2 Hours. |
3. Per instance configuration, it is recommended to use either `connectApi` or `fusion` as a service for chosen indicator type, and not both, as most of the data between both services is duplicated.
## Recorded Future Feed
This integration downloads from Recorded Future a list of IP addresses, domains, URLs, CVEs or file hashes with known risk associations.
The risk list includes risk scores and supporting evidence details.
- The 'Connect Api' feed can be configured to load a specific risk list by specifying a risk rule.
If no risk rule is specified, Recorded Future’s default risk list is used, which only contains indicators with score above 65.
To find the available risk rules for every indicator you can use the ‘rf-get-risk-rules’ command.
- The 'Fusion' feed be configured to load a custom risk list from a user-specified Recorded Future file path.
If no file path is specified, the default risk list file is used.

Recorded Future's indicators scoring:
- Above 90 - Very Malicious
- Between 65 to 90 - Malicious
- Between 25 to 90 - Suspicious
- Between 5 to 25 - Unusual

To access this resource, a valid Recorded Future API token is required.