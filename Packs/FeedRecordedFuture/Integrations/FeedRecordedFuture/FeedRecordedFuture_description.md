## Recorded Future Feed
This integration downloads from Recorded Future a list of IPs , domains, URLs, or file hash with known risk.
The risk list includes risk scores and supporting evidence details.
- The feed can be configured to load a specific risk list by specifying a risk rule.
If no risk rule is specified, Recorded Future’s default risk list is used, which only contains indicators with score above 65.
To find the available risk rules for every indicator you can use the ‘rf-get-risk-rules’ command.
- The feed can also be configured to load a custom risk list from a user-specified Recorded Future file path.
If no file path is specified, the default risk list file is used.

Recorded Future's indicators scoring:
- Above 90 - Very Malicious
- Between 65 to 90 - Malicious
- Between 25 to 90 - Suspicious
- Between 5 to 25 - Unusual

To access this resource, you need a valid Recorded Future API token.