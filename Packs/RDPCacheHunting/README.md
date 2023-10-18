## What Does This Pack Do?


This pack offers a set of tools to detect suspicious activity in RDP cache files on a system. It helps you search, collect, and analyze the contents of these files to identify potential indicators of compromise (IOCs). 

## Getting Started / How to Set up the Pack

To get started with this pack, follow the instructions below:

1. Go to Marketplace and install this pack.
2. Create a new job and select the incident type "RDP Sessions".
3. Add any additional details to the job.
4. Refer to the pack's documentation for further instructions.

### Additional Technical Details

This RDP Cache Hunting pack provides an efficient way to investigate potential suspicious activity on your Remote Desktop Protocol (RDP) connections. 

It allows you to collect RDP bitmap cache files using XDR, CarbonBlack, or Powershell, extract tiles from them, process the collages, and extract text from the tiles. You can then search the extracted text for indicators of compromise (IOCs) using the MITRE ATT&CK Software list and Mandiant Stringsifter ML ranking capabilities. 

The overall score of the pack is determined by summing up the similarity ratios for the strings and tools found in the similarity check (with a maximum score of 5 per finding) and the Stringsifter rank of any executable found using `'extractindicators'`. If the score is 0, no suspicious strings were found. 

This pack will help you detect potential internal RDP sessions on predefined hosts, identify any suspicious activity, and provide you with the collage processed for further analysis.
