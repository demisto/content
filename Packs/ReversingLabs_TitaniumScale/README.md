## What is the ReversingLabs TitaniumScale Cortex XSOAR integration pack?
TitaniumScale Worker incorporates ReversingLabs TitaniumCore, the world’s fastest and most
comprehensive software platform for automated static decomposition and analysis of binary files.
TitaniumCore can automatically unpack and extract all available information from all variants of more
than 300 PE packer, archive, installation package, firmware image, document and mobile application
formats.
The extracted information includes metadata such as strings, format header details, function names,
library dependencies, file segments and capabilities, along with static analysis results. This
information is contained in the TitaniumScale Worker Analysis Report.

This pack provides Cortex XSOAR integrations created by ReversingLabs that allow seamless and effective use of TitaniumScale services through the Cortex XSOAR interface.

This pack also includes 1 playbook:
- **Detonate File - ReversingLabs TitaniumScale**: Upload sample to ReversingLabs TitaniumScale instance and retrieve the analysis report.

#### Currently available integrations:
- ReversingLabs TitaniumScale
    - Enables the use of TitaniumScale services for submitting samples and fetching analysis reports.
    - The included commands can be used separately in the War Room or as part of a playbook.

