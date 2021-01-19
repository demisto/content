## Overview

The JARM pack for Cortex XSOAR leverages a the [pyJARM](https://github.com/PaloAltoNetworks/pyjarm) library for generating JARM fingerprints. pyJARM is based on the original [Salesforce research and implementation](https://github.com/salesforce/jarm) for fingerprinting servers using TLS. JARM is an active Transport Layer Security (TLS) server fingerprinting tool.
JARM can be useful in a number of use-cases including:
1. Verifying that a group of servers share the same TLS configuration.
2. Comparing JARM fingerprints to the fingerprints of known malicious actors to identify servers that may belong to a specific threat actor.
3. Identifying whether your own servers are using the expected TLS configuration by comparing with a Known-good server.
JARM is an active fingerprinting tool, which means that generating a JARM fingerprint requires making multiple connections to the target server. Specifically, the JARM fingerprinting uses 10 custom crafted TLS client hello packets to generate the raw information necessary for fingerprinting. 
You can read more about how JARM works [here](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a). 

## Default Indicator Type
This pack includes the JARM indicator type.

## Indicator Fields
This following are the indicator fields for the JARM indicator layout.
- Fingerprint
- IP
- Port

## Commands
This pack includes following Command.
- **jarm-fingerprint** - Accepts a host and a port to attempt to generate a JARM fingerprint for.
