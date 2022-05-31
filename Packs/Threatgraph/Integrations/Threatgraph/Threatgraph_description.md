### Threatgraph

Uses the deprecated crowdstrike graph api to return process and other information.
This is required UNTIL a replacement has been created as currently none does.

Supply a CrowdStrike sensor ID (e.g. from host) and process id (e.g. what triggered the event)
and the ThreatGraph API is invoked, finding all parent/child information as well as IP and other relevant information