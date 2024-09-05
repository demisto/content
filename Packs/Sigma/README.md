# Sigma

#### Overview

The Sigma Detection Rules Pack provides integration with Sigma, a generic and open signature format for SIEM systems. This pack enables you to create, manage, and utilize Sigma detection rules within Cortex XSOAR. Sigma rules allow you to describe relevant log events in a straightforward and universal format, which can be easily converted to SIEM-specific queries.

#### What does this pack do?

This new pack enables the user to import Sigma rules either via a string or by a file into the XSOAR TIM. Once in the system the user can use the built in scripts to convert there newly added rules into the format of his choice and use it to query 3rd party security products.

#### Content delivered with the pack

- An additional XSOAR indicator type called "Sigma Rule".
- All the relevant fields needed to store the data of the "Sigma Rule" indicator.
- A new layout for the newly added indicator type.
- Utility scripts needed to import Sigma rules and export them in the user chosen format.

##### Additional Information

_For more information about Sigma and its usages please visit [Sigma HQ](https://sigmahq.io/).
