Note: This is a beta pack, which lets you implement and test pre-release software. Since the pack is beta, it might contain bugs. Updates to the pack during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the pack to help us identify issues, fix them, and continually improve.

Vectra® is the leading AI-driven threat detection and response platform for the enterprise.
Only Vectra optimizes AI to detect advanced attacker behaviors across hybrid and multi-cloud environments.
The resulting high-fidelity signal and rich context enables security teams to prioritize, investigate and respond to threats in real-time.
Learn more at [Vectra Website](https://www.vectra.ai).

This pack is designed to quickly integrate with Vectra Detect platform to detect and analyze malicious attacks in progress by creating incident based on Accounts, Hosts or Detections. It gives security engineers visibility into advanced threats to speed detection and remediation response times.

## What does this pack do?

* Mirrors incidents between Cortex XSOAR incidents and Vectra Detect Accounts, Hosts and Detections alerts.
* Enriches incidents
* Download detection PCAP
* Push tags to Vectra Detect platform

## Before you start

Make sure you have the following content packs:

* Base
* Common Scripts
* Common Types

## Pack configuration

To get up and running with this pack, you must have a valid API token on your Vectra Detect instance.  

It can be retrieved from the Vectra UI > My Profile > General \(tab\) > API Token.  
Be sure that the user has a role with sufficient permissions to do all the actions.

