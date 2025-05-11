# Windows LOLBIN Scripting Engine Connected to a Rare External Host

## Overview
This playbook handles alerts related to Windows LOLBINs (Living-Off-the-Land Binaries) scripting engines connecting to rare external hosts, which may indicate command and control activity.

## Use Cases
- Detecting and responding to suspicious scripting activity
- Identifying and remediating potential command and control channels
- Blocking malicious URLs discovered in command lines
- Containing compromised endpoints

## MITRE ATT&CK Techniques
- T1071 - Application Layer Protocol
- T1059 - Command and Scripting Interpreter
- TA0011 - Command and Control
- TA0002 - Execution

## Playbook Workflow

### Analysis Stage
- Searches for related Cortex XSIAM alerts connected to the current incident
- Performs command line analysis to detect malicious patterns and scripts
- Assigns a risk score based on command behavior

### Investigation Stage
- Checks for URLs in the command line and enriches them for reputation
- Evaluates URLs for malicious indicators
- Examines related BTP alerts, bad URLs, and suspicious commands
- Determines if the activity is likely malicious or a false positive

### Remediation Stage
1. **Process Termination**
   - Checks if the causality was already blocked by the agent
   - Attempts to terminate the malicious process tree if not already blocked
   - Provides manual remediation guidance if automatic termination fails

2. **URL Blocking**
   - Identifies malicious URLs for blocking
   - Requests analyst approval for URL blocking through PAN-OS
   - If approved, uses PAN-OS to block malicious URLs through Custom URL Categories

3. **Endpoint Containment**
   - Determines if the affected endpoint is a workstation or server
   - For workstations, requests approval to isolate the endpoint if high-confidence malicious activity is detected
   - For servers or disconnected endpoints, prompts the analyst for manual remediation

### Alert Resolution
- Closes the alert as True Positive with appropriate resolution notes when malicious activity is confirmed
- Closes the alert as False Positive if investigation determines benign activity

## Dependencies
- Cortex XSIAM 2.4 or later for causality termination functionality
- PAN-OS for URL blocking capabilities (uses the "PAN-OS - Block URL - Custom URL Category" sub-playbook)
- CommandLineAnalysis script for analyzing command behavior
- SearchAlertsV2 script for finding related alerts

## Outputs
This playbook doesn't produce specific outputs but performs several remediation actions including:
- Process termination
- URL blocking
- Endpoint isolation (when appropriate and approved)