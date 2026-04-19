# Superna Zero Trust Snapshot

## Overview

You can run this playbook for any incident where data security is at risk and an immutable snapshot is needed to protect critical data. The snapshot can be used to recover data and Cyber Storage analytics from Security Edition can detect malicious data activity and log file access. This is necessary to root cause what data was affected by a security incident.

## Playbook Tasks

1. **Start** - Initiates the playbook
2. **Superna Zero Trust Snapshot Critical Paths** - Creates a snapshot of Superna critical paths for ransomware rapid recovery using the SupernaZeroTrust integration
3. **Done** - Completes the playbook

## Inputs

| **Name** | **Description** | **Required** |
| --- | --- | --- |
| username | Username from incident context | No |

## Outputs

The playbook stores the snapshot operation result in the context path:

- SupernaZeroTrust.Snapshot.Result

## Use Cases

- Ransomware incident response
- Data breach investigation
- Critical data protection during security incidents
- Cyber storage analytics and forensics

## Dependencies

This playbook requires the SupernaZeroTrust integration to be configured with valid API credentials and base URL.
