import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

usecasestepsdata = """{
    "URL Enrichment": {
        "type": "playbook",
        "name": "URL Enrichment - Generic v2"
    },
    "IP Enrichment": {
        "type": "playbook",
        "name": "IP Enrichment - Generic v2"
    },
    "User Enrichment": {
        "type": "playbook",
        "name": "Account Enrichment - Generic v2.1"
    },
    "Host Enrichment": {
        "type": "playbook",
        "name": "Endpoint Enrichment - Generic v2.1"
    },
    "Domain Enrichment": {
        "type": "playbook",
        "name": "Domain Enrichment - Generic v2"
    },
    "Email Address Enrichment": {
        "type": "playbook",
        "name": "Email Address Enrichment - Generic v2.1"
    },
    "File Enrichment": {
        "type": "playbook",
        "name": "File Enrichment - Generic v2"
    },
    "Entity Enrichment": {
        "type": "playbook",
        "name": "Entity Enrichment - Generic v4"
    },
    "Email Notifications": {
        "type": "header",
        "name": "Email Notifications"
    },
    "Chat App Notifications": {
        "type": "header",
        "name": "Chat App Notifications"
    },
    "Ticketing": {
        "type": "header",
        "name": "Ticketing"
    },
    "Timeline": {
        "type": "header",
        "name": "Timeline"
    },
    "Analyst Notes": {
        "type": "header",
        "name": "Analyst Notes"
    },
    "Lock AD user account": {
        "type": "playbook",
        "name": "Block Account - Generic v2"
    },
    "Lock AD service account": {
        "type": "playbook",
        "name": "Block Account - Generic v2"
    },
    "EDL Block (IP/Domain/URL)": {
        "type": "playbook",
        "name": "Block Indicators - Generic v3"
    },
    "PAN-DB re-categorization": {
        "type": "playbook",
        "name": "PAN-OS - Block URL - Custom URL Category"
    },
    "Block email sender": {
        "type": "playbook",
        "name": "Block Email - Generic v2"
    },
    "Quarantine email": {
        "type": "playbook",
        "name": "Search And Delete Emails - Generic v2"
    },
    "Quarantine files": {
        "type": "playbook",
        "name": "Block File - Generic v2"
    },
    "Quarantine device": {
        "type": "playbook",
        "name": "Isolate Endpoint - Generic V2"
    },
    "Disable project": {
        "type": "playbook",
        "name": "Cloud Response - Generic"
    },
    "Re-image request": {
        "type": "header",
        "name": "Re-image request"
    },
    "Password Reset": {
        "type": "header",
        "name": "Password Reset"
    },
    "Search and destroy": {
        "type": "header",
        "name": "Search and destroy"
    },
    "External website takedown": {
        "type": "header",
        "name": "External website takedown"
    },
    "Revoke physical badge access": {
        "type": "header",
        "name": "Revoke physical badge access"
    },
    "Kill sessions": {
        "type": "header",
        "name": "Kill sessions"
    },
    "Calculate Severity": {
        "type": "playbook",
        "name": "Calculate Severity - Generic v2"
    }
}
"""

demisto.executeCommand("createList", {"listName": "UseCaseSteps", "listData": usecasestepsdata})
