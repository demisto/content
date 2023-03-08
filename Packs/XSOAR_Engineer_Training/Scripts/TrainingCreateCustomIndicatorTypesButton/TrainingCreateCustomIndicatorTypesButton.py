import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import json

# check to see if they already exist, so you can't run it more than once
results = demisto.executeCommand("demisto-api-get", {"uri": "/reputation"})[0]["Contents"]["response"]
current_indicators = [x["details"] for x in results]

if "Private IP" not in current_indicators:
    private_ip_indicator = {
        "regex": "(10((?:\[\.\]|\.)(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172(?:\[\.\]|\.)(1[6-9]|2[0-9]|3[01]))|192(?:\[\.\]|\.)168)((?:\[\.\]|\.)(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})",
        "details": "Private IP",
        "reputationScriptName": None,
        "enhancementScriptNames": [],
        "layout": "ipRep",
        "excludedBrands": [],
        "disabled": False,
        "updateAfter": None,
        "reputationCommand": "private-ip",
        "formatScript": None,
        "contextPath": None,
        "contextValue": None,
        "shouldPublish": True,
        "shouldCommit": True,
        "commitMessage": "Indicator type edited",
        "manualMapping": {},
        "expiration": 0,
        "shouldShareComments": False,
        "propagationLabels": ["all"]
    }

    demisto.executeCommand("demisto-api-post", {"uri": "/reputation", "body": json.dumps(private_ip_indicator)})
    demisto.results("Created Private IP custom Indicator type")
else:
    demisto.results("Private IP indicator already exists, doing nothing....")

if "CXHost" not in current_indicators:
    cxhost_indicator = {
        "regex": "(crossiscoming\d{3,5})",
        "details": "CXHost",
        "reputationScriptName": None,
        "enhancementScriptNames": [],
        "layout": "hostRep",
        "excludedBrands": [],
        "disabled": False,
        "updateAfter": None,
        "reputationCommand": "cxhost",
        "formatScript": None,
        "contextPath": None,
        "contextValue": None,
        "shouldPublish": True,
        "shouldCommit": True,
        "commitMessage": "Indicator type edited",
        "manualMapping": {},
        "expiration": 0,
        "shouldShareComments": False,
        "propagationLabels": ["all"]
    }

    demisto.executeCommand("demisto-api-post", {"uri": "/reputation", "body": json.dumps(cxhost_indicator)})
    demisto.results("Created CXHost custom Indicator type")
else:
    demisto.results("CXHost indicator already exists, doing nothing....")
