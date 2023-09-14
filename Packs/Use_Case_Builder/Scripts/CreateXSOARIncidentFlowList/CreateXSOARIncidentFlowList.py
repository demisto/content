import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

incidentflowdata = """<body style="font-family: Arial, sans-serif; background-color: #f5f5f5; margin: 0; padding: \
0;"> <div style="display: flex; justify-content: space-evently; flex-wrap: wrap;"> <!-- Incident Playbooks (
Ingestion) --> <div style="flex: 1; min-width: 250px; max-width: 30%; margin: 20px; box-shadow: 0 1px 3px rgba(0, 0, \
0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);"> <h1 style="background-color: #62BB46; color: white; padding: 15px; margin: \
0;">Incident Playbooks (Ingestion)</h1> <ul style="list-style-type: none; margin: 0; padding: 20px;"> <li \
style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px \
3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Cortex XDR Incident</li> <li style="background-color: white; \
color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
0 1px 2px rgba(0, 0, 0, 0.24);">Prisma Saas Alert</li> <li style="background-color: white; color: gray;padding: \
10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, \
0.24);">Prisma Cloud Alert</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: \
10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Okta Alert</li> \
<li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">WinEvent Alert</li> <li style="background-color: white; \
color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
0 1px 2px rgba(0, 0, 0, 0.24);">Linux Alert</li> <li style="background-color: white; color: gray;padding: \
10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, \
0.24);">Proofpoint Alert</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: \
10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">G-Suite Alert</li> \
<li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">GCP Alert</li> <li style="background-color: white; \
color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
0 1px 2px rgba(0, 0, 0, 0.24);">Support Requests</li> <li style="background-color: white; color: gray;padding: \
10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, \
0.24);">NGFW Alert</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: \
10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Abuse Reports</li> \
<li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Onboarding/Offboarding</li> <li style="background-color: \
white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
0 1px 2px rgba(0, 0, 0, 0.24);">Expanse Alert</li> <li style="background-color: white; color: gray;padding: \
10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, \
0.24);">Monitoring Alert</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: \
10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Password Spray \
Alert</li> </ul> </div> \

    <!-- Analysis Playbooks (Enrichment) --> <div style="flex: 1; min-width: 250px; max-width: 30%; margin: 20px; \
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);"> <h1 style="background-color: #1e90ff; \
    color: white; padding: 15px; margin: 0;">Analysis Playbooks (Enrichment)</h1> <ul style="list-style-type: none; \
    margin: 0; padding: 20px;"> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: \
    10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Upon \
    Trigger</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: \
    5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Calculate Severity</li> <li \
    style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
    1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Start SLA Timers</li> <li style="background-color: \
    white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, \
    0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Notification</li> <li style="background-color: white; color: gray;padding: \
    10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, \
    0.24);">Gather Details</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: \
    10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">User \
    Enrichment</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: \
    5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Host Enrichment</li> <li \
    style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
    1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">URL Enrichment</li> <li style="background-color: \
    white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, \
    0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Domain Enrichment</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">Email Address Enrichment</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">File Enrichment</li> <li style="background-color: white; color: gray;padding: \
    10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, \
    0.24);">IP Enrichment</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: \
    10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Related email \
    search</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: \
    5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Related log search</li> <li \
    style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
    1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Forensic capture</li> <li style="background-color: \
    white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, \
    0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Kill sessions</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">Ask user a question</li> </ul> </div> \

    <!-- Containment Subplaybooks (Analyst/User Actions) --> <div style="flex: 1; min-width: 250px; max-width: 30%; \
    margin: 20px; box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);"> <h1 \
    style="background-color: #ff7f00; color: white; padding: 15px; margin: 0;">Containment Subplaybooks (Analyst/User \
    Actions)</h1> <ul style="list-style-type: none; margin: 0; padding: 20px;"> <li style="background-color: white; \
    color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">Lock AD user account</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">Lock AD service account</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">EDL Block (IP/Domain/URL)</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">PAN-DB re-categorization</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">Block email sender</li> <li style="background-color: white; color: gray;padding: \
    10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, \
    0.24);">Quarantine email</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: \
    10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Quarantine \
    files</li> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: \
    5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Quarantine device</li> <li \
    style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
    1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Disable project</li> </ul> </div> \

    <!-- Eradication Playbooks --> <div style="flex: 1; min-width: 250px; max-width: 30%; margin: 20px; box-shadow: 0 \
    1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);"> <h1 style="background-color: #ff0000; color: white; \
    padding: 15px; margin: 0;">Eradication Playbooks</h1> <ul style="list-style-type: none; margin: 0; padding: \
    20px;"> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: \
    5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Re-image request</li> <li \
    style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
    1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Password Reset</li> <li style="background-color: \
    white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, \
    0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Search and destroy</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">External website takedown</li> <li style="background-color: white; color: \
    gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), \
    0 1px 2px rgba(0, 0, 0, 0.24);">Revoke physical badge access</li> </ul> </div> \

    <!-- Post-Incident Metrics --> <div style="flex: 1; min-width: 250px; max-width: 30%; margin: 20px; box-shadow: 0 \
    1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);"> <h1 style="background-color: #696969; color: white; \
    padding: 15px; margin: 0;">Post-Incident Metrics</h1> <ul style="list-style-type: none; margin: 0; padding: \
    20px;"> <li style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: \
    5px;box-shadow: 0 1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Metrics incl. effort</li> <li \
    style="background-color: white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 \
    1px 3px rgba(0, 0, 0, 0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Lessons Learned</li> <li style="background-color: \
    white; color: gray;padding: 10px;margin-bottom: 10px;border-radius: 5px;box-shadow: 0 1px 3px rgba(0, 0, 0, \
    0.12), 0 1px 2px rgba(0, 0, 0, 0.24);">Timeline</li> </ul> </div> </div> </body> """

demisto.executeCommand("createList", {"listName": "XSOARIncidentFlow", "listData": incidentflowdata})
