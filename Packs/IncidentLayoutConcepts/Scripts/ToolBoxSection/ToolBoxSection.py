import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# This script is used to control what is displayed in the "Link Based Commands" section.
incidentJSON = demisto.incidents()[0]
incidentContext = demisto.context()

# You can hardcode commands that will be displayed in the sections. In this example, I allow the analyst the option to change the running playbook.
# These commands do not have a wrapper to configure the output to be displayed in the output section
table = [
    {'Commands': '%%%{"message": "Reset Demo",       "action":"DeleteContext",     "params": {"all": "yes", "keysToKeep" : "File"}}%%%'},
    {'Commands': '%%%{"message": "Set Playbook - Execute Email Purge",       "action":"setPlaybook",     "params": {"name": "O365 - Security And Compliance - Search And Delete"}}%%%'},
    {'Commands': '%%%{"message": "Set Playbook - Create case in ServiceNow", "action":"setPlaybook",     "params": {"name": "Create ServiceNow Ticket"}}%%%'}
]


# toolbox-wrapper automation
# The toolbox-wrapper script can accept N arguments. It must always have the "command" argument.

# Conditional check and decide what link\actions the analyst should see
# Check is the incident has a file and if that file is an Email. Allows the "Parse Email" automation to execute.
if incidentContext.get('File'):
    if type(incidentContext.get('File')) == dict and incidentContext.get('File').get('Extension') == 'eml':
        table.append({'Commands': '%%%{"message": "Parse Email",                   "action":"toolbox-wrapper", "params": {"command": "ParseEmailFilesV2", "entryid": "'
                     + incidentContext.get('File').get('EntryID') + '"}}%%%'})
# Once the above command is executed. The "Email" context key is created. The below conditional check will be satisfied and will then allow the analyst to extract indicator.
if incidentContext.get('Email') and not incidentContext.get('ExtractedIndicators'):
    table.append({'Commands': '%%%{"message": "Extract Indicators from Email Key",                   "action":"toolbox-wrapper", "params": {"command": "extractIndicators", "text": "${Email}"}}%%%'})
if incidentJSON.get('emailhtml'):
    table.append({'Commands': '%%%{"message": "Rasterize Email (Using emailhtml)",                   "action":"toolbox-wrapper", "params": {"command": "rasterize-email", "htmlBody": "${incident.emailhtml}"}}%%%'})
if incidentContext.get('URLSanitationList'):
    table.append({'Commands': '%%%{"message": "Show extracted URL list",                             "action":"toolbox-wrapper", "params": {"command": "Print", "value": "${URLSanitationList}"}}%%%'})
if incidentContext.get('URLSanitationList'):
    table.append({'Commands': '%%%{"message": "Delete URLSanitationList Key",                        "action":"toolbox-wrapper", "params": {"command": "DeleteContext", "key": "URLSanitationList"}}%%%'})
if incidentContext.get('ExtractedIndicators'):
    if (not incidentContext.get('URLSanitationList') and incidentContext.get('ExtractedIndicators').get('URL')):
        table.append({'Commands': '%%%{"message": "Run URL Sanitation",                                  "action":"toolbox-wrapper", "params": {"command": "URL_Sanitation_v11", "purgeImageURLs": "true", "url": "${ExtractedIndicators.URL}"}}%%%'})

data = tableToMarkdown("", table, headers=[f'Commands'])

# line added inside the IDE
# Another line added inside the IDE

demisto.results({
    'Type': entryTypes['note'],
    'ContentsFormat': formats['markdown'],
    'Contents': data
})
