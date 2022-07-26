Playbook to demonstrate the features of XSOAR-Web-Server. It sends an email to a certain user upto 2 times and captures the response

<html>
    <head>
    </head>
    <body>
        <a href=${WS-ActionDetails(val.action_string=="yes").action_url}>Click here to acknowledge receipt of report</a><br>
        <a href=${WS-ActionDetails(val.action_string=="no").action_url}>Click here to notify that the report was not received </a>
    </body>
</html>

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* xsoar-ws-email-loop

### Integrations
* XSOARWebServer

### Scripts
* GenerateSummaryReports
* CreateEmailHtmlBody

### Commands
* xsoar-ws-setup-simple-action
* setIncident

## Playbook Inputs
---
There are no inputs for this playbook.

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![xsoar-ws-email-user](Insert the link to your image here)