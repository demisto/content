# Case Management Pack Implementation Guide

Whether you're creating Incidents manually in XSOAR, or fetching from a SIEM, this pack provides some helpful content to help with those goals.

## Default Incident Type

This Pack includes an Incident Type of '**Case**', which has optimized layouts for Case Management, including for manual Incident creation.  To use this as a default for XSOAR, navigate to +Settings -> Advanced -> Incident Types+ and select Case and Set as Default.

## Incident Ingestion

Setting Case as the default type means you can enable a fetch from any integration and it will default to this type.  

Use the **Case Management - Generic Mapper** and all data from the incoming incident will be added and displayed in the labels section.  This means you can quickly bring in alerts from various systems, and then further tune the data, layouts, and playbooks as future improvements.

## Layouts

The Case type has an optimized layout for both the summary pages, and the new/edit screen.  This layout includes some useful action buttons for Analysts to utilize in their day to day.

This layout can be used as a template for future Incident types you create in your system.

## Playbook

The default playbook for the Case type is **Case Management - Generic v2**, this playbook is very simple, but does have a few optional add-ons you might want to enable.  At it's core the playbook simply does the following:

- Extract & Enrich Indicators: Extract IOCs (hashes, ips, urls) from the incoming Incident data, and mark these items as a note.
- Calculate Severity
- Set SLAs for the Incident or the Time to Assign or Remediation SLA Timers
- Start Timers
- Send email notification for Incidents of Critical or High Severity
- Pause and wait for Analyst review

### Timers

Optionally this playbook has built in Timers for adding metrics for Mean Time to Assignment or Mean Time to Remediation to the metrics you are tracking in the system.  To take advantage of these timers, you can add the included **TimersOnOwnerChange** script to as a field trigger script on the Owner field.   This script will stop the Time to Assignment timer and start the Remediation SLA timer when an owner is first assigned to the Incident.

To set this up:

1. +Settings -> Objects Setup -> Incidents -> Fields+
2. Find and edit the Owner field
3. Select **TimersOnOwnerChange** on the 'Script to run when field value changes' option

## Dashboards

This pack includes 2 dashboards:

- **Incident Overview**: High level summary of all Incidents in the system, by type, severity, owner, unassigned, etc.
- **My Incidents**: Analyst focused dashboard for them to work Incidents assigned to them or Incidents they are participating in.  This dashboard also shows any War Room chats they may have been mentioned in.

### Optional Widgets

There are 3 optional widgets you can add to these dashboards, if you've enabled the Timers as noted above:

- Mean Time to Assignment: Shows the average time to assignment for Incidents in the system where the Time to Assignment Timer was used.
- Mean Time to Remediation (Remediation SLA): Shows the average time to remediation for Incidents where the Remediation SLA Timer was used.
- My Mean Time to Remediation (Remediation SLA): Shows the average time to remediation for Incidents where the Owner is the viewing user.

You can add these Timers to existing or a new dashboard from the home screen!  If you're building your own playbooks, you can include these timers to track these metrics on those as well!

## Dynamic Sections

The **CaseMgmtAnalystTools** automation script is used as a dynamic section on the layout to provide a list of quick links to Analysts to help them investigate the Incident.  

To create your own list, create an XSOAR list called "+Case Management Analyst Tools+", and add a Markdown Table with your own list.

The **CaseMgmtResponseProcess** automation script is used as a dynamic section to provide a response process on the Analyst Tools section of the layout.  This is customizable by Incident Type!

## Additional Automations

The **CaseMgmtIncidentTypesDisplay** is a field display script that can be tied to the Type field.  Use this to restrict the Incident Types which are displayed to Analysts when created manually, and prevent changing the Incident Type from being changed on existing Incidents.  

To set this up:

1. Create an XSOAR list (+Settings -> Advanced -> Lists+) called +IncidentTypesFromList+ with a comma seperated list of Incident Types to display (i.e. Case,Phishing,Malware)
1. +Settings -> Objects Setup -> Incidents -> Fields+
2. Find and edit the Type field
3. Select CaseMgmtIncidentTypesDisplay on the 'field display script' option

You can also use the **CaseMgmtIncidentTypesByRole** automaton to further breack this down by the users Roles!

# What Next?

Want to take it to the next level?  The next steps after implementing this pack might include the following:

- Pivot incoming alerts from SIEMs etc to their own Incident types, with their own playbooks to automate away the mundane!
- Use pre-processing rules to drop or link duplicate alerts!
- Map data from incoming alerts to fields, allowing search ability, correlation of Incidents between different alert sources (i.e. map a username from different sources to the same field in XSOAR!)
- Modify the Case layout on new types, replacing the labels section with the data from the incoming Incident that you mapped to fields.  This maintains a consistent look and feel for your Analysts, but places the information they need directly on the Incident.
