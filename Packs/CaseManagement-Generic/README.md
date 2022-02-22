# Case Management Pack Implementation Guide

This dashboard is a quick primer for using this Case Management Pack.  Whether you're creating Incidents manually in XSOAR, or fetching from a SIEM, this pack provides some helpful content to help with those goals.

## Default Incident Type

This Pack includes an Incident Type of 'Case', which has optimized layouts for Case Management, including for manual Incident creation.  To use this as a default for XSOAR, navigate to Settings -> Advanced -> Incident Types and select Case and Set as Default.

## Incident Ingestion

Setting Case as the default type means you can enable a fetch from any integration and it will default to this type.  This means no mapping & classification is really required, as data from the incoming incident will be displayed in the labels section.  This means you can quickly bring in alerts from various systems, and then further tune the data, layouts, and playbooks as future improvements.

## Layouts

The Case type has an optimized layout for both the summary pages, and the new/edit screen.  This layout includes some useful action buttons for Analysts to utilize in their day to day.

This layout can use used as a template for future Incident types you create in your system, you can copy it (5.5) or use as the default for a Incident type (6.0)

## Playbook

The default playbook for the Case type is 'Case Management - Generic', this playbook is very simple, but does have a few optional add-ons you might want to enable.  At it's core the playbook simply does the following:

- Extract & Enrich Indicators: Extract IOCs (hashes, ips, urls) from the incoming Incident data, and mark these items as a note.
- Pause and wait for Analyst review

### Timers

Optionally this playbook has built in Timers for adding metrics for Mean Time to Assignment or Mean Time to Remediation to the metrics you are tracking in the system.  To take advantage of these timers, you can add the included TimersOnOwnerChange script to as a field trigger script on the Owner field.   This script will stop the Time to Assignment timer and start the Remediation SLA timer when an owner is first assigned to the Incident.

To set this up:
1. Settings -> Advanced -> Fields
2. Find and edit the Owner field
3. Select TimersOnOwnerChange on the 'Script to run when field value changes' option

## Dashboards

This pack includes 3 dashboards:

- Incident Overview: High level summary of all Incidents in the system, by type, severity, owner, unassigned, etc.
- My Incidents: Analyst focused dashboard for them to work Incidents assigned to them or Incidents they are participating in.  This dashboard also shows any War Room chats they may have been mentioned in.
- Case Management Implementation Guide: That's this dashboard, and is intended as a guide for implementing this pack, feel free to delete it once done.

### Optional Widgets

There are 3 optional widgets you can add to these dashboards, if you've enabled the Timers as noted above:

- Mean Time to Assignment: Shows the average time to assignment for Incidents in the system where the Time to Assignment Timer was used.
- Mean Time to Remediation (Remediation SLA): Shows the average time to remediation for Incidents where the Remediation SLA Timer was used.
- My Mean Time to Remediation (Remediation SLA): Shows the average time to remediation for Incidents where the Owner is the viewing user.

You can add these Timers to existing or a new dashboard from the home screen!  If you're building your own playbooks, you can include these timers to track these metrics on those as well!

## Incident Action Buttons

This pack includes a pair of useful Incident action button scripts, which are added to the layout included in this pack, but can be added to any other Incident types you create or out of the box types:

- Assign to Me (AssignToMeButton): Assigns an Incident to the user who clicked the button.
- Link Incidents (LinkIncidents): Allows a user to link or unlink Incidents, also takes a comma separated list of Incidents to link or unlink.

# What Next?

Want to take it to the next level?  The next steps after implementing this pack might include the following:

- Pivot incoming alerts from SIEMs etc to their own Incident types, with their own playbooks to automate away the mundane!
- Use pre-processing rules to drop or link duplicate alerts!
- Map data from incoming alerts to fields, allowing search ability, correlation of Incidents between different alert sources (i.e. map a username from different sources to the same field in XSOAR!)
- Modify the Case layout on new types, replacing the labels section with the data from the incoming Incident that you mapped to fields.  This maintains a consistent look and feel for your Analysts, but places the information they need directly on the Incident.
