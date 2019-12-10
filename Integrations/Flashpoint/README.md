Use flashpoint integration for reduce business risk. The integration was
integrated and tested with Demisto 5.0 This integration was integrated
and tested with version xx of Flashpoint

Detailed Description
--------------------

Populate this section with the .md file contents for detailed
description.

Fetch Incidents
---------------

Populate this section with Fetch incidents data

Configure Flashpoint on Demisto
-------------------------------

1.  Navigate to **Settings** \> **Integrations**  \> **Servers &
    Services**.
2.  Search for Flashpoint.
3.  Click **Add instance** to create and configure a new integration
    instance.
    -   **Name**: a textual name for the integration instance.
    -   **API Key**

4.  Click **Test** to validate the new instance.

Commands
--------

You can execute these commands from the Demisto CLI, as part of an
automation, or in a playbook. After you successfully execute a command,
a DBot message appears in the War Room with the command details.

1.  Lookup the "IP" type indicator details: ip
2.  Lookup the "Domain" type indicator details: domain
3.  Lookup the "Filename" type indicator details: filename
4.  Lookup the "URL" type indicator details: url
5.  Lookup the "File" type indicator details: file
6.  Lookup the "Email" type indicator details: email
7.  Search for the Intelligence Reports using a keyword:
    flashpoint-search-intelligence-reports
8.  Get a single report by its ID:
    flashpoint-get-single-intelligence-report
9.  Get related reports for a given report id:
    flashpoint-get-related-reports
10. For getting single event:
    flashpoint-get-single-event
11. Get all event details:
    flashpoint-get-events
12. Lookup any type of indicator:
    flashpoint-common-lookup
13. Get forum details:
    flashpoint-get-forum-details
14. Get room details:
    flashpoint-get-forum-room-details
15. Get user details:
    flashpoint-get-forum-user-details
16. Get post details:
    flashpoint-get-forum-post-details
17. Search forum sites using a keyword:
    flashpoint-search-forum-sites
18. Search forum posts using a keyword:
    flashpoint-search-forum-posts

