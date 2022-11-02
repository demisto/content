# Cisco AMP Secure Endpoint
Cisco Advanced malware protection software is designed to prevent, detect, and help remove threats in an efficient manner from computer systems.
Threats can take the form of software viruses and other malware such as ransomware, worms, Trojans, spyware, adware, and fileless malware.

# See the API Documentation
The API documentation can be found in: [Cisco AMP API](https://api-docs.amp.cisco.com/).</br>
Choose the relevant API and then select version: `v1`.

# Fetch Incidents
Incidents are fetched through the command: `cisco-amp-event-list`.</br>
The fetched event types can be controlled through `event_id` that can be received from the command: `cisco-amp-event-type-list`.

# Polling Command
The commands: `cisco-amp-computer-isolation-create` and `cisco-amp-computer-isolation-delete` supports polling.</br> The polling is done when the status of an endpoint has changed.

# Integration Commands
- cisco-amp-app-trajectory-query-list
- cisco-amp-computer-activity-list
- cisco-amp-computer-delete
- cisco-amp-computer-isolation-create
- cisco-amp-computer-isolation-delete
- cisco-amp-computer-isolation-feature-availability-get
- cisco-amp-computer-isolation-get
- cisco-amp-computer-list
- cisco-amp-computer-move
- cisco-amp-computer-trajectory-list
- cisco-amp-computer-user-activity-list
- cisco-amp-computer-user-trajectory-list
- cisco-amp-computer-vulnerabilities-list
- cisco-amp-event-list
- cisco-amp-event-type-list
- cisco-amp-file-list-item-create
- cisco-amp-file-list-item-delete
- cisco-amp-file-list-item-list
- cisco-amp-file-list-list
- cisco-amp-group-create
- cisco-amp-group-delete
- cisco-amp-group-list
- cisco-amp-group-parent-update
- cisco-amp-group-policy-update
- cisco-amp-indicator-list
- cisco-amp-policy-list
- cisco-amp-version-get
- cisco-amp-vulnerability-list
- endpoint
- file