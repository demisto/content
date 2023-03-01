# Cisco AMP Secure Endpoint
Cisco Advanced Malware Protection software is designed to prevent, detect, and help remove threats in an efficient manner from computer systems.
Threats can take the form of software viruses and other malware such as ransomware, worms, Trojans, spyware, adware, and fileless malware.

# See the API Documentation
The API documentation can be found in: [Cisco AMP API](https://api-docs.amp.cisco.com/).</br>
Choose the relevant API and then select version: `v1`.

# Fetch Incidents
Incidents are fetched through the command: `cisco-amp-event-list`.</br>
The fetched event types can be controlled through `event_id` that can be received from the command: `cisco-amp-event-type-list`.

# Polling Command
The following commands support polling: 
- `cisco-amp-computer-isolation-create`
- `cisco-amp-computer-isolation-delete`

The polling is done when the status of an endpoint has changed.
