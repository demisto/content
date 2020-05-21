# Pack Documentation
The pack investigates an event whereby a user creates multiple application login attempts from various locations in a short time period (impossible traveler). It gathers user, timestamp and IP information associated with the multiple application login attempts and determines whether the event is malicious or a false positive.



##### Triggers
The investigation is triggered by SIEM integrations where access events have been created by ingestion of firewall or VPN logs. Any SIEM integration supported by Cortex XSOAR can be used, some of which are:
- SplunkPy
- ArcSight ESM v2
- IBM QRadar

##### Configuration
- Configure your SIEM in Cortex XSOAR and enable fetching incidents.
- Create an integration that provides IP geo-location details (coordinates are required, country is optional). 
Some integrations that can provide this information are:
  - Ipstack
  - ipinfo
- Create a classification for the SIEM integration that would trigger `Impossible Traveler` incidents in Cortex XSOAR.
- Create a mapping for the SIEM integration that maps data from the ingested events to the following incident fields:
  - Source IP
  - Previous Source IP
  - Destination IP
  - Sign in Date Time
  - Previous Sign in Date Time
  - Username (optional)
- Make sure the `Impossible Traveler` incident type is configured to run the `Impossible Traveler` playbook.
- Configure the inputs of the `Impossible Traveler` playbook.

##### Main Playbook Stages and Capabilities
- Retrieves geographical locations for the IPs from which application connections originated.
- Generates a link to a map showing the travel the user supposedly made, judging by the locations of the IP addresses used by them. Then, creates an image of that map.
- Uses the calculated distance between the IP locations and the time difference between the 2 login events to determine whether the user traveled faster than the MPH (Miles Per Hour) limit set in the playbook input.
- Based on the previous point, either sets the incident as false positive or contacts the user's manager for approval of the supposed travel done by the user.
- Checks whether the user logged in from an IP address configured as whitelist in the playbook inputs. This allows the user to create seemingly impossible travels using IPs known and allowed by the organization.
- Updates the incident details and severity with any progression - whether the incident was a false positive, a true positive but using whitelisted IPs or simply a true positive (a malicious incident).
- Incidents that are found to be disallowed impossible travels allow disabling the user in Active Directory and blocking the originating IP addresses.


##### Best Practices & Suggestions
- best practice

##### Visualization
