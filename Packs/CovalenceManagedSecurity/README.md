Threats can come from many sources, both externally and internally, and are often the result of vulnerable software, improperly configured devices and systems, or human error. To achieve maximum protection, you need to consider your vulnerabilities, monitor across the entire threat surface, and apply an attacker's mindset in order to create a proactive security posture rather than a solely reactive one.   

Covalence monitors across your endpoints, cloud and network, correlating information across all three, identifying threats, and protecting you from attacks and vulnerabilities.   

This pack collects the alerts that have been triaged to remove false positives, which are then generated in XSOAR as incidents. The lifecycle for the incident is managed within XSOAR. In this pack, an incident in XSOAR is equivalent to an ARO (Action, Recommendation, Observation) in Covalence.   

# What does this pack do ?

- Gathers the triaged security alerts from endpoint, cloud, and network security monitoring
- Converts the alerts into XSOAR incidents, with the following information:
   - Type
   - Severity
   - Organization
   - Title
   - Description of the incident/event
   - Mitigation steps
- Allows you to run ad-hoc queries in Covalence for AROs
- Allows you to manage the incident through its lifecycle within XSOAR, from its generation through to close
- Lists monitored organization, of interest for MSPs or equivalent who are managing alerts for multiple organizations

Note this pack should not be executed alongside the Covalence for Service Providers pack, or duplicate incidents will be generated.   
