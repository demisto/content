#### What is the Respond Analyst/Mandiant Defense Engine?
Disclaimer: Respond Software was recently acquired by FireEye and has rebranded from the Respond Analyst to the Mandiant Defense Engine. These terms refer to the same product. Most of this integration was written prior to rebranding, and primarily includes references to Respond. This will be updated in the future, at which point this disclaimer will be removed. 

Mandiant Defense is the cybersecurity investigation automation solution that connects the dots across disparate cybersecurity data to find real incidents fast. The Mandiant Defense engine is built to accelerate investigations for security operations teams in defense agencies, government bodies, universities, large enterprises, and leading managed service providers to get investigation power at machine speed. Mandiant Defense works with the broadest range of vendors, sensors, threat intelligence and data repositories in the industry to improve detection and response while raising security analyst productivity.

#### What does this pack do?

This pack provides a set of commands which can be executed against an instance of the Respond Analyst. The commands allow users to retrieve information from Respond and modify incidents from within XSOAR. Additionally, this integration supports bi-directional mirroring (for XSOAR v6 and above) of 
- incident closure status
- incident assignee
- incident feedback and notes
- incident title
- incident description

When fetch incidents is enabled, the pack will pull all open incidents from Respond into XSOAR. Each incident in XSOAR will follow the naming convention `<Respond Tenant Id>:<Respond Incident Id>`

It is worth noting that this pack does not pull in all of the data on each incident in Respond, rather a subset deemed to be most critical and helpful based on customer feedback. There is a link to the Respond incident provided on every corresponding XSOAR incident in case a user needs to retrieve additional information.
