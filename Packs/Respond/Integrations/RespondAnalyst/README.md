#### What is Respond?


#### What does this pack do?

This pack provides a set of commands which can be executed against an instance of the Respond Software Analyst. The commands allow users to retrieve information from Respond and modify incidents from within XSOAR. Additionally, this integration supports bi-directional mirroring (for XSOAR v6 and above) of 
- incident closure status
- incident assignee
- incident feedback and notes
- incident title
- incident description

When fetch incidents is enabled, the pack will pull all open incidents from Respond into XSOAR. Each incident in XSOAR will follow the naming convention `<Respond Tenant Id>:<Respond Incident Id>`

It is worth noting that this pack does not pull in all of the data on each incident in Respond, rather a subset deemed to be most critical and helpful based on customer feedback. There is a link to the Respond incident provided on every corresponding XSOAR incident in case a user needs to retrieve additional information.
