# An example configuration:

- Name - user choice
- Select 'Fetches incidents'
- Classifier - empty
- Incident type - 'Gatewatcher incident'
- Mapper (incoming) - 'Gatewatcher Mapper Incoming'
- GCenter IP address - GCenter IP
- GCenter API token - a GCenter API token with Administrator role
- GCenter version - 2.5.3.103
- GCenter username - user specific
- GCenter password - user specific
- Check the TLS certificate - user choice
- Use system proxy settings - user choice
- First fetch - how far in time XSOAR will start its first query of GCenter events
- Fetch limit - the number of events grabbed from the GCenter, XSOAR recommends 200 so here the recommendation is 100 (alerts + metadata are fetched)
- Incidents Fetch Interval - when XSOAR will re-run its fetch routine, another routine is runned if the last one terminated (Following message on Integrations/Instances screen: 'Pulled X incidents at DATE')
- Do not use by default
- Log level - user choice
- Run on Single engine: - user choice
