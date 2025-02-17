# MISP Threat Actors Feed

This pack provides a feed integration for ingesting threat actor data from the MISP Threat Actors Galaxy.

## About This Pack

The MISP Threat Actors Feed pack allows you to ingest threat actor data from the MISP Threat Actors Galaxy, providing valuable threat intelligence to enhance your security operations. This feed includes detailed information about known threat actors, their aliases, associated countries, and descriptions.

### What does this pack do?

- Fetches threat actor data from the MISP Threat Actors Galaxy.
- Creates indicators for each threat actor with rich metadata.
- Establishes relationships between threat actors and their targets or attributed locations.
- Supports custom tagging and TLP color assignment.
- Provides command for manual retrieval of threat actor information.

## Pack Contents

### Integrations
**FeedMISPThreatActors**: The main integration for fetching and processing threat actor data.

## Use Cases

- Enhance threat intelligence by incorporating known threat actor information.
- Identify potential threats based on actor profiles and their historical activities.
- Correlate internal incidents with known threat actor behaviors.