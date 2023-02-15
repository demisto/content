Fetching incidents can be challenging when testing and building playbooks as the required integration is normally connected to a live system and an incident must be generated in the 3rd party system to simulate an fetching event.
This can be challenging or impossible depending upon the integration and test environment.

JSONSampler is intended to assist with mocking the fetching of incidents for testing and development purposes.
By providing a JSON string as input to the integration, events can be fetched at a scheduled interval.
These simulated incidents can go through the complete incident lifecycle of classification, mapping, preprocessing, playbook processing and incident closure.

Instances of the JSONSampler integration can also be configured in test environments to perform load testing by setting the fetch time to mimic the frequency of events expected in a production environment.
In this way, the load can be tested and validated before releasing a use case to production.
