
## new pre-release SplunkPy integration.
the new integration is now using the Splunk real-time queries feature.
which means that every event will become an incident in XSOAR when Splunk will finish indexing the event (the second that the event is ready to search).

### known limitations
- in case that the instance will fail for some reason (e.g. connection problems etc.) there is no option to get back the missing incidents (you will need to create them manually). this feature is in our roadmap, but it’s not implemented at this point in time.
- also, the new enrichment feature is also not available and will be added in future releases.

#### Notes
- there is no a fetch incidents method in this integration the replacement for this is **Long running instance** checkbox.
- also, we removed a few "fetch related" parameters from the instance configuration (such as first fetch time, Use Splunk Clock Time, Timezone, and the time param names) for this integration, since it’s not relevant at this point of time (we fetch events in real-time only).

please reach out to our support team for any problems with this integration, and we will handle your problem ASAP.