## Zoom Event Collector
Use this integration to collect operation logs and activity reports automatically from Zoom.
You can also use the ***zoom-get-events*** command to manually collect events.


### Troubleshooting

- Indicators that are passed through the integration undergo formatting and deduplication, which may lead to an apparent loss of indicators.  
  For instance, enabling the `Strip ports from URLs` option may cause two URLs that are similar but use different ports to be merged into a single indicator after formatting, resulting in the removal of one of them as a duplicate.
- In case all fields are selected, there is a potential memory issue when dealing with CSV or JSON format files that exceed 150,000 entries.
