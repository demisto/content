### Get access to RiskIQ Security Intelligence Services Feed

* RiskIQ Security Intelligence Services requires an existing enterprise contract in order to function. More specifically, clients need to be licensed for at least one or all of the Attack Analytics modules.
* Existing clients can use their API keys in order to enable the functionality within XSOAR. If API keys are unknown or have been misplaced, clients can contact their account representative directly or send an email to **support@riskiq.com**.


### Fetch Indicators
* The XSOAR instance with **ElasticSearch** is required as this integration would ingest large amount of indicators from SIS to XSOAR.
* Every interval one S3 file will be ingested if found for each given feed type.
* Set Feed Fetch Interval based on the total number of selected Feed Type.
* If you face error related to **Docker Timeout**,  Set or increase **feedintregrationscript.timeout** parameter in configuration (Settings > About > Troubleshooting  > Server Configuration).

