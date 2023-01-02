# Google Cloud Platform

This pack includes Cortex XSIAM content.

## Configuration on Server Side

For information on how to configure log collections from Google Cloud Platform, please refer to the following documentation [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/external-data-ingestion/ingest-network-connection-logs/ingest-logs-and-data-from-gcp.html).

## Collect Events from Vendor
Please refer to the documentation provided above.

The collector for Google Cloud platform can be found here:
1. Navigate to the "Data Sources" -> "Add Data Source" -> search "Google Cloud Platform".
2. Press "Connect".
3. Enter the following details: "Subscription Name", "Credentials" (Json file containing your service account key), Choose Log type - "Flow or Audit Logs".


 For more information on this type of collector, please refer to the the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).