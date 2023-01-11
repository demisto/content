# Microsoft EXCHANGE SERVER

This pack includes XSIAM content 

## Configuration on Server Side

1. Open the EAC and navigate to Servers > Servers > select the Mailbox server that you want to configure > and click Edit 

2. On the server properties page, click Transport Logs. In the Message tracking log section, change any of the following settings:

   `Enable message tracking log`: To disable message tracking on the server, clear the check box. To enable message tracking on the server, select the check box.

   `Message tracking log path`: The value you specify must be on the local Exchange server. If the folder doesn't exist, it's created for you when you click Save.

#### Example log path:
`C:\Program Files\Microsoft\Exchange Server\V15\TransportRoles\Logs\MessageTracking\`

*Ensure that the tracking log path here matches the one in the YAML configuration.*

3. When you're finished, click Save.
## Filebeat Collection
In order to use the collector, you need to use the following option to collect events from the vendor:

- [XDRC (XDR Collector)](#xdrc-xdr-collector)

You will need to configure the vendor and product for this specific collector.

### XDRC (XDR Collector)

You will need to use the information described [here](https://docs.paloaltonetworks.com/cortex/cortex-xdr/cortex-xdr-pro-admin/cortex-xdr-collectors/xdr-collector-datasets#id7f0fcd4d-b019-4959-a43a-40b03db8a8b2).

You can configure the vendor and product by replacing [vendor]\_[product]\_raw with msft_exchange_raw

When configuring the instance, you should use a YAML that configures the vendor and product, just as seen in the below configuration for the Microsoft Exchange product.

Copy and paste the below YAML in the "Filebeat Configuration File" section (inside the relevant profile under the "XDR Collectors Profiles").

#### Filebeat Configuration file:

```commandline
filebeat.inputs:
- type: filestream
  enabled: true
  paths:
    - "C:\\Program Files\\Microsoft\\Exchange Server\\V15\\TransportRoles\\Logs\\MessageTracking\\*.LOG"
  processors:
    - add_fields:
        fields:
          vendor: msft
          product: exchange
    - drop_event.when.not.regexp.message: "^[0-9]+.*"
    - add_locale: ~
    - decode_csv_fields:
        fields: 
          message: decoded.csv 
        separator: ","
    - extract_array:
        field: decoded.csv
        mappings:
          dissect.date_time: 0
          dissect.client_ip: 1
          dissect.client_hostname: 2
          dissect.server_ip: 3
          dissect.server_hostname: 4
          dissect.source_context: 5
          dissect.connector_id: 6
          dissect.source: 7
          dissect.event_id: 8
          dissect.internal_message_id: 9
          dissect.message_id: 10
          dissect.network_message_id: 11
          dissect.recipient_address: 12
          dissect.recipient_status: 13
          dissect.total_bytes: 14
          dissect.recipient_count: 15
          dissect.related_recipient_address: 16
          dissect.reference: 17
          dissect.message_subject: 18
          dissect.sender_address: 19
          dissect.return_path: 20
          dissect.message_info: 21
          directionality: 22
          dissect.tenant_id: 23
          dissect.original_client_ip: 24
          dissect.original_server_ip: 25
          dissect.custom_data: 26
          dissect.transport_traffic_type: 27
          dissect.log_id: 28
          dissect.schema_version: 29
```

This configuration will collect the data into a dataset named `msft_exchange_raw`.

**Please note**: The above configuration uses the default location of the Message Tracking logs. In case your Exchange server saves the Message Tracking logs under a different location, you would need to change it in the yaml (under the `paths` field).