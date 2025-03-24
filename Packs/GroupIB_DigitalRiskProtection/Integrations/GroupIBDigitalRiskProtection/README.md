Pack helps to integrate Group-IB Digital Risk Protection and get violations directly into Cortex XSOAR. 

## Configure Group-IB Threat Intelligence in Cortex

| Name                  | Required | Description |
|-----------------------|----------|-------------|
| **GIB DRP URL**       | true     | The FQDN/IP the integration should connect to. |
| **Fetch incidents**   | true     | Whether to start the integration for collecting incident violations. |
| **Classifier**        | true     | Specifies which collections and received data should be linked to which incidents. |
| **Incident type**     | false    | Specifies the type of incident to collect the received data into. This field should be ignored as our Classifier and Mapper handle this. |
| **Mapper**           | true     | Specifies which data should be linked to which incident types. |
