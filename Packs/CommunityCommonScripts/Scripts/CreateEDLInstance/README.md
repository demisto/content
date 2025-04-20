Use this automation to create an EDL instance on XSOAR.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags |  |

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| PortListName | The Listname in XSOAR of ports in use  |
| InstanceName | The Name of the EDL instance to create |
| Query | The indicator query used to populate the EDL |
| Port | Specify specific port to use when creating the EDL instance., else it will be random \(3000-50000\) |

## Outputs
---

| **Name** | **Port** | **PortListName** | **Query** |
| --- | --- | --- | --- |
| Testing | 8008 | EDL_PORT_LIST | tags:block and type:IP |

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.