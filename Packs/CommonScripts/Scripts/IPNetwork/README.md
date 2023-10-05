Gather information regarding CIDR -
    1. Broadcast_address
    2. CIDR
    3. First_address
    4. Last address
    5. Max prefix len
    6. Num addresses
    7. Private
    8. Version


## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | ip |
| Cortex XSOAR Version | 5.0.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| cidr | IP/CIDR, e.g. 192.168.0.0/24 |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Network.CIDR | Network CIDR. | String |
| Network.Num_addresses | Number of availble addresses in the CIDR. | Number |
| Network.First_address | First address in the network CIDR. | String |
| Network.Last_address | Last address in the network CIDR. | String |
| Network.Version | Version of IP. | Number |
| Network.Private | True if IP is private. | Boolean |
| Network.Max_prefix_len | Max prefix length of CIDR. | Number |
| Network.Broadcast_address | Broadcast address of CIDR. | String |
