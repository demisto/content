An integration to help you automate IP calulations

## Configure IPCalc on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for IPCalc.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | IP Version | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ipcalc-return-subnet-addresses
***
Return a list of ip addresses in a subnet


#### Base Command

`ipcalc-return-subnet-addresses`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | Subnet to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPCalc.IP.Address | String | Subnet addresses | 


#### Command Example
```!ipcalc-return-subnet-addresses subnet="192.168.20.20/30"```

#### Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Address": [
                "192.168.20.21",
                "192.168.20.22"
            ]
        }
    }
}
```

#### Human Readable Output

>### List Addresses
>|IP Addresses:|
>|---|
>| 192.168.20.21 |
>| 192.168.20.22 |


### ipcalc-return-subnet-network
***
Return the network id of a subnet


#### Base Command

`ipcalc-return-subnet-network`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | Subnet to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPCalc.IP.Network | String | Subnet network | 


#### Command Example
```!ipcalc-return-subnet-network subnet="192.168.10.10/16"```

#### Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Network": "192.168.0.0/16"
        }
    }
}
```

#### Human Readable Output

>### Subnet Network
>|Network:|
>|---|
>| 192.168.0.0/16 |


### ipcalc-return-subnet-first-address
***
Return subnet first address


#### Base Command

`ipcalc-return-subnet-first-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | Subnet to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPCalc.IP.Address | String | First ip address | 


#### Command Example
```!ipcalc-return-subnet-first-address subnet="192.168.20.20/21"```

#### Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Address": "192.168.16.1"
        }
    }
}
```

#### Human Readable Output

>### First Address
>|Address:|
>|---|
>| 192.168.16.1 |


### ipcalc-return-subnet-last-address
***
Return subnet last address


#### Base Command

`ipcalc-return-subnet-last-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | Subnet to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPCalc.IP.Address | String | Last ip address | 


#### Command Example
```!ipcalc-return-subnet-last-address subnet="192.168.20.20/21"```

#### Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Address": "192.168.23.254"
        }
    }
}
```

#### Human Readable Output

>### Last Address
>|Address:|
>|---|
>| 192.168.23.254 |


### ipcalc-return-subnet-broadcast-address
***
Return subnet broadcast address


#### Base Command

`ipcalc-return-subnet-broadcast-address`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | Subnet to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPCalc.IP.Address | String | Subnet addresses | 


#### Command Example
```!ipcalc-return-subnet-broadcast-address subnet="192.168.20.20/21"```

#### Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Address": "192.168.23.255"
        }
    }
}
```

#### Human Readable Output

>### Broadcast Address
>|Address:|
>|---|
>| 192.168.23.255 |


### ipcalc-check-subnet-collision
***
Return subnet collision address


#### Base Command

`ipcalc-check-subnet-collision`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet_one | First subnet. | Required | 
| subnet_two | Second subnet. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPCalc.IP.Collision.subnet1 | String | Collission first subnet | 
| IPCalc.IP.Collision.subnet2 | String | Collission second subnet | 
| IPCalc.IP.Collision.collision | String | Collission result | 


#### Command Example
```!ipcalc-check-subnet-collision subnet_one="192.168.20.20/21" subnet_two="192.168.20.21"```

#### Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Collision": {
                "collision": "True",
                "subnet1": "192.168.20.20/21",
                "subnet2": "192.168.20.21"
            }
        }
    }
}
```

#### Human Readable Output

>### Collision Check
>|collision|subnet1|subnet2|
>|---|---|---|
>| True | 192.168.20.20/21 | 192.168.20.21 |


### ipcalc-return-subnet-iana-allocation
***
Return subnet iana allocation information


#### Base Command

`ipcalc-return-subnet-iana-allocation`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | Subnet to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPCalc.IP.Allocation.allocation | String | IANA IP allocation type | 
| IPCalc.IP.Allocation.subnet | String | Subnet | 


#### Command Example
```!ipcalc-return-subnet-iana-allocation subnet="192.168.10.10/23"```

#### Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Allocation": {
                "allocation": "PRIVATE",
                "subnet": "192.168.10.10/23"
            }
        }
    }
}
```

#### Human Readable Output

>### Iana Allocation
>|allocation|subnet|
>|---|---|
>| PRIVATE | 192.168.10.10/23 |


### ipcalc-return-subnet-binary
***
Return subnet in binary format


#### Base Command

`ipcalc-return-subnet-binary`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| subnet | Subnet to use. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| IPCalc.IP.Binary.binary | String | Subnet binary | 
| IPCalc.IP.Binary.subnet | String | Subnet address | 


#### Command Example
```!ipcalc-return-subnet-binary subnet="192.168.20.20"```

#### Context Example
```json
{
    "IPCalc": {
        "IP": {
            "Binary": {
                "binary": "11000000101010000001010000010100",
                "subnet": "192.168.20.20"
            }
        }
    }
}
```

#### Human Readable Output

>### Subnet Binary
>|binary|subnet|
>|---|---|
>| 11000000101010000001010000010100 | 192.168.20.20 |

