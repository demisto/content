Use the Genian NAC integration to block IP addresses using the assign tag.

Genian NAC network sensing technology powered by Device Platform Intelligence (DPI) discovers and presents all detected devices’ business contextual and risk-related information along with their technical information without disturbing existing network infrastructure. The resulting intelligence enhances visibility and allows operators to detect and respond to any non-compliant or compromised devices in real time.

With the result of comprehensive network visibility, Genian NAC can ensure compliance from all connected devices by leveraging Virtual In-Line Packet Inspection which operates at Layer 2. This technology has complete control over endpoint device traffic over TCP and UDP by eliminating the need for complex configurations and network changes.

## Genians Genian NAC Module Requirements

Before you can use this integration in Cortex XSOAR, you need to enable certain modules in your Genian NAC environment.

#### Genian NAC Web Console

1. This is the network address of the Genian NAC Enterprise or standalone Appliance. (The host on which the the Genian NAC is hosted.) For example, if the Genian NAC is hosted at the IP address *192.168.100.100*, then you enter *https://192.168.10.100:8443/mc2*

#### Enforcement Mode

1. Go to *System > System > Click IP of Sensor > Click Sensor Tab > Click Sensor on the right*
2. Go to *Sensor Operation > Sensor Mode* and change the *Sensor Mode* to '**host**'
3. Change *Sensor Operationg Mode* to '**Enforcement**'
    - Monitoring: (Default) Monitoring mode. No blocking.
    - Enforcement: Blocking mode

#### Specifying the Tag to be assigned to the node under control.

1. Go to *Preferences > Properties > Tag*
2. Create new Tag or use existing Tag (e.g. THREAT)

#### Create Enforcement Policy

Reference the Enforcement Policy section in the [Genian NAC Docs](https://docs.genians.com/release/en/controlling/understanding-policy.html#enforcement-policy)


## Configuration Parameters

#### Server IP

1. Input Genian NAC IP Address (e.g. 192.168.100.100)

#### API Key

1. You can generate an API Key in the Genian NAC Web Console.
    - Go to *Management > User > Administrator tab > API Key* to generate a key and save it.
2. Input API Key (e.g. 912fae69-b454-4608-bf4b-fa142353b463)

#### Tag Name

1. Input Tag Name for IP Block (e.g. THREAT, GUEST)


## Configure Genian NAC in Cortex

    - Name: a textual name for the integration instance.
    - Server IP
    - API Key
    - Tag Name


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook. After you successfully execute a command, a DBot message appears in the War Room with the command details.

1. [Post IP address to a tag: genians-assign-ip-tag](#Post-IP-address-to-a-tag)
2. [Delete IP address from a tag: genians-unassign-ip-tag](#Delete-IP-address-from-a-tag)

### Post IP address to a tag
***
Assigns a tag to the Node specified.

#### Base Command

`genians-assign-ip-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP Address (e.g. 192.168.100.87) | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| genians.tag.nodeId | string | nodeid of IP | 
| genians.tag.Name | string | Tag name | 

#### Raw Output

```
[
    {
        "Type": "node",
        "Description": "Threat",
        "IDX": 9,
        "nodeId": "dd9394cc-4495-103a-8010-2cf05d0cf498-537696fb",
        "Name": "THREAT"
    }
]
```

### Delete IP address from a tag
***
Removes the tag(s) from the Node specified.

#### Base Command

`genians-unassign-ip-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | IP Address (e.g. 192.168.100.87) | Required | 

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| genians.tag.nodeId | string | nodeid of IP | 
| genians.tag.Name | string | Tag name | 

#### Raw Output

```[]```