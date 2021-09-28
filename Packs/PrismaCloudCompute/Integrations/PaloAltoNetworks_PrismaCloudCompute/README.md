![image](https://user-images.githubusercontent.com/49071222/72906531-0e452a00-3d3b-11ea-8703-8b97ddf30be0.png)


This integration lets you import **Palo Alto Networks - Prisma Cloud Compute** alerts into Cortex XSOAR

## Use Cases

- Manage Prisma Cloud Compute alerts in Cortex XSOAR.
- You can create new playbooks, or extend the default ones, to analyze alerts, assign tasks based on your analysis, and open tickets on other platforms.

## Configure Prisma Cloud Compute to Send Alerts to Cortex XSOAR

To send alerts from Prisma Cloud Compute to Cortex XSOAR, you need to create an alert profile.

1. Log in to your Prisma Cloud Compute console.
2. Navigate to **Manage > Alerts**.
3. Click **Add Profile** to create a new alert profile.
4. On the left, select **Demisto** from the provider list.
5. On the right, select the alert triggers. Alert triggers specify which alerts are sent to Cortex XSOAR.
6. Click **Save** to save the alert profile.

## Configure Cortex XSOAR

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for **Prisma Cloud Compute**.
3. Click **Add instance** to create and configure a new integration.
   
   | Parameter Name | Description | Default |
   | -------------- | ----------- | ------- |
   | **Name** | A meaningful name for the integration instance. | Prisma Cloud Compute_&lt;alertProfileName&gt; |
   | **Fetches incidents** | Configures this integration instance to fetch alerts from Prisma Cloud Compute. | N/A |
   | **Prisma Cloud Compute Console URL** | URL address and port of your Prisma Cloud Compute console. Copy the address from the alert profile created in Prisma Cloud Compute. | https:/<span></span>/proxyserver.com |
   | **Prisma Cloud Compute Project Name (if applicable)** | Copy the project name from the alert profile created in Prisma Cloud Compute and enter paste in this field. | N/A |
   | **Trust any certificate (not secure)** | Skips verification of the CA certificate (not recommended). | N/A |
   | **Use system proxy settings** | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | <span></span>https://proxyserver.com |
   | **Credentials** | Prisma Cloud Compute login credentials. | N/A |
   | **Prisma Cloud Compute CA Certificate** | CA Certificate used by Prisma Cloud Compute. Copy the certificate from the alert profile created in Prisma Cloud Compute. | N/A |
4. Click **Test** to validate the integration.
5. Click **Done** to save the integration.


## Using the Integration and Scripts

The integration ships with four default playbooks and four scripts that are used by the playbooks. The scripts encode the raw JSON alerts into Cortex XSOAR objects that can then be used in the playbooks. The scripts are:

* PrismaCloudComputeParseAuditAlert
* PrismaCloudComputeParseComplianceAlert
* PrismaCloudComputeParseVulnerabilityAlert
* PrismaCloudComputeParseCloudDiscoveryAlert


To better understand how playbooks and scripts interoperate, consider the _Prisma Cloud Compute - Vulnerability Alert_ playbook.

* When the playbook is triggered, the **Parse Vulnerability Alert** starts running.
* The task runs the **PrismaCloudComputeParseVulnerabilityAlert** script, which takes the `prismacloudcomputerawalertjson` field of the incident (the raw JSON alert data) as input.

![image](https://user-images.githubusercontent.com/49071222/72902982-1601d000-3d35-11ea-8be2-a12ac8ea8862.png)


* Click **outputs** to see how the script transformed the raw JSON input into a Demisto object.


![image](https://user-images.githubusercontent.com/49071222/72903545-1189e700-3d36-11ea-9a35-81b756a5fc6d.png)


At this point, you can add tasks that extend the playbook to check and respond to alerts depending on the properties of the Demisto object.


## Troubleshooting

If any alerts are missing in Cortex XSOAR, check the status of the integration.

![image](https://user-images.githubusercontent.com/49071222/72086124-18b0fe00-330f-11ea-894b-6b2f9f0528fd.png)

### prisma-cwpp-list-runtime-policies
***
List runtime policies


#### Base Command

`prisma-cwpp-list-runtime-policies`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_type | The policy type. Possible values are: container, host, serverless, app-embedded. Default is container. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Prisma.CWPP.Policy._id | String | The Policy ID | 


#### Command Example
```json
{
    "Prisma": {
        "CWPP": {
            "Policy": {
                "_id": "containerRuntime",
                "learningDisabled": false,
                "rules": [
                    {
                        "advancedProtection": true,
                        "cloudMetadataEnforcement": false,
                        "collections": [
                            {
                                "accountIDs": [
                                    "*"
                                ],
                                "appIDs": [
                                    "*"
                                ],
                                "clusters": [
                                    "aks-sm"
                                ],
                                "codeRepos": [
                                    "*"
                                ],
                                "color": "#DB2798",
                                "containers": [
                                    "*"
                                ],
                                "functions": [
                                    "*"
                                ],
                                "hosts": [
                                    "*"
                                ],
                                "images": [
                                    "vulnerables/web-dvwa:latest"
                                ],
                                "labels": [
                                    "*"
                                ],
                                "modified": "2021-09-24T06:23:00.353Z",
                                "name": "dvwa",
                                "namespaces": [
                                    "default"
                                ],
                                "owner": "smangkalopak@paloaltonetworks.com",
                                "prisma": false,
                                "system": false
                            }
                        ],
                        "dns": {
                            "blacklist": [],
                            "effect": "disable",
                            "whitelist": []
                        },
                        "filesystem": {
                            "backdoorFiles": true,
                            "blacklist": [],
                            "checkNewFiles": true,
                            "effect": "alert",
                            "skipEncryptedBinaries": false,
                            "suspiciousELFHeaders": true,
                            "whitelist": []
                        },
                        "kubernetesEnforcement": false,
                        "modified": "2021-09-24T06:23:11.615Z",
                        "name": "demo exec proc",
                        "network": {
                            "blacklistIPs": [],
                            "blacklistListeningPorts": [],
                            "blacklistOutboundPorts": [],
                            "detectPortScan": true,
                            "effect": "alert",
                            "skipModifiedProc": false,
                            "skipRawSockets": false,
                            "whitelistIPs": [],
                            "whitelistListeningPorts": [],
                            "whitelistOutboundPorts": []
                        },
                        "owner": "smangkalopak@paloaltonetworks.com",
                        "previousName": "",
                        "processes": {
                            "blacklist": [
                                "apt-get",
                                "curl",
                                "ps"
                            ],
                            "checkCryptoMiners": true,
                            "checkLateralMovement": true,
                            "effect": "prevent",
                            "whitelist": []
                        },
                        "wildFireAnalysis": "alert"
                    },
                    {
                        "advancedProtection": true,
                        "cloudMetadataEnforcement": false,
                        "collections": [
                            {
                                "accountIDs": [
                                    "*"
                                ],
                                "appIDs": [
                                    "*"
                                ],
                                "clusters": [
                                    "*"
                                ],
                                "codeRepos": [
                                    "*"
                                ],
                                "color": "#C8D6DD",
                                "containers": [
                                    "*"
                                ],
                                "description": "C RULE",
                                "functions": [
                                    "*"
                                ],
                                "hosts": [
                                    "*"
                                ],
                                "images": [
                                    "UBUNTU:LATEST"
                                ],
                                "labels": [
                                    "*"
                                ],
                                "modified": "2021-09-08T18:41:03.187Z",
                                "name": "JRULE",
                                "namespaces": [
                                    "*"
                                ],
                                "owner": "caswalker@paloaltonetworks.com",
                                "prisma": false,
                                "system": false
                            }
                        ],
                        "dns": {
                            "blacklist": [],
                            "effect": "disable",
                            "whitelist": []
                        },
                        "filesystem": {
                            "backdoorFiles": true,
                            "blacklist": [],
                            "checkNewFiles": true,
                            "effect": "alert",
                            "skipEncryptedBinaries": false,
                            "suspiciousELFHeaders": true,
                            "whitelist": []
                        },
                        "kubernetesEnforcement": false,
                        "modified": "2021-09-08T18:42:28.502Z",
                        "name": "jrule",
                        "network": {
                            "blacklistIPs": [],
                            "blacklistListeningPorts": [],
                            "blacklistOutboundPorts": [],
                            "detectPortScan": true,
                            "effect": "alert",
                            "skipModifiedProc": false,
                            "skipRawSockets": false,
                            "whitelistIPs": [],
                            "whitelistListeningPorts": [],
                            "whitelistOutboundPorts": []
                        },
                        "owner": "caswalker@paloaltonetworks.com",
                        "previousName": "",
                        "processes": {
                            "blacklist": [
                                "apt"
                            ],
                            "checkCryptoMiners": true,
                            "checkLateralMovement": true,
                            "effect": "alert",
                            "whitelist": []
                        },
                        "wildFireAnalysis": "alert"
                    }
                ]
            }
        }
    }
}
```
#### Human Readable Output


>### Policies of type - container:
>|_id|learningDisabled|rules|
>|---|---|---|
>| containerRuntime | false | demo exec proc, jrule, sm cve, ba-dvwa, dimar-aks, Phimm Rule |

### prisma-cwpp-add-policy-rule
***
Add a new policy rule


#### Base Command

`prisma-cwpp-add-policy-rule`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| policy_type | The policy type. Possible values are: container, host, serverless, app-embedded. Default is container. | Optional | 
| rule_object | The rule object. | Required | 
| policy_to_update | The policy to update. | Required | 


#### Context Output

There is no context output for this command.

#### Command Example
``` ```

#### Human Readable Output

Policy successfully updated
