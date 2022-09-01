
## Configure Taegis XDR on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Taegis XDR
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | Taegis Environment | The environment to utilize | True |
    | Client ID | Client ID as described in the [Taegis Documentation](https://docs.ctpx.secureworks.com/apis/api_authenticate/) | True |
    | Client Secret | Client Secret as described in the [Taegis Documentation](https://docs.ctpx.secureworks.com/apis/api_authenticate/) | True |
    | Use system proxy settings | Defines whether the system proxy is used or not | False |

4. Click **Test** to validate the URLs, token, and connection.


## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.



### taegis-create-investigation

#### Base Command

`!taegis-create-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| description | The subject or description of the investigation | True |
| priority | The priority for the investigiation [Default: 3] | False |

#### Command Example

```
!taegis-create-investigation priority=1 description="XSOAR Created Investigation"
```

#### Context Example

```
{
    "TaegisXDR": {
        "id": "593fa115-abad-4a52-9fc4-2ec403a8a1e4"
    }
}
```


### taegis-fetch-alerts

#### Base Command

`!taegis-fetch-alerts`

#### Input

| **Argument Name** | **Description** | Default | **Required** |
| --- | --- | --- | --- |
| ids | A list of alerts by IDs | `936c1cc1-db8f-430c-837c-1c914fcca35a` | False |
| limit | Number of results to when `ids` is not defined | `10` | False |
| offset | The result to start from when `ids` is not defined | `0` | False |
| cql_query | The query to utilize when searching for Alerts | `from alert severity >= 0.6 and status='OPEN'` | False |

#### Command Examples

```
!taegis-fetch-alerts ids=`["6594e97f-a898-5b28-82b2-ea03293cdaa1"]`
```

#### Context Example

```
{
    "TaegisXDR": [
        {
            "id": "c4f33b53-eaba-47ac-8272-199af0f7935b",
            "metadata": {
                "title": "Test Alert",
                "description": "This is a test alert",
                "severity": 0.5,
            }
        }
    ]
}
```



### taegis-execute-playbook

#### Base Command
`!taegis-execute-playbook`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Playbook instance ID to execute | True |
| inputs | JSON object of inputs to pass into the playbook execution | False |

#### Command Example

```
!taegis-execute-playbook id=UGxheWJvb2tJbnN0YW5jZTphZDNmNzBlZi1mN2U0LTQ0OWYtODJiMi1hYWQwMjQzZTA2NTg=
!taegis-execute-playbook id=UGxheWJvb2tJbnN0YW5jZTphZDNmNzBlZi1mN2U0LTQ0OWYtODJiMi1hYWQwMjQzZTA2NTg= inputs=`{'myvar': 'myval'}`
```

#### Context Example

```
{
    "id": "UGxheWJvb2tFeGVjdXRpb246NGYwZDZiNGQtNWNiZS00NDkxLTg3YzYtMDZkNjkxYzMwMTg4"
}
```


### taegis-fetch-investigation

#### Base Command
`!taegis-fetch-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID to lookup | True |

#### Command Example

```
!taegis-fetch-investigation id=936c1cc1-db8f-430c-837c-1c914fcca35a
```


### taegis-fetch-investigation-alerts

#### Base Command
`!taegis-fetch-investigation-alerts`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID to lookup | True |

#### Command Example

```
!taegis-fetch-investigation-alerts id=936c1cc1-db8f-430c-837c-1c914fcca35a
```

#### Context Example

```
{
    "TaegisXDR": [
        {
            "id": "c4f33b53-eaba-47ac-8272-199af0f7935b",
            "description": "Test Alert",
            "message": "This is a test alert",
            "severity": 0.5,
        }
    ]
}
```



### taegis-fetch-investigations

#### Base Command
`!taegis-fetch-investigations`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| page |  | False |
| page_size | | False |

#### Command Example

```
!taegis-fetch-investigations
```

#### Context Example

```
{
    "TaegisXDR": [
        {
            "description": "Test Investigation",
            "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d",
            "key_findings": "",
            "priority": 2,
            "service_desk_id": "",
            "service_desk_type": "",
            "status": "Open"
        }
    ]
}
```


### taegis-fetch-playbook-execution

#### Base Command
`!taegis-fetch-playbook-execution`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Playbook execution ID to fetch | True |

#### Command Example

```
!taegis-fetch-playbook-execution id=UGxheWJvb2tFeGVjdXRpb246NGYwZDZiNGQtNWNiZS00NDkxLTg3YzYtMDZkNjkxYzMwMTg4
```

#### Context Example

```
{
            "createdAt": "2022-01-01T13:51:24Z",
            "executionTime": 1442,
            "id": "UGxheWJvb2tFeGVjdXRpb246NGYwZDZiNGQtNWNiZS00NDkxLTg3YzYtMDZkNjkxYzMwMTg4",
            "inputs": {
                "alert": {
                    "message": "Test Alert",
                }
            },
            "instance": {
                "name": "Test Alert Instance",
                "playbook": {
                    "name": "Taegis.PagerDutyAlertEvent"
                }
            },
            "outputs": "d6b65662-c1da-4109-8553-c5664918c952",
            "state": "Completed",
            "updatedAt": "2022-01-01T13:51:31Z"
        }
```


### taegis-update-investigation

#### Base Command
`!taegis-update-investigation`

#### Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Investigation ID to update | True |
| key_findings | | False |
| prioirity | The priority of the Investigation (1-5) | False |
| service_desk_id | An ID or ticket # to relate to an Investigation | False |
| service_desk_type | The type of id related to an investigation (e.g. Jira) | False |
| status | The current status of the Investigation | False |

Note: At least 1 of the above inputs (in addition to id) must be defined

##### Permitted Status Values

* Active
* Closed: Authorized Activity
* Closed: False Positive Alert
* Closed: Informational
* Closed: Not Vulnerable
* Open
* Suspended

#### Command Example

```
!taegis-update-investigation id="936c1cc1-db8f-430c-837c-1c914fcca35a" priority=3 status="Open" service_desk_id="XDR-1234" service_desk_type="Jira"
```

#### Context Example

```
{
    "TaegisXDR": {
        "id": "c2e09554-833e-41a1-bc9d-8160aec0d70d"
    }
}
```
