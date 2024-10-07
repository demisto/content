Darktrace is a Cyber AI platform for threat detection and response across cloud, email, industrial, and the network.
This integration was integrated and tested with version 6.0.0 of Darktrace

## Configure Darktrace ASM in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| isFetch | Fetch incidents | False |
| insecure | Trust any certificate \(not secure\) | False |
| api_token | API Token | True |
| alert_type | Incident types to fetch | False |
| min_severity | Minimum Risk severity to fetch | False |
| max_alerts | Maximum Risks per fetch | False |
| first_fetch | First fetch time | False |


## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### darktrace-asm-get-risk

***
Returns the Risk object associated with the given Risk ID.

#### Base Command

`darktrace-asm-get-risk`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| risk_id | Darktrace ASM Risk ID | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.risk | dict | Darktrace Risk object. |
| Darktrace.risk.asset | dict | Darktrace ASM Asset object associated with the given Risk. |
| Darktrace.risk.asset.brand | string | Brand of associtated Asset. |
| Darktrace.risk.asset.tags | list | List of Tags associated with Asset. |
| Darktrace.risk.asset.id | string | Asset ID. |
| Darktrace.risk.asset.updatedAt | timestamp | Last time Asset was updated. |
| Darktrace.risk.asset.securityrating | string | Security rating of Asset. |
| Darktrace.risk.asset.isMalicious | boolean | Malicious state of the Asset. | 
| Darktrace.risk.asset.createdAt | timestamp | Time Asset was created. |
| Darktrace.risk.asset.state | string | State of Asset. |
| Darktrace.risk.comments | dict | Dictionary of comments by comment ID. |
| Darktrace.risk.description | string | Description of Risk. |
| Darktrace.risk.endedAt | timestamp | End time of Risk. |
| Darktrace.risk.evidence | string | Evidence gathered indicating the Risk. |
| Darktrace.risk.id | string | Risk ID. |
| Darktrace.risk.mitigatedAt | timestamp | Mitigation time of Risk. |
| Darktrace.risk.proposedAction | string | Recommended action to solve Risk. |
| Darktrace.risk.securityRating | string | Security rating of Risk. |
| Darktrace.risk.startedAt | timestamp | Start time of Risk. |
| Darktrace.risk.title | string | Name of Risk. |
| Darktrace.risk.type | string | Type of Risk. |

#### Command Example

```!darktrace-asm-get-risk risk_id=Umlza1R5cGU6MTE5Nzc=```

#### Context Example

```
"risk": {
      "id": "Umlza1R5cGU6MTE5Nzc=",
      "type": "SSL",
      "startedAt": "2022-05-27T18:38:45.439551+00:00",
      "endedAt": "2023-06-07T09:59:49.344739+00:00",
      "title": "HSTS header missing",
      "description": "The HSTS header enforces users to always visit your website through SSL, after their first visit.",
      "evidence": "No HSTS header present.",
      "proposedAction": "Turn on the HSTS header, read more on https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
      "asset": {
        "id": "QXBwbGljYXRpb25UeXBlOjIyNjg0",
        "state": "Unconfirmed",
        "brand": "Darktrace",
        "createdAt": "2022-05-27 14:18:24.264958+00:00",
        "updatedAt": "2023-06-29 06:40:41.007652+00:00",
        "securityrating": "f",
        "isMalicious": true,
        "tags": []
      },
      "securityRating": "b",
      "mitigatedAt": 2023-06-06T09:59:49.344739+00:00,
      "comments": {
        "edges": [
          {
            "node": {
              "id": "Q29tbWVudFR5cGU6ODM=",
              "text": "API TEST EDIT"
            }
          }
        ]
      }
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| asset | id: QXBwbGljYXRpb25UeXBlOjIyNjg0<br>state: Unconfirmed<br>brand: Darktrace<br>createdAt: "2022-05-27 14:18:24.264958+00:00<br>updatedAt: 2023-06-29 06:40:41.007652+00:00<br>securityrating: f<br>isMalicious: true<br>tags: EXAMPLE_TAG |
>| comments | Q29tbWVudFR5cGU6ODM=: "XSOAR Test Comment"<br>Q29tbWVudFR5cGU6ODN=: "XSOAR Test Comment 2" |
>| descirption | The HSTS header enforces users to always visit your website through SSL, after their first visit. |
>| endedAt | 2023-06-07T09:59:49.344739+00:00 |
>| evidence | No HSTS header present. |
>| id | Umlza1R5cGU6MTE5Nzc= |
>| mitigatedAt | 2023-06-06T09:59:49.344739+00:00 |
>| proposedAction | Turn on the HSTS header, read more on https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html |
>| securityRating | b |
>| startedAt | 2022-05-27T18:38:45.439551+00:00 |
>| title | HSTS header missing |
>| type | SSL |

### darktrace-asm-get-asset

***
Returns the Asset object associated with the given Asset ID.  The output will depend on the type of Asset(IP Address, Netblock, FQDN or Application).

#### Base Command

`darktrace-asm-get-asset`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| asset_id | Darktrace ASM Asset ID | Required |

#### Context Output: All Asset types

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.asset | dict | Darktrace ASM Asset object. |
| Darktrace.asset.brand | string | Brand that the Asset is associated with. |
| Darktrace.asset.comments | list | List of comments by comment ID. |
| Darktrace.asset.createdAt | timestamp | Creation time of Asset. |
| Darktrace.asset.discoverySources | list | List of discovery sources. |
| Darktrace.asset.id | string | Asset ID. |
| Darktrace.asset.isMalicious | bool | Malicious state of Asset. |
| Darktrace.asset.risks | list | List of Risks associated with Asset. |
| Darktrace.asset.securityrating | string | Security rating of Asset. |
| Darktrace.asset.state | string | State of Asset. |
| Darktrace.asset.tags | list | List of tags applied to Asset within Darktrace UI. |
| Darktrace.asset.type | string | Type of Asset. |
| Darktrace.asset.updatedAt | timestamp | Last time Asset was updated. |


#### Context Output: Application Asset type

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.asset.fqdns | list | List of FQDNS associated with Asset. |
| Darktrace.asset.ipaddresses | list | List of IPs associated with Asset. |
| Darktrace.asset.protocol | string | Protocol associated with the Asset |
| Darktrace.asset.screenshot | string | Screenshot of webpage associated with Asset. |
| Darktrace.asset.technologies | list | List of technologies associated with Asset. |
| Darktrace.asset.uri | string | URI associated with Asset. |

#### Context Output: IP Address Asset type

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.asset.lat | string | Latitude of the Asset. |
| Darktrace.asset.lon | string | Longitude of the Asset. |
| Darktrace.asset.geoCity | string | City Asset is located. |
| Darktrace.asset.geoCountry | string | Country Asset is located. |
| Darktrace.asset.address | string | IP address of the Asset |
| Darktrace.asset.netblock | string | Netblock of the Asset. |

#### Context Output: FQDN Asset type

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.asset.name | string | Hostname associated with Asset. |
| Darktrace.asset.dnsRecords | string | DNS records associated with Asset. |
| Darktrace.asset.resolvesTo | list | List of IPs the Asset hostname resolves to. |
| Darktrace.asset.whois | string | WhoIs information associated with Asset. |
| Darktrace.asset.registeredDomain | string | Domain associated with Asset. |

#### Context Output: Netblock Asset type

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.asset.netname | string | Name of the Asset. |
| Darktrace.asset.ipAddresses | list | List of IP addresses associated with Asset. |

#### Command Example

```!darktrace-asm-get-asset asset_id=QXBwbGljYXRpb25UeXBlOjI2NjI4```

#### Context Example

```
"application": {
      "brand": "Darktrace",
      "comments": [
        {
          "id": "Q29tbWVudFR5cGU6OTc=",
          "text": "Test comment"
        }
      ],
      "createdAt": "2022-06-27 18:34:50.473256+00:00",
      "discoverySources": [
        {
          "id": "RGlzY292ZXJ5U291cmNlVHlwZTo1NDc0Ng==",
          "description": "Record retrieved from FQDN careers.darktrace.com"
        },
        {
          "id": "RGlzY292ZXJ5U291cmNlVHlwZTo1NDc1Nw==",
          "description": "Application from https://careers.darktrace.com/"
        }
      ],
      "fqdns": [
        {
          "id": "RnFkblR5cGU6MjY2Mjc=",
          "name": "careers.darktrace.com"
        }
      ],
      "id": "QXBwbGljYXRpb25UeXBlOjI2NjI4",
      "ipaddresses": [
        {
          "id": "SVBBZGRyZXNzVHlwZToxNTU3Njc=",
          "address": "1.1.1.1"
        },
        {
          "id": "SVBBZGRyZXNzVHlwZToxNTU3Njg=",
          "address": "1.1.1.1"
        }
      ],
      "isMalicious": false,
      "risks": [
        {
          "id": "Umlza1R5cGU6NjYzNjA=",
          "title": "Vulnerable software found - jquery ui/1.13.0 (highest CVE score 4.3)"
        },
        {
          "id": "Umlza1R5cGU6MTU1ODQ=",
          "title": "Excessive cookie lifetime (> 1 year)"
        },
        {
          "id": "Umlza1R5cGU6MzQ4MzQ=",
          "title": "Excessive cookie lifetime (> 1 year)"
        }
      ],
      "screenshot": "https://storage.googleapis.com/asm-prod-1931-z5b5n7ow5w-copy/http_screenshot/screenshot_155822.jpg?Expires=1710617440&GoogleAccessId=asm-prod-1931-cyberweb%40dt-asm-prod.iam.gserviceaccount.com&Signature=Vbz1hBo%2Bo3ZYTRvg5p%2F%2F%2FTFFf4PHRgPaVUrcpaDG8Kp%2BOT2dSm8O2NC1HFJXQW420yD2zppJ5IbOCt46vJ6LZMvx5kcdm7IY1U6yKbedRGACfbpUQaXEjmXN1gLhVawnoET94CYqnmlYue6%2Fy4B6cS4fZwvH6sllm2OnbDZ%2FZacoSw9Xmf214R0M%2FgY3OjKuXapaAnu779r5c8fkjL8cSvX8E8PzkxToGF9ysTNuWVqZc46H05xxUtb8QSauiggAijBeSLg%2Blol1wVj0ZuMP%2Fb1kJvXNpCr6x0Dem6ITe4C%2FPrbiqcNMvwSZChptiDBhgoXGRAm%2FRJokWqktST19Nw%3D%3D",
      "securityrating": "b",
      "state": "Confirmed",
      "tags": [
        "MANAGED BY INTERNAL DEV"
      ],
      "updatedAt": "2023-08-21 00:31:57.299904+00:00",
      "uri": "https://careers.darktrace.com",
      "technologies": [
        {
          "id": "VGVjaG5vbG9neVR5cGU6MTU4MjY2",
          "name": "Amazon ALB"
        },
        {
          "id": "VGVjaG5vbG9neVR5cGU6MTU4MjY3",
          "name": "Amazon Web Services"
        },
        {
          "id": "VGVjaG5vbG9neVR5cGU6MTE1MjU3",
          "name": "Bootstrap"
        }
      ],
      "protocol": "HTTP"
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| brand | Darktrace |
>| comments | Q29tbWVudFR5cGU6OTc=: "Test comment" |
>| createdAt | 2022-06-27 18:34:50.473256+00:00 |
>| discoverySources | RGlzY292ZXJ5U291cmNlVHlwZTo1NDc0Ng==: Record retrieved from FQDN careers.darktrace.com<br>RGlzY292ZXJ5U291cmNlVHlwZTo1NDc1Nw==: Application from https://careers.darktrace.com/ |
>| fqdns | RnFkblR5cGU6MjY2Mjc=: careers.darktrace.com |
>| id | QXBwbGljYXRpb25UeXBlOjI2NjI4 |
>| ipaddresses | SVBBZGRyZXNzVHlwZToxNTU3Njc=: 1.1.1.1<br>SVBBZGRyZXNzVHlwZToxNTU3Njg=: 1.1.1.1 |
>| isMalicious | false |
>| protocol | HTTP |
>| risks | Umlza1R5cGU6NjYzNjA=: Vulnerable software found - jquery ui/1.13.0 (highest CVE score 4.3)<br>Umlza1R5cGU6MTU1ODQ=: Excessive cookie lifetime (> 1 year)<br>Umlza1R5cGU6MzQ4MzQ=: Excessive cookie lifetime (> 1 year) |
>| screenshot | https://storage.googleapis.com/asm-prod-1931-z5b5n7ow5w-copy/http_screenshot/screenshot_155822.jpg?Expires=1710617295&GoogleAccessId=asm-prod-1931-cyberweb%40dt-asm-prod.iam.gserviceaccount.com&Signature=HjT83fw4EV%2F6notDq7tQB24oAr049F4UZ8OUDJ3hiuAaD%2F3y7xFOniBLDyZNtZBMlUDDJgrG6%2BhXbuJ0Sdobhsk%2Bj6KZknqa6xao0eyv%2BT%2FQGysZSxol8YHn%2BykRBkX8Umajs%2F5KRR8GRWc46o7m%2FnW1Rdop4qUuGKPy82UUOWwbyfcI7yYOGH8nky2b0o95QyfvR4%2Fa4GeCEHL8cz8RksGh4imWICWcTDu18OlGNruI%2F0sAiivHVbzPnOnBBFwFunAIXez9THr5oItqIoTzV%2FrNdwIFHc0rRIvtvNpuUVcrQo7%2FqaDunYZSmPu0Hf6eaL7cR6ZbYbXuKchlr2eAOQ%3D%3D |
>| securityrating | b|
>| state | Confirmed |
>| tags | MANAGED BY INTERNAL DEV |
>| technologies | VGVjaG5vbG9neVR5cGU6MTU4MjY2: Amazon ALB<br>VGVjaG5vbG9neVR5cGU6MTU4MjY3: Amazon Web Services<br>VGVjaG5vbG9neVR5cGU6MTE1MjU3: Bootstrap |
>| type | application |
>| updatedAt | 2023-08-21 00:31:57.299904+00:00 |
>| uri | https://careers.darktrace.com |

### darktrace-asm-mitigate-risk

***
Mitigates Risk within the Darktrace UI.  **Warning: Mitigating a Risk without taking action to resolve the Risk means you accept a Risk and it will no longer appear with the Darktrace UI.**

#### Base Command

`darktrace-asm-mitigate-risk`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| risk_id | Darktrace ASM Risk ID | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.risk.success | boolean | Status of mitigation. |

### Command Example

```!darktrace-asm-mitigate-risk risk_id=Umlza1R5cGU6MTE5Nzc=```

#### Context Example

```
"closeRisk": {
      "success": true,
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| success | true |

### darktrace-asm-post-comment

***
Post a comment to a Risk or an Asset within the Darktrace UI.

#### Base Command

`darktrace-asm-post-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | Darktrace ASM Risk or Asset ID | Required |
| comment | Text of comment to be applied | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.comment.comment.id | string | Unique ID of Comment. |
| Darktrace.comment.comment.text | string | Text of Comment. |
| Darktrace.comment.success | boolean | Status of post. |

### Command Example

```!darktrace-asm-post-comment id=QXBwbGljYXRpb25UeXBlOjI2NjI4 comment="API Test Comment"```

#### Context Example

```
"placeComment": {
      "success": true,
      "comment": {
        "id": "Q29tbWVudFR5cGU6OTg=",
        "text": "API Test Comment"
      }
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| comment | id: Q29tbWVudFR5cGU6OTg=<br>text: API Test Comment  |
>| success | true |

### darktrace-asm-edit-comment

***
Edit an existing comment within the Darktrace UI.

#### Base Command

`darktrace-asm-edit-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment_id | ID of comment to be edited | Required |
| comment | Text of comment to be applied | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.comment.comment.id | string | Unique ID of Comment. |
| Darktrace.comment.comment.text | string | Text of Comment. |
| Darktrace.comment.success | boolean | Status of edit. |

### Command Example

```!darktrace-asm-edit-comment comment_id=Q29tbWVudFR5cGU6OTg= comment="API Test Comment Edited"```

#### Context Example

```
"editComment": {
      "success": true,
      "comment": {
        "id": "Q29tbWVudFR5cGU6OTg=",
        "text": "API Test Comment Edited"
      }
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| comment | id: Q29tbWVudFR5cGU6OTg=<br>text: API Test Comment Edited  |
>| success | true |

### darktrace-asm-delete-comment

***
Delete an existing comment within the Darktrace UI.

#### Base Command

`darktrace-asm-delete-comment`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| comment_id | ID of comment to be deleted | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.comment.success | boolean | Status of deletion. |

### Command Example

```!darktrace-asm-delete-comment comment_id=Q29tbWVudFR5cGU6OTg=```

#### Context Example

```
"deleteComment": {
      "success": true
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| success | true |

### darktrace-asm-create-tag

***
Creat a new Tag within the Darktrace UI.  Tags can be applied to Assets.

#### Base Command

`darktrace-asm-create-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Name of Tag to create | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.tag.success | boolean | Status of creation. |
| Darktrace.tag.tag.id | string | Tag ID. |
| Darktrace.tag.tag.name | string | Name of Tag. |

### Command Example

```!darktrace-asm-create-tag tag_name="API TEST"```

#### Context Example

```
"createTag": {
      "success": true,
      "tag": {
            "id": "VGFnVHlwZTo1Mg==",
            "name": "API TEST"
       }
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| success | true |
>| tag | id: VGFnVHlwZTo1Mg==<br>name: API TEST |

### darktrace-asm-assign-tag

***
Assign an existing Tag to an Asset within the Darktrace UI.

#### Base Command

`darktrace-asm-assign-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Name of Tag to apply to Asset | Required |
| asset_id | Asset ID to apply Tag to | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.tag.success | boolean | Status of assignment. |
| Darktrace.tag.asset.id | string | Asset ID. |
| Darktrace.tag.asset.tags | list | List of Tags assigned to Asset. |

### Command Example

```!darktrace-asm-assign-tag tag_name="API TEST" asset_id=SVBBZGRyZXNzVHlwZTox```

#### Context Example

```
"assignTag": {
      "success": true,
      "asset": {
        "id": "SVBBZGRyZXNzVHlwZTox",
        "tags": [
          "API TEST"
        ]
      }
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| asset | id: SVBBZGRyZXNzVHlwZTox<br>tags: API TEST |
>| success | true |

### darktrace-asm-unassign-tag

***
Unssign an existing Tag from an Asset within the Darktrace UI.

#### Base Command

`darktrace-asm-unassign-tag`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| tag_name | Name of Tag to remove from Asset | Required |
| asset_id | Asset ID to remove Tag from | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Darktrace.tag.success | boolean | Status of assignment. |
| Darktrace.tag.asset.id | string | Asset ID. |
| Darktrace.tag.asset.tags | list | List of Tags assigned to Asset. |

### Command Example

```!darktrace-asm-unassign-tag tag_name="API TEST" asset_id=SVBBZGRyZXNzVHlwZTox```

#### Context Example

```
"unassignTag": {
      "success": true,
      "asset": {
        "id": "SVBBZGRyZXNzVHlwZTox",
        "tags": []
      }
    }
```

#### Human Readable Output

>| Field | Value |
>| --- | --- |
>| asset | id: SVBBZGRyZXNzVHlwZTox<br>tags: |
>| success | true |