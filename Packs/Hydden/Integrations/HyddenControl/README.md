This is the Hydden Control integration for Cortex XSIAM.

## Configure Hydden Control on Cortex XSIAM

1. Navigate to **Settings** > **Data Sources & Integrations**.
2. Search for Hydden Control.
3. Click **Add instance** to create and configure a new integration instance.

 | **Parameter** | **Description** | **Required** |
 | --- | --- | --- |
 | Hydden API URL (e.g., https://control.hydden.ai/api/public/v1) | Public API root. | True |
 | Client ID | Client ID for the Hydden REST API. | True |
 | Client Secret | Client secret for the Hydden REST API. | True |
 | HTTP request timeout (seconds) | Optional. Default 300. A cold blast-radius call can take several minutes. | False |
 | Trust any certificate (not secure) | Skip TLS certificate validation. | False |
 | Use system proxy settings | Use the Cortex system proxy. | False |

4. Click **Test** to validate the URL, credentials, and connection.

## Commands

You can execute these commands from the Cortex XSIAM CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### hydden-blast-radius

***
Return the subject's blast radius from Hydden Control. Calls `GET /blast-radius?ref=<account_id>&type=<type>`.

#### Base Command

`hydden-blast-radius`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Cortex account ID. Sent to Hydden as the `ref` query parameter. | Required |
| type | Subject the ref names: `account` (default) or `group`. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hydden.Identity.blast_radius | String | The subject's blast radius score, as a string. |
| Hydden.Identity.score | Number | The reach score for the subject. |
| Hydden.Identity.reachable_resources | Number | Number of resources the subject can reach. |
| Hydden.Identity.tenant_resources | Number | Total resources in the tenant. |
| Hydden.Identity.share_of_tenant | Number | Fraction of tenant resources the subject reaches. |
| Hydden.Identity.denied_resources | Number | Resources reachable by grant but blocked by a deny rule. |
| Hydden.Identity.subject_ref | String | The ref the score was computed for. |
| Hydden.Identity.subject_type | String | The subject type the score was computed for. |
| Hydden.Identity.computed_at | Date | When the score was computed. |

#### Command example

```!hydden-blast-radius account_id="00000000-0000-0000-0000-000000000000" type="account"```

#### Context Example

```json
{
    "Hydden": {
        "Identity": {
            "blast_radius": "73",
            "score": 73,
            "reachable_resources": 7,
            "subject_ref": "00000000-0000-0000-0000-000000000000",
            "subject_type": "account"
        }
    }
}
```

#### Human Readable Output

> Blast radius for account 00000000-0000-0000-0000-000000000000: 73

### hydden-deprovision-account

***
Deprovision an account across the fabric, including disabling the account and removing group and role memberships. Calls `POST /account-actions/deprovision?ref=<account_id>`. This command is potentially harmful.

#### Base Command

`hydden-deprovision-account`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| account_id | Cortex account ID. Sent to Hydden as the `ref` query parameter. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Hydden.Identity.deprovisioned | Boolean | Whether deprovisioning succeeded. |

#### Command example

```!hydden-deprovision-account account_id="00000000-0000-0000-0000-000000000000"```

#### Context Example

```json
{
    "Hydden": {
        "Identity": {
            "deprovisioned": true
        }
    }
}
```

#### Human Readable Output

> Account 00000000-0000-0000-0000-000000000000 was deprovisioned successfully.
