Creates the indicator of a Group-IB DRP violation from its incident.

The **Group-IB Digital Risk Protection - Violation Incident Postprocessing** playbook runs it on a
new incident whose **GIB DRP Indicator Wanted** field is set, which the fetch sets for the violation
types selected in **Create indicators from Violations** on the instance.

The script creates the indicator with `createNewIndicator` and links it to the incident
(`relatedIncidents`). It sets **Group-IB Digital Risk Protection** as its source, the violation's
first detection and current status date as first and last seen, the violation title as description,
and the violation type and brand as tags. The verdict follows the violation type: Counterfeit, Scam, Malware and Phishing are
*Malicious*; Partner policy compliance, Piracy and Trademark are *Suspicious*; No violation is
*Benign*. An unknown type is *Suspicious*.

Only an `http` or `https` URL, a domain or an IPv4 address becomes an indicator. DRP writes many
URIs without a scheme: `//bad.example/login` is read as an https URL and `bad.example` as a domain.
A URI with any other scheme (`mail://`, `tg://`), a marketplace seller id or a messenger handle
creates no indicator; the automation says so and ends without error.

When the violation is over (resolved, handed to legal, found false or rejected), the
`GIBDRPIncidentUpdate` pre-processing rule and the `GIBDRPResolveViolation` automation expire the
indicator if **GIB DRP Expire Indicator On Close** is set on the incident, which the fetch sets from
the instance's **Expire the indicator when the violation is closed**.

## Script Data

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | drp |
| Cortex XSOAR Version | 6.10.0 |

## Inputs

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| value | The violation URI to create the indicator from. Defaults to the incident's GIB DRP Violation URI field. | Optional |

## Outputs

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| GIBDRP.ViolationIndicator.uri | String | The violation URI the automation was given. |
| GIBDRP.ViolationIndicator.created | Boolean | Whether an indicator was created. |
| GIBDRP.ViolationIndicator.value | String | The indicator value \(the URI normalized to an http or https URL, a domain or an IP\). |
| GIBDRP.ViolationIndicator.type | String | The indicator type \(URL, Domain or IP\). |
| GIBDRP.ViolationIndicator.verdict | String | The verdict the indicator was created with \(Malicious, Suspicious or Benign\). |

## Script Examples

### Example command

```!GIBDRPCreateViolationIndicator value=//acme-login.example/verify```

### Context Example

```json
{
    "GIBDRP": {
        "ViolationIndicator": {
            "created": true,
            "type": "URL",
            "uri": "//acme-login.example/verify",
            "value": "https://acme-login.example/verify",
            "verdict": "Malicious"
        }
    }
}
```

### Human Readable Output

>Created the **URL** indicator `https://acme-login.example/verify` (Malicious) from the violation and linked it to this incident.
