Builds A JSON array based on the values provided by the user for the 'threatstream-import-indicator-without-approval' command.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | basescript |
| Cortex XSOAR Version | 6.8.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| email_values | A comma-separated list of emails. |
| md5_values | A comma-separated list of MD5 hashes. |
| ip_values | A comma-separated list of IPs. |
| url_values | A comma-separated list of URLs. |
| domain_values | A comma-separated list of domains. |
| email_indicator_type | The indicator type \(Itype\) of the emails provided. By default the type will be “Malware Email” \(mal_email\). |
| md5_indicator_type | The indicator type \(Itype\) of the hashes provided. By default the type will be “Malware MD5” \(mal_md5\). |
| ip_indicator_type | The indicator type \(Itype\) of the ip provided. By default the type will be “Malware IP” \(mal_ip\). |
| url_indicator_type | The indicator type \(Itype\) of the URLs  provided. By default the type will be “Malware URL” \(mal_url\). |
| domain_indicator_type | The indicator type \(Itype\) of the domains provided. By default the type will be “Malware Domain” \(mal_domain\). |
| indicator_query | The indicators query, based lucene search syntax. |

Note: If both a query (indicator_query) and values (e.g., email_values) are provided as arguments, the values will be ignored.

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| ThreatstreamBuildIocImportJson | The string output represents a JSON object. | String |

## Script Examples

### Example command

```!ThreatstreamBuildIocImportJson indicator_query="type: Domain"```

### Context Example

```json
{
    "ThreatstreamBuildIocImportJson": "{'objects': [{'value': 'my.domain1.com', 'itype': 'mal_domain'}, {'value': 'my.domain2.com', 'itype': 'mal_domain'}]}"
}
```

### Human Readable Output

>{'objects': [{'value': 'my.domain1.com', 'itype': 'mal_domain'}, {'value': 'my.domain2.com', 'itype': 'mal_domain'}]}

### Example command

```!ThreatstreamBuildIocImportJson indicator_query="type: Domain" domain_indicator_type=spam_domain```

### Context Example

```json
{
    "ThreatstreamBuildIocImportJson": "{'objects': [{'value': 'my.domain1.com', 'itype': 'spam_domain'}, {'value': 'my.domain2.com', 'itype': 'spam_domain'}]}"
}
```

### Human Readable Output

>{'objects': [{'value': 'my.domain1.com', 'itype': 'spam_domain'}, {'value': 'my.domain2.com', 'itype': 'spam_domain'}]}
