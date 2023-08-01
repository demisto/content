Script is designed to de-duplicate, decode, un-escape, whitelist and drop (images, logos and other non-clickables) URLs. Also checks URL for PII information, if found, is replaced with "username@domain".
## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| url |  |
| domain | Checks URL for PII information. If found, is replaced with "username@domain". |
| purgeImageURLs | Remove URLs that end with png,jpg,bmp,tiff,gif and jpeg |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| urlList | New list of URLs | Unknown |
