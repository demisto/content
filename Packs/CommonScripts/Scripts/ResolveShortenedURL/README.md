This script resolves the original URL from a given shortened URL and places the resolved URL in the playbook context and output.

**Disclaimer:**  

- The service visits the URL and follows redirects on the server, which exposes the server IP address to the redirect URLs.

## Script Data

---

| **Name** | **Description** |
| --- | --- |
| Script Type | python3 |
| Tags | Utility |
| Cortex XSOAR Version | 6.5.0 |

## Inputs

---

| **Argument Name** | **Description** |
| --- | --- |
| url | The URL to resolve. |
| redirect_limit | A maximum number of recursions to run in case of nested shortened-URLs. Use 0 for unlimited \(not recommended\). |
| insecure | Trust any certificate \(not secure\). |

## Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL.Data | The resolved URL data. | string |
| ResolveShortenedURL.OriginalURL | The original shortened URL. | string |
| ResolveShortenedURL.ResolvedURL | The resolved URL. | string |
| ResolveShortenedURL.RedirectCount | The number of redirects followed to resolve the URL. | int |
| ResolveShortenedURL.RedirectHistory | The history of redirects followed to resolve the URL. | list |
