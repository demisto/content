This script resolves the original URL from a given shortened URL and places the resolved URL in the playbook context and output.

**Disclaimer:**  
- Using online services for resolving URLs exposes the server IP address to these services.  
- The `Built-In` service visits the URL and follows redirects on the server, which exposes the server IP address to the redirect URLs.
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
| service | The service to use for resolving the URL. If not set, a default service is used. |
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
| ResolveShortenedURL.ServiceName | The name of the service used to resolve the URL. | string |
| ResolveShortenedURL.UsageCount | The usage count for the current IP. If the count exceeds 10 in an hour, an error is returned. Relevant only if the unshorten.me service is used. | int |
| ResolveShortenedURL.RedirectCount | The number of redirects followed to resolve the URL. | int |
| ResolveShortenedURL.RedirectHistory | The history of redirects followed to resolve the URL. | list |
