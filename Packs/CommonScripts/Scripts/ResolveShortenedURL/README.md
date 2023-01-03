Resolve the original URL from the given shortened URL and place it in both as output and in the context of a playbook.

**Disclaimer:**  
Using online services for unshortening exposes the IP address of the server to these services.  
Using the `Built-In` service will visit the URL and follow redirects on the server, which will expose the IP address of the server to the redirecting & redirected URLs
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
| service | Service to use for resolving the URL. If not set, a default service will be used. |
| url | URL to resolve |
| redirect_limit | A maximum number of recursions to run in case of nested shortened-URLs. Use 0 for unlimited \(not recommended\). |
| insecure | Trust any certificate \(not secure\) |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| URL.Data | Resolved URL. | string |
| ResolveShortenedURL.OriginalURL | The original shortened URL. | string |
| ResolveShortenedURL.ResolvedURL | The resolved URL. | string |
| ResolveShortenedURL.ServiceName | The name of the service that was used to resolve the URL. | string |
| ResolveShortenedURL.UsageCount | The usage count for the current IP. If the count exceeds 10 in an hour, an error will be returned. Relevant only if unshorten.me service is used. | int |
| ResolveShortenedURL.RedirectCount | The number of redirects that were followed to resolve the URL. | int |
| ResolveShortenedURL.RedirectHistory | The history of redirects that were followed to resolve the URL. | list |
