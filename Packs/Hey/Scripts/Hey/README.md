Use rakyll/hey to test a web application with a load of requests.

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | URL to query. |
| requests_number | Number of requests to run. Default is 200. |
| timeout | Timeout for each request in seconds. Default is 20, use 0 for infinite. |
| concurrency | Number of workers to run concurrently. |
| duration | Duration of application to send requests \(in seconds\). |
| method | HTTP method. |
| headers | Custom HTTP header. Comma separated list of "key=value". e.g. Type=IP,Size=100. |
| disable_compression | Disable compression. |
| results_map | Additional information to add to the result. Comma separated list of "key=value". e.g. Content-Type=text/plain,Accept=\*/\*. |
| body | HTTP request body. |
| proxy | HTTP Proxy address as host:port. |
| enable_http2 | Enable HTTP/2. |
| disable_redirects | Disable following of HTTP redirects. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| Hey.Timeout | Timeout for each request. | number |
| Hey.Concurrency | Max number of concurrent workers. | number |
| Hey.Requests | Number of requests sent to URL. | number |
| Hey.SlowestTime | The slowest time it took for a request to finish. | number |
| Hey.FastestTime | The fastest time it took for a request to finish. | number |
| Hey.SuccessfulResponses | The number of responses that returned with 200 status code. | number |
| Hey.AverageTime | The average time it took for a request to finish. | number |
| Hey.Result | The full result in text format when output is set to "human_readable" | number |
