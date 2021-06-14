Use rakyll/hey to test a web application with a load of requests.

## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| url | URL to query. |
| n | Number of requests to run. Default is 200. |
| t | Timeout for each request in seconds. Default is 20, use 0 for infinite. |
| c | Number of workers to run concurrently. |
| z | Duration of application to send requests. |
| m | HTTP method. |
| disable_compression | Disable compression. |
| output_type | Output type of the result. |
| results_map | Additional information to add to the result. Semicolon separated list of "key=value". e.g. Type=IP;Size=100. |

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
| Hey.Result | The full result in text format when output_type is set to "human_readable" | number |
