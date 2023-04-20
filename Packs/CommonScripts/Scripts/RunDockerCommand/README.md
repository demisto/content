Allows you to run commands against a local Docker container. A command such as `wc` with word count, or other types of commands that you want on the docker container. 

We recommend for tools that you want to use that are not part of the default Docker container, to cope this Automation script and then create a customer docker container with /docker_image_create with a custom docker container to add any command level tool to Cortex XSOAR and output the results directly to the context.

## Script Data
---

| **Name** | **Description** |
| --- | --- |
| Script Type | python |
| Tags | Utilities |


## Inputs
---

| **Argument Name** | **Description** |
| --- | --- |
| cmd | The command to enter. |
| sysargs | The sysargs to enter. |

## Outputs
---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| CommandResults.Command | Contains the command line tool name and arguments that were run. | Unknown |
| CommandResults.Results | Returns the results as a single string of the results. The results of the command will need to be parsed into the preferred format. Use commands such as `ExtractRegex` or create your own follow on automation script that will parse the results into your preferred format. | Unknown |
