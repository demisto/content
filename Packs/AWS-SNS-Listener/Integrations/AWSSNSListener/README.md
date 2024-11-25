Amazon Simple Notification Service (SNS) is a managed service that provides message delivery from publishers to subscribers.
This integration was integrated and tested with version January 2024 of AWS-SNS-Listener.

## Configure AWS-SNS-Listener in Cortex


| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| Long running instance |  Integration is long running by default| |
| Listen Port | Runs the service on this port from within Cortex XSOAR. Requires a unique port for each long-running integration instance. Do not use the same port for multiple instances. Note: If you click the test button more than once, a failure may occur mistakenly indicating that the port is already in use. | False |
| Username | Uses basic authentication for accessing the list. If empty, no authentication is enforced. \(For Cortex XSOAR 8 and Cortex XSIAM\) Optional for engines, otherwise mandatory. | False |
| Password |  | False |
| Endpoint | Set the endpoint of your listener. example: /snsv2 | False |
| Certificate (Required for HTTPS) | \(For Cortex XSOAR 6.x\) For use with HTTPS - the certificate that the service should use. \(For Cortex XSOAR 8 and Cortex XSIAM\) Custom certificates are not supported. | False |
| Private Key (Required for HTTPS) | \(For Cortex XSOAR 6.x\) For use with HTTPS - the private key that the service should use. \(For Cortex XSOAR 8 and Cortex XSIAM\) When using an engine, configure a private API key. Not supported on the Cortex XSOAR​​ or Cortex XSIAM server. | False |
| Store sample events for mapping | Because this is a push-based integration, it cannot fetch sample events in the mapping wizard. After you finish mapping, it is recommended to turn off the sample events storage to reduce performance overhead. | False |
| Use system proxy settings |  | False |



## Commands

You can execute these commands from the CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.