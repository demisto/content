
This integration lets you import **Palo Alto Networks IoT** alerts and vulnerabilities into Palo Alto Networks XSOAR.

## Use Cases

- Fetch Palo Alto Networks IoT alerts and vulnerabilities
- Fetch a device details by using a device ID
- You can create new playbooks, or extend the default ones, to analyze alerts and vulnerabilities, enrich the incident by having the device details and assign the incidents to different parties based on the Category and Profile of the device.

## Palo Alto Networks IoT API connection

This integration requires the API access to be configured.

To obtain the **Access Key ID** and **Secret Access Key**, please refer to the official **Zingbox API User Guide**:
https://support.zingbox.com/hc/en-us/articles/360009569073-Zingbox-API-User-Guide

## Configure XSOAR

1. Navigate to **Settings > Integrations > Servers & Services**.
2. Search for **PaloAltoNetworks_IoT**.
3. Click **Add instance** to create and configure a new integration.

   | Parameter Name | Description | Default |
   | -------------- | ----------- | ------- |
   | **Name** | A meaningful name for the integration instance. | PaloAltoNetworks_IoT_instance_1 |
   | **Palo Alto Networks IoT Security Portal URL** | URL address and port of your Palo Alto Networks IoT Security Portal. | https://example.iot.paloaltonetworks.com |
   | **Tenant ID** | Tenant ID used in API requests | N/A |
   | **Access Key ID** | X-Key-Id used in API requests | N/A |
   | **Secret Access Key** | X-Access-Key used in API requests | N/A |
   | **Trust any certificate (not secure)** | Skips verification of the CA certificate (not recommended). | N/A |
   | **Use system proxy settings** | Runs the integration instance using the proxy server (HTTP or HTTPS) that you defined in the server configuration. | https://proxyserver.com |
   | **Fetch IoT Alerts** | Configures this integration instance to fetch alerts from Palo Alto Networks IoT security portal. | False |
   | **Fetch IoT Vulnerabilities** | Configures this integration instance to fetch vulnerabilities from Palo Alto Networks IoT security portal. | False |
   | **The timeout for querying APIs** | A http timeout when querying the IoT security portal APIs | 60 |

4. Click **Test** to validate the integration.
5. Click **Done** to save the integration.

## Commands
You can execute these commands from the XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### iot-security-get-device
***
Get a device in details

##### Base Command

`iot-security-get-device`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| deviceID | The device ID (e.g. MAC address) | Required |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| device | unknown | device details |

### iot-security-list-devices
***
Get a list of devices

##### Base Command

`iot-security-list-devices`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| offset | offset in pagination | Optional |
| pagelength | pagelength in pagination (0 <= pagelength <= 1000) | Optional |

##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| devices | unknown | a list of devices |

### iot-security-list-alerts
***
Get a list of alerts

##### Base Command

`iot-security-list-alerts`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stime | The starting time of the list of alerts, default: -1 | Optional |
| offset | The maximum size of the alerts list, default: 1000 | Optional |

### iot-security-list-vulns
***
Get a list of vulnerabilities

##### Base Command

`iot-security-list-vulns`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| stime | The starting time of the list of vulnerabilities, default: -1 | Optional |
| offset | The maximum size of the vulnerabilities list, default: 1000 | Optional |

### iot-security-resolve-alert
***
Resolve an alert incident in IoT security portal

##### Base Command

`iot-security-resolve-alert`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the alert ID, e.g. 5eb9fa8127b736d82bf7840a | Required |
| reason | the resolution reason | Optional |
| reason_type | the resolution reason type, either "No Action Needed" or "Issue Mitigated" | Optional |

### iot-security-resolve-vuln
***
Resolve an vulnerability incident in IoT security portal

##### Base Command

`iot-security-resolve-vuln`

##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | the vulnerability ID, e.g. vuln-99124066 | Required |
| full_name | the vulnerability name, e.g. CVE-1234 | Required |
| reason | the resolution reason | Optional |
