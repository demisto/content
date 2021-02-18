DEPRECATED. Use "PAN-OS Query Logs For Indicators" playbook instead. Queries traffic logs in a PAN-OS Panorama or Firewall device.

## Dependencies
This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks
* GenericPolling

### Integrations
This playbook does not use any integrations.

### Scripts
This playbook does not use any scripts.

### Commands
* panorama-get-traffic-logs
* panorama-check-traffic-logs-status
* panorama-query-traffic-logs

## Playbook Inputs
---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- | 
| number_of_logs | The number of logs to retrieve. The maximum is 5,000. | 100 | Optional |
| direction | Specify the log display order. "Forward" means the oldest is first, "Backward" means the newest is first. The default is "Backward". | backward | Optional |
| query | Specify the match criteria for the logs. This is similar to the query provided in the web interface under the **Monitor** tab when viewing the logs. | - | Optional |
| source | The source address for the query. | - | Optional |
| destination | The destination address for the query. | - | Optional |
| receive_time | The start time for the query. For example, YYYY/MM/DD HH:MM:SS. | - |Optional |
| application | The application for the query. | - |Optional |
| to_port | The destination port for the query. | - | Optional |
| action | The action for the query. | allow |Optional |

## Playbook Outputs
---
There are no outputs for this playbook.

## Playbook Image
---
![PanoramaQueryTrafficLogs](https://raw.githubusercontent.com/demisto/content/1bdd5229392bd86f0cc58265a24df23ee3f7e662/docs/images/playbooks/PanoramaQueryTrafficLogs.png)
