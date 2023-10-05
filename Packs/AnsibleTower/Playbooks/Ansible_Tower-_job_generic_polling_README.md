Generic polling playbook to launch a specific job template. Returns the job status when the job finishes running.

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* GenericPolling

### Integrations

* Ansible Automation Platform

### Scripts

This playbook does not use any scripts.

### Commands

* ansible-tower-job-launch
* ansible-tower-job-events-list-by-id
* ansible-tower-job-stdout

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| job_template_id | The job template id to launch.  |  | Required |
| credentials_id | Select the credentials that allows Tower to access the nodes this job will be run against \(if needed\). |  | Optional |
| Inventory_id | Select the inventory containing the hosts you want this job to manage \(if needed\). |  | Optional |
| extra_variables | Pass extra command line variables to the playbook \(if needed\). |  | Optional |
| show_output | Print output from the job that is running. | true | Optional |
| Interval | Polling frequency - how often the polling command should run \(in minutes\) | 1 | Optional |
| Timeout | How much time \(in minutes\) to wait before a timeout occurs. | 15 | Optional |
| return_job_events | Choose if you want to return the job's raw events | false | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| AnsibleAWX.Job.id | Job id | unknown |
| AnsibleAWX.Job.status | Job status | unknown |
| AnsibleAWX.JobStdout.content | job stdout | unknown |
| AnsibleAWX.JobEvents.stdout | Standard output of the job. | unknown |
| AnsibleAWX.JobEvents.type | Data type for this job event. | unknown |
| AnsibleAWX.JobEvents.id | Database ID for this job event. | unknown |
| AnsibleAWX.JobEvents.job | Job ID. | unknown |
| AnsibleAWX.JobEvents.host | Host ID associated with the event. | unknown |
| AnsibleAWX.JobEvents.task | Task name. | unknown |
| AnsibleAWX.JobEvents.start_line | Starting line number of the execution. | unknown |
| AnsibleAWX.JobEvents.end_line | Ending line number of the execution. | unknown |
| AnsibleAWX.JobEvents.event_data | Job event data. | unknown |

## Playbook Image

---

