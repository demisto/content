# HarfangLab EDR connector

HarfangLab EDR provides a connector with Palo Alto Cortex XSOAR, providing: 
  * 60 commands to remotely manage the HarfangLab's EDR Manager
  * 1 alert type (**Hurukai alert**)
  * 1 specific layout (**Hurukai alert layout**) to provide the most relevant information to an analyst
  * 1 alert mapper (**Hurukai alert mapper**) to map a Hurukai alert into a XSOAR incident 
  * 1 alert management playbook (**Hurukai alert management**) to deal with security events that are periodically fetches from the HarfangLab EDR Manager
  * 20 subplaybooks dedicated to starting jobs, periodically checking their status and fetching their results once finished.

The following commands are implemented in the connector:

| Command name					| Description										|
|:----------------------------------------------|:--------------------------------------------------------------------------------------|
|harfanglab-assign-policy-to-agent|Assign a policy to an agent|
|harfanglab-change-security-event-status|Command used to change the status of a security event|
|harfanglab-deisolate-endpoint|Command used to deisolate an endpoint and reconnect it to the network|
|harfanglab-endpoint-search|Search for endpoint information from a hostname|
|harfanglab-get-endpoint-info|Get endpoint information from agent\_id|
|harfanglab-hunt-search-hash|Command used to search IOC in database|
|harfanglab-hunt-search-runned-process-hash|Command used to search runned process associated with Hash|
|harfanglab-hunt-search-running-process-hash|Command used to search running process associated with Hash|
|harfanglab-isolate-endpoint|Command used to isolate an endpoint from the network while remaining connected to the EDR manager|
|harfanglab-job-artifact-all|Start a job to download all artifacts from a host (Windows MFT, Hives, evt/evtx, Prefetch, USN, Linux logs and file list)|
|harfanglab-job-artifact-downloadfile|Start a job to download a file from a host (Windows / Linux)|
|harfanglab-job-artifact-evtx|Start a job to download the event logs from a host (Windows)|
|harfanglab-job-artifact-filesystem|Start a job to download Linux filesystem entries from a host (Linux)|
|harfanglab-job-artifact-hives|Start a job to download the hives from a host (Windows)|
|harfanglab-job-artifact-logs|Start a job to download Linux log files from a host (Linux)|
|harfanglab-job-artifact-mft|Start a job to download the MFT from a host (Windows)|
|harfanglab-job-artifact-ramdump|Start a job to get the entine RAM from a host (Windows / Linux)|
|harfanglab-job-driverlist|Start a job to get the list of drivers from a host (Windows)|
|harfanglab-job-info|Get job status information|
|harfanglab-job-ioc|Start a job to search for IOCs on a host (Windows / Linux)|
|harfanglab-job-list|Start a job to get the list of network connections from a host (Windows / Linux)|
|harfanglab-job-networkconnectionlist|Start a job to get the list of network connections from a host (Windows / Linux)|
|harfanglab-job-networksharelist|Start a job to get the list of network shares from a host (Windows)|
|harfanglab-job-persistencelist|Start a job to get the list of persistence items from a host (Linux)|
|harfanglab-job-pipelist|Start a job to get the list of pipes from a host (Windows)|
|harfanglab-job-prefetchlist|Start a job to get the list of prefetches from a host (Windows)|
|harfanglab-job-processlist|Start a job to get the list of processes from a host (Windows / Linux)|
|harfanglab-job-runkeylist|Start a job to get the list of run keys from a host (Windows)|
|harfanglab-job-scheduledtasklist|Start a job to get the list of scheduled tasks from a host (Windows)|
|harfanglab-job-servicelist|Start a job to get the list of services from a host (Windows)|
|harfanglab-job-sessionlist|Start a job to get the list of sessions from a host (Windows)|
|harfanglab-job-startuplist|Start a job to get the list of startup items from a host (Windows)|
|harfanglab-job-wmilist|Start a job to get the list of WMI items from a host (Windows)|
|harfanglab-result-artifact-all|Get all artifacts from a hostname from job results|
|harfanglab-result-artifact-downloadfile|Get a hostname's file from job results|
|harfanglab-result-artifact-evtx|Get a hostname's log files from job results|
|harfanglab-result-artifact-filesystem|Get a hostname's filesystem entries from job results|
|harfanglab-result-artifact-hives|Get a hostname's hives from job results|
|harfanglab-result-artifact-logs|Get a hostname's log files from job results|
|harfanglab-result-artifact-mft|Get a hostname's MFT from job results|
|harfanglab-result-artifact-ramdump|Get a hostname's RAM dump from job results|
|harfanglab-result-driverlist|Get a hostname's loaded drivers from job results|
|harfanglab-result-ioc|Get the list of items matching IOCs searched in an IOC job|
|harfanglab-result-networkconnectionlist|Get a hostname's network connections from job results|
|harfanglab-result-networksharelist|Get a hostname's network shares from job results|
|harfanglab-result-persistencelist|Get a hostname's persistence items from job results|
|harfanglab-result-pipelist|Get a hostname's list of pipes from job results|
|harfanglab-result-prefetchlist|Get a hostname's list of prefetches from job results|
|harfanglab-result-processlist|Get a hostname's list of processes from job results|
|harfanglab-result-runkeylist|Get a hostname's list of run keys from job results|
|harfanglab-result-scheduledtasklist|Get a hostname's list of scheduled tasks from job results|
|harfanglab-result-servicelist|Get a hostname's list of services from job results|
|harfanglab-result-sessionlist|Get a hostname's sessions from job results|
|harfanglab-result-startuplist|Get a hostname's startup items from job results|
|harfanglab-result-wmilist|Get a hostname's WMI items from job results|
|harfanglab-telemetry-binary|Search for binaries|
|harfanglab-telemetry-eventlog|Search event logs from a specific hostname|
|harfanglab-telemetry-network|Search network connections from a specific hostname|
|harfanglab-telemetry-processes|Search processes on a specific hostname|

The connector also allows to fetch security events from a HarfangLab EDR manager. It uses the following parameters:

  * **API URL**: HarfangLab EDR manager's URL
  * **API key**: API key to authenticate to the manager
  * **alert_type**: list of coma-separated alert types to fetch (such as _sigma, yara, hlai, vt, ransom, etc._)
  * **min_severity**: minimum severity of alerts to fetch (_Low, Medium, High, Critical_)
  * **alert_status**: fetches alert with an ACTIVE (new, investigating, probable false positive,...) or CLOSED (false positive, closed) status
  * **insecure**: indicates whether the certificate of the EDR manager should be verified
  * **proxy**: indicates whether to use the system proxy settings or to try to reach the API without using the proxy



