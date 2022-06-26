The Engine API is an HTTP API served by Docker Engine. It is the API the Docker client uses to communicate with the Engine, so everything the Docker client can do can be done with the API.
This integration was integrated and tested with version xx of Docker Engine API

## Configure Docker Engine API on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Docker Engine API.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Required** |
    | --- | --- |
    | Server URL (e.g. https://www.example.com:1000) | True |
    | Docker Client Certificate | True |
    | Docker Client Private Key | True |
    | CA Certificate | False |
    | Trust any certificate (not secure) | False |
    | Use system proxy settings | False |
    | Registry Identity Token | False |
    | Registry Username | False |
    | Registry Password | False |
    | Registry Server Address (e.g. docker.io) | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### docker-build-prune
***
Delete builder cache


#### Base Command

`docker-build-prune`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| keep_storage | Amount of disk space in bytes to keep for cache. | Optional | 
| prune_all | Remove all types of build cache. | Optional | 
| filters | A JSON encoded value of the filters (a `map[string][]string`) to process on the list of build cache objects.  Available filters:  - `until= duration `: duration relative to daemon's time, during which build cache was not used, in Go's duration format (e.g., '24h') - `id= id ` - `parent= id ` - `type= string ` - `description= string ` - `inuse` - `shared` - `private` . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.BuildPruneResponse.SpaceReclaimed | Number | Disk space reclaimed in bytes | 

### docker-config-create
***
Create a config


#### Base Command

`docker-config-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| configspec_name | User-defined name of the config. | Optional | 
| configspec_labels | User-defined key/value metadata. | Optional | 
| configspec_data | Base64-url-safe-encoded ([RFC 4648](https://tools.ietf.org/html/rfc4648#section-5)) config data. . | Optional | 
| configspec_templating_Name | configspec_templating Name. | Optional | 
| configspec_templating_Options | configspec_templating Options. | Optional | 


#### Context Output

There is no context output for this command.
### docker-config-inspect
***
Inspect a config


#### Base Command

`docker-config-inspect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the config. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Config.ID | String | Docker Config ID | 
| Docker.Config.CreatedAt | String | Docker Config CreatedAt | 
| Docker.Config.UpdatedAt | String | Docker Config UpdatedAt | 

### docker-config-list
***
List configs


#### Base Command

`docker-config-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | A JSON encoded value of the filters . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Config.ID | String | Docker Config ID | 
| Docker.Config.CreatedAt | String | Docker Config CreatedAt | 
| Docker.Config.UpdatedAt | String | Docker Config UpdatedAt | 

### docker-container-changes
***
Get changes on a container’s filesystem


#### Base Command

`docker-container-changes`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID or name of the container. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ContainerChangeResponseItem.Path | String | Path to file that has changed | 
| Docker.ContainerChangeResponseItem.Kind | Number | Kind of change | 

### docker-container-create
***
Create a container


#### Base Command

`docker-container-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Assign the specified name to the container. Must match `/?[a-zA-Z0-9][a-zA-Z0-9_.-]+`. . | Optional | 
| containerconfig_hostname | The hostname to use for the container, as a valid RFC 1123 hostname. | Optional | 
| containerconfig_domainname | The domain name to use for the container. | Optional | 
| containerconfig_user | The user that commands are run as inside the container. | Optional | 
| containerconfig_attachstdin | Whether to attach to `stdin`. | Optional | 
| containerconfig_attachstdout | Whether to attach to `stdout`. | Optional | 
| containerconfig_attachstderr | Whether to attach to `stderr`. | Optional | 
| containerconfig_exposedports | An object mapping ports to an empty object in the form:  `{" port / tcp\|udp\|sctp ": {}}` . | Optional | 
| containerconfig_tty | Attach standard streams to a TTY, including `stdin` if it is not closed. . | Optional | 
| containerconfig_openstdin | Open `stdin`. | Optional | 
| containerconfig_stdinonce | Close `stdin` after one attached client disconnects. | Optional | 
| containerconfig_env | A list of environment variables to set inside the container in the form `["VAR=value", ...]`. A variable without `=` is removed from the environment, rather than to have an empty value. . | Optional | 
| containerconfig_cmd | Command to run specified as a string or an array of strings. . | Optional | 
| containerconfig_healthcheck_Test | containerconfig_healthcheck Test. | Optional | 
| containerconfig_healthcheck_Interval | containerconfig_healthcheck Interval. | Optional | 
| containerconfig_healthcheck_Timeout | containerconfig_healthcheck Timeout. | Optional | 
| containerconfig_healthcheck_Retries | containerconfig_healthcheck Retries. | Optional | 
| containerconfig_healthcheck_StartPeriod | containerconfig_healthcheck StartPeriod. | Optional | 
| containerconfig_argsescaped | Command is already escaped (Windows only). | Optional | 
| containerconfig_image | The name of the image to use when creating the container/ . | Optional | 
| containerconfig_volumes | An object mapping mount point paths inside the container to empty objects. . | Optional | 
| containerconfig_workingdir | The working directory for commands to run in. | Optional | 
| containerconfig_entrypoint | The entry point for the container as a string or an array of strings.  If the array consists of exactly one empty string (`[""]`) then the entry point is reset to system default (i.e., the entry point used by docker when there is no `ENTRYPOINT` instruction in the `Dockerfile`). . | Optional | 
| containerconfig_networkdisabled | Disable networking for the container. | Optional | 
| containerconfig_macaddress | MAC address of the container. | Optional | 
| containerconfig_onbuild | `ONBUILD` metadata that were defined in the image's `Dockerfile`. . | Optional | 
| containerconfig_labels | User-defined key/value metadata. | Optional | 
| containerconfig_stopsignal | Signal to stop a container as a string or unsigned integer. . | Optional | 
| containerconfig_stoptimeout | Timeout to stop a container in seconds. | Optional | 
| containerconfig_shell | Shell for when `RUN`, `CMD`, and `ENTRYPOINT` uses a shell. . | Optional | 
| hostconfig_binds | A list of volume bindings for this container. | Optional | 
| hostconfig_containeridfile | Path to a file where the container ID is written. | Optional | 
| hostconfig_logconfig_Type | hostconfig_logconfig Type. | Optional | 
| hostconfig_logconfig_Config | Log Config. | Optional | 
| hostconfig_networkmode | Network mode to use for this container. | Optional | 
| hostconfig_portbindings | hostconfig port bindings. | Optional | 
| hostconfig_restartpolicy_Name | hostconfig_restartpolicy Name. | Optional | 
| hostconfig_restartpolicy_MaximumRetryCount | hostconfig_restartpolicy MaximumRetryCount. | Optional | 
| hostconfig_autoremove | Automatically remove the container when the container's process exits. This has no effect if `RestartPolicy` is set. . | Optional | 
| hostconfig_volumedriver | Driver that this container uses to mount volumes. | Optional | 
| hostconfig_volumesfrom | A list of volumes to inherit from another container. | Optional | 
| hostconfig_mounts | Specification for mounts to be added to the container. . | Optional | 
| hostconfig_capadd | A list of kernel capabilities to add to the container. Conflicts with option 'Capabilities'. . | Optional | 
| hostconfig_capdrop | A list of kernel capabilities to drop from the container. Conflicts with option 'Capabilities'. . | Optional | 
| hostconfig_cgroupnsmode | cgroup namespace mode for the container. Possible values are:  - `"private"`: the container runs in its own private cgroup namespace - `"host"`: use the host system's cgroup namespace  If not specified, the daemon default is used, which can either be `"private"` or `"host"`, depending on daemon version, kernel support and configuration. . Possible values are: private, host. | Optional | 
| hostconfig_dns | A list of DNS servers for the container to use. | Optional | 
| hostconfig_dnsoptions | A list of DNS options. | Optional | 
| hostconfig_dnssearch | A list of DNS search domains. | Optional | 
| hostconfig_extrahosts | A list of hostnames/IP mappings to add to the container's `/etc/hosts` file. Specified in the form `["hostname:IP"]`. . | Optional | 
| hostconfig_groupadd | A list of additional groups that the container process will run as. . | Optional | 
| hostconfig_ipcmode | IPC sharing mode for the container. Possible values are:  - `"none"`: own private IPC namespace, with /dev/shm not mounted - `"private"`: own private IPC namespace - `"shareable"`: own private IPC namespace, with a possibility to share it with other containers - `"container: name\|id "`: join another (shareable) container's IPC namespace - `"host"`: use the host system's IPC namespace  If not specified, daemon default is used, which can either be `"private"` or `"shareable"`, depending on daemon version and configuration. . | Optional | 
| hostconfig_cgroup | Cgroup to use for the container. | Optional | 
| hostconfig_links | A list of links for the container in the form `container_name:alias`. . | Optional | 
| hostconfig_oomscoreadj | An integer value containing the score given to the container in order to tune OOM killer preferences. . | Optional | 
| hostconfig_pidmode | Set the PID (Process) Namespace mode for the container. It can be either:  - `"container: name\|id "`: joins another container's PID namespace - `"host"`: use the host's PID namespace inside the container . | Optional | 
| hostconfig_privileged | Gives the container full access to the host. | Optional | 
| hostconfig_publishallports | Allocates an ephemeral host port for all of a container's exposed ports.  Ports are de-allocated when the container stops and allocated when the container starts. The allocated port might be changed when restarting the container.  The port is selected from the ephemeral port range that depends on the kernel. For example, on Linux the range is defined by `/proc/sys/net/ipv4/ip_local_port_range`. . | Optional | 
| hostconfig_readonlyrootfs | Mount the container's root filesystem as read only. | Optional | 
| hostconfig_securityopt | A list of string values to customize labels for MLS systems, such as SELinux. | Optional | 
| hostconfig_storageopt | Storage driver options for this container, in the form `{"size": "120G"}`. . | Optional | 
| hostconfig_tmpfs | A map of container directories which should be replaced by tmpfs mounts, and their corresponding mount options. For example:  ``` { "/run": "rw,noexec,nosuid,size=65536k" } ``` . | Optional | 
| hostconfig_utsmode | UTS namespace to use for the container. | Optional | 
| hostconfig_usernsmode | Sets the usernamespace mode for the container when usernamespace remapping option is enabled. . | Optional | 
| hostconfig_shmsize | Size of `/dev/shm` in bytes. If omitted, the system uses 64MB. . | Optional | 
| hostconfig_sysctls | A list of kernel  meters (sysctls) to set in the container. For example:  ``` {"net.ipv4.ip_forward": "1"} ``` . | Optional | 
| hostconfig_runtime | Runtime to use with this container. | Optional | 
| hostconfig_consolesize | Initial console size, as an `[height, width]` array. (Windows only) . | Optional | 
| hostconfig_isolation | Isolation technology of the container. (Windows only) . Possible values are: default, process, hyperv. | Optional | 
| hostconfig_maskedpaths | The list of paths to be masked inside the container (this overrides the default set of paths). . | Optional | 
| hostconfig_readonlypaths | The list of paths to be set as read-only inside the container (this overrides the default set of paths). . | Optional | 
| networkingconfig_endpointsconfig | A mapping of network name to endpoint configuration for that network. . | Optional | 


#### Context Output

There is no context output for this command.
#### Command example
```!docker-container-create name="hello-docker" containerconfig_image="alpine:latest"```
#### Context Example
```json
{
    "Docker": {
        "Id": "29d287878de866198541bcb4f58391cbd45a3415f899ed0c59d90134d9fb442e",
        "Warnings": []
    }
}
```

#### Human Readable Output

>### Results
>|Id|Warnings|
>|---|---|
>| 29d287878de866198541bcb4f58391cbd45a3415f899ed0c59d90134d9fb442e |  |


### docker-container-inspect
***
Inspect a container


#### Base Command

`docker-container-inspect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID or name of the container. | Required | 
| size | Return the size of container as fields `SizeRw` and `SizeRootFs`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ContainerInspectResponse.Id | String | The ID of the container | 
| Docker.ContainerInspectResponse.Created | String | The time the container was created | 
| Docker.ContainerInspectResponse.Path | String | The path to the command being run | 
| Docker.ContainerInspectResponse.Image | String | The container's image ID | 
| Docker.ContainerInspectResponse.ResolvConfPath | String | Docker ContainerInspectResponse ResolvConfPath | 
| Docker.ContainerInspectResponse.HostnamePath | String | Docker ContainerInspectResponse HostnamePath | 
| Docker.ContainerInspectResponse.HostsPath | String | Docker ContainerInspectResponse HostsPath | 
| Docker.ContainerInspectResponse.LogPath | String | Docker ContainerInspectResponse LogPath | 
| Docker.ContainerInspectResponse.Name | String | Docker ContainerInspectResponse Name | 
| Docker.ContainerInspectResponse.RestartCount | Number | Docker ContainerInspectResponse RestartCount | 
| Docker.ContainerInspectResponse.Driver | String | Docker ContainerInspectResponse Driver | 
| Docker.ContainerInspectResponse.Platform | String | Docker ContainerInspectResponse Platform | 
| Docker.ContainerInspectResponse.MountLabel | String | Docker ContainerInspectResponse MountLabel | 
| Docker.ContainerInspectResponse.ProcessLabel | String | Docker ContainerInspectResponse ProcessLabel | 
| Docker.ContainerInspectResponse.AppArmorProfile | String | Docker ContainerInspectResponse AppArmorProfile | 
| Docker.ContainerInspectResponse.SizeRw | Number | The size of files that have been created or changed by this container.  | 
| Docker.ContainerInspectResponse.SizeRootFs | Number | The total size of all the files in this container. | 
| Docker.ContainerInspectResponse.Mounts.Type | String | Docker ContainerInspectResponse Mounts Type | 
| Docker.ContainerInspectResponse.Mounts.Name | String | Docker ContainerInspectResponse Mounts Name | 
| Docker.ContainerInspectResponse.Mounts.Source | String | Docker ContainerInspectResponse Mounts Source | 
| Docker.ContainerInspectResponse.Mounts.Destination | String | Docker ContainerInspectResponse Mounts Destination | 
| Docker.ContainerInspectResponse.Mounts.Driver | String | Docker ContainerInspectResponse Mounts Driver | 
| Docker.ContainerInspectResponse.Mounts.Mode | String | Docker ContainerInspectResponse Mounts Mode | 
| Docker.ContainerInspectResponse.Mounts.RW | Boolean | Docker ContainerInspectResponse Mounts RW | 
| Docker.ContainerInspectResponse.Mounts.Propagation | String | Docker ContainerInspectResponse Mounts Propagation | 

### docker-container-list
***
List containers


#### Base Command

`docker-container-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_all | Return all containers. By default, only running containers are shown. . | Optional | 
| limit | Return this number of most recently created containers, including non-running ones. . | Optional | 
| size | Return the size of container as fields `SizeRw` and `SizeRootFs`. . | Optional | 
| filters | Filters to process on the container list, encoded as JSON (a `map[string][]string`). For example, `{"status": ["paused"]}` will only return paused containers.  Available filters:  - `ancestor`=(` image-name [: tag ]`, ` image id `, or ` image@digest `) - `before`=(` container id ` or ` container name `) - `expose`=(` port [/ proto ]`\|` startport-endport /[ proto ]`) - `exited= int ` containers with exit code of ` int ` - `health`=(`starting`\|`healthy`\|`unhealthy`\|`none`) - `id= ID ` a container's ID - `isolation=`(`default`\|`process`\|`hyperv`) (Windows daemon only) - `is-task=`(`true`\|`false`) - `label=key` or `label="key=value"` of a container label - `name= name ` a container's name - `network`=(` network id ` or ` network name `) - `publish`=(` port [/ proto ]`\|` startport-endport /[ proto ]`) - `since`=(` container id ` or ` container name `) - `status=`(`created`\|`restarting`\|`running`\|`removing`\|`paused`\|`exited`\|`dead`) - `volume`=(` volume name ` or ` mount point destination `) . | Optional | 


#### Context Output

There is no context output for this command.
### docker-container-stats
***
Get container stats based on resource usage


#### Base Command

`docker-container-stats`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID or name of the container. | Required | 
| stream | Stream the output. If false, the stats will be output once and then it will disconnect. . | Optional | 
| one_shot | Only get a single stat instead of waiting for 2 cycles. Must be used with `stream=false`. . | Optional | 


#### Context Output

There is no context output for this command.
### docker-container-top
***
List processes running inside a container


#### Base Command

`docker-container-top`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID or name of the container. | Required | 
| ps_args | The arguments to pass to `ps`. For example, `aux`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ContainerTopResponse.Processes | String | Docker ContainerTopResponse Processes | 

### docker-image-history
***
Get the history of an image


#### Base Command

`docker-image-history`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Image name or ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.HistoryResponseItem.Id | String | Docker HistoryResponseItem Id | 
| Docker.HistoryResponseItem.Created | Number | Docker HistoryResponseItem Created | 
| Docker.HistoryResponseItem.CreatedBy | String | Docker HistoryResponseItem CreatedBy | 
| Docker.HistoryResponseItem.Size | Number | Docker HistoryResponseItem Size | 
| Docker.HistoryResponseItem.Comment | String | Docker HistoryResponseItem Comment | 

### docker-image-inspect
***
Inspect an image


#### Base Command

`docker-image-inspect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Image name or id. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Image.Id | String | Docker Image ID | 
| Docker.Image.Parent | String | Docker Image Parent | 
| Docker.Image.Comment | String | Docker Image Comment | 
| Docker.Image.Created | String | Docker Image Created | 
| Docker.Image.Container | String | Docker Image Container | 
| Docker.Image.DockerVersion | String | Docker Image DockerVersion | 
| Docker.Image.Author | String | Docker Image Author | 
| Docker.Image.Architecture | String | Docker Image Architecture | 
| Docker.Image.Os | String | Docker Image Os | 
| Docker.Image.OsVersion | String | Docker Image OsVersion | 
| Docker.Image.Size | Number | Docker Image Size | 
| Docker.Image.VirtualSize | Number | Docker Image VirtualSize | 

### docker-image-list
***
List Images


#### Base Command

`docker-image-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| list_all | Show all images. Only images from a final layer (no children) are shown by default. | Optional | 
| filters | A JSON encoded value of the filters. | Optional | 
| digests | Show digest information as a `RepoDigests` field on each image. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ImageSummary.Id | String | Docker Image Summary ID | 
| Docker.ImageSummary.ParentId | String | Docker Image Summary ParentId | 
| Docker.ImageSummary.Created | Number | Docker Image Summary Created | 
| Docker.ImageSummary.Size | Number | Docker Image Summary Size | 
| Docker.ImageSummary.SharedSize | Number | Docker Image Summary SharedSize | 
| Docker.ImageSummary.VirtualSize | Number | Docker Image Summary VirtualSize | 
| Docker.ImageSummary.Containers | Number | Docker Image Summary Containers | 

### docker-image-prune
***
Delete unused images


#### Base Command

`docker-image-prune`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | Filters to process on the prune list. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ImagePruneResponse.ImagesDeleted.Untagged | String | The image ID of an image that was untagged | 
| Docker.ImagePruneResponse.ImagesDeleted.Deleted | String | The image ID of an image that was deleted | 
| Docker.ImagePruneResponse.SpaceReclaimed | Number | Disk space reclaimed in bytes | 

### docker-image-search
***
Search images


#### Base Command

`docker-image-search`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| term | Term to search. | Required | 
| limit | Maximum number of results to return. | Optional | 
| filters | A JSON encoded value of the filters (a `map[string][]string`) to process on the images list. Available filters:  - `is-automated=(true\|false)` - `is-official=(true\|false)` - `stars= number ` Matches images that has at least 'number' stars. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ImageSearchResponseItem.description | String | Docker ImageSearchResponseItem description | 
| Docker.ImageSearchResponseItem.is_official | Boolean | Docker ImageSearchResponseItem is_official | 
| Docker.ImageSearchResponseItem.is_automated | Boolean | Docker ImageSearchResponseItem is_automated | 
| Docker.ImageSearchResponseItem.name | String | Docker ImageSearchResponseItem name | 
| Docker.ImageSearchResponseItem.star_count | Number | Docker ImageSearchResponseItem star_count | 

### docker-network-create
***
Create a network


#### Base Command

`docker-network-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| networkconfig_name | The network's name. | Required | 
| networkconfig_checkduplicate | Check for networks with duplicate names. Since Network is primarily keyed based on a random ID and not on the name, and network name is strictly a user-friendly alias to the network which is uniquely identified using ID, there is no guaranteed way to check for duplicates. CheckDuplicate is there to provide a best effort checking of any networks which has the same name but it is not guaranteed to catch all name collisions. . | Optional | 
| networkconfig_driver | Name of the network driver plugin to use. | Optional | 
| networkconfig_internal | Restrict external access to the network. | Optional | 
| networkconfig_attachable | Globally scoped network is manually attachable by regular containers from workers in swarm mode. . | Optional | 
| networkconfig_ingress | Ingress network is the network which provides the routing-mesh in swarm mode. . | Optional | 
| networkconfig_ipam_Driver | networkconfig_ipam Driver. | Optional | 
| networkconfig_ipam_Config | networkconfig_ipam Config. | Optional | 
| networkconfig_ipam_Options | networkconfig_ipam Options. | Optional | 
| networkconfig_enableipv6 | Enable IPv6 on the network. | Optional | 
| networkconfig_options | Network specific options to be used by the drivers. | Optional | 
| networkconfig_labels | User-defined key/value metadata. | Optional | 


#### Context Output

There is no context output for this command.
### docker-network-list
***
List networks


#### Base Command

`docker-network-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | JSON encoded value of the filters  . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Network.Name | String | Docker Network Name | 
| Docker.Network.Id | String | Docker Network Id | 
| Docker.Network.Created | String | Docker Network Created | 
| Docker.Network.Scope | String | Docker Network Scope | 
| Docker.Network.Driver | String | Docker Network Driver | 
| Docker.Network.EnableIPv6 | Boolean | Docker Network EnableIPv6 | 
| Docker.Network.Internal | Boolean | Docker Network Internal | 
| Docker.Network.Attachable | Boolean | Docker Network Attachable | 
| Docker.Network.Ingress | Boolean | Docker Network Ingress | 
| Docker.Network.Containers.Name | String | Docker Network Containers Name | 
| Docker.Network.Containers.EndpointID | String | Docker Network Containers EndpointID | 
| Docker.Network.Containers.MacAddress | String | Docker Network Containers MacAddress | 
| Docker.Network.Containers.IPv4Address | String | Docker Network Containers IPv4Address | 
| Docker.Network.Containers.IPv6Address | String | Docker Network Containers IPv6Address | 

### docker-network-prune
***
Delete unused networks


#### Base Command

`docker-network-prune`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | Filters to process on the prune list. . | Optional | 


#### Context Output

There is no context output for this command.
### docker-node-inspect
***
Inspect a node


#### Base Command

`docker-node-inspect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | The ID or name of the node. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Node.ID | String | Docker Node ID | 
| Docker.Node.CreatedAt | String | Date and time at which the node was added to the swarm in \[RFC 3339\]\(https://www.ietf.org/rfc/rfc3339.txt\) format with nano-seconds.  | 
| Docker.Node.UpdatedAt | String | Date and time at which the node was last updated in \[RFC 3339\]\(https://www.ietf.org/rfc/rfc3339.txt\) format with nano-seconds.  | 

### docker-node-list
***
List nodes


#### Base Command

`docker-node-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | Filters to process on the nodes list, encoded as JSON (a `map[string][]string`).  Available filters: - `id= node id ` - `label= engine label ` - `membership=`(`accepted`\|`pending`)` - `name= node name ` - `node.label= node label ` - `role=`(`manager`\|`worker`)` . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Node.ID | String | Docker Node ID | 
| Docker.Node.CreatedAt | String | Date and time at which the node was added to the swarm in \[RFC 3339\]\(https://www.ietf.org/rfc/rfc3339.txt\) format with nano-seconds.  | 
| Docker.Node.UpdatedAt | String | Date and time at which the node was last updated in \[RFC 3339\]\(https://www.ietf.org/rfc/rfc3339.txt\) format with nano-seconds.  | 

### docker-secret-create
***
Create a secret


#### Base Command

`docker-secret-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secretspec_name | User-defined name of the secret. | Optional | 
| secretspec_labels | User-defined key/value metadata. | Optional | 
| secretspec_data | Base64-url-safe-encoded ([RFC 4648](https://tools.ietf.org/html/rfc4648#section-5)) data to store as secret.  This field is only used to _create_ a secret, and is not returned by other endpoints. . | Optional | 
| secretspec_driver_Name | secretspec_driver Name. | Optional | 
| secretspec_driver_Options | secretspec_driver Options. | Optional | 
| secretspec_templating_Name | secretspec_templating Name. | Optional | 
| secretspec_templating_Options | secretspec_templating Options. | Optional | 


#### Context Output

There is no context output for this command.
### docker-secret-inspect
***
Inspect a secret


#### Base Command

`docker-secret-inspect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID of the secret. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Secret.ID | String | Docker Secret ID | 
| Docker.Secret.CreatedAt | String | Docker Secret CreatedAt | 
| Docker.Secret.UpdatedAt | String | Docker Secret UpdatedAt | 

### docker-secret-list
***
List secrets


#### Base Command

`docker-secret-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | A JSON encoded value of the filters (a `map[string][]string`) to process on the secrets list.  Available filters:  - `id= secret id ` - `label= key  or label= key =value` - `name= secret name ` - `names= secret name ` . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Secret.ID | String | Docker Secret ID | 
| Docker.Secret.CreatedAt | String | Docker Secret CreatedAt | 
| Docker.Secret.UpdatedAt | String | Docker Secret UpdatedAt | 

### docker-swarm-init
***
Initialize a new swarm


#### Base Command

`docker-swarm-init`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| listenaddr | Listen address used for inter-manager communication, as well as determining the networking interface used for the VXLAN Tunnel Endpoint (VTEP). This can either be an address/port combination in the form `192.168.1.1:4567`, or an interface followed by a port number, like `eth0:4567`. If the port number is omitted, the default swarm listening port is used. . | Optional | 
| advertiseaddr | Externally reachable address advertised to other nodes. This can either be an address/port combination in the form `192.168.1.1:4567`, or an interface followed by a port number, like `eth0:4567`. If the port number is omitted, the port number from the listen address is used. If `AdvertiseAddr` is not specified, it will be automatically detected when possible. . | Optional | 
| datapathaddr | Address or interface to use for data path traffic (format: ` ip\|interface `), for example,  `192.168.1.1`, or an interface, like `eth0`. If `DataPathAddr` is unspecified, the same address as `AdvertiseAddr` is used.  The `DataPathAddr` specifies the address that global scope network drivers will publish towards other  nodes in order to reach the containers running on this node. Using this  meter it is possible to se te the container data traffic from the management traffic of the cluster. . | Optional | 
| datapathport | DataPathPort specifies the data path port number for data traffic. Acceptable port range is 1024 to 49151. if no port is set or is set to 0, default port 4789 will be used. . | Optional | 
| defaultaddrpool | Default Address Pool specifies default subnet pools for global scope networks. . | Optional | 
| forcenewcluster | Force creation of a new swarm. | Optional | 
| subnetsize | SubnetSize specifies the subnet size of the networks created from the default subnet pool. . | Optional | 
| spec_Name | spec Name. | Optional | 
| spec_Labels | spec Labels. | Optional | 
| spec_Orchestration | spec Orchestration. | Optional | 
| spec_Raft | spec Raft. | Optional | 
| spec_Dispatcher | spec Dispatcher. | Optional | 
| spec_CAConfig | spec CAConfig. | Optional | 
| spec_EncryptionConfig | spec EncryptionConfig. | Optional | 
| spec_TaskDefaults | spec TaskDefaults. | Optional | 


#### Context Output

There is no context output for this command.
### docker-swarm-inspect
***
Inspect swarm


#### Base Command

`docker-swarm-inspect`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.
### docker-swarm-join
***
Join an existing swarm


#### Base Command

`docker-swarm-join`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| listenaddr | Listen address used for inter-manager communication if the node gets promoted to manager, as well as determining the networking interface used for the VXLAN Tunnel Endpoint (VTEP). . | Optional | 
| advertiseaddr | Externally reachable address advertised to other nodes. This can either be an address/port combination in the form `192.168.1.1:4567`, or an interface followed by a port number, like `eth0:4567`. If the port number is omitted, the port number from the listen address is used. If `AdvertiseAddr` is not specified, it will be automatically detected when possible. . | Optional | 
| datapathaddr | Address or interface to use for data path traffic (format: ` ip\|interface `), for example,  `192.168.1.1`, or an interface, like `eth0`. If `DataPathAddr` is unspecified, the same address as `AdvertiseAddr` is used.  The `DataPathAddr` specifies the address that global scope network drivers will publish towards other nodes in order to reach the containers running on this node. Using this  meter it is possible to se te the container data traffic from the management traffic of the cluster. . | Optional | 
| remoteaddrs | Addresses of manager nodes already participating in the swarm. . | Optional | 
| jointoken | Secret token for joining this swarm. | Optional | 


#### Context Output

There is no context output for this command.
### docker-swarm-leave
***
Leave a swarm


#### Base Command

`docker-swarm-leave`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| force | Force leave swarm, even if this is the last manager or that it will  eak the cluster. . | Optional | 


#### Context Output

There is no context output for this command.
### docker-swarm-unlock
***
Unlock a locked manager


#### Base Command

`docker-swarm-unlock`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| unlockkey | The swarm's unlock key. | Optional | 


#### Context Output

There is no context output for this command.
### docker-swarm-unlockkey
***
Get the unlock key


#### Base Command

`docker-swarm-unlockkey`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.UnlockKeyResponse.UnlockKey | String | The swarm's unlock key. | 

### docker-system-data-usage
***
Get data usage information


#### Base Command

`docker-system-data-usage`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.SystemDataUsageResponse.LayersSize | Number | Docker SystemDataUsageResponse LayersSize | 
| Docker.SystemDataUsageResponse.Images.Id | String | Docker SystemDataUsageResponse Images ID | 
| Docker.SystemDataUsageResponse.Images.ParentId | String | Docker SystemDataUsageResponse Images ParentId | 
| Docker.SystemDataUsageResponse.Images.Created | Number | Docker SystemDataUsageResponse Images Created | 
| Docker.SystemDataUsageResponse.Images.Size | Number | Docker SystemDataUsageResponse Images Size | 
| Docker.SystemDataUsageResponse.Images.SharedSize | Number | Docker SystemDataUsageResponse Images SharedSize | 
| Docker.SystemDataUsageResponse.Images.VirtualSize | Number | Docker SystemDataUsageResponse Images VirtualSize | 
| Docker.SystemDataUsageResponse.Images.Containers | Number | Docker SystemDataUsageResponse Images Containers | 
| Docker.SystemDataUsageResponse.Volumes.Name | String | Name of the volume. | 
| Docker.SystemDataUsageResponse.Volumes.Driver | String | Name of the volume driver used by the volume. | 
| Docker.SystemDataUsageResponse.Volumes.Mountpoint | String | Mount path of the volume on the host. | 
| Docker.SystemDataUsageResponse.Volumes.CreatedAt | String | Date/Time the volume was created. | 
| Docker.SystemDataUsageResponse.Volumes.Scope | String | The level at which the volume exists. Either \`global\` for cluster-wide, or \`local\` for machine level.  | 
| Docker.SystemDataUsageResponse.BuildCache.ID | String | Docker SystemDataUsageResponse BuildCache ID | 
| Docker.SystemDataUsageResponse.BuildCache.Parent | String | Docker SystemDataUsageResponse BuildCache Parent | 
| Docker.SystemDataUsageResponse.BuildCache.Type | String | Docker SystemDataUsageResponse BuildCache Type | 
| Docker.SystemDataUsageResponse.BuildCache.Description | String | Docker SystemDataUsageResponse BuildCache Description | 
| Docker.SystemDataUsageResponse.BuildCache.InUse | Boolean | Docker SystemDataUsageResponse BuildCache InUse | 
| Docker.SystemDataUsageResponse.BuildCache.Shared | Boolean | Docker SystemDataUsageResponse BuildCache Shared | 
| Docker.SystemDataUsageResponse.BuildCache.Size | Number | Amount of disk space used by the build cache \(in bytes\).  | 
| Docker.SystemDataUsageResponse.BuildCache.CreatedAt | String | Date and time at which the build cache was created in \[RFC 3339\]\(https://www.ietf.org/rfc/rfc3339.txt\) format with nano-seconds.  | 
| Docker.SystemDataUsageResponse.BuildCache.LastUsedAt | String | Date and time at which the build cache was last used in \[RFC 3339\]\(https://www.ietf.org/rfc/rfc3339.txt\) format with nano-seconds.  | 
| Docker.SystemDataUsageResponse.BuildCache.UsageCount | Number | Docker SystemDataUsageResponse BuildCache UsageCount. | 

### docker-system-info
***
Get system information


#### Base Command

`docker-system-info`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.SystemInfo.ID | String | Unique identifier of the daemon.   p    /  /p       Note  : The format of the ID itself is not part of the API, and   should not be considered stable.  | 
| Docker.SystemInfo.Containers | Number | Total number of containers on the host. | 
| Docker.SystemInfo.ContainersRunning | Number | Number of containers with status \`"running"\`.  | 
| Docker.SystemInfo.ContainersPaused | Number | Number of containers with status \`"paused"\`.  | 
| Docker.SystemInfo.ContainersStopped | Number | Number of containers with status \`"stopped"\`.  | 
| Docker.SystemInfo.Images | Number | Total number of images on the host.  Both \_tagged\_ and \_untagged\_ \(dangling\) images are counted.  | 
| Docker.SystemInfo.Driver | String | Name of the storage driver in use. | 
| Docker.SystemInfo.DriverStatus | String | Status of the storage driver in use. | 
| Docker.SystemInfo.DockerRootDir | String | Root directory of persistent Docker state.  Defaults to \`/var/lib/docker\` on Linux, and \`C:\\ProgramData\\docker\` on Windows.  | 
| Docker.SystemInfo.MemoryLimit | Boolean | Indicates if the host has memory limit support enabled. | 
| Docker.SystemInfo.SwapLimit | Boolean | Indicates if the host has memory swap limit support enabled. | 
| Docker.SystemInfo.KernelMemory | Boolean | Indicates if the host has kernel memory limit support enabled.   p    /  /p       Deprecated  : This field is deprecated as the kernel 5.4 deprecated   \`kmem.limit_in_bytes\`.  | 
| Docker.SystemInfo.CpuCfsPeriod | Boolean | Indicates if CPU CFS\(Completely Fair Scheduler\) period is supported by the host.  | 
| Docker.SystemInfo.CpuCfsQuota | Boolean | Indicates if CPU CFS\(Completely Fair Scheduler\) quota is supported by the host.  | 
| Docker.SystemInfo.CPUShares | Boolean | Indicates if CPU Shares limiting is supported by the host.  | 
| Docker.SystemInfo.CPUSet | Boolean | Indicates if CPUsets \(cpuset.cpus, cpuset.mems\) are supported by the host.  See \[cpuset\(7\)\]\(https://www.kernel.org/doc/Documentation/cgroup-v1/cpusets.txt\)  | 
| Docker.SystemInfo.PidsLimit | Boolean | Indicates if the host kernel has PID limit support enabled. | 
| Docker.SystemInfo.OomKillDisable | Boolean | Indicates if OOM killer disable is supported on the host. | 
| Docker.SystemInfo.IPv4Forwarding | Boolean | Indicates IPv4 forwarding is enabled. | 
| Docker.SystemInfo.BridgeNfIptables | Boolean | Indicates if \` idge-nf-call-iptables\` is available on the host. | 
| Docker.SystemInfo.BridgeNfIp6tables | Boolean | Indicates if \` idge-nf-call-ip6tables\` is available on the host. | 
| Docker.SystemInfo.Debug | Boolean | Indicates if the daemon is running in debug-mode / with debug-level logging enabled.  | 
| Docker.SystemInfo.NFd | Number | The total number of file Descriptors in use by the daemon process.  This information is only returned if debug-mode is enabled.  | 
| Docker.SystemInfo.NGoroutines | Number | The  number of goroutines that currently exist.  This information is only returned if debug-mode is enabled.  | 
| Docker.SystemInfo.SystemTime | String | Current system-time in \[RFC 3339\]\(https://www.ietf.org/rfc/rfc3339.txt\) format with nano-seconds.  | 
| Docker.SystemInfo.LoggingDriver | String | The logging driver to use as a default for new containers.  | 
| Docker.SystemInfo.CgroupDriver | String | The driver to use for managing cgroups.  | 
| Docker.SystemInfo.CgroupVersion | String | The version of the cgroup.  | 
| Docker.SystemInfo.NEventsListener | Number | Number of event listeners subscribed. | 
| Docker.SystemInfo.KernelVersion | String | Kernel version of the host.  On Linux, this information obtained from \`uname\`. On Windows this information is queried from the  kbd HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\ /kbd  registry value, for example _"10.0 14393 \(14393.1198.amd64fre.rs1_release_sec.170427-1353\)"_.  | 
| Docker.SystemInfo.OperatingSystem | String | Name of the host's operating system, for example: "Ubuntu 16.04.2 LTS" or "Windows Server 2016 Datacenter"  | 
| Docker.SystemInfo.OSVersion | String | Version of the host's operating system   p    /  /p       Note  : The information returned in this field, including its   very existence, and the formatting of values, should not be considered   stable, and may change without notice.  | 
| Docker.SystemInfo.OSType | String | Generic type of the operating system of the host, as returned by the Go runtime \(\`GOOS\`\).  Currently returned values are "linux" and "windows". A full list of possible values can be found in the \[Go documentation\]\(https://golang.org/doc/install/source\#environment\).  | 
| Docker.SystemInfo.Architecture | String | Hardware architecture of the host, as returned by the Go runtime \(\`GOARCH\`\).  A full list of possible values can be found in the \[Go documentation\]\(https://golang.org/doc/install/source\#environment\).  | 
| Docker.SystemInfo.NCPU | Number | The number of logical CPUs usable by the daemon.  The number of available CPUs is checked by querying the operating system when the daemon starts. Changes to operating system CPU allocation after the daemon is started are not reflected.  | 
| Docker.SystemInfo.MemTotal | Number | Total amount of physical memory available on the host, in bytes.  | 
| Docker.SystemInfo.IndexServerAddress | String | Address / URL of the index server that is used for image search, and as a default for user authentication for Docker Hub and Docker Cloud.  | 
| Docker.SystemInfo.HttpProxy | String | HTTP-proxy configured for the daemon. This value is obtained from the \[\`HTTP_PROXY\`\]\(https://www.gnu.org/software/wget/manual/html_node/Proxies.html\) environment variable. Credentials \(\[user info component\]\(https://tools.ietf.org/html/rfc3986\#section-3.2.1\)\) in the proxy URL are masked in the API response.  Containers do not automatically inherit this configuration.  | 
| Docker.SystemInfo.HttpsProxy | String | HTTPS-proxy configured for the daemon. This value is obtained from the \[\`HTTPS_PROXY\`\]\(https://www.gnu.org/software/wget/manual/html_node/Proxies.html\) environment variable. Credentials \(\[user info component\]\(https://tools.ietf.org/html/rfc3986\#section-3.2.1\)\) in the proxy URL are masked in the API response.  Containers do not automatically inherit this configuration.  | 
| Docker.SystemInfo.NoProxy | String | Comma-se ted list of domain extensions for which no proxy should be used. This value is obtained from the \[\`NO_PROXY\`\]\(https://www.gnu.org/software/wget/manual/html_node/Proxies.html\) environment variable.  Containers do not automatically inherit this configuration.  | 
| Docker.SystemInfo.Name | String | Hostname of the host. | 
| Docker.SystemInfo.ExperimentalBuild | Boolean | Indicates if experimental features are enabled on the daemon.  | 
| Docker.SystemInfo.ServerVersion | String | Version string of the daemon.      Note  : the \[standalone Swarm API\]\(https://docs.docker.com/swarm/swarm-api/\)   returns the Swarm version instead of the daemon  version, for example   \`swarm/1.2.8\`.  | 
| Docker.SystemInfo.ClusterStore | String | URL of the distributed storage backend.   The storage backend is used for multihost networking \(to store network and endpoint information\) and by the node discovery mechanism.   p    /  /p       Deprecated  : This field is only propagated when using standalone Swarm   mode, and overlay networking using an external k/v store. Overlay   networks with Swarm mode enabled use the built-in raft store, and   this field will be empty.  | 
| Docker.SystemInfo.ClusterAdvertise | String | The network endpoint that the Engine advertises for the purpose of node discovery. ClusterAdvertise is a \`host:port\` combination on which the daemon is reachable by other hosts.   p    /  /p       Deprecated  : This field is only propagated when using standalone Swarm   mode, and overlay networking using an external k/v store. Overlay   networks with Swarm mode enabled use the built-in raft store, and   this field will be empty.  | 
| Docker.SystemInfo.Runtimes.path | String | Name and, optional, path, of the OCI executable binary.  If the path is omitted, the daemon searches the host's \`$PATH\` for the binary and uses the first result.  | 
| Docker.SystemInfo.DefaultRuntime | String | Name of the default OCI runtime that is used when starting containers.  The default can be overridden per-container at create time.  | 
| Docker.SystemInfo.LiveRestoreEnabled | Boolean | Indicates if live restore is enabled.  If enabled, containers are kept running when the daemon is shutdown or upon daemon start if running containers are detected.  | 
| Docker.SystemInfo.Isolation | String | Represents the isolation technology to use as a default for containers. The supported values are platform-specific.  If no isolation value is specified on daemon start, on Windows client, the default is \`hyperv\`, and on Windows server, the default is \`process\`.  This option is currently not used on other platforms.  | 
| Docker.SystemInfo.InitBinary | String | Name and, optional, path of the \`docker-init\` binary.  If the path is omitted, the daemon searches the host's \`$PATH\` for the binary and uses the first result.  | 
| Docker.SystemInfo.ProductLicense | String | Reports a summary of the product license on the daemon.  If a commercial license has been applied to the daemon, information such as number of nodes, and expiration are included.  | 
| Docker.SystemInfo.DefaultAddressPools.Base | String | The network address in CIDR format | 
| Docker.SystemInfo.DefaultAddressPools.Size | Number | The network pool size | 

### docker-system-version
***
Get version


#### Base Command

`docker-system-version`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.SystemVersion.Components.Name | String | Name of the component  | 
| Docker.SystemVersion.Components.Version | String | Version of the component  | 
| Docker.SystemVersion.Version | String | The version of the daemon | 
| Docker.SystemVersion.ApiVersion | String | The default \(and highest\) API version that is supported by the daemon  | 
| Docker.SystemVersion.MinAPIVersion | String | The minimum API version that is supported by the daemon  | 
| Docker.SystemVersion.GitCommit | String | The Git commit of the source code that was used to build the daemon  | 
| Docker.SystemVersion.GoVersion | String | The version Go used to compile the daemon, and the version of the Go runtime in use.  | 
| Docker.SystemVersion.Os | String | The operating system that the daemon is running on \("linux" or "windows"\)  | 
| Docker.SystemVersion.Arch | String | The architecture that the daemon is running on  | 
| Docker.SystemVersion.KernelVersion | String | The kernel version \(\`uname -r\`\) that the daemon is running on.  This field is omitted when empty.  | 
| Docker.SystemVersion.Experimental | Boolean | Indicates if the daemon is started with experimental features enabled.  This field is omitted when empty / false.  | 
| Docker.SystemVersion.BuildTime | String | The date and time that the daemon was compiled.  | 

### docker-task-list
***
List tasks


#### Base Command

`docker-task-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | A JSON encoded value of the filters (a `map[string][]string`) to process on the tasks list.  Available filters:  - `desired-state=(running \| shutdown \| accepted)` - `id= task id ` - `label=key` or `label="key=value"` - `name= task name ` - `node= node id or name ` - `service= service name ` . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Task.ID | String | The ID of the task. | 
| Docker.Task.CreatedAt | String | Docker Task CreatedAt. | 
| Docker.Task.UpdatedAt | String | Docker Task UpdatedAt. | 
| Docker.Task.Name | String | Name of the task. | 
| Docker.Task.ServiceID | String | The ID of the service this task is part of. | 
| Docker.Task.Slot | Number | Docker Task Slot | 
| Docker.Task.NodeID | String | The ID of the node that this task is on. | 

### docker-volume-create
***
Create a volume


#### Base Command

`docker-volume-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| volumeconfig_name | The new volume's name. If not specified, Docker generates a name. . | Optional | 
| volumeconfig_driver | Name of the volume driver to use. | Optional | 
| volumeconfig_driveropts | A mapping of driver options and values. These options are passed directly to the driver and are driver specific. . | Optional | 
| volumeconfig_labels | User-defined key/value metadata. | Optional | 


#### Context Output

There is no context output for this command.
### docker-volume-inspect
***
Inspect a volume


#### Base Command

`docker-volume-inspect`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Volume name or ID. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.Volume.Name | String | Name of the volume. | 
| Docker.Volume.Driver | String | Name of the volume driver used by the volume. | 
| Docker.Volume.Mountpoint | String | Mount path of the volume on the host. | 
| Docker.Volume.CreatedAt | String | Date/Time the volume was created. | 
| Docker.Volume.Scope | String | The level at which the volume exists. Either \`global\` for cluster-wide, or \`local\` for machine level.  | 

### docker-volume-list
***
List volumes


#### Base Command

`docker-volume-list`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | JSON encoded value of the filters (a `map[string][]string`) to process on the volumes list. Available filters:  - `dangling= boolean ` When set to `true` (or `1`), returns all    volumes that are not in use by a container. When set to `false`    (or `0`), only volumes that are in use by one or more    containers are returned. - `driver= volume-driver-name ` Matches volumes based on their driver. - `label= key ` or `label= key : value ` Matches volumes based on    the presence of a `label` alone or a `label` and a value. - `name= volume-name ` Matches all or part of a volume name. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.VolumeListResponse.Volumes.Name | String | Name of the volume. | 
| Docker.VolumeListResponse.Volumes.Driver | String | Name of the volume driver used by the volume. | 
| Docker.VolumeListResponse.Volumes.Mountpoint | String | Mount path of the volume on the host. | 
| Docker.VolumeListResponse.Volumes.CreatedAt | String | Date/Time the volume was created. | 
| Docker.VolumeListResponse.Volumes.Scope | String | The level at which the volume exists. Either \`global\` for cluster-wide, or \`local\` for machine level.  | 

### docker-volume-prune
***
Delete unused volumes


#### Base Command

`docker-volume-prune`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| filters | Filters to process on the prune list, encoded as JSON (a `map[string][]string`).  Available filters: - `label` (`label= key `, `label= key = value `, `label!= key `, or `label!= key = value `) Prune volumes with (or without, in case `label!=...` is used) the specified labels. . | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.VolumePruneResponse.SpaceReclaimed | Number | Disk space reclaimed in bytes | 

### docker-container-delete
***
Remove a container


#### Base Command

`docker-container-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| id | ID or name of the container. | Required | 
| v | Remove anonymous volumes associated with the container. Possible values are: false, true. Default is false. | Optional | 
| force | If the container is running, kill it before removing it. Possible values are: false, true. Default is false. | Optional | 
| link | Remove the specified link associated with the container. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ContainerDelete.Status Code | String | Image Tag Result | 

#### Command example
```!docker-container-delete id="hello-docker"```
#### Context Example
```json
{
    "Docker": {
        "Status Code": 204
    }
}
```

#### Human Readable Output

>### Results
>|Status Code|
>|---|
>| 204 |


### docker-image-delete
***
Remove an image, along with any untagged parent images that were referenced by that image. Images can't be removed if they have descendant images, are being used by a running container or are being used by a build.


#### Base Command

`docker-image-delete`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Image name or ID. | Required | 
| force | Remove the image even if it is being used by stopped containers or has other tags. Possible values are: false, true. Default is false. | Optional | 
| noprune | Do not delete untagged parent images. Possible values are: false, true. Default is false. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ImageDeleteResponseItem | string | Deletion Response | 

#### Command example
```!docker-image-delete name="alpine:latest"```
#### Context Example
```json
{
    "Docker": {
        "ImageDeleteResponseItem": [
            {
                "Untagged": "alpine:latest"
            },
            {
                "Untagged": "alpine@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Untagged|
>|---|
>| alpine:latest |
>| alpine@sha256:686d8c9dfa6f3ccfc8230bc3178d23f84eeaf7e457f36f271ab1acc53015037c |


### docker-image-create
***
Create an image by either pulling it from a registry or importing it.


#### Base Command

`docker-image-create`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| from_image | Name of the image to pull. The name may include a tag or digest. This parameter may only be used when pulling an image. The pull is cancelled if the HTTP connection is closed. | Optional | 
| from_src | Source to import. The value may be a URL from which the image can be retrieved or - to read the image from the request body. This parameter may only be used when importing an image. | Optional | 
| repo | Repository name given to an image when it is imported. The repo may include a tag. This parameter may only be used when importing an image. | Optional | 
| tag | Tag or digest. If empty when pulling an image, this causes all tags for the given image to be pulled. | Optional | 
| message | Set commit message for imported image. | Optional | 
| platform | Platform in the format os[/arch[/variant]]. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ImageCreate.Status | String | Image Create result | 

#### Command example
```!docker-image-create from_image="alpine:latest"```
#### Context Example
```json
{
    "Docker": {
        "ImageCreate": {
            "status": "Status: Downloaded newer image for alpine:latest"
        }
    }
}
```

#### Human Readable Output

>### Results
>|status|
>|---|
>| Status: Downloaded newer image for alpine:latest |


### docker-image-push
***
Push an image to a registry. If you wish to push an image on to a private registry, that image must already have a tag which references the registry. For example, registry.example.com/myimage:latest. The push is cancelled if the HTTP connection is closed.


#### Base Command

`docker-image-push`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Image name or ID. | Required | 
| tag | The tag to associate with the image on the registry. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ImagePush | String | Image Push Result | 

#### Command example
```!docker-image-push name="sergebakharev/alpine:test"```
#### Context Example
```json
{
    "Docker": {
        "ImagePush": {
            "aux": {
                "Digest": "sha256:4ff3ca91275773af45cb4b0834e12b7eb47d1c18f770a0b151381cd227f4c253",
                "Size": 528,
                "Tag": "test"
            },
            "progressDetail": {}
        }
    }
}
```

#### Human Readable Output

>### Results
>|aux|progressDetail|
>|---|---|
>| Tag: test<br/>Digest: sha256:4ff3ca91275773af45cb4b0834e12b7eb47d1c18f770a0b151381cd227f4c253<br/>Size: 528 |  |


### docker-image-tag
***
Tag an image so that it becomes part of a repository.


#### Base Command

`docker-image-tag`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| name | Image name or ID to tag. | Required | 
| repo | The repository to tag in. For example, someuser/someimage. | Optional | 
| tag | The name of the new tag. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Docker.ImageTag.Status Code | String | Image Tag Result | 

#### Command example
```!docker-image-tag name="alpine:latest" repo="sergebakharev/alpine" tag="test"```
#### Context Example
```json
{
    "Docker": {
        "ImageTag": {
            "Status Code": 201
        }
    }
}
```

#### Human Readable Output

>### Results
>|Status Code|
>|---|
>| 201 |

