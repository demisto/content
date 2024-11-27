The Engine API is an HTTP API served by Docker Engine. It is the API the Docker client uses to communicate with the Engine, so everything the Docker client can do can be done with the API.
This integration was integrated and tested with version 20.10.17 ([API Version 1.41](https://docs.docker.com/engine/api/v1.41/)) of Docker Engine API
## Configure Docker Engine API in Cortex


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

Note: The Docker private key must be first stored into XSOAR as a credential attribute of a [saved credential](https://xsoar.pan.dev/docs/reference/articles/managing-credentials#configure-cortex-xsoar-credentials), and this credential must be selected as the auth key.


## Docker Engine
Docker Engine is an open source containerization technology for building and containerizing your applications. Docker Engine acts as a client-server application with:

- A server with a long-running daemon process dockerd.
- APIs which specify interfaces that programs can use to talk to and instruct the Docker daemon.
- A command line interface (CLI) client docker.

The CLI uses Docker APIs to control or interact with the Docker daemon through scripting or direct CLI commands. Many other Docker applications use the underlying API and CLI. The daemon creates and manage Docker objects, such as images, containers, networks, and volumes.

## Requirements
By default, Docker runs through a non-networked UNIX socket. It can also optionally communicate using an HTTP socket. This integration manages a Docker Server that has had it's Docker daemon API interface exposed over HTTPS.

Refer to the [Docker documentation](https://docs.docker.com/engine/security/protect-access/#use-tls-https-to-protect-the-docker-daemon-socket) for how to configure Docker server to securely accept HTTPS connections.

To use this integration you need:
1. The Docker server to be running in TLS (HTTPS) mode
2. Have generated a certificate for this integration to act as a Docker Client authorised to manage this server

The integration takes the client certificate, private key, and CA's certificate as paramaters. These three are expected in the PEM format.

If a CA cert is not provided, the Docker server certificate will be validated using the public CA's included in [Python Requests](https://pypi.org/project/requests/). Or not validated at all if `Trust any certificate (not secure)` is selected.


### Docker Registry Authentication
Authentication for registries is handled by the integration not the Docker Server. This is configured as a integration parameter. This can be in the form of either a identitytoken or Username/Password/Serveraddress. These four parameters are optional and if none authentication credentials are provided the integration will function in "Anonymous mode". Some Commands may not function as a result.
## Commands
You can execute these commands from the CLI, as part of an automation, or in a playbook.
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


#### Command Example
```!docker-build-prune```

#### Context Example
```json
{
    "Docker": {
        "BuildPruneResponse": {
            "CachesDeleted": null,
            "SpaceReclaimed": 0
        }
    }
}
```

#### Human Readable Output

>### Results
>|CachesDeleted|SpaceReclaimed|
>|---|---|
>|  | 0 |


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

#### Command Example
```!docker-config-create configspec_name="test_config" configspec_data="VEhJUyBJUyBOT1QgQSBSRUFMIENFUlRJRklDQVRFCg=="```

#### Context Example
```json
{
    "Docker": {
        "ID": "vfih5lb2qn8rrxla178td04al"
    }
}
```

#### Human Readable Output

>### Results
>|ID|
>|---|
>| vfih5lb2qn8rrxla178td04al |


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


#### Command Example
```!docker-config-inspect id="ud0ychozv55f7n0pzk6qo9kq9"```

#### Context Example
```json
{
    "Docker": {
        "Config": {
            "message": "config ud0ychozv55f7n0pzk6qo9kq9 not found"
        }
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| config ud0ychozv55f7n0pzk6qo9kq9 not found |


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


#### Command Example
```!docker-config-list```

#### Context Example
```json
{
    "Docker": {
        "Config": [
            {
                "CreatedAt": "2021-01-10T07:33:59.040093065Z",
                "ID": "vfih5lb2qn8rrxla178td04al",
                "Spec": {
                    "Data": "VEhJUyBJUyBOT1QgQSBSRUFMIENFUlRJRklDQVRFCg==",
                    "Labels": {},
                    "Name": "test_config"
                },
                "UpdatedAt": "2021-01-10T07:33:59.040093065Z",
                "Version": {
                    "Index": 11
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|CreatedAt|ID|Spec|UpdatedAt|Version|
>|---|---|---|---|---|
>| 2021-01-10T07:33:59.040093065Z | vfih5lb2qn8rrxla178td04al | Name: test_config<br/>Labels: {}<br/>Data: VEhJUyBJUyBOT1QgQSBSRUFMIENFUlRJRklDQVRFCg== | 2021-01-10T07:33:59.040093065Z | Index: 11 |


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


#### Command Example
```!docker-container-changes id="04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94"```

#### Context Example
```json
{
    "Docker": {
        "ContainerChangeResponseItem": [
            {
                "Kind": 0,
                "Path": "/tmp"
            },
            {
                "Kind": 1,
                "Path": "/tmp/opentaxii.yml"
            },
            {
                "Kind": 1,
                "Path": "/opentaxii.yml"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Kind|Path|
>|---|---|
>| 0 | /tmp |
>| 1 | /tmp/opentaxii.yml |
>| 1 | /opentaxii.yml |


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

#### Command Example
```!docker-container-create name="hello-docker" containerconfig_image="hello-world"```

#### Context Example
```json
{
    "Docker": {
        "message": "Conflict. The container name \"/hello-docker\" is already in use by container \"7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41\". You have to remove (or rename) that container to be able to reuse that name."
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| Conflict. The container name "/hello-docker" is already in use by container "7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41". You have to remove (or rename) that container to be able to reuse that name. |

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


#### Command Example
```!docker-container-inspect id="7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41"```

#### Context Example
```json
{
    "Docker": {
        "ContainerInspectResponse": {
            "AppArmorProfile": "",
            "Args": [],
            "Config": {
                "AttachStderr": false,
                "AttachStdin": false,
                "AttachStdout": false,
                "Cmd": [
                    "/hello"
                ],
                "Domainname": "",
                "Entrypoint": null,
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                ],
                "Hostname": "7997c8bd061e",
                "Image": "hello-world",
                "Labels": {},
                "OnBuild": null,
                "OpenStdin": false,
                "StdinOnce": false,
                "StopSignal": "SIGTERM",
                "Tty": false,
                "User": "",
                "Volumes": null,
                "WorkingDir": ""
            },
            "Created": "2021-01-08T16:22:02.396165935Z",
            "Driver": "overlay2",
            "ExecIDs": null,
            "GraphDriver": {
                "Data": {
                    "LowerDir": "/var/lib/docker/overlay2/2ce039a43f37e7fae47787c5533de9e83f2c2d16876938e1183e6ee7dbf7f3d8-init/diff:/var/lib/docker/overlay2/1f480a7135adc30bb61259a8c1b45c7213946dfc1959c082a53c174d47c8f73f/diff",
                    "MergedDir": "/var/lib/docker/overlay2/2ce039a43f37e7fae47787c5533de9e83f2c2d16876938e1183e6ee7dbf7f3d8/merged",
                    "UpperDir": "/var/lib/docker/overlay2/2ce039a43f37e7fae47787c5533de9e83f2c2d16876938e1183e6ee7dbf7f3d8/diff",
                    "WorkDir": "/var/lib/docker/overlay2/2ce039a43f37e7fae47787c5533de9e83f2c2d16876938e1183e6ee7dbf7f3d8/work"
                },
                "Name": "overlay2"
            },
            "HostConfig": {
                "AutoRemove": false,
                "Binds": null,
                "BlkioDeviceReadBps": null,
                "BlkioDeviceReadIOps": null,
                "BlkioDeviceWriteBps": null,
                "BlkioDeviceWriteIOps": null,
                "BlkioWeight": 0,
                "BlkioWeightDevice": null,
                "CapAdd": null,
                "CapDrop": null,
                "Cgroup": "",
                "CgroupParent": "",
                "CgroupnsMode": "host",
                "ConsoleSize": [
                    0,
                    0
                ],
                "ContainerIDFile": "",
                "CpuCount": 0,
                "CpuPercent": 0,
                "CpuPeriod": 0,
                "CpuQuota": 0,
                "CpuRealtimePeriod": 0,
                "CpuRealtimeRuntime": 0,
                "CpuShares": 0,
                "CpusetCpus": "",
                "CpusetMems": "",
                "DeviceCgroupRules": null,
                "DeviceRequests": null,
                "Devices": null,
                "Dns": [],
                "DnsOptions": [],
                "DnsSearch": [],
                "ExtraHosts": null,
                "GroupAdd": null,
                "IOMaximumBandwidth": 0,
                "IOMaximumIOps": 0,
                "IpcMode": "private",
                "Isolation": "",
                "KernelMemory": 0,
                "KernelMemoryTCP": 0,
                "Links": null,
                "LogConfig": {
                    "Config": {},
                    "Type": "json-file"
                },
                "MaskedPaths": [
                    "/proc/asound",
                    "/proc/acpi",
                    "/proc/kcore",
                    "/proc/keys",
                    "/proc/latency_stats",
                    "/proc/timer_list",
                    "/proc/timer_stats",
                    "/proc/sched_debug",
                    "/proc/scsi",
                    "/sys/firmware"
                ],
                "Memory": 0,
                "MemoryReservation": 0,
                "MemorySwap": 0,
                "MemorySwappiness": null,
                "NanoCpus": 0,
                "NetworkMode": "default",
                "OomKillDisable": false,
                "OomScoreAdj": 0,
                "PidMode": "",
                "PidsLimit": null,
                "PortBindings": null,
                "Privileged": false,
                "PublishAllPorts": false,
                "ReadonlyPaths": [
                    "/proc/bus",
                    "/proc/fs",
                    "/proc/irq",
                    "/proc/sys",
                    "/proc/sysrq-trigger"
                ],
                "ReadonlyRootfs": false,
                "RestartPolicy": {
                    "MaximumRetryCount": 0,
                    "Name": ""
                },
                "Runtime": "runc",
                "SecurityOpt": null,
                "ShmSize": 67108864,
                "UTSMode": "",
                "Ulimits": null,
                "UsernsMode": "",
                "VolumeDriver": "",
                "VolumesFrom": null
            },
            "HostnamePath": "/var/lib/docker/containers/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41/hostname",
            "HostsPath": "/var/lib/docker/containers/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41/hosts",
            "Id": "7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41",
            "Image": "sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b",
            "LogPath": "/var/lib/docker/containers/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41-json.log",
            "MountLabel": "",
            "Mounts": [],
            "Name": "/hello-docker",
            "NetworkSettings": {
                "Bridge": "",
                "EndpointID": "",
                "Gateway": "",
                "GlobalIPv6Address": "",
                "GlobalIPv6PrefixLen": 0,
                "HairpinMode": false,
                "IPAddress": "",
                "IPPrefixLen": 0,
                "IPv6Gateway": "",
                "LinkLocalIPv6Address": "",
                "LinkLocalIPv6PrefixLen": 0,
                "MacAddress": "",
                "Networks": {
                    "bridge": {
                        "Aliases": null,
                        "DriverOpts": null,
                        "EndpointID": "",
                        "Gateway": "",
                        "GlobalIPv6Address": "",
                        "GlobalIPv6PrefixLen": 0,
                        "IPAMConfig": null,
                        "IPAddress": "",
                        "IPPrefixLen": 0,
                        "IPv6Gateway": "",
                        "Links": null,
                        "MacAddress": "",
                        "NetworkID": "b5b425aad28e5f4b9c9b118257ce214455d84a7901e5a90d79e3ae4f527f725e"
                    }
                },
                "Ports": {},
                "SandboxID": "6d48185534118ce5b3549501c122dd1f67831418c306ef2291cfda6763db6e0e",
                "SandboxKey": "/var/run/docker/netns/6d4818553411",
                "SecondaryIPAddresses": null,
                "SecondaryIPv6Addresses": null
            },
            "Path": "/hello",
            "Platform": "linux",
            "ProcessLabel": "",
            "ResolvConfPath": "/var/lib/docker/containers/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41/resolv.conf",
            "RestartCount": 0,
            "State": {
                "Dead": false,
                "Error": "",
                "ExitCode": 0,
                "FinishedAt": "2021-01-08T16:26:46.413127348Z",
                "OOMKilled": false,
                "Paused": false,
                "Pid": 0,
                "Restarting": false,
                "Running": false,
                "StartedAt": "2021-01-08T16:26:46.401416786Z",
                "Status": "exited"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|AppArmorProfile|Args|Config|Created|Driver|ExecIDs|GraphDriver|HostConfig|HostnamePath|HostsPath|Id|Image|LogPath|MountLabel|Mounts|Name|NetworkSettings|Path|Platform|ProcessLabel|ResolvConfPath|RestartCount|State|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>|  |  | Hostname: 7997c8bd061e<br/>Domainname: <br/>User: <br/>AttachStdin: false<br/>AttachStdout: false<br/>AttachStderr: false<br/>Tty: false<br/>OpenStdin: false<br/>StdinOnce: false<br/>Env: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin<br/>Cmd: /hello<br/>Image: hello-world<br/>Volumes: null<br/>WorkingDir: <br/>Entrypoint: null<br/>OnBuild: null<br/>Labels: {}<br/>StopSignal: SIGTERM | 2021-01-08T16:22:02.396165935Z | overlay2 |  | Data: {"LowerDir": "/var/lib/docker/overlay2/2ce039a43f37e7fae47787c5533de9e83f2c2d16876938e1183e6ee7dbf7f3d8-init/diff:/var/lib/docker/overlay2/1f480a7135adc30bb61259a8c1b45c7213946dfc1959c082a53c174d47c8f73f/diff", "MergedDir": "/var/lib/docker/overlay2/2ce039a43f37e7fae47787c5533de9e83f2c2d16876938e1183e6ee7dbf7f3d8/merged", "UpperDir": "/var/lib/docker/overlay2/2ce039a43f37e7fae47787c5533de9e83f2c2d16876938e1183e6ee7dbf7f3d8/diff", "WorkDir": "/var/lib/docker/overlay2/2ce039a43f37e7fae47787c5533de9e83f2c2d16876938e1183e6ee7dbf7f3d8/work"}<br/>Name: overlay2 | Binds: null<br/>ContainerIDFile: <br/>LogConfig: {"Type": "json-file", "Config": {}}<br/>NetworkMode: default<br/>PortBindings: null<br/>RestartPolicy: {"Name": "", "MaximumRetryCount": 0}<br/>AutoRemove: false<br/>VolumeDriver: <br/>VolumesFrom: null<br/>CapAdd: null<br/>CapDrop: null<br/>CgroupnsMode: host<br/>Dns: <br/>DnsOptions: <br/>DnsSearch: <br/>ExtraHosts: null<br/>GroupAdd: null<br/>IpcMode: private<br/>Cgroup: <br/>Links: null<br/>OomScoreAdj: 0<br/>PidMode: <br/>Privileged: false<br/>PublishAllPorts: false<br/>ReadonlyRootfs: false<br/>SecurityOpt: null<br/>UTSMode: <br/>UsernsMode: <br/>ShmSize: 67108864<br/>Runtime: runc<br/>ConsoleSize: 0,<br/>0<br/>Isolation: <br/>CpuShares: 0<br/>Memory: 0<br/>NanoCpus: 0<br/>CgroupParent: <br/>BlkioWeight: 0<br/>BlkioWeightDevice: null<br/>BlkioDeviceReadBps: null<br/>BlkioDeviceWriteBps: null<br/>BlkioDeviceReadIOps: null<br/>BlkioDeviceWriteIOps: null<br/>CpuPeriod: 0<br/>CpuQuota: 0<br/>CpuRealtimePeriod: 0<br/>CpuRealtimeRuntime: 0<br/>CpusetCpus: <br/>CpusetMems: <br/>Devices: null<br/>DeviceCgroupRules: null<br/>DeviceRequests: null<br/>KernelMemory: 0<br/>KernelMemoryTCP: 0<br/>MemoryReservation: 0<br/>MemorySwap: 0<br/>MemorySwappiness: null<br/>OomKillDisable: false<br/>PidsLimit: null<br/>Ulimits: null<br/>CpuCount: 0<br/>CpuPercent: 0<br/>IOMaximumIOps: 0<br/>IOMaximumBandwidth: 0<br/>MaskedPaths: /proc/asound,<br/>/proc/acpi,<br/>/proc/kcore,<br/>/proc/keys,<br/>/proc/latency_stats,<br/>/proc/timer_list,<br/>/proc/timer_stats,<br/>/proc/sched_debug,<br/>/proc/scsi,<br/>/sys/firmware<br/>ReadonlyPaths: /proc/bus,<br/>/proc/fs,<br/>/proc/irq,<br/>/proc/sys,<br/>/proc/sysrq-trigger | /var/lib/docker/containers/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41/hostname | /var/lib/docker/containers/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41/hosts | 7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41 | sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b | /var/lib/docker/containers/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41-json.log |  |  | /hello-docker | Bridge: <br/>SandboxID: 6d48185534118ce5b3549501c122dd1f67831418c306ef2291cfda6763db6e0e<br/>HairpinMode: false<br/>LinkLocalIPv6Address: <br/>LinkLocalIPv6PrefixLen: 0<br/>Ports: {}<br/>SandboxKey: /var/run/docker/netns/6d4818553411<br/>SecondaryIPAddresses: null<br/>SecondaryIPv6Addresses: null<br/>EndpointID: <br/>Gateway: <br/>GlobalIPv6Address: <br/>GlobalIPv6PrefixLen: 0<br/>IPAddress: <br/>IPPrefixLen: 0<br/>IPv6Gateway: <br/>MacAddress: <br/>Networks: {"bridge": {"IPAMConfig": null, "Links": null, "Aliases": null, "NetworkID": "b5b425aad28e5f4b9c9b118257ce214455d84a7901e5a90d79e3ae4f527f725e", "EndpointID": "", "Gateway": "", "IPAddress": "", "IPPrefixLen": 0, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "", "DriverOpts": null}} | /hello | linux |  | /var/lib/docker/containers/7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41/resolv.conf | 0 | Status: exited<br/>Running: false<br/>Paused: false<br/>Restarting: false<br/>OOMKilled: false<br/>Dead: false<br/>Pid: 0<br/>ExitCode: 0<br/>Error: <br/>StartedAt: 2021-01-08T16:26:46.401416786Z<br/>FinishedAt: 2021-01-08T16:26:46.413127348Z |


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

#### Command Example
```!docker-container-list```

#### Context Example
```json
{
    "Docker": {
        "ContainerSummary": [
            {
                "Command": "tini -- /docker-entrypoint.sh mongo-express",
                "Created": 1609920735,
                "HostConfig": {
                    "NetworkMode": "mongodb_default"
                },
                "Id": "57d49db83f2ced79c87e5c50d2b407bbb7bc33c3a95a03e142477f3a3b79ded5",
                "Image": "mongo-express",
                "ImageID": "sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e",
                "Labels": {
                    "com.docker.compose.config-hash": "0a75befcc34f36ab677c5d8f09d2ee8063e8ad3d",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "mongodb",
                    "com.docker.compose.service": "mongo-express",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/mongodb-express"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "mongodb_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "2628f2ac3df2f3b5a8059fe3e736d9fe9da4d428c9da9220dad5d2eb100258fa",
                            "Gateway": "1.0.0.1",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.3",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:1a:00:03",
                            "NetworkID": "5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 8081,
                        "PublicPort": 8081,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            },
            {
                "Command": "docker-entrypoint.sh mongod",
                "Created": 1609920723,
                "HostConfig": {
                    "NetworkMode": "mongodb_default"
                },
                "Id": "161f9d908f5bc34a9638a496b492cce47a16cd47268ec61f04e10b1224dbd2a3",
                "Image": "mongo",
                "ImageID": "sha256:c97feb3412a387d4d3bbd8653b09ef26683263a192e0e8dc6554e65bfb637a86",
                "Labels": {
                    "com.docker.compose.config-hash": "74e20e7feccade15ae2ce2378088081ae5726a05",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "mongodb",
                    "com.docker.compose.service": "mongo",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [
                    {
                        "Destination": "/data/db",
                        "Driver": "local",
                        "Mode": "z",
                        "Name": "mongodb",
                        "Propagation": "",
                        "RW": true,
                        "Source": "/var/lib/docker/volumes/mongodb/_data",
                        "Type": "volume"
                    },
                    {
                        "Destination": "/data/configdb",
                        "Driver": "local",
                        "Mode": "",
                        "Name": "88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55",
                        "Propagation": "",
                        "RW": true,
                        "Source": "",
                        "Type": "volume"
                    }
                ],
                "Names": [
                    "/mongodb"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "mongodb_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "2f478dd56c3bfa4b0bfb2a6bdfa5a7f95f20960dbc5045238567f4f7c2b5e46d",
                            "Gateway": "1.0.0.1",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.2",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:1a:00:02",
                            "NetworkID": "5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 27017,
                        "PublicPort": 27017,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            },
            {
                "Command": "/entrypoint.sh /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000",
                "Created": 1609863181,
                "HostConfig": {
                    "NetworkMode": "bridge"
                },
                "Id": "04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94",
                "Image": "eclecticiq/opentaxii:latest",
                "ImageID": "sha256:aa50897f28e43c1110328f1b8740a2ad097031e8d2443266e562fe74be1a7a19",
                "Labels": {
                    "maintainer": "EclecticIQ <opentaxii@eclecticiq.com>"
                },
                "Mounts": [
                    {
                        "Destination": "/data",
                        "Driver": "local",
                        "Mode": "z",
                        "Name": "opentaxii-data",
                        "Propagation": "",
                        "RW": true,
                        "Source": "/var/lib/docker/volumes/opentaxii-data/_data",
                        "Type": "volume"
                    },
                    {
                        "Destination": "/input",
                        "Driver": "local",
                        "Mode": "z",
                        "Name": "opentaxii-input",
                        "Propagation": "",
                        "RW": true,
                        "Source": "/var/lib/docker/volumes/opentaxii-input/_data",
                        "Type": "volume"
                    }
                ],
                "Names": [
                    "/test-taxii"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "bridge": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "3fccdab7ca5ad3f11ef72dd8d76044160c0cc66e005643d9584fbcb903500c1b",
                            "Gateway": "1.0.0.7",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.2",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:11:00:02",
                            "NetworkID": "bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 9000,
                        "PublicPort": 6000,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608827060,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "14d3c9c9c306e427b8cd4a2e4d80ddd6ad38684936224f3e36440b6b6f08bc34",
                "Image": "opencti/connector-ipinfo:4.0.3",
                "ImageID": "sha256:cd608aa8a042cb46adf5aaa3c43ce92a85b3817c5254b8de0e53b49b7a729c6b",
                "Labels": {
                    "com.docker.compose.config-hash": "3a9bd111dfb135ed1a839ad5e164068c78b2b630",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "connector-export-file-stix",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_connector-ipinfo"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "717ad998186f308ebefb4f0f71c04ae5fbc143e450bed9eba8570d9adc099624",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:08",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 22 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608564498,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "7ba5c18139e09bd2a34e7be27db70520c6901dad7db901dd073c1f96abfc9034",
                "Image": "opencti/connector-import-file-pdf-observables:4.0.3",
                "ImageID": "sha256:51afb662d3c993510447e431e3da8495140690cb9c1ca93c7cf19424a63ce223",
                "Labels": {
                    "com.docker.compose.config-hash": "336a368bc6eb7eae69a090a9ac80f9614d02685e",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "connector-import-file-pdf-observables",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_connector-import-file-pdf-observables"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "e99d6307854d91785af35603157c0a82826a5ebe59b3072924770dd7e66be07c",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.2",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:02",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 22 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608564460,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "2aa24d29411d89e1d3fcd708b0dae10e32a84d53d9164a5998c217e054d31bd9",
                "Image": "opencti/connector-import-file-stix:4.0.3",
                "ImageID": "sha256:cfd88d87460e5c1e0d7c82ee58258208c80d8acbd9417afe2f7cea10bfef4dd9",
                "Labels": {
                    "com.docker.compose.config-hash": "d39640557a02e44f4983eac94b75e00a8b975e07",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "connector-import-file-stix",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_connector-import-file-stix"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "254bd9e38c903fc40203b0935a627ff078764e0692e948af6e99088512909f5a",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:07",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 7 seconds"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608564417,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "5f92895691ca7eeb6c8bc3f4914cd6210a3d59a72e8e48890f336d352cbc9753",
                "Image": "opencti/connector-export-file-csv:4.0.3",
                "ImageID": "sha256:25500204dfbea42059fc77100177de2c5d92cd4219ca6437831bfc26c53b628c",
                "Labels": {
                    "com.docker.compose.config-hash": "64d591ae3f975e1a79738447dd38d1e554486f44",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "connector-export-file-csv",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_connector-export-file-csv"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "91a3c7767104581ddb04f739c3cc313e7bfe0f6db5ad4c6865970d1e60bf99b7",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:09",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 22 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608564294,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "65ddee16a51d57e8b57f6b00acd7f9ae5b92152731276d6d4d497c2f979e2b1e",
                "Image": "opencti/connector-export-file-stix:4.0.3",
                "ImageID": "sha256:42efb539088b86558557e24c10d00810014e5e820f0d7ac8bb8d0fd3981a0bda",
                "Labels": {
                    "com.docker.compose.config-hash": "3a9bd111dfb135ed1a839ad5e164068c78b2b630",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "connector-export-file-stix",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_connector-export-file-stix"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "8cd31e2f66b6df498962e8cc4df17f741b842546c4fd61ac9a79c2f6805f66bc",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:04",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 22 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608564112,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "c61e3108d286e07032f8ec44f3e5883bac00838a673972e871c31d970b75d155",
                "Image": "opencti/connector-history:4.0.3",
                "ImageID": "sha256:0257f00635aca1087fa630362c470f22c4661bc87d4e6e8c54c64f5795dfce1e",
                "Labels": {
                    "com.docker.compose.config-hash": "6ac905cdbdc63d012688d34a06393c135d384c79",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "connector-history",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_connector-history"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "048b58a95cd8a27e6f640c844e9b5ea7c65c4fdcbdc5dfdc683986daf6813e4a",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:0d",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 22 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608563957,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "2220832cc2840320c53156993563fce5298d4e0317d71b42851067f02c762423",
                "Image": "opencti/connector-alienvault:4.0.3",
                "ImageID": "sha256:3e718135d5fb38c0af85c9c00b64160082a407722d929572a190d6092c604e15",
                "Labels": {
                    "com.docker.compose.config-hash": "3a9bd111dfb135ed1a839ad5e164068c78b2b630",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "connector-export-file-stix",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_connector-alienvault"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "3a8b638639e908f26163f7271bb88eee017a3fc5cb253bf180e8b190ebca5a80",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:0c",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 22 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608562731,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "cc1743f3d83750f973796d0aaadba7ec5fb67361906666b2a48be0512d82a050",
                "Image": "opencti/worker:4.0.3",
                "ImageID": "sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473",
                "Labels": {
                    "com.docker.compose.config-hash": "4f611b1efe20fd3b147a1b830afceff276398af1",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "worker",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_worker_2"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "03f052a4e86e16124c279fe9e593e4686fcc658b57d82b51c031163f2076cfc6",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:0e",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 22 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608561358,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "118fe891bacfe3328ad64677ac492f0568547740458090594600950613774fcf",
                "Image": "opencti/worker:4.0.3",
                "ImageID": "sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473",
                "Labels": {
                    "com.docker.compose.config-hash": "4f611b1efe20fd3b147a1b830afceff276398af1",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "worker",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti_worker_1"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "ce7645ab046233a84fc7c2c9ce796a120edfd790280a52fb9df55f2066458141",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:0f",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [],
                "State": "running",
                "Status": "Up 22 minutes"
            },
            {
                "Command": "docker-entrypoint.sh redis-server",
                "Created": 1608559382,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "4be1f8dec98809ec2cf360d1d882beb8c819a58111070a04affbc714a071d1a0",
                "Image": "redis:6.0.9",
                "ImageID": "sha256:ef47f3b6dc11e8f17fb39a6e46ecaf4efd47b3d374e92aeb9f2606896b751251",
                "Labels": {
                    "com.docker.compose.config-hash": "daf5e1ad7b16619b8c479df88301daf432c5a564",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "redis",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [
                    {
                        "Destination": "/data",
                        "Driver": "local",
                        "Mode": "z",
                        "Name": "redisdata",
                        "Propagation": "",
                        "RW": true,
                        "Source": "/var/lib/docker/volumes/redisdata/_data",
                        "Type": "volume"
                    }
                ],
                "Names": [
                    "/redis"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "996d21e0ac5c57239c1622bba9c9a5d303a82cec1c15146a94c84766cd460966",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.3",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:03",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 6379,
                        "PublicPort": 6379,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            },
            {
                "Command": "/tini -- /usr/local/bin/docker-entrypoint.sh eswrapper",
                "Created": 1608559270,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "5c3b991454ad1daa7d2f287cc0450d69f0c1e0a7778f8f55199b5201da3b5390",
                "Image": "docker.elastic.co/elasticsearch/elasticsearch:7.10.1",
                "ImageID": "sha256:558380375f1a36c20e67c3a0b7bf715c659d75520d0e688b066d5e708918d716",
                "Labels": {
                    "com.docker.compose.config-hash": "6367ce3fdc8ac903d07574f97c9dc4a7208f3aef",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "elasticsearch",
                    "com.docker.compose.version": "1.5.0",
                    "org.label-schema.build-date": "2020-12-05T01:00:33.671820Z",
                    "org.label-schema.license": "Elastic-License",
                    "org.label-schema.name": "Elasticsearch",
                    "org.label-schema.schema-version": "1.0",
                    "org.label-schema.url": "https://www.elastic.co/products/elasticsearch",
                    "org.label-schema.usage": "https://www.elastic.co/guide/en/elasticsearch/reference/index.html",
                    "org.label-schema.vcs-ref": "1c34507e66d7db1211f66f3513706fdf548736aa",
                    "org.label-schema.vcs-url": "https://github.com/elastic/elasticsearch",
                    "org.label-schema.vendor": "Elastic",
                    "org.label-schema.version": "7.10.1",
                    "org.opencontainers.image.created": "2020-12-05T01:00:33.671820Z",
                    "org.opencontainers.image.documentation": "https://www.elastic.co/guide/en/elasticsearch/reference/index.html",
                    "org.opencontainers.image.licenses": "Elastic-License",
                    "org.opencontainers.image.revision": "1c34507e66d7db1211f66f3513706fdf548736aa",
                    "org.opencontainers.image.source": "https://github.com/elastic/elasticsearch",
                    "org.opencontainers.image.title": "Elasticsearch",
                    "org.opencontainers.image.url": "https://www.elastic.co/products/elasticsearch",
                    "org.opencontainers.image.vendor": "Elastic",
                    "org.opencontainers.image.version": "7.10.1"
                },
                "Mounts": [
                    {
                        "Destination": "/usr/share/elasticsearch/data",
                        "Driver": "local",
                        "Mode": "z",
                        "Name": "esdata",
                        "Propagation": "",
                        "RW": true,
                        "Source": "/var/lib/docker/volumes/esdata/_data",
                        "Type": "volume"
                    }
                ],
                "Names": [
                    "/elasticsearch"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "64904da59143266418038a1f64c1f7573d0a31f79ed0a32998ce94172ba49c88",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:06",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 9200,
                        "PublicPort": 9200,
                        "Type": "tcp"
                    },
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 9300,
                        "PublicPort": 9300,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            },
            {
                "Command": "docker-entrypoint.sh rabbitmq-server",
                "Created": 1608559125,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "93b8c8f3e5c5b959b5382b20ec3f441d1b960124419e809d86f0a34cee59d7c8",
                "Image": "rabbitmq:3.8-management",
                "ImageID": "sha256:1ecd87fb78edc5feada026b0f926bcf7458eb9c80db8100618e1df725645540e",
                "Labels": {
                    "com.docker.compose.config-hash": "d18573c6a89abeacddfab591aca6e68b2921b90a",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "rabbitmq",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [
                    {
                        "Destination": "/var/lib/rabbitmq",
                        "Driver": "local",
                        "Mode": "z",
                        "Name": "amqpdata",
                        "Propagation": "",
                        "RW": true,
                        "Source": "/var/lib/docker/volumes/amqpdata/_data",
                        "Type": "volume"
                    }
                ],
                "Names": [
                    "/rabbitmq"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "2eb072c87b19c95fac0f6121af754ea0cec052a27cb4f2aee8755c2aec92dfce",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.1",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:0a",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 15672,
                        "PublicPort": 15672,
                        "Type": "tcp"
                    },
                    {
                        "PrivatePort": 15691,
                        "Type": "tcp"
                    },
                    {
                        "PrivatePort": 15692,
                        "Type": "tcp"
                    },
                    {
                        "PrivatePort": 25672,
                        "Type": "tcp"
                    },
                    {
                        "PrivatePort": 4369,
                        "Type": "tcp"
                    },
                    {
                        "PrivatePort": 5671,
                        "Type": "tcp"
                    },
                    {
                        "PrivatePort": 5672,
                        "Type": "tcp"
                    },
                    {
                        "PrivatePort": 15671,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            },
            {
                "Command": "/entrypoint.sh",
                "Created": 1608557349,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "0b7479a2f6abb93887cfb881dc8e4464e48df384887cb483c99a134cf894644b",
                "Image": "opencti/platform:4.0.3",
                "ImageID": "sha256:b03e4ab4fe4739d8ef6cd6a6639ccea8e09eaee8f6fb8842be9225c3719e27cd",
                "Labels": {
                    "com.docker.compose.config-hash": "22687afb96da8b20f51629f9868dfd237ad601a6",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "opencti",
                    "com.docker.compose.version": "1.5.0"
                },
                "Mounts": [],
                "Names": [
                    "/opencti"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "588234b49254b09744635401d2c95f092f7884bac7ae85e3e23e6cccab00abb7",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.1",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:0b",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 8080,
                        "PublicPort": 8080,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            },
            {
                "Command": "/usr/bin/docker-entrypoint.sh server /data",
                "Created": 1608557040,
                "HostConfig": {
                    "NetworkMode": "openctiv4_default"
                },
                "Id": "cddbc48191628fde8991adfed5d0e4c2704f4e09b9b79d96549be8baf608984d",
                "Image": "minio/minio:RELEASE.2020-12-12T08-39-07Z",
                "ImageID": "sha256:f1a30c1dd760a7927d12a559c55fcf6ccb7efbbe79295ecc9394b7e4fe21d216",
                "Labels": {
                    "architecture": "x86_64",
                    "build-date": "2020-10-31T05:07:05.471303",
                    "com.docker.compose.config-hash": "da8a89d63690ae08df58294ad3685f61c201125e",
                    "com.docker.compose.container-number": "1",
                    "com.docker.compose.oneoff": "False",
                    "com.docker.compose.project": "openctiv4",
                    "com.docker.compose.service": "minio",
                    "com.docker.compose.version": "1.5.0",
                    "com.redhat.build-host": "cpt-1002.osbs.prod.upshift.rdu2.redhat.com",
                    "com.redhat.component": "ubi8-minimal-container",
                    "com.redhat.license_terms": "https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI",
                    "description": "MinIO object storage is fundamentally different. Designed for performance and the S3 API, it is 100% open-source. MinIO is ideal for large, private cloud environments with stringent security requirements and delivers mission-critical availability across a diverse range of workloads.",
                    "distribution-scope": "public",
                    "io.k8s.description": "The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.",
                    "io.k8s.display-name": "Red Hat Universal Base Image 8 Minimal",
                    "io.openshift.expose-services": "",
                    "io.openshift.tags": "minimal rhel8",
                    "maintainer": "MinIO Inc <dev@min.io>",
                    "name": "MinIO",
                    "release": "RELEASE.2020-11-25T22-36-25Z",
                    "summary": "MinIO is a High Performance Object Storage, API compatible with Amazon S3 cloud storage service.",
                    "url": "https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.3-201",
                    "vcs-ref": "f53dab37c7541dd0080f410727c5886e85c09ee7",
                    "vcs-type": "git",
                    "vendor": "MinIO Inc <dev@min.io>",
                    "version": "RELEASE.2020-11-25T22-36-25Z"
                },
                "Mounts": [
                    {
                        "Destination": "/data",
                        "Driver": "local",
                        "Mode": "z",
                        "Name": "s3data",
                        "Propagation": "",
                        "RW": true,
                        "Source": "/var/lib/docker/volumes/s3data/_data",
                        "Type": "volume"
                    }
                ],
                "Names": [
                    "/minio"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "openctiv4_default": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "b3d4562edf6ea434a58ac398ca2c179cb95740af5e4c3bf970499544413397a4",
                            "Gateway": "1.0.0.5",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": {},
                            "IPAddress": "1.0.0.5",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:18:00:05",
                            "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 9000,
                        "PublicPort": 5000,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            },
            {
                "Command": "/portainer",
                "Created": 1608307988,
                "HostConfig": {
                    "NetworkMode": "default"
                },
                "Id": "63de66e6e323ae7e189aeeba070adc184b386456ffe0dde9e3a88b8da0660d54",
                "Image": "portainer/portainer-ce",
                "ImageID": "sha256:a0a227bf03ddc8b88bbb74b1b84a8a7220c8fa95b122cbde2a7444f32dc30659",
                "Labels": {},
                "Mounts": [
                    {
                        "Destination": "/data",
                        "Driver": "local",
                        "Mode": "z",
                        "Name": "portainer_data",
                        "Propagation": "",
                        "RW": true,
                        "Source": "/var/lib/docker/volumes/portainer_data/_data",
                        "Type": "volume"
                    },
                    {
                        "Destination": "/var/run/docker.sock",
                        "Mode": "",
                        "Propagation": "rprivate",
                        "RW": true,
                        "Source": "/var/run/docker.sock",
                        "Type": "bind"
                    }
                ],
                "Names": [
                    "/portainer"
                ],
                "NetworkSettings": {
                    "Networks": {
                        "bridge": {
                            "Aliases": null,
                            "DriverOpts": null,
                            "EndpointID": "338cd95d726c3fde9674c4e86a9754ad5041ed9f3ea67b533224d8d27f2203f8",
                            "Gateway": "1.0.0.7",
                            "GlobalIPv6Address": "",
                            "GlobalIPv6PrefixLen": 0,
                            "IPAMConfig": null,
                            "IPAddress": "1.0.0.3",
                            "IPPrefixLen": 16,
                            "IPv6Gateway": "",
                            "Links": null,
                            "MacAddress": "02:42:ac:11:00:03",
                            "NetworkID": "bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34"
                        }
                    }
                },
                "Ports": [
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 8000,
                        "PublicPort": 8000,
                        "Type": "tcp"
                    },
                    {
                        "IP": "0.0.0.0",
                        "PrivatePort": 9000,
                        "PublicPort": 9000,
                        "Type": "tcp"
                    }
                ],
                "State": "running",
                "Status": "Up 23 minutes"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Command|Created|HostConfig|Id|Image|ImageID|Labels|Mounts|Names|NetworkSettings|Ports|State|Status|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| tini -- /docker-entrypoint.sh mongo-express | 1609920735 | NetworkMode: mongodb_default | 57d49db83f2ced79c87e5c50d2b407bbb7bc33c3a95a03e142477f3a3b79ded5 | mongo-express | sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e | com.docker.compose.config-hash: 0a75befcc34f36ab677c5d8f09d2ee8063e8ad3d<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: mongodb<br/>com.docker.compose.service: mongo-express<br/>com.docker.compose.version: 1.5.0 |  | /mongodb-express | Networks: {"mongodb_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b", "EndpointID": "2628f2ac3df2f3b5a8059fe3e736d9fe9da4d428c9da9220dad5d2eb100258fa", "Gateway": "1.0.0.1", "IPAddress": "1.0.0.3", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:1a:00:03", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 8081, 'PublicPort': 8081, 'Type': 'tcp'} | running | Up 23 minutes |
>| docker-entrypoint.sh mongod | 1609920723 | NetworkMode: mongodb_default | 161f9d908f5bc34a9638a496b492cce47a16cd47268ec61f04e10b1224dbd2a3 | mongo | sha256:c97feb3412a387d4d3bbd8653b09ef26683263a192e0e8dc6554e65bfb637a86 | com.docker.compose.config-hash: 74e20e7feccade15ae2ce2378088081ae5726a05<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: mongodb<br/>com.docker.compose.service: mongo<br/>com.docker.compose.version: 1.5.0 | {'Type': 'volume', 'Name': 'mongodb', 'Source': '/var/lib/docker/volumes/mongodb/_data', 'Destination': '/data/db', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''},<br/>{'Type': 'volume', 'Name': '88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55', 'Source': '', 'Destination': '/data/configdb', 'Driver': 'local', 'Mode': '', 'RW': True, 'Propagation': ''} | /mongodb | Networks: {"mongodb_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b", "EndpointID": "2f478dd56c3bfa4b0bfb2a6bdfa5a7f95f20960dbc5045238567f4f7c2b5e46d", "Gateway": "1.0.0.1", "IPAddress": "1.0.0.2", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:1a:00:02", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 27017, 'PublicPort': 27017, 'Type': 'tcp'} | running | Up 23 minutes |
>| /entrypoint.sh /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000 | 1609863181 | NetworkMode: bridge | 04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94 | eclecticiq/opentaxii:latest | sha256:aa50897f28e43c1110328f1b8740a2ad097031e8d2443266e562fe74be1a7a19 | maintainer: EclecticIQ <opentaxii@eclecticiq.com> | {'Type': 'volume', 'Name': 'opentaxii-data', 'Source': '/var/lib/docker/volumes/opentaxii-data/_data', 'Destination': '/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''},<br/>{'Type': 'volume', 'Name': 'opentaxii-input', 'Source': '/var/lib/docker/volumes/opentaxii-input/_data', 'Destination': '/input', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''} | /test-taxii | Networks: {"bridge": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34", "EndpointID": "3fccdab7ca5ad3f11ef72dd8d76044160c0cc66e005643d9584fbcb903500c1b", "Gateway": "1.0.0.7", "IPAddress": "1.0.0.2", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:11:00:02", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 9000, 'PublicPort': 6000, 'Type': 'tcp'} | running | Up 23 minutes |
>| /entrypoint.sh | 1608827060 | NetworkMode: openctiv4_default | 14d3c9c9c306e427b8cd4a2e4d80ddd6ad38684936224f3e36440b6b6f08bc34 | opencti/connector-ipinfo:4.0.3 | sha256:cd608aa8a042cb46adf5aaa3c43ce92a85b3817c5254b8de0e53b49b7a729c6b | com.docker.compose.config-hash: 3a9bd111dfb135ed1a839ad5e164068c78b2b630<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: connector-export-file-stix<br/>com.docker.compose.version: 1.5.0 |  | /opencti_connector-ipinfo | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "717ad998186f308ebefb4f0f71c04ae5fbc143e450bed9eba8570d9adc099624", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:08", "DriverOpts": null}} |  | running | Up 22 minutes |
>| /entrypoint.sh | 1608564498 | NetworkMode: openctiv4_default | 7ba5c18139e09bd2a34e7be27db70520c6901dad7db901dd073c1f96abfc9034 | opencti/connector-import-file-pdf-observables:4.0.3 | sha256:51afb662d3c993510447e431e3da8495140690cb9c1ca93c7cf19424a63ce223 | com.docker.compose.config-hash: 336a368bc6eb7eae69a090a9ac80f9614d02685e<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: connector-import-file-pdf-observables<br/>com.docker.compose.version: 1.5.0 |  | /opencti_connector-import-file-pdf-observables | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "e99d6307854d91785af35603157c0a82826a5ebe59b3072924770dd7e66be07c", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.2", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:02", "DriverOpts": null}} |  | running | Up 22 minutes |
>| /entrypoint.sh | 1608564460 | NetworkMode: openctiv4_default | 2aa24d29411d89e1d3fcd708b0dae10e32a84d53d9164a5998c217e054d31bd9 | opencti/connector-import-file-stix:4.0.3 | sha256:cfd88d87460e5c1e0d7c82ee58258208c80d8acbd9417afe2f7cea10bfef4dd9 | com.docker.compose.config-hash: d39640557a02e44f4983eac94b75e00a8b975e07<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: connector-import-file-stix<br/>com.docker.compose.version: 1.5.0 |  | /opencti_connector-import-file-stix | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "254bd9e38c903fc40203b0935a627ff078764e0692e948af6e99088512909f5a", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:07", "DriverOpts": null}} |  | running | Up 7 seconds |
>| /entrypoint.sh | 1608564417 | NetworkMode: openctiv4_default | 5f92895691ca7eeb6c8bc3f4914cd6210a3d59a72e8e48890f336d352cbc9753 | opencti/connector-export-file-csv:4.0.3 | sha256:25500204dfbea42059fc77100177de2c5d92cd4219ca6437831bfc26c53b628c | com.docker.compose.config-hash: 64d591ae3f975e1a79738447dd38d1e554486f44<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: connector-export-file-csv<br/>com.docker.compose.version: 1.5.0 |  | /opencti_connector-export-file-csv | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "91a3c7767104581ddb04f739c3cc313e7bfe0f6db5ad4c6865970d1e60bf99b7", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:09", "DriverOpts": null}} |  | running | Up 22 minutes |
>| /entrypoint.sh | 1608564294 | NetworkMode: openctiv4_default | 65ddee16a51d57e8b57f6b00acd7f9ae5b92152731276d6d4d497c2f979e2b1e | opencti/connector-export-file-stix:4.0.3 | sha256:42efb539088b86558557e24c10d00810014e5e820f0d7ac8bb8d0fd3981a0bda | com.docker.compose.config-hash: 3a9bd111dfb135ed1a839ad5e164068c78b2b630<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: connector-export-file-stix<br/>com.docker.compose.version: 1.5.0 |  | /opencti_connector-export-file-stix | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "8cd31e2f66b6df498962e8cc4df17f741b842546c4fd61ac9a79c2f6805f66bc", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:04", "DriverOpts": null}} |  | running | Up 22 minutes |
>| /entrypoint.sh | 1608564112 | NetworkMode: openctiv4_default | c61e3108d286e07032f8ec44f3e5883bac00838a673972e871c31d970b75d155 | opencti/connector-history:4.0.3 | sha256:0257f00635aca1087fa630362c470f22c4661bc87d4e6e8c54c64f5795dfce1e | com.docker.compose.config-hash: 6ac905cdbdc63d012688d34a06393c135d384c79<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: connector-history<br/>com.docker.compose.version: 1.5.0 |  | /opencti_connector-history | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "048b58a95cd8a27e6f640c844e9b5ea7c65c4fdcbdc5dfdc683986daf6813e4a", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:0d", "DriverOpts": null}} |  | running | Up 22 minutes |
>| /entrypoint.sh | 1608563957 | NetworkMode: openctiv4_default | 2220832cc2840320c53156993563fce5298d4e0317d71b42851067f02c762423 | opencti/connector-alienvault:4.0.3 | sha256:3e718135d5fb38c0af85c9c00b64160082a407722d929572a190d6092c604e15 | com.docker.compose.config-hash: 3a9bd111dfb135ed1a839ad5e164068c78b2b630<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: connector-export-file-stix<br/>com.docker.compose.version: 1.5.0 |  | /opencti_connector-alienvault | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "3a8b638639e908f26163f7271bb88eee017a3fc5cb253bf180e8b190ebca5a80", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:0c", "DriverOpts": null}} |  | running | Up 22 minutes |
>| /entrypoint.sh | 1608562731 | NetworkMode: openctiv4_default | cc1743f3d83750f973796d0aaadba7ec5fb67361906666b2a48be0512d82a050 | opencti/worker:4.0.3 | sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473 | com.docker.compose.config-hash: 4f611b1efe20fd3b147a1b830afceff276398af1<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: worker<br/>com.docker.compose.version: 1.5.0 |  | /opencti_worker_2 | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "03f052a4e86e16124c279fe9e593e4686fcc658b57d82b51c031163f2076cfc6", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:0e", "DriverOpts": null}} |  | running | Up 22 minutes |
>| /entrypoint.sh | 1608561358 | NetworkMode: openctiv4_default | 118fe891bacfe3328ad64677ac492f0568547740458090594600950613774fcf | opencti/worker:4.0.3 | sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473 | com.docker.compose.config-hash: 4f611b1efe20fd3b147a1b830afceff276398af1<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: worker<br/>com.docker.compose.version: 1.5.0 |  | /opencti_worker_1 | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "ce7645ab046233a84fc7c2c9ce796a120edfd790280a52fb9df55f2066458141", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:0f", "DriverOpts": null}} |  | running | Up 22 minutes |
>| docker-entrypoint.sh redis-server | 1608559382 | NetworkMode: openctiv4_default | 4be1f8dec98809ec2cf360d1d882beb8c819a58111070a04affbc714a071d1a0 | redis:6.0.9 | sha256:ef47f3b6dc11e8f17fb39a6e46ecaf4efd47b3d374e92aeb9f2606896b751251 | com.docker.compose.config-hash: daf5e1ad7b16619b8c479df88301daf432c5a564<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: redis<br/>com.docker.compose.version: 1.5.0 | {'Type': 'volume', 'Name': 'redisdata', 'Source': '/var/lib/docker/volumes/redisdata/_data', 'Destination': '/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''} | /redis | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "996d21e0ac5c57239c1622bba9c9a5d303a82cec1c15146a94c84766cd460966", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.3", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:03", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 6379, 'PublicPort': 6379, 'Type': 'tcp'} | running | Up 23 minutes |
>| /tini -- /usr/local/bin/docker-entrypoint.sh eswrapper | 1608559270 | NetworkMode: openctiv4_default | 5c3b991454ad1daa7d2f287cc0450d69f0c1e0a7778f8f55199b5201da3b5390 | docker.elastic.co/elasticsearch/elasticsearch:7.10.1 | sha256:558380375f1a36c20e67c3a0b7bf715c659d75520d0e688b066d5e708918d716 | com.docker.compose.config-hash: 6367ce3fdc8ac903d07574f97c9dc4a7208f3aef<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: elasticsearch<br/>com.docker.compose.version: 1.5.0<br/>org.label-schema.build-date: 2020-12-05T01:00:33.671820Z<br/>org.label-schema.license: Elastic-License<br/>org.label-schema.name: Elasticsearch<br/>org.label-schema.schema-version: 1.0<br/>org.label-schema.url: https://www.elastic.co/products/elasticsearch<br/>org.label-schema.usage: https://www.elastic.co/guide/en/elasticsearch/reference/index.html<br/>org.label-schema.vcs-ref: 1c34507e66d7db1211f66f3513706fdf548736aa<br/>org.label-schema.vcs-url: https://github.com/elastic/elasticsearch<br/>org.label-schema.vendor: Elastic<br/>org.label-schema.version: 7.10.1<br/>org.opencontainers.image.created: 2020-12-05T01:00:33.671820Z<br/>org.opencontainers.image.documentation: https://www.elastic.co/guide/en/elasticsearch/reference/index.html<br/>org.opencontainers.image.licenses: Elastic-License<br/>org.opencontainers.image.revision: 1c34507e66d7db1211f66f3513706fdf548736aa<br/>org.opencontainers.image.source: https://github.com/elastic/elasticsearch<br/>org.opencontainers.image.title: Elasticsearch<br/>org.opencontainers.image.url: https://www.elastic.co/products/elasticsearch<br/>org.opencontainers.image.vendor: Elastic<br/>org.opencontainers.image.version: 7.10.1 | {'Type': 'volume', 'Name': 'esdata', 'Source': '/var/lib/docker/volumes/esdata/_data', 'Destination': '/usr/share/elasticsearch/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''} | /elasticsearch | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "64904da59143266418038a1f64c1f7573d0a31f79ed0a32998ce94172ba49c88", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:06", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 9200, 'PublicPort': 9200, 'Type': 'tcp'},<br/>{'IP': '0.0.0.0', 'PrivatePort': 9300, 'PublicPort': 9300, 'Type': 'tcp'} | running | Up 23 minutes |
>| docker-entrypoint.sh rabbitmq-server | 1608559125 | NetworkMode: openctiv4_default | 93b8c8f3e5c5b959b5382b20ec3f441d1b960124419e809d86f0a34cee59d7c8 | rabbitmq:3.8-management | sha256:1ecd87fb78edc5feada026b0f926bcf7458eb9c80db8100618e1df725645540e | com.docker.compose.config-hash: d18573c6a89abeacddfab591aca6e68b2921b90a<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: rabbitmq<br/>com.docker.compose.version: 1.5.0 | {'Type': 'volume', 'Name': 'amqpdata', 'Source': '/var/lib/docker/volumes/amqpdata/_data', 'Destination': '/var/lib/rabbitmq', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''} | /rabbitmq | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "2eb072c87b19c95fac0f6121af754ea0cec052a27cb4f2aee8755c2aec92dfce", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.1", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:0a", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 15672, 'PublicPort': 15672, 'Type': 'tcp'},<br/>{'PrivatePort': 15691, 'Type': 'tcp'},<br/>{'PrivatePort': 15692, 'Type': 'tcp'},<br/>{'PrivatePort': 25672, 'Type': 'tcp'},<br/>{'PrivatePort': 4369, 'Type': 'tcp'},<br/>{'PrivatePort': 5671, 'Type': 'tcp'},<br/>{'PrivatePort': 5672, 'Type': 'tcp'},<br/>{'PrivatePort': 15671, 'Type': 'tcp'} | running | Up 23 minutes |
>| /entrypoint.sh | 1608557349 | NetworkMode: openctiv4_default | 0b7479a2f6abb93887cfb881dc8e4464e48df384887cb483c99a134cf894644b | opencti/platform:4.0.3 | sha256:b03e4ab4fe4739d8ef6cd6a6639ccea8e09eaee8f6fb8842be9225c3719e27cd | com.docker.compose.config-hash: 22687afb96da8b20f51629f9868dfd237ad601a6<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: opencti<br/>com.docker.compose.version: 1.5.0 |  | /opencti | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "588234b49254b09744635401d2c95f092f7884bac7ae85e3e23e6cccab00abb7", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.1", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:0b", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 8080, 'PublicPort': 8080, 'Type': 'tcp'} | running | Up 23 minutes |
>| /usr/bin/docker-entrypoint.sh server /data | 1608557040 | NetworkMode: openctiv4_default | cddbc48191628fde8991adfed5d0e4c2704f4e09b9b79d96549be8baf608984d | minio/minio:RELEASE.2020-12-12T08-39-07Z | sha256:f1a30c1dd760a7927d12a559c55fcf6ccb7efbbe79295ecc9394b7e4fe21d216 | architecture: x86_64<br/>build-date: 2020-10-31T05:07:05.471303<br/>com.docker.compose.config-hash: da8a89d63690ae08df58294ad3685f61c201125e<br/>com.docker.compose.container-number: 1<br/>com.docker.compose.oneoff: False<br/>com.docker.compose.project: openctiv4<br/>com.docker.compose.service: minio<br/>com.docker.compose.version: 1.5.0<br/>com.redhat.build-host: cpt-1002.osbs.prod.upshift.rdu2.redhat.com<br/>com.redhat.component: ubi8-minimal-container<br/>com.redhat.license_terms: https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI<br/>description: MinIO object storage is fundamentally different. Designed for performance and the S3 API, it is 100% open-source. MinIO is ideal for large, private cloud environments with stringent security requirements and delivers mission-critical availability across a diverse range of workloads.<br/>distribution-scope: public<br/>io.k8s.description: The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.<br/>io.k8s.display-name: Red Hat Universal Base Image 8 Minimal<br/>io.openshift.expose-services: <br/>io.openshift.tags: minimal rhel8<br/>maintainer: MinIO Inc <dev@min.io><br/>name: MinIO<br/>release: RELEASE.2020-11-25T22-36-25Z<br/>summary: MinIO is a High Performance Object Storage, API compatible with Amazon S3 cloud storage service.<br/>url: https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.3-201<br/>vcs-ref: f53dab37c7541dd0080f410727c5886e85c09ee7<br/>vcs-type: git<br/>vendor: MinIO Inc <dev@min.io><br/>version: RELEASE.2020-11-25T22-36-25Z | {'Type': 'volume', 'Name': 's3data', 'Source': '/var/lib/docker/volumes/s3data/_data', 'Destination': '/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''} | /minio | Networks: {"openctiv4_default": {"IPAMConfig": {}, "Links": null, "Aliases": null, "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86", "EndpointID": "b3d4562edf6ea434a58ac398ca2c179cb95740af5e4c3bf970499544413397a4", "Gateway": "1.0.0.5", "IPAddress": "1.0.0.5", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:18:00:05", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 9000, 'PublicPort': 5000, 'Type': 'tcp'} | running | Up 23 minutes |
>| /portainer | 1608307988 | NetworkMode: default | 63de66e6e323ae7e189aeeba070adc184b386456ffe0dde9e3a88b8da0660d54 | portainer/portainer-ce | sha256:a0a227bf03ddc8b88bbb74b1b84a8a7220c8fa95b122cbde2a7444f32dc30659 |  | {'Type': 'volume', 'Name': 'portainer_data', 'Source': '/var/lib/docker/volumes/portainer_data/_data', 'Destination': '/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''},<br/>{'Type': 'bind', 'Source': '/var/run/docker.sock', 'Destination': '/var/run/docker.sock', 'Mode': '', 'RW': True, 'Propagation': 'rprivate'} | /portainer | Networks: {"bridge": {"IPAMConfig": null, "Links": null, "Aliases": null, "NetworkID": "bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34", "EndpointID": "338cd95d726c3fde9674c4e86a9754ad5041ed9f3ea67b533224d8d27f2203f8", "Gateway": "1.0.0.7", "IPAddress": "1.0.0.3", "IPPrefixLen": 16, "IPv6Gateway": "", "GlobalIPv6Address": "", "GlobalIPv6PrefixLen": 0, "MacAddress": "02:42:ac:11:00:03", "DriverOpts": null}} | {'IP': '0.0.0.0', 'PrivatePort': 8000, 'PublicPort': 8000, 'Type': 'tcp'},<br/>{'IP': '0.0.0.0', 'PrivatePort': 9000, 'PublicPort': 9000, 'Type': 'tcp'} | running | Up 23 minutes |


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

#### Command Example
```!docker-container-stats id="04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94"```

#### Context Example
```json
{
    "Docker": {
        "blkio_stats": {
            "io_merged_recursive": [],
            "io_queue_recursive": [],
            "io_service_bytes_recursive": [
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Read",
                    "value": 51187712
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Write",
                    "value": 8192
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Sync",
                    "value": 51187712
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Async",
                    "value": 8192
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Discard",
                    "value": 0
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Total",
                    "value": 51195904
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Read",
                    "value": 51187712
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Write",
                    "value": 8192
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Sync",
                    "value": 51187712
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Async",
                    "value": 8192
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Discard",
                    "value": 0
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Total",
                    "value": 51195904
                }
            ],
            "io_service_time_recursive": [],
            "io_serviced_recursive": [
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Read",
                    "value": 921
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Write",
                    "value": 2
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Sync",
                    "value": 921
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Async",
                    "value": 2
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Discard",
                    "value": 0
                },
                {
                    "major": 8,
                    "minor": 0,
                    "op": "Total",
                    "value": 923
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Read",
                    "value": 903
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Write",
                    "value": 2
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Sync",
                    "value": 903
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Async",
                    "value": 2
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Discard",
                    "value": 0
                },
                {
                    "major": 253,
                    "minor": 0,
                    "op": "Total",
                    "value": 905
                }
            ],
            "io_time_recursive": [],
            "io_wait_time_recursive": [],
            "sectors_recursive": []
        },
        "cpu_stats": {
            "cpu_usage": {
                "percpu_usage": [
                    80337610,
                    246108128,
                    104408379,
                    375538972,
                    131439025,
                    327257147,
                    130127173,
                    187607760
                ],
                "total_usage": 1582824194,
                "usage_in_kernelmode": 150000000,
                "usage_in_usermode": 1400000000
            },
            "online_cpus": 8,
            "system_cpu_usage": 613825660000000,
            "throttling_data": {
                "periods": 0,
                "throttled_periods": 0,
                "throttled_time": 0
            }
        },
        "id": "04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94",
        "memory_stats": {
            "limit": 8143470592,
            "max_usage": 107409408,
            "stats": {
                "active_anon": 50569216,
                "active_file": 2973696,
                "cache": 48525312,
                "dirty": 0,
                "hierarchical_memory_limit": 9223372036854772000,
                "hierarchical_memsw_limit": 9223372036854772000,
                "inactive_anon": 0,
                "inactive_file": 45281280,
                "mapped_file": 14598144,
                "pgfault": 28974,
                "pgmajfault": 0,
                "pgpgin": 34947,
                "pgpgout": 10597,
                "rss": 50515968,
                "rss_huge": 0,
                "total_active_anon": 50569216,
                "total_active_file": 2973696,
                "total_cache": 48525312,
                "total_dirty": 0,
                "total_inactive_anon": 0,
                "total_inactive_file": 45281280,
                "total_mapped_file": 14598144,
                "total_pgfault": 28974,
                "total_pgmajfault": 0,
                "total_pgpgin": 34947,
                "total_pgpgout": 10597,
                "total_rss": 50515968,
                "total_rss_huge": 0,
                "total_unevictable": 0,
                "total_writeback": 0,
                "unevictable": 0,
                "writeback": 0
            },
            "usage": 107155456
        },
        "name": "/test-taxii",
        "networks": {
            "eth0": {
                "rx_bytes": 1436,
                "rx_dropped": 0,
                "rx_errors": 0,
                "rx_packets": 18,
                "tx_bytes": 0,
                "tx_dropped": 0,
                "tx_errors": 0,
                "tx_packets": 0
            }
        },
        "num_procs": 0,
        "pids_stats": {
            "current": 3
        },
        "precpu_stats": {
            "cpu_usage": {
                "percpu_usage": [
                    80234549,
                    246108128,
                    104408379,
                    375538972,
                    131439025,
                    327257147,
                    130127173,
                    187607760
                ],
                "total_usage": 1582721133,
                "usage_in_kernelmode": 150000000,
                "usage_in_usermode": 1400000000
            },
            "online_cpus": 8,
            "system_cpu_usage": 613817680000000,
            "throttling_data": {
                "periods": 0,
                "throttled_periods": 0,
                "throttled_time": 0
            }
        },
        "preread": "2021-01-10T07:34:03.405981877Z",
        "read": "2021-01-10T07:34:04.407988262Z",
        "storage_stats": {}
    }
}
```

#### Human Readable Output

>### Results
>|blkio_stats|cpu_stats|id|memory_stats|name|networks|num_procs|pids_stats|precpu_stats|preread|read|storage_stats|
>|---|---|---|---|---|---|---|---|---|---|---|---|
>| io_service_bytes_recursive: {'major': 8, 'minor': 0, 'op': 'Read', 'value': 51187712},<br/>{'major': 8, 'minor': 0, 'op': 'Write', 'value': 8192},<br/>{'major': 8, 'minor': 0, 'op': 'Sync', 'value': 51187712},<br/>{'major': 8, 'minor': 0, 'op': 'Async', 'value': 8192},<br/>{'major': 8, 'minor': 0, 'op': 'Discard', 'value': 0},<br/>{'major': 8, 'minor': 0, 'op': 'Total', 'value': 51195904},<br/>{'major': 253, 'minor': 0, 'op': 'Read', 'value': 51187712},<br/>{'major': 253, 'minor': 0, 'op': 'Write', 'value': 8192},<br/>{'major': 253, 'minor': 0, 'op': 'Sync', 'value': 51187712},<br/>{'major': 253, 'minor': 0, 'op': 'Async', 'value': 8192},<br/>{'major': 253, 'minor': 0, 'op': 'Discard', 'value': 0},<br/>{'major': 253, 'minor': 0, 'op': 'Total', 'value': 51195904}<br/>io_serviced_recursive: {'major': 8, 'minor': 0, 'op': 'Read', 'value': 921},<br/>{'major': 8, 'minor': 0, 'op': 'Write', 'value': 2},<br/>{'major': 8, 'minor': 0, 'op': 'Sync', 'value': 921},<br/>{'major': 8, 'minor': 0, 'op': 'Async', 'value': 2},<br/>{'major': 8, 'minor': 0, 'op': 'Discard', 'value': 0},<br/>{'major': 8, 'minor': 0, 'op': 'Total', 'value': 923},<br/>{'major': 253, 'minor': 0, 'op': 'Read', 'value': 903},<br/>{'major': 253, 'minor': 0, 'op': 'Write', 'value': 2},<br/>{'major': 253, 'minor': 0, 'op': 'Sync', 'value': 903},<br/>{'major': 253, 'minor': 0, 'op': 'Async', 'value': 2},<br/>{'major': 253, 'minor': 0, 'op': 'Discard', 'value': 0},<br/>{'major': 253, 'minor': 0, 'op': 'Total', 'value': 905}<br/>io_queue_recursive: <br/>io_service_time_recursive: <br/>io_wait_time_recursive: <br/>io_merged_recursive: <br/>io_time_recursive: <br/>sectors_recursive:  | cpu_usage: {"total_usage": 1582824194, "percpu_usage": [80337610, 246108128, 104408379, 375538972, 131439025, 327257147, 130127173, 187607760], "usage_in_kernelmode": 150000000, "usage_in_usermode": 1400000000}<br/>system_cpu_usage: 613825660000000<br/>online_cpus: 8<br/>throttling_data: {"periods": 0, "throttled_periods": 0, "throttled_time": 0} | 04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94 | usage: 107155456<br/>max_usage: 107409408<br/>stats: {"active_anon": 50569216, "active_file": 2973696, "cache": 48525312, "dirty": 0, "hierarchical_memory_limit": 9223372036854771712, "hierarchical_memsw_limit": 9223372036854771712, "inactive_anon": 0, "inactive_file": 45281280, "mapped_file": 14598144, "pgfault": 28974, "pgmajfault": 0, "pgpgin": 34947, "pgpgout": 10597, "rss": 50515968, "rss_huge": 0, "total_active_anon": 50569216, "total_active_file": 2973696, "total_cache": 48525312, "total_dirty": 0, "total_inactive_anon": 0, "total_inactive_file": 45281280, "total_mapped_file": 14598144, "total_pgfault": 28974, "total_pgmajfault": 0, "total_pgpgin": 34947, "total_pgpgout": 10597, "total_rss": 50515968, "total_rss_huge": 0, "total_unevictable": 0, "total_writeback": 0, "unevictable": 0, "writeback": 0}<br/>limit: 8143470592 | /test-taxii | eth0: {"rx_bytes": 1436, "rx_packets": 18, "rx_errors": 0, "rx_dropped": 0, "tx_bytes": 0, "tx_packets": 0, "tx_errors": 0, "tx_dropped": 0} | 0 | current: 3 | cpu_usage: {"total_usage": 1582721133, "percpu_usage": [80234549, 246108128, 104408379, 375538972, 131439025, 327257147, 130127173, 187607760], "usage_in_kernelmode": 150000000, "usage_in_usermode": 1400000000}<br/>system_cpu_usage: 613817680000000<br/>online_cpus: 8<br/>throttling_data: {"periods": 0, "throttled_periods": 0, "throttled_time": 0} | 2021-01-10T07:34:03.405981877Z | 2021-01-10T07:34:04.407988262Z |  |


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


#### Command Example
```!docker-container-top id="04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94"```

#### Context Example
```json
{
    "Docker": {
        "ContainerTopResponse": {
            "Processes": [
                [
                    "root",
                    "3830",
                    "3780",
                    "0",
                    "11:10",
                    "?",
                    "00:00:01",
                    "/venv/bin/python3 /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000"
                ],
                [
                    "root",
                    "6188",
                    "3830",
                    "0",
                    "11:10",
                    "?",
                    "00:00:00",
                    "/venv/bin/python3 /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000"
                ],
                [
                    "root",
                    "6190",
                    "3830",
                    "0",
                    "11:10",
                    "?",
                    "00:00:00",
                    "/venv/bin/python3 /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000"
                ]
            ],
            "Titles": [
                "UID",
                "PID",
                "PPID",
                "C",
                "STIME",
                "TTY",
                "TIME",
                "CMD"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|Processes|Titles|
>|---|---|
>| ['root', '3830', '3780', '0', '11:10', '?', '00:00:01', '/venv/bin/python3 /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000'],<br/>['root', '6188', '3830', '0', '11:10', '?', '00:00:00', '/venv/bin/python3 /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000'],<br/>['root', '6190', '3830', '0', '11:10', '?', '00:00:00', '/venv/bin/python3 /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000'] | UID,<br/>PID,<br/>PPID,<br/>C,<br/>STIME,<br/>TTY,<br/>TIME,<br/>CMD |


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


#### Command Example
```!docker-image-history name="05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e"```

#### Context Example
```json
{
    "Docker": {
        "HistoryResponseItem": [
            {
                "Comment": "",
                "Created": 1609870186,
                "CreatedBy": "/bin/sh -c #(nop)  CMD [\"mongo-express\"]",
                "Id": "sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e",
                "Size": 0,
                "Tags": [
                    "mongo-express:latest"
                ]
            },
            {
                "Comment": "",
                "Created": 1609870186,
                "CreatedBy": "/bin/sh -c #(nop)  ENTRYPOINT [\"tini\" \"--\" \"/docker-entrypoint.sh\"]",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609870186,
                "CreatedBy": "/bin/sh -c cp config.default.js config.js",
                "Id": "missing",
                "Size": 8142,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609870185,
                "CreatedBy": "/bin/sh -c #(nop) WORKDIR /node_modules/mongo-express",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609870185,
                "CreatedBy": "/bin/sh -c #(nop) COPY file:ad71ad0a2a1967b86be9140686f9a9aa6f78dc470d2ec9de89cbf1a25e85b550 in / ",
                "Id": "missing",
                "Size": 1017,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609870184,
                "CreatedBy": "/bin/sh -c set -eux; \tapk add --no-cache --virtual .me-install-deps git; \tnpm install mongo-express@$MONGO_EXPRESS; \tapk del --no-network .me-install-deps",
                "Id": "missing",
                "Size": 38458723,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609870163,
                "CreatedBy": "/bin/sh -c #(nop)  ENV MONGO_EXPRESS=0.54.0",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609870162,
                "CreatedBy": "/bin/sh -c #(nop)  ENV ME_CONFIG_EDITORTHEME=default ME_CONFIG_MONGODB_SERVER=mongo ME_CONFIG_MONGODB_ENABLE_ADMIN=true ME_CONFIG_BASICAUTH_USERNAME= ME_CONFIG_BASICAUTH_PASSWORD= VCAP_APP_HOST=0.0.0.0",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609870162,
                "CreatedBy": "/bin/sh -c #(nop)  EXPOSE 8081",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609870162,
                "CreatedBy": "/bin/sh -c apk add --no-cache bash tini",
                "Id": "missing",
                "Size": 2026658,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609867823,
                "CreatedBy": "/bin/sh -c #(nop)  CMD [\"node\"]",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609867822,
                "CreatedBy": "/bin/sh -c #(nop)  ENTRYPOINT [\"docker-entrypoint.sh\"]",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609867822,
                "CreatedBy": "/bin/sh -c #(nop) COPY file:238737301d47304174e4d24f4def935b29b3069c03c72ae8de97d94624382fce in /usr/local/bin/ ",
                "Id": "missing",
                "Size": 116,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609867821,
                "CreatedBy": "/bin/sh -c apk add --no-cache --virtual .build-deps-yarn curl gnupg tar   && for key in     6A010C5166006599AA17F08146C2130DFD2497F5   ; do     gpg --batch --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys \"$key\" ||     gpg --batch --keyserver hkp://ipv4.pool.sks-keyservers.net --recv-keys \"$key\" ||     gpg --batch --keyserver hkp://pgp.mit.edu:80 --recv-keys \"$key\" ;   done   && curl -fsSLO --compressed \"https://yarnpkg.com/downloads/$YARN_VERSION/yarn-v$YARN_VERSION.tar.gz\"   && curl -fsSLO --compressed \"https://yarnpkg.com/downloads/$YARN_VERSION/yarn-v$YARN_VERSION.tar.gz.asc\"   && gpg --batch --verify yarn-v$YARN_VERSION.tar.gz.asc yarn-v$YARN_VERSION.tar.gz   && mkdir -p /opt   && tar -xzf yarn-v$YARN_VERSION.tar.gz -C /opt/   && ln -s /opt/yarn-v$YARN_VERSION/bin/yarn /usr/local/bin/yarn   && ln -s /opt/yarn-v$YARN_VERSION/bin/yarnpkg /usr/local/bin/yarnpkg   && rm yarn-v$YARN_VERSION.tar.gz.asc yarn-v$YARN_VERSION.tar.gz   && apk del .build-deps-yarn   && yarn --version",
                "Id": "missing",
                "Size": 7622724,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609867816,
                "CreatedBy": "/bin/sh -c #(nop)  ENV YARN_VERSION=1.22.5",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609867816,
                "CreatedBy": "/bin/sh -c addgroup -g 1000 node     && adduser -u 1000 -G node -s /bin/sh -D node     && apk add --no-cache         libstdc++     && apk add --no-cache --virtual .build-deps         curl     && ARCH= && alpineArch=\"$(apk --print-arch)\"       && case \"${alpineArch##*-}\" in         x86_64)           ARCH='x64'           CHECKSUM=\"783fbfc85228418d0630b778214bdcea3a82d5c3ac13aefcc14e4a81e977d9c9\"           ;;         *) ;;       esac   && if [ -n \"${CHECKSUM}\" ]; then     set -eu;     curl -fsSLO --compressed \"https://unofficial-builds.nodejs.org/download/release/v$NODE_VERSION/node-v$NODE_VERSION-linux-$ARCH-musl.tar.xz\";     echo \"$CHECKSUM  node-v$NODE_VERSION-linux-$ARCH-musl.tar.xz\" | sha256sum -c -       && tar -xJf \"node-v$NODE_VERSION-linux-$ARCH-musl.tar.xz\" -C /usr/local --strip-components=1 --no-same-owner       && ln -s /usr/local/bin/node /usr/local/bin/nodejs;   else     echo \"Building from source\"     && apk add --no-cache --virtual .build-deps-full         binutils-gold         g++         gcc         gnupg         libgcc         linux-headers         make         python2     && for key in       4ED778F539E3634C779C87C6D7062848A1AB005C       94AE36675C464D64BAFA68DD7434390BDBE9B9C5       1C050899334244A8AF75E53792EF661D867B9DFA       71DCFD284A79C3B38668286BC97EC7A07EDE3FC1       8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600       C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8       C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C       DD8F2338BAE7501E3DD5AC78C273792F7D83545D       A48C2BEE680E841632CD4E44F07496B3EB3C1762       108F52B48DB57BB0CC439B2997B01419BD92F80A       B9E2F5981AA6E0CD28160D9FF13993A75599653C     ; do       gpg --batch --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys \"$key\" ||       gpg --batch --keyserver hkp://ipv4.pool.sks-keyservers.net --recv-keys \"$key\" ||       gpg --batch --keyserver hkp://pgp.mit.edu:80 --recv-keys \"$key\" ;     done     && curl -fsSLO --compressed \"https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION.tar.xz\"     && curl -fsSLO --compressed \"https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt.asc\"     && gpg --batch --decrypt --output SHASUMS256.txt SHASUMS256.txt.asc     && grep \" node-v$NODE_VERSION.tar.xz\\$\" SHASUMS256.txt | sha256sum -c -     && tar -xf \"node-v$NODE_VERSION.tar.xz\"     && cd \"node-v$NODE_VERSION\"     && ./configure     && make -j$(getconf _NPROCESSORS_ONLN) V=     && make install     && apk del .build-deps-full     && cd ..     && rm -Rf \"node-v$NODE_VERSION\"     && rm \"node-v$NODE_VERSION.tar.xz\" SHASUMS256.txt.asc SHASUMS256.txt;   fi   && rm -f \"node-v$NODE_VERSION-linux-$ARCH-musl.tar.xz\"   && apk del .build-deps   && node --version   && npm --version",
                "Id": "missing",
                "Size": 75656589,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1609867804,
                "CreatedBy": "/bin/sh -c #(nop)  ENV NODE_VERSION=12.20.1",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1608164389,
                "CreatedBy": "/bin/sh -c #(nop)  CMD [\"/bin/sh\"]",
                "Id": "missing",
                "Size": 0,
                "Tags": null
            },
            {
                "Comment": "",
                "Created": 1608164389,
                "CreatedBy": "/bin/sh -c #(nop) ADD file:8ed80010e443da19d72546bcee9a35e0a8d244c72052b1994610bf5939d479c2 in / ",
                "Id": "missing",
                "Size": 5614943,
                "Tags": null
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Comment|Created|CreatedBy|Id|Size|Tags|
>|---|---|---|---|---|---|
>|  | 1609870186 | /bin/sh -c #(nop)  CMD ["mongo-express"] | sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e | 0 | mongo-express:latest |
>|  | 1609870186 | /bin/sh -c cp config.default.js config.js | missing | 8142 |  |
>|  | 1609870185 | /bin/sh -c #(nop) WORKDIR /node_modules/mongo-express | missing | 0 |  |
>|  | 1609870185 | /bin/sh -c #(nop) COPY file:ad71ad0a2a1967b86be9140686f9a9aa6f78dc470d2ec9de89cbf1a25e85b550 in /  | missing | 1017 |  |
>|  | 1609870184 | /bin/sh -c set -eux; 	apk add --no-cache --virtual .me-install-deps git; 	npm install mongo-express@$MONGO_EXPRESS; 	apk del --no-network .me-install-deps | missing | 38458723 |  |
>|  | 1609870163 | /bin/sh -c #(nop)  ENV MONGO_EXPRESS=0.54.0 | missing | 0 |  |
>|  | 1609870162 | /bin/sh -c #(nop)  ENV ME_CONFIG_EDITORTHEME=default ME_CONFIG_MONGODB_SERVER=mongo ME_CONFIG_MONGODB_ENABLE_ADMIN=true ME_CONFIG_BASICAUTH_USERNAME= ME_CONFIG_BASICAUTH_PASSWORD= VCAP_APP_HOST=0.0.0.0 | missing | 0 |  |
>|  | 1609870162 | /bin/sh -c #(nop)  EXPOSE 8081 | missing | 0 |  |
>|  | 1609870162 | /bin/sh -c apk add --no-cache bash tini | missing | 2026658 |  |
>|  | 1609867823 | /bin/sh -c #(nop)  CMD ["node"] | missing | 0 |  |
>|  | 1609867822 | /bin/sh -c #(nop)  ENTRYPOINT ["docker-entrypoint.sh"] | missing | 0 |  |
>|  | 1609867822 | /bin/sh -c #(nop) COPY file:238737301d47304174e4d24f4def935b29b3069c03c72ae8de97d94624382fce in /usr/local/bin/  | missing | 116 |  |
>|  | 1609867821 | /bin/sh -c apk add --no-cache --virtual .build-deps-yarn curl gnupg tar   && for key in     6A010C5166006599AA17F08146C2130DFD2497F5   ; do     gpg --batch --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys "$key" \|\|     gpg --batch --keyserver hkp://ipv4.pool.sks-keyservers.net --recv-keys "$key" \|\|     gpg --batch --keyserver hkp://pgp.mit.edu:80 --recv-keys "$key" ;   done   && curl -fsSLO --compressed "https://yarnpkg.com/downloads/$YARN_VERSION/yarn-v$YARN_VERSION.tar.gz"   && curl -fsSLO --compressed "https://yarnpkg.com/downloads/$YARN_VERSION/yarn-v$YARN_VERSION.tar.gz.asc"   && gpg --batch --verify yarn-v$YARN_VERSION.tar.gz.asc yarn-v$YARN_VERSION.tar.gz   && mkdir -p /opt   && tar -xzf yarn-v$YARN_VERSION.tar.gz -C /opt/   && ln -s /opt/yarn-v$YARN_VERSION/bin/yarn /usr/local/bin/yarn   && ln -s /opt/yarn-v$YARN_VERSION/bin/yarnpkg /usr/local/bin/yarnpkg   && rm yarn-v$YARN_VERSION.tar.gz.asc yarn-v$YARN_VERSION.tar.gz   && apk del .build-deps-yarn   && yarn --version | missing | 7622724 |  |
>|  | 1609867816 | /bin/sh -c #(nop)  ENV YARN_VERSION=1.22.5 | missing | 0 |  |
>|  | 1609867816 | /bin/sh -c addgroup -g 1000 node     && adduser -u 1000 -G node -s /bin/sh -D node     && apk add --no-cache         libstdc++     && apk add --no-cache --virtual .build-deps         curl     && ARCH= && alpineArch="$(apk --print-arch)"       && case "${alpineArch##*-}" in         x86_64)           ARCH='x64'           CHECKSUM="783fbfc85228418d0630b778214bdcea3a82d5c3ac13aefcc14e4a81e977d9c9"           ;;         *) ;;       esac   && if [ -n "${CHECKSUM}" ]; then     set -eu;     curl -fsSLO --compressed "https://unofficial-builds.nodejs.org/download/release/v$NODE_VERSION/node-v$NODE_VERSION-linux-$ARCH-musl.tar.xz";     echo "$CHECKSUM  node-v$NODE_VERSION-linux-$ARCH-musl.tar.xz" \| sha256sum -c -       && tar -xJf "node-v$NODE_VERSION-linux-$ARCH-musl.tar.xz" -C /usr/local --strip-components=1 --no-same-owner       && ln -s /usr/local/bin/node /usr/local/bin/nodejs;   else     echo "Building from source"     && apk add --no-cache --virtual .build-deps-full         binutils-gold         g++         gcc         gnupg         libgcc         linux-headers         make         python2     && for key in       4ED778F539E3634C779C87C6D7062848A1AB005C       94AE36675C464D64BAFA68DD7434390BDBE9B9C5       1C050899334244A8AF75E53792EF661D867B9DFA       71DCFD284A79C3B38668286BC97EC7A07EDE3FC1       8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600       C4F0DFFF4E8C1A8236409D08E73BC641CC11F4C8       C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C       DD8F2338BAE7501E3DD5AC78C273792F7D83545D       A48C2BEE680E841632CD4E44F07496B3EB3C1762       108F52B48DB57BB0CC439B2997B01419BD92F80A       B9E2F5981AA6E0CD28160D9FF13993A75599653C     ; do       gpg --batch --keyserver hkp://p80.pool.sks-keyservers.net:80 --recv-keys "$key" \|\|       gpg --batch --keyserver hkp://ipv4.pool.sks-keyservers.net --recv-keys "$key" \|\|       gpg --batch --keyserver hkp://pgp.mit.edu:80 --recv-keys "$key" ;     done     && curl -fsSLO --compressed "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION.tar.xz"     && curl -fsSLO --compressed "https://nodejs.org/dist/v$NODE_VERSION/SHASUMS256.txt.asc"     && gpg --batch --decrypt --output SHASUMS256.txt SHASUMS256.txt.asc     && grep " node-v$NODE_VERSION.tar.xz\$" SHASUMS256.txt \| sha256sum -c -     && tar -xf "node-v$NODE_VERSION.tar.xz"     && cd "node-v$NODE_VERSION"     && ./configure     && make -j$(getconf _NPROCESSORS_ONLN) V=     && make install     && apk del .build-deps-full     && cd ..     && rm -Rf "node-v$NODE_VERSION"     && rm "node-v$NODE_VERSION.tar.xz" SHASUMS256.txt.asc SHASUMS256.txt;   fi   && rm -f "node-v$NODE_VERSION-linux-$ARCH-musl.tar.xz"   && apk del .build-deps   && node --version   && npm --version | missing | 75656589 |  |
>|  | 1609867804 | /bin/sh -c #(nop)  ENV NODE_VERSION=12.20.1 | missing | 0 |  |
>|  | 1608164389 | /bin/sh -c #(nop)  CMD ["/bin/sh"] | missing | 0 |  |
>|  | 1608164389 | /bin/sh -c #(nop) ADD file:8ed80010e443da19d72546bcee9a35e0a8d244c72052b1994610bf5939d479c2 in /  | missing | 5614943 |  |


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


#### Command Example
```!docker-image-inspect name="05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e"```

#### Context Example
```json
{
    "Docker": {
        "Image": {
            "Architecture": "amd64",
            "Author": "",
            "Comment": "",
            "Config": {
                "AttachStderr": false,
                "AttachStdin": false,
                "AttachStdout": false,
                "Cmd": [
                    "mongo-express"
                ],
                "Domainname": "",
                "Entrypoint": [
                    "tini",
                    "--",
                    "/docker-entrypoint.sh"
                ],
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "NODE_VERSION=12.20.1",
                    "YARN_VERSION=1.22.5",
                    "ME_CONFIG_EDITORTHEME=default",
                    "ME_CONFIG_MONGODB_SERVER=mongo",
                    "ME_CONFIG_MONGODB_ENABLE_ADMIN=true",
                    "ME_CONFIG_BASICAUTH_USERNAME=",
                    "ME_CONFIG_BASICAUTH_PASSWORD=",
                    "VCAP_APP_HOST=0.0.0.0",
                    "MONGO_EXPRESS=0.54.0"
                ],
                "ExposedPorts": {
                    "8081/tcp": {}
                },
                "Hostname": "",
                "Image": "sha256:a40e2035f4c886f16698034a527edd6a4c3bff2dbf22ecb5dcb461ac33ea798a",
                "Labels": null,
                "OnBuild": null,
                "OpenStdin": false,
                "StdinOnce": false,
                "Tty": false,
                "User": "",
                "Volumes": null,
                "WorkingDir": "/node_modules/mongo-express"
            },
            "Container": "91acb3f551fd19d56a0f0b1582f664f2069239a5d9ed999ac38dc161392fedc9",
            "ContainerConfig": {
                "AttachStderr": false,
                "AttachStdin": false,
                "AttachStdout": false,
                "Cmd": [
                    "/bin/sh",
                    "-c",
                    "#(nop) ",
                    "CMD [\"mongo-express\"]"
                ],
                "Domainname": "",
                "Entrypoint": [
                    "tini",
                    "--",
                    "/docker-entrypoint.sh"
                ],
                "Env": [
                    "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "NODE_VERSION=12.20.1",
                    "YARN_VERSION=1.22.5",
                    "ME_CONFIG_EDITORTHEME=default",
                    "ME_CONFIG_MONGODB_SERVER=mongo",
                    "ME_CONFIG_MONGODB_ENABLE_ADMIN=true",
                    "ME_CONFIG_BASICAUTH_USERNAME=",
                    "ME_CONFIG_BASICAUTH_PASSWORD=",
                    "VCAP_APP_HOST=0.0.0.0",
                    "MONGO_EXPRESS=0.54.0"
                ],
                "ExposedPorts": {
                    "8081/tcp": {}
                },
                "Hostname": "91acb3f551fd",
                "Image": "sha256:a40e2035f4c886f16698034a527edd6a4c3bff2dbf22ecb5dcb461ac33ea798a",
                "Labels": {},
                "OnBuild": null,
                "OpenStdin": false,
                "StdinOnce": false,
                "Tty": false,
                "User": "",
                "Volumes": null,
                "WorkingDir": "/node_modules/mongo-express"
            },
            "Created": "2021-01-05T18:09:46.916579532Z",
            "DockerVersion": "19.03.12",
            "GraphDriver": {
                "Data": {
                    "LowerDir": "/var/lib/docker/overlay2/c0484e122f4fe26b7f63c04e38ccc18b2a932ae7ba00a1f223d966ce6889ec8d/diff:/var/lib/docker/overlay2/eab51a1fd1f1abde2b80839670b68909d0edbd1ae5528526308ee496593da92d/diff:/var/lib/docker/overlay2/f152df862c74cc8f87423425a78c618e38285b61ad193e5c9d69abc4b801ebfd/diff:/var/lib/docker/overlay2/79be70a57f5523e094ddf66406736876bda8d400cf4e41cae52650b938c1ea4f/diff:/var/lib/docker/overlay2/a0082ccffb2ad9b0bf73e98617defb1511ba6537c21709675b2b2b474f9c9642/diff:/var/lib/docker/overlay2/5b5385f706911829168165cd805284c213400e11c849838a9835e44e8c81692c/diff:/var/lib/docker/overlay2/a621ef67bdf8bbd8965845f159240e790d8bd621fa123f97e94c56b9828bf0b3/diff",
                    "MergedDir": "/var/lib/docker/overlay2/5c7904a490e6f7f175426b17d1d9ef26951da650895e437bfc36ec11a99e4c37/merged",
                    "UpperDir": "/var/lib/docker/overlay2/5c7904a490e6f7f175426b17d1d9ef26951da650895e437bfc36ec11a99e4c37/diff",
                    "WorkDir": "/var/lib/docker/overlay2/5c7904a490e6f7f175426b17d1d9ef26951da650895e437bfc36ec11a99e4c37/work"
                },
                "Name": "overlay2"
            },
            "Id": "sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e",
            "Metadata": {
                "LastTagTime": "0001-01-01T00:00:00Z"
            },
            "Os": "linux",
            "Parent": "",
            "RepoDigests": [
                "mongo-express@sha256:6ae44c697cd2381772f8ea8f0571008b62e36301305b113df7f35f2e683e8255"
            ],
            "RepoTags": [
                "mongo-express:latest"
            ],
            "RootFS": {
                "Layers": [
                    "sha256:0fcbbeeeb0d7fc5c06362d7a6717b999e605574c7210eff4f7418f6e9be9fbfe",
                    "sha256:62d0a87660b82baeaac545f86febf9fa085015fc446edaa836b06189662a21bf",
                    "sha256:ab2b283144664cdf32922dbb6e6febceee3941aed7d77840765959d131b4cfd1",
                    "sha256:6693766656f04c9719744dcfa046c0d51c12676eb75880f325ccebf56a9a1d60",
                    "sha256:09a8b406deae52f384b03c2e7914f65fdbda67c412e4c7249542407e825fda9d",
                    "sha256:1a0d48792d28c938b4decb611fb3eebe6bf4efe4405ccfc1d77229bfd47a0ca4",
                    "sha256:a88f4e88722d6d6a553a5f35b624e6d6b1e20e3b22bb6c099524d437223dcba3",
                    "sha256:4257a8584459b164c82f0e8da2c79ada2f760d82dfee8bcd26f77a2de2f82a06"
                ],
                "Type": "layers"
            },
            "Size": 129388912,
            "VirtualSize": 129388912
        }
    }
}
```

#### Human Readable Output

>### Results
>|Architecture|Author|Comment|Config|Container|ContainerConfig|Created|DockerVersion|GraphDriver|Id|Metadata|Os|Parent|RepoDigests|RepoTags|RootFS|Size|VirtualSize|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| amd64 |  |  | Hostname: <br/>Domainname: <br/>User: <br/>AttachStdin: false<br/>AttachStdout: false<br/>AttachStderr: false<br/>ExposedPorts: {"8081/tcp": {}}<br/>Tty: false<br/>OpenStdin: false<br/>StdinOnce: false<br/>Env: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,<br/>NODE_VERSION=12.20.1,<br/>YARN_VERSION=1.22.5,<br/>ME_CONFIG_EDITORTHEME=default,<br/>ME_CONFIG_MONGODB_SERVER=mongo,<br/>ME_CONFIG_MONGODB_ENABLE_ADMIN=true,<br/>ME_CONFIG_BASICAUTH_USERNAME=,<br/>ME_CONFIG_BASICAUTH_PASSWORD=,<br/>VCAP_APP_HOST=0.0.0.0,<br/>MONGO_EXPRESS=0.54.0<br/>Cmd: mongo-express<br/>Image: sha256:a40e2035f4c886f16698034a527edd6a4c3bff2dbf22ecb5dcb461ac33ea798a<br/>Volumes: null<br/>WorkingDir: /node_modules/mongo-express<br/>Entrypoint: tini,<br/>--,<br/>/docker-entrypoint.sh<br/>OnBuild: null<br/>Labels: null | 91acb3f551fd19d56a0f0b1582f664f2069239a5d9ed999ac38dc161392fedc9 | Hostname: 91acb3f551fd<br/>Domainname: <br/>User: <br/>AttachStdin: false<br/>AttachStdout: false<br/>AttachStderr: false<br/>ExposedPorts: {"8081/tcp": {}}<br/>Tty: false<br/>OpenStdin: false<br/>StdinOnce: false<br/>Env: PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin,<br/>NODE_VERSION=12.20.1,<br/>YARN_VERSION=1.22.5,<br/>ME_CONFIG_EDITORTHEME=default,<br/>ME_CONFIG_MONGODB_SERVER=mongo,<br/>ME_CONFIG_MONGODB_ENABLE_ADMIN=true,<br/>ME_CONFIG_BASICAUTH_USERNAME=,<br/>ME_CONFIG_BASICAUTH_PASSWORD=,<br/>VCAP_APP_HOST=0.0.0.0,<br/>MONGO_EXPRESS=0.54.0<br/>Cmd: /bin/sh,<br/>-c,<br/>#(nop) ,<br/>CMD ["mongo-express"]<br/>Image: sha256:a40e2035f4c886f16698034a527edd6a4c3bff2dbf22ecb5dcb461ac33ea798a<br/>Volumes: null<br/>WorkingDir: /node_modules/mongo-express<br/>Entrypoint: tini,<br/>--,<br/>/docker-entrypoint.sh<br/>OnBuild: null<br/>Labels: {} | 2021-01-05T18:09:46.916579532Z | 19.03.12 | Data: {"LowerDir": "/var/lib/docker/overlay2/c0484e122f4fe26b7f63c04e38ccc18b2a932ae7ba00a1f223d966ce6889ec8d/diff:/var/lib/docker/overlay2/eab51a1fd1f1abde2b80839670b68909d0edbd1ae5528526308ee496593da92d/diff:/var/lib/docker/overlay2/f152df862c74cc8f87423425a78c618e38285b61ad193e5c9d69abc4b801ebfd/diff:/var/lib/docker/overlay2/79be70a57f5523e094ddf66406736876bda8d400cf4e41cae52650b938c1ea4f/diff:/var/lib/docker/overlay2/a0082ccffb2ad9b0bf73e98617defb1511ba6537c21709675b2b2b474f9c9642/diff:/var/lib/docker/overlay2/5b5385f706911829168165cd805284c213400e11c849838a9835e44e8c81692c/diff:/var/lib/docker/overlay2/a621ef67bdf8bbd8965845f159240e790d8bd621fa123f97e94c56b9828bf0b3/diff", "MergedDir": "/var/lib/docker/overlay2/5c7904a490e6f7f175426b17d1d9ef26951da650895e437bfc36ec11a99e4c37/merged", "UpperDir": "/var/lib/docker/overlay2/5c7904a490e6f7f175426b17d1d9ef26951da650895e437bfc36ec11a99e4c37/diff", "WorkDir": "/var/lib/docker/overlay2/5c7904a490e6f7f175426b17d1d9ef26951da650895e437bfc36ec11a99e4c37/work"}<br/>Name: overlay2 | sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e | LastTagTime: 0001-01-01T00:00:00Z | linux |  | mongo-express@sha256:6ae44c697cd2381772f8ea8f0571008b62e36301305b113df7f35f2e683e8255 | mongo-express:latest | Type: layers<br/>Layers: sha256:0fcbbeeeb0d7fc5c06362d7a6717b999e605574c7210eff4f7418f6e9be9fbfe,<br/>sha256:62d0a87660b82baeaac545f86febf9fa085015fc446edaa836b06189662a21bf,<br/>sha256:ab2b283144664cdf32922dbb6e6febceee3941aed7d77840765959d131b4cfd1,<br/>sha256:6693766656f04c9719744dcfa046c0d51c12676eb75880f325ccebf56a9a1d60,<br/>sha256:09a8b406deae52f384b03c2e7914f65fdbda67c412e4c7249542407e825fda9d,<br/>sha256:1a0d48792d28c938b4decb611fb3eebe6bf4efe4405ccfc1d77229bfd47a0ca4,<br/>sha256:a88f4e88722d6d6a553a5f35b624e6d6b1e20e3b22bb6c099524d437223dcba3,<br/>sha256:4257a8584459b164c82f0e8da2c79ada2f760d82dfee8bcd26f77a2de2f82a06 | 129388912 | 129388912 |


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


#### Command Example
```!docker-image-list```

#### Context Example
```json
{
    "Docker": {
        "ImageSummary": [
            {
                "Containers": -1,
                "Created": 1609870186,
                "Id": "sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "mongo-express@sha256:6ae44c697cd2381772f8ea8f0571008b62e36301305b113df7f35f2e683e8255"
                ],
                "RepoTags": [
                    "mongo-express:latest"
                ],
                "SharedSize": -1,
                "Size": 129388912,
                "VirtualSize": 129388912
            },
            {
                "Containers": -1,
                "Created": 1609866227,
                "Id": "sha256:70d8624ce3a1f02008bcdb8ba2bf4001e178bcb0ab90bdfab0eb17fd4ea2ca7f",
                "Labels": null,
                "ParentId": "sha256:c6c592c10fd1c88676835629a4b9d19f3e1354ca7d927c2d829628a53b427b3c",
                "RepoDigests": null,
                "RepoTags": [
                    "taxiserver:latest"
                ],
                "SharedSize": -1,
                "Size": 298529298,
                "VirtualSize": 298529298
            },
            {
                "Containers": -1,
                "Created": 1609798872,
                "Id": "sha256:c97feb3412a387d4d3bbd8653b09ef26683263a192e0e8dc6554e65bfb637a86",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "mongo@sha256:7722bd2778a299b6f4a62b93a0d2741c734ba7332a090131030ca28261a9a198"
                ],
                "RepoTags": [
                    "mongo:latest"
                ],
                "SharedSize": -1,
                "Size": 492934722,
                "VirtualSize": 492934722
            },
            {
                "Containers": -1,
                "Created": 1608474777,
                "Id": "sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/worker@sha256:5eef44425b59c272135cb6460232891cd607ccc4b5557a441cce3120624b9538"
                ],
                "RepoTags": [
                    "opencti/worker:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 129818770,
                "VirtualSize": 129818770
            },
            {
                "Containers": -1,
                "Created": 1608474717,
                "Id": "sha256:b03e4ab4fe4739d8ef6cd6a6639ccea8e09eaee8f6fb8842be9225c3719e27cd",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/platform@sha256:19a610656b32bf6ff894e04a0dcf9064ce3e850b3fc2f497f5478a21598753e5"
                ],
                "RepoTags": [
                    "opencti/platform:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 718444737,
                "VirtualSize": 718444737
            },
            {
                "Containers": -1,
                "Created": 1608473851,
                "Id": "sha256:0257f00635aca1087fa630362c470f22c4661bc87d4e6e8c54c64f5795dfce1e",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/connector-history@sha256:a80726951eb8d10acb6700c1ba1a602178e672f52b72787ed23f79d473d588cc"
                ],
                "RepoTags": [
                    "opencti/connector-history:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 68894193,
                "VirtualSize": 68894193
            },
            {
                "Containers": -1,
                "Created": 1608473623,
                "Id": "sha256:cd608aa8a042cb46adf5aaa3c43ce92a85b3817c5254b8de0e53b49b7a729c6b",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/connector-ipinfo@sha256:ae818dcf18b0acf5bdd25279ada6feb7f05c9b1745c847d3930a1fdaee555c57"
                ],
                "RepoTags": [
                    "opencti/connector-ipinfo:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 94145314,
                "VirtualSize": 94145314
            },
            {
                "Containers": -1,
                "Created": 1608472895,
                "Id": "sha256:3e718135d5fb38c0af85c9c00b64160082a407722d929572a190d6092c604e15",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/connector-alienvault@sha256:417b9cf7ed4f8ab5ebb391c52a38decfa306ef89b5dbc1853a85280f75fdd78d"
                ],
                "RepoTags": [
                    "opencti/connector-alienvault:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 67196705,
                "VirtualSize": 67196705
            },
            {
                "Containers": -1,
                "Created": 1608472820,
                "Id": "sha256:25500204dfbea42059fc77100177de2c5d92cd4219ca6437831bfc26c53b628c",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/connector-export-file-csv@sha256:d36ba9933590e3ade436fefa790fe03918a561cc69a944b473fc8eac5ca580f0"
                ],
                "RepoTags": [
                    "opencti/connector-export-file-csv:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 66382884,
                "VirtualSize": 66382884
            },
            {
                "Containers": -1,
                "Created": 1608472784,
                "Id": "sha256:42efb539088b86558557e24c10d00810014e5e820f0d7ac8bb8d0fd3981a0bda",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/connector-export-file-stix@sha256:3f0d74c5c77295edff0e7bb8ff7fa67db496c9f851b52643d705a0044d0fd67b"
                ],
                "RepoTags": [
                    "opencti/connector-export-file-stix:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 66377600,
                "VirtualSize": 66377600
            },
            {
                "Containers": -1,
                "Created": 1608472749,
                "Id": "sha256:51afb662d3c993510447e431e3da8495140690cb9c1ca93c7cf19424a63ce223",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/connector-import-file-pdf-observables@sha256:1f778d9cfb81b3f1d7e4456b9123022dca285da4bd5431360035dd13ec23e9ca"
                ],
                "RepoTags": [
                    "opencti/connector-import-file-pdf-observables:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 114490806,
                "VirtualSize": 114490806
            },
            {
                "Containers": -1,
                "Created": 1608472472,
                "Id": "sha256:cfd88d87460e5c1e0d7c82ee58258208c80d8acbd9417afe2f7cea10bfef4dd9",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/connector-import-file-stix@sha256:2e43819b4d1ef5f4de3a74382e5334e52647100553ea1b411a5bad87fa9e2984"
                ],
                "RepoTags": [
                    "opencti/connector-import-file-stix:4.0.3"
                ],
                "SharedSize": -1,
                "Size": 66375700,
                "VirtualSize": 66375700
            },
            {
                "Containers": -1,
                "Created": 1608200626,
                "Id": "sha256:dca5e1ed7218f3145b4414b6599a8aec9385857664bd6cc928ea9fba26febf3f",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "opencti/platform@sha256:183a3c085644615eab322d9d460d875c4d6b3f4c03bd5c4bac3e467771c79bdf"
                ],
                "RepoTags": [
                    "opencti/platform:4.0.2",
                    "opencti/platform:latest"
                ],
                "SharedSize": -1,
                "Size": 718413368,
                "VirtualSize": 718413368
            },
            {
                "Containers": -1,
                "Created": 1608165887,
                "Id": "sha256:1ecd87fb78edc5feada026b0f926bcf7458eb9c80db8100618e1df725645540e",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "rabbitmq@sha256:849677f6903921038a4541dd907e48a7d0e64a4cea63302acd73f9ee208789ce"
                ],
                "RepoTags": [
                    "rabbitmq:3.8-management"
                ],
                "SharedSize": -1,
                "Size": 197693093,
                "VirtualSize": 197693093
            },
            {
                "Containers": -1,
                "Created": 1608160149,
                "Id": "sha256:959fcab9b1e95d6d7ec1fc4c25491dd7e8cf43aed7346e089d2b564f83cbf58b",
                "Labels": {
                    "maintainer": "ownCloud DevOps <devops@owncloud.com>",
                    "org.label-schema.build-date": "2020-12-16T23:07:14Z",
                    "org.label-schema.name": "ownCloud Server",
                    "org.label-schema.schema-version": "1.0",
                    "org.label-schema.vcs-ref": "6da3457d723a5ffee6bc0eea945e0ba3fdbd629b",
                    "org.label-schema.vcs-url": "https://github.com/owncloud-docker/server.git",
                    "org.label-schema.vendor": "ownCloud GmbH"
                },
                "ParentId": "",
                "RepoDigests": [
                    "owncloud/server@sha256:e5be595c31734b25133c69aec27c32e87fe011201540b940f1acbd629f910691"
                ],
                "RepoTags": [
                    "owncloud/server:latest"
                ],
                "SharedSize": -1,
                "Size": 1363203435,
                "VirtualSize": 1363203435
            },
            {
                "Containers": -1,
                "Created": 1607763909,
                "Id": "sha256:f1a30c1dd760a7927d12a559c55fcf6ccb7efbbe79295ecc9394b7e4fe21d216",
                "Labels": {
                    "architecture": "x86_64",
                    "build-date": "2020-10-31T05:07:05.471303",
                    "com.redhat.build-host": "cpt-1002.osbs.prod.upshift.rdu2.redhat.com",
                    "com.redhat.component": "ubi8-minimal-container",
                    "com.redhat.license_terms": "https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI",
                    "description": "MinIO object storage is fundamentally different. Designed for performance and the S3 API, it is 100% open-source. MinIO is ideal for large, private cloud environments with stringent security requirements and delivers mission-critical availability across a diverse range of workloads.",
                    "distribution-scope": "public",
                    "io.k8s.description": "The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.",
                    "io.k8s.display-name": "Red Hat Universal Base Image 8 Minimal",
                    "io.openshift.expose-services": "",
                    "io.openshift.tags": "minimal rhel8",
                    "maintainer": "MinIO Inc <dev@min.io>",
                    "name": "MinIO",
                    "release": "RELEASE.2020-11-25T22-36-25Z",
                    "summary": "MinIO is a High Performance Object Storage, API compatible with Amazon S3 cloud storage service.",
                    "url": "https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.3-201",
                    "vcs-ref": "f53dab37c7541dd0080f410727c5886e85c09ee7",
                    "vcs-type": "git",
                    "vendor": "MinIO Inc <dev@min.io>",
                    "version": "RELEASE.2020-11-25T22-36-25Z"
                },
                "ParentId": "",
                "RepoDigests": [
                    "minio/minio@sha256:a2eeb964863632a274f3eed08fc256b790ca83a020e164dd18e1e5f402d9f8d4"
                ],
                "RepoTags": [
                    "minio/minio:RELEASE.2020-12-12T08-39-07Z"
                ],
                "SharedSize": -1,
                "Size": 182261690,
                "VirtualSize": 182261690
            },
            {
                "Containers": -1,
                "Created": 1607703900,
                "Id": "sha256:ef47f3b6dc11e8f17fb39a6e46ecaf4efd47b3d374e92aeb9f2606896b751251",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "redis@sha256:0f724af268d0d3f5fb1d6b33fc22127ba5cbca2d58523b286ed3122db0dc5381"
                ],
                "RepoTags": [
                    "redis:6.0.9"
                ],
                "SharedSize": -1,
                "Size": 104252176,
                "VirtualSize": 104252176
            },
            {
                "Containers": -1,
                "Created": 1607130473,
                "Id": "sha256:558380375f1a36c20e67c3a0b7bf715c659d75520d0e688b066d5e708918d716",
                "Labels": {
                    "org.label-schema.build-date": "2020-12-05T01:00:33.671820Z",
                    "org.label-schema.license": "Elastic-License",
                    "org.label-schema.name": "Elasticsearch",
                    "org.label-schema.schema-version": "1.0",
                    "org.label-schema.url": "https://www.elastic.co/products/elasticsearch",
                    "org.label-schema.usage": "https://www.elastic.co/guide/en/elasticsearch/reference/index.html",
                    "org.label-schema.vcs-ref": "1c34507e66d7db1211f66f3513706fdf548736aa",
                    "org.label-schema.vcs-url": "https://github.com/elastic/elasticsearch",
                    "org.label-schema.vendor": "Elastic",
                    "org.label-schema.version": "7.10.1",
                    "org.opencontainers.image.created": "2020-12-05T01:00:33.671820Z",
                    "org.opencontainers.image.documentation": "https://www.elastic.co/guide/en/elasticsearch/reference/index.html",
                    "org.opencontainers.image.licenses": "Elastic-License",
                    "org.opencontainers.image.revision": "1c34507e66d7db1211f66f3513706fdf548736aa",
                    "org.opencontainers.image.source": "https://github.com/elastic/elasticsearch",
                    "org.opencontainers.image.title": "Elasticsearch",
                    "org.opencontainers.image.url": "https://www.elastic.co/products/elasticsearch",
                    "org.opencontainers.image.vendor": "Elastic",
                    "org.opencontainers.image.version": "7.10.1"
                },
                "ParentId": "",
                "RepoDigests": [
                    "docker.elastic.co/elasticsearch/elasticsearch@sha256:5d8f1962907ef60746a8cf61c8a7f2b8755510ee36bdee0f65417f90a38a0139"
                ],
                "RepoTags": [
                    "docker.elastic.co/elasticsearch/elasticsearch:7.10.1"
                ],
                "SharedSize": -1,
                "Size": 773756675,
                "VirtualSize": 773756675
            },
            {
                "Containers": -1,
                "Created": 1598864687,
                "Id": "sha256:a0a227bf03ddc8b88bbb74b1b84a8a7220c8fa95b122cbde2a7444f32dc30659",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "portainer/portainer-ce@sha256:0ab9d25e9ac7b663a51afc6853875b2055d8812fcaf677d0013eba32d0bf0e0d"
                ],
                "RepoTags": [
                    "portainer/portainer-ce:latest"
                ],
                "SharedSize": -1,
                "Size": 195546824,
                "VirtualSize": 195546824
            },
            {
                "Containers": -1,
                "Created": 1578014497,
                "Id": "sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "hello-world@sha256:1a523af650137b8accdaed439c17d684df61ee4d74feac151b5b337bd29e7eec"
                ],
                "RepoTags": [
                    "hello-world:latest"
                ],
                "SharedSize": -1,
                "Size": 13336,
                "VirtualSize": 13336
            },
            {
                "Containers": -1,
                "Created": 1573631696,
                "Id": "sha256:3f6237885724af871088cfbb9d787ea4aebb37c0565e207e897c7f51ce0ad0ed",
                "Labels": {
                    "maintainer": "Thomas Boerger <thomas@webhippie.de>",
                    "org.label-schema.build-date": "2019-11-13T07:54:28Z",
                    "org.label-schema.name": "MariaDB",
                    "org.label-schema.schema-version": "1.0",
                    "org.label-schema.vcs-ref": "1e1f1924a0477f837c8a4399467594a0a5c3bada",
                    "org.label-schema.vcs-url": "https://github.com/dockhippie/mariadb.git",
                    "org.label-schema.vendor": "Thomas Boerger",
                    "org.label-schema.version": "latest"
                },
                "ParentId": "",
                "RepoDigests": [
                    "webhippie/mariadb@sha256:8a2c927529e5fd6238f08f79e3855d90a353e4475481574aa4bf0b90550b5db9"
                ],
                "RepoTags": [
                    "webhippie/mariadb:latest"
                ],
                "SharedSize": -1,
                "Size": 656206898,
                "VirtualSize": 656206898
            },
            {
                "Containers": -1,
                "Created": 1573631680,
                "Id": "sha256:42ab00c664c227dce98aec279e4098cb569084d6597e562dd226c98df32dc058",
                "Labels": {
                    "maintainer": "Thomas Boerger <thomas@webhippie.de>",
                    "org.label-schema.build-date": "2019-11-13T07:54:26Z",
                    "org.label-schema.name": "Redis",
                    "org.label-schema.schema-version": "1.0",
                    "org.label-schema.vcs-ref": "7b176b8e39cb973ed19aee8243ba63a6e75ffe60",
                    "org.label-schema.vcs-url": "https://github.com/dockhippie/redis.git",
                    "org.label-schema.vendor": "Thomas Boerger",
                    "org.label-schema.version": "latest"
                },
                "ParentId": "",
                "RepoDigests": [
                    "webhippie/redis@sha256:42f6d51be6a7a5ef6fb672e98507824816566f0b1f89c19b2d585f54e26b2529"
                ],
                "RepoTags": [
                    "webhippie/redis:latest"
                ],
                "SharedSize": -1,
                "Size": 59184716,
                "VirtualSize": 59184716
            },
            {
                "Containers": -1,
                "Created": 1551262109,
                "Id": "sha256:aa50897f28e43c1110328f1b8740a2ad097031e8d2443266e562fe74be1a7a19",
                "Labels": {
                    "maintainer": "EclecticIQ <opentaxii@eclecticiq.com>"
                },
                "ParentId": "",
                "RepoDigests": [
                    "eclecticiq/opentaxii@sha256:647b07724ae60b31accaf57a56fb8e7ee8f25506e3d283dce5ef6ca89002d662"
                ],
                "RepoTags": [
                    "eclecticiq/opentaxii:latest"
                ],
                "SharedSize": -1,
                "Size": 188188625,
                "VirtualSize": 188188625
            },
            {
                "Containers": -1,
                "Created": 1548789201,
                "Id": "sha256:f3f4b8ddca6feca170e6239933cbf5139f52d8496737df497911850440f40a5a",
                "Labels": null,
                "ParentId": "",
                "RepoDigests": [
                    "adoptopenjdk/openjdk11-openj9@sha256:60718fa9eb6b6bc4ab6fe7f3a9db31b8725fb63ebdda833a43f541c07792ff5c"
                ],
                "RepoTags": [
                    "adoptopenjdk/openjdk11-openj9:jdk-x.x.x.x-alpine-slim"
                ],
                "SharedSize": -1,
                "Size": 237380314,
                "VirtualSize": 237380314
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Containers|Created|Id|Labels|ParentId|RepoDigests|RepoTags|SharedSize|Size|VirtualSize|
>|---|---|---|---|---|---|---|---|---|---|
>| -1 | 1609870186 | sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e |  |  | mongo-express@sha256:6ae44c697cd2381772f8ea8f0571008b62e36301305b113df7f35f2e683e8255 | mongo-express:latest | -1 | 129388912 | 129388912 |
>| -1 | 1609866227 | sha256:70d8624ce3a1f02008bcdb8ba2bf4001e178bcb0ab90bdfab0eb17fd4ea2ca7f |  | sha256:c6c592c10fd1c88676835629a4b9d19f3e1354ca7d927c2d829628a53b427b3c |  | taxiserver:latest | -1 | 298529298 | 298529298 |
>| -1 | 1609798872 | sha256:c97feb3412a387d4d3bbd8653b09ef26683263a192e0e8dc6554e65bfb637a86 |  |  | mongo@sha256:7722bd2778a299b6f4a62b93a0d2741c734ba7332a090131030ca28261a9a198 | mongo:latest | -1 | 492934722 | 492934722 |
>| -1 | 1608474777 | sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473 |  |  | opencti/worker@sha256:5eef44425b59c272135cb6460232891cd607ccc4b5557a441cce3120624b9538 | opencti/worker:4.0.3 | -1 | 129818770 | 129818770 |
>| -1 | 1608474717 | sha256:b03e4ab4fe4739d8ef6cd6a6639ccea8e09eaee8f6fb8842be9225c3719e27cd |  |  | opencti/platform@sha256:19a610656b32bf6ff894e04a0dcf9064ce3e850b3fc2f497f5478a21598753e5 | opencti/platform:4.0.3 | -1 | 718444737 | 718444737 |
>| -1 | 1608473851 | sha256:0257f00635aca1087fa630362c470f22c4661bc87d4e6e8c54c64f5795dfce1e |  |  | opencti/connector-history@sha256:a80726951eb8d10acb6700c1ba1a602178e672f52b72787ed23f79d473d588cc | opencti/connector-history:4.0.3 | -1 | 68894193 | 68894193 |
>| -1 | 1608473623 | sha256:cd608aa8a042cb46adf5aaa3c43ce92a85b3817c5254b8de0e53b49b7a729c6b |  |  | opencti/connector-ipinfo@sha256:ae818dcf18b0acf5bdd25279ada6feb7f05c9b1745c847d3930a1fdaee555c57 | opencti/connector-ipinfo:4.0.3 | -1 | 94145314 | 94145314 |
>| -1 | 1608472895 | sha256:3e718135d5fb38c0af85c9c00b64160082a407722d929572a190d6092c604e15 |  |  | opencti/connector-alienvault@sha256:417b9cf7ed4f8ab5ebb391c52a38decfa306ef89b5dbc1853a85280f75fdd78d | opencti/connector-alienvault:4.0.3 | -1 | 67196705 | 67196705 |
>| -1 | 1608472820 | sha256:25500204dfbea42059fc77100177de2c5d92cd4219ca6437831bfc26c53b628c |  |  | opencti/connector-export-file-csv@sha256:d36ba9933590e3ade436fefa790fe03918a561cc69a944b473fc8eac5ca580f0 | opencti/connector-export-file-csv:4.0.3 | -1 | 66382884 | 66382884 |
>| -1 | 1608472784 | sha256:42efb539088b86558557e24c10d00810014e5e820f0d7ac8bb8d0fd3981a0bda |  |  | opencti/connector-export-file-stix@sha256:3f0d74c5c77295edff0e7bb8ff7fa67db496c9f851b52643d705a0044d0fd67b | opencti/connector-export-file-stix:4.0.3 | -1 | 66377600 | 66377600 |
>| -1 | 1608472749 | sha256:51afb662d3c993510447e431e3da8495140690cb9c1ca93c7cf19424a63ce223 |  |  | opencti/connector-import-file-pdf-observables@sha256:1f778d9cfb81b3f1d7e4456b9123022dca285da4bd5431360035dd13ec23e9ca | opencti/connector-import-file-pdf-observables:4.0.3 | -1 | 114490806 | 114490806 |
>| -1 | 1608472472 | sha256:cfd88d87460e5c1e0d7c82ee58258208c80d8acbd9417afe2f7cea10bfef4dd9 |  |  | opencti/connector-import-file-stix@sha256:2e43819b4d1ef5f4de3a74382e5334e52647100553ea1b411a5bad87fa9e2984 | opencti/connector-import-file-stix:4.0.3 | -1 | 66375700 | 66375700 |
>| -1 | 1608200626 | sha256:dca5e1ed7218f3145b4414b6599a8aec9385857664bd6cc928ea9fba26febf3f |  |  | opencti/platform@sha256:183a3c085644615eab322d9d460d875c4d6b3f4c03bd5c4bac3e467771c79bdf | opencti/platform:4.0.2,<br/>opencti/platform:latest | -1 | 718413368 | 718413368 |
>| -1 | 1608165887 | sha256:1ecd87fb78edc5feada026b0f926bcf7458eb9c80db8100618e1df725645540e |  |  | rabbitmq@sha256:849677f6903921038a4541dd907e48a7d0e64a4cea63302acd73f9ee208789ce | rabbitmq:3.8-management | -1 | 197693093 | 197693093 |
>| -1 | 1608160149 | sha256:959fcab9b1e95d6d7ec1fc4c25491dd7e8cf43aed7346e089d2b564f83cbf58b | maintainer: ownCloud DevOps <devops@owncloud.com><br/>org.label-schema.build-date: 2020-12-16T23:07:14Z<br/>org.label-schema.name: ownCloud Server<br/>org.label-schema.schema-version: 1.0<br/>org.label-schema.vcs-ref: 6da3457d723a5ffee6bc0eea945e0ba3fdbd629b<br/>org.label-schema.vcs-url: https://github.com/owncloud-docker/server.git<br/>org.label-schema.vendor: ownCloud GmbH |  | owncloud/server@sha256:e5be595c31734b25133c69aec27c32e87fe011201540b940f1acbd629f910691 | owncloud/server:latest | -1 | 1363203435 | 1363203435 |
>| -1 | 1607763909 | sha256:f1a30c1dd760a7927d12a559c55fcf6ccb7efbbe79295ecc9394b7e4fe21d216 | architecture: x86_64<br/>build-date: 2020-10-31T05:07:05.471303<br/>com.redhat.build-host: cpt-1002.osbs.prod.upshift.rdu2.redhat.com<br/>com.redhat.component: ubi8-minimal-container<br/>com.redhat.license_terms: https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI<br/>description: MinIO object storage is fundamentally different. Designed for performance and the S3 API, it is 100% open-source. MinIO is ideal for large, private cloud environments with stringent security requirements and delivers mission-critical availability across a diverse range of workloads.<br/>distribution-scope: public<br/>io.k8s.description: The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.<br/>io.k8s.display-name: Red Hat Universal Base Image 8 Minimal<br/>io.openshift.expose-services: <br/>io.openshift.tags: minimal rhel8<br/>maintainer: MinIO Inc <dev@min.io><br/>name: MinIO<br/>release: RELEASE.2020-11-25T22-36-25Z<br/>summary: MinIO is a High Performance Object Storage, API compatible with Amazon S3 cloud storage service.<br/>url: https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.3-201<br/>vcs-ref: f53dab37c7541dd0080f410727c5886e85c09ee7<br/>vcs-type: git<br/>vendor: MinIO Inc <dev@min.io><br/>version: RELEASE.2020-11-25T22-36-25Z |  | minio/minio@sha256:a2eeb964863632a274f3eed08fc256b790ca83a020e164dd18e1e5f402d9f8d4 | minio/minio:RELEASE.2020-12-12T08-39-07Z | -1 | 182261690 | 182261690 |
>| -1 | 1607703900 | sha256:ef47f3b6dc11e8f17fb39a6e46ecaf4efd47b3d374e92aeb9f2606896b751251 |  |  | redis@sha256:0f724af268d0d3f5fb1d6b33fc22127ba5cbca2d58523b286ed3122db0dc5381 | redis:6.0.9 | -1 | 104252176 | 104252176 |
>| -1 | 1607130473 | sha256:558380375f1a36c20e67c3a0b7bf715c659d75520d0e688b066d5e708918d716 | org.label-schema.build-date: 2020-12-05T01:00:33.671820Z<br/>org.label-schema.license: Elastic-License<br/>org.label-schema.name: Elasticsearch<br/>org.label-schema.schema-version: 1.0<br/>org.label-schema.url: https://www.elastic.co/products/elasticsearch<br/>org.label-schema.usage: https://www.elastic.co/guide/en/elasticsearch/reference/index.html<br/>org.label-schema.vcs-ref: 1c34507e66d7db1211f66f3513706fdf548736aa<br/>org.label-schema.vcs-url: https://github.com/elastic/elasticsearch<br/>org.label-schema.vendor: Elastic<br/>org.label-schema.version: 7.10.1<br/>org.opencontainers.image.created: 2020-12-05T01:00:33.671820Z<br/>org.opencontainers.image.documentation: https://www.elastic.co/guide/en/elasticsearch/reference/index.html<br/>org.opencontainers.image.licenses: Elastic-License<br/>org.opencontainers.image.revision: 1c34507e66d7db1211f66f3513706fdf548736aa<br/>org.opencontainers.image.source: https://github.com/elastic/elasticsearch<br/>org.opencontainers.image.title: Elasticsearch<br/>org.opencontainers.image.url: https://www.elastic.co/products/elasticsearch<br/>org.opencontainers.image.vendor: Elastic<br/>org.opencontainers.image.version: 7.10.1 |  | docker.elastic.co/elasticsearch/elasticsearch@sha256:5d8f1962907ef60746a8cf61c8a7f2b8755510ee36bdee0f65417f90a38a0139 | docker.elastic.co/elasticsearch/elasticsearch:7.10.1 | -1 | 773756675 | 773756675 |
>| -1 | 1598864687 | sha256:a0a227bf03ddc8b88bbb74b1b84a8a7220c8fa95b122cbde2a7444f32dc30659 |  |  | portainer/portainer-ce@sha256:0ab9d25e9ac7b663a51afc6853875b2055d8812fcaf677d0013eba32d0bf0e0d | portainer/portainer-ce:latest | -1 | 195546824 | 195546824 |
>| -1 | 1578014497 | sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b |  |  | hello-world@sha256:1a523af650137b8accdaed439c17d684df61ee4d74feac151b5b337bd29e7eec | hello-world:latest | -1 | 13336 | 13336 |
>| -1 | 1573631696 | sha256:3f6237885724af871088cfbb9d787ea4aebb37c0565e207e897c7f51ce0ad0ed | maintainer: Thomas Boerger <thomas@webhippie.de><br/>org.label-schema.build-date: 2019-11-13T07:54:28Z<br/>org.label-schema.name: MariaDB<br/>org.label-schema.schema-version: 1.0<br/>org.label-schema.vcs-ref: 1e1f1924a0477f837c8a4399467594a0a5c3bada<br/>org.label-schema.vcs-url: https://github.com/dockhippie/mariadb.git<br/>org.label-schema.vendor: Thomas Boerger<br/>org.label-schema.version: latest |  | webhippie/mariadb@sha256:8a2c927529e5fd6238f08f79e3855d90a353e4475481574aa4bf0b90550b5db9 | webhippie/mariadb:latest | -1 | 656206898 | 656206898 |
>| -1 | 1573631680 | sha256:42ab00c664c227dce98aec279e4098cb569084d6597e562dd226c98df32dc058 | maintainer: Thomas Boerger <thomas@webhippie.de><br/>org.label-schema.build-date: 2019-11-13T07:54:26Z<br/>org.label-schema.name: Redis<br/>org.label-schema.schema-version: 1.0<br/>org.label-schema.vcs-ref: 7b176b8e39cb973ed19aee8243ba63a6e75ffe60<br/>org.label-schema.vcs-url: https://github.com/dockhippie/redis.git<br/>org.label-schema.vendor: Thomas Boerger<br/>org.label-schema.version: latest |  | webhippie/redis@sha256:42f6d51be6a7a5ef6fb672e98507824816566f0b1f89c19b2d585f54e26b2529 | webhippie/redis:latest | -1 | 59184716 | 59184716 |
>| -1 | 1551262109 | sha256:aa50897f28e43c1110328f1b8740a2ad097031e8d2443266e562fe74be1a7a19 | maintainer: EclecticIQ <opentaxii@eclecticiq.com> |  | eclecticiq/opentaxii@sha256:647b07724ae60b31accaf57a56fb8e7ee8f25506e3d283dce5ef6ca89002d662 | eclecticiq/opentaxii:latest | -1 | 188188625 | 188188625 |
>| -1 | 1548789201 | sha256:f3f4b8ddca6feca170e6239933cbf5139f52d8496737df497911850440f40a5a |  |  | adoptopenjdk/openjdk11-openj9@sha256:60718fa9eb6b6bc4ab6fe7f3a9db31b8725fb63ebdda833a43f541c07792ff5c | adoptopenjdk/openjdk11-openj9:jdk-x.x.x.x-alpine-slim | -1 | 237380314 | 237380314 |


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


#### Command Example
```!docker-image-prune```

#### Context Example
```json
{
    "Docker": {
        "ImagePruneResponse": {
            "ImagesDeleted": null,
            "SpaceReclaimed": 0
        }
    }
}
```

#### Human Readable Output

>### Results
>|ImagesDeleted|SpaceReclaimed|
>|---|---|
>|  | 0 |

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
```!docker-image-push name="example/alpine:test"```
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


#### Command Example
```!docker-image-search term="centos"```

#### Context Example
```json
{
    "Docker": {
        "ImageSearchResponseItem": [
            {
                "description": "The official build of CentOS.",
                "is_automated": false,
                "is_official": true,
                "name": "centos",
                "star_count": 6365
            },
            {
                "description": "CentOS image for GPDB development. Tag names often have GCC because we make flavors based on that",
                "is_automated": false,
                "is_official": false,
                "name": "pivotaldata/centos-gpdb-dev",
                "star_count": 13
            },
            {
                "description": "Using the mingw toolchain to cross-compile to Windows from CentOS",
                "is_automated": false,
                "is_official": false,
                "name": "pivotaldata/centos-mingw",
                "star_count": 3
            },
            {
                "description": "Base centos, freshened up a little with a Dockerfile action",
                "is_automated": false,
                "is_official": false,
                "name": "pivotaldata/centos",
                "star_count": 5
            },
            {
                "description": "OpenSSH / Supervisor / EPEL/IUS/SCL Repos - CentOS.",
                "is_automated": true,
                "is_official": false,
                "name": "jdeathe/centos-ssh",
                "star_count": 117
            },
            {
                "description": "Ansible on Centos7",
                "is_automated": true,
                "is_official": false,
                "name": "ansible/centos7-ansible",
                "star_count": 132
            },
            {
                "description": "Centos container with \"headless\" VNC session, Xfce4 UI and preinstalled Firefox and Chrome browser",
                "is_automated": true,
                "is_official": false,
                "name": "consol/centos-xfce-vnc",
                "star_count": 124
            },
            {
                "description": "CentOS with a toolchain, but unaffiliated with GPDB or any other particular product",
                "is_automated": false,
                "is_official": false,
                "name": "pivotaldata/centos-gcc-toolchain",
                "star_count": 3
            },
            {
                "description": "CentOS with SSH",
                "is_automated": true,
                "is_official": false,
                "name": "kinogmt/centos-ssh",
                "star_count": 29
            },
            {
                "description": "centos6-lnmp-php56",
                "is_automated": true,
                "is_official": false,
                "name": "imagine10255/centos6-lnmp-php56",
                "star_count": 58
            },
            {
                "description": "systemd enabled base container. ",
                "is_automated": true,
                "is_official": false,
                "name": "centos/systemd",
                "star_count": 92
            },
            {
                "description": "centos with smartentry",
                "is_automated": true,
                "is_official": false,
                "name": "smartentry/centos",
                "star_count": 0
            },
            {
                "description": "CentOS Base Image! Built and Updates Daily!",
                "is_automated": true,
                "is_official": false,
                "name": "blacklabelops/centos",
                "star_count": 1
            },
            {
                "description": "centos ruby",
                "is_automated": true,
                "is_official": false,
                "name": "drecom/centos-ruby",
                "star_count": 6
            },
            {
                "description": "Simple CentOS docker image with SSH access",
                "is_automated": false,
                "is_official": false,
                "name": "tutum/centos",
                "star_count": 46
            },
            {
                "description": "Base Centos Image -- Updated hourly",
                "is_automated": true,
                "is_official": false,
                "name": "darksheer/centos",
                "star_count": 3
            },
            {
                "description": "Vanilla CentOS 7 with Oracle Java Development Kit 8 and latest Maven version.",
                "is_automated": true,
                "is_official": false,
                "name": "indigo/centos-maven",
                "star_count": 1
            },
            {
                "description": "CentosOS 7 image for GPDB development",
                "is_automated": false,
                "is_official": false,
                "name": "pivotaldata/centos7-dev",
                "star_count": 0
            },
            {
                "description": "centos base image",
                "is_automated": true,
                "is_official": false,
                "name": "mcnaughton/centos-base",
                "star_count": 1
            },
            {
                "description": "MySQL 5.7 SQL database server\n",
                "is_automated": false,
                "is_official": false,
                "name": "centos/mysql-57-centos7",
                "star_count": 86
            },
            {
                "description": "Docker image that has systems administration tools used on CentOS Atomic host",
                "is_automated": true,
                "is_official": false,
                "name": "centos/tools",
                "star_count": 7
            },
            {
                "description": "Oracle Java 8 Docker image based on Centos 7",
                "is_automated": true,
                "is_official": false,
                "name": "mamohr/centos-java",
                "star_count": 3
            },
            {
                "description": "Latest CentOS image with the JRE pre-installed.",
                "is_automated": true,
                "is_official": false,
                "name": "nathonfowlie/centos-jre",
                "star_count": 8
            },
            {
                "description": "MariaDB 10.1 SQL database server\n",
                "is_automated": false,
                "is_official": false,
                "name": "centos/mariadb-101-centos7",
                "star_count": 12
            },
            {
                "description": "PostgreSQL is an advanced Object-Relational database management system\n",
                "is_automated": false,
                "is_official": false,
                "name": "centos/postgresql-96-centos7",
                "star_count": 45
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|description|is_automated|is_official|name|star_count|
>|---|---|---|---|---|
>| The official build of CentOS. | false | true | centos | 6365 |
>| CentOS image for GPDB development. Tag names often have GCC because we make flavors based on that | false | false | pivotaldata/centos-gpdb-dev | 13 |
>| Using the mingw toolchain to cross-compile to Windows from CentOS | false | false | pivotaldata/centos-mingw | 3 |
>| Base centos, freshened up a little with a Dockerfile action | false | false | pivotaldata/centos | 5 |
>| OpenSSH / Supervisor / EPEL/IUS/SCL Repos - CentOS. | true | false | jdeathe/centos-ssh | 117 |
>| Ansible on Centos7 | true | false | ansible/centos7-ansible | 132 |
>| Centos container with "headless" VNC session, Xfce4 UI and preinstalled Firefox and Chrome browser | true | false | consol/centos-xfce-vnc | 124 |
>| CentOS with a toolchain, but unaffiliated with GPDB or any other particular product | false | false | pivotaldata/centos-gcc-toolchain | 3 |
>| CentOS with SSH | true | false | kinogmt/centos-ssh | 29 |
>| centos6-lnmp-php56 | true | false | imagine10255/centos6-lnmp-php56 | 58 |
>| systemd enabled base container.  | true | false | centos/systemd | 92 |
>| centos with smartentry | true | false | smartentry/centos | 0 |
>| CentOS Base Image! Built and Updates Daily! | true | false | blacklabelops/centos | 1 |
>| centos ruby | true | false | drecom/centos-ruby | 6 |
>| Simple CentOS docker image with SSH access | false | false | tutum/centos | 46 |
>| Base Centos Image -- Updated hourly | true | false | darksheer/centos | 3 |
>| Vanilla CentOS 7 with Oracle Java Development Kit 8 and latest Maven version. | true | false | indigo/centos-maven | 1 |
>| CentosOS 7 image for GPDB development | false | false | pivotaldata/centos7-dev | 0 |
>| centos base image | true | false | mcnaughton/centos-base | 1 |
>| MySQL 5.7 SQL database server<br/> | false | false | centos/mysql-57-centos7 | 86 |
>| Docker image that has systems administration tools used on CentOS Atomic host | true | false | centos/tools | 7 |
>| Oracle Java 8 Docker image based on Centos 7 | true | false | mamohr/centos-java | 3 |
>| Latest CentOS image with the JRE pre-installed. | true | false | nathonfowlie/centos-jre | 8 |
>| MariaDB 10.1 SQL database server<br/> | false | false | centos/mariadb-101-centos7 | 12 |
>| PostgreSQL is an advanced Object-Relational database management system<br/> | false | false | centos/postgresql-96-centos7 | 45 |


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
```!docker-image-tag name="alpine:latest" repo="example/alpine" tag="test"```
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

#### Command Example
```!docker-network-create networkconfig_name="test-network1"```

#### Context Example
```json
{
    "Docker": {
        "Id": "5878fae3ab77e56b2599a830342c343ea66bed1f7808c277b5a7d8f30f3b054d",
        "Warning": ""
    }
}
```

#### Human Readable Output

>### Results
>|Id|Warning|
>|---|---|
>| 5878fae3ab77e56b2599a830342c343ea66bed1f7808c277b5a7d8f30f3b054d |  |


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


#### Command Example
```!docker-network-list```

#### Context Example
```json
{
    "Docker": {
        "Network": [
            {
                "Attachable": false,
                "ConfigFrom": {
                    "Network": ""
                },
                "ConfigOnly": false,
                "Containers": null,
                "Created": "2021-01-10T07:33:54.637849596Z",
                "Driver": "overlay",
                "EnableIPv6": false,
                "IPAM": {
                    "Config": [
                        {
                            "Gateway": "10.0.0.1",
                            "Subnet": "10.0.0.0/24"
                        }
                    ],
                    "Driver": "default",
                    "Options": null
                },
                "Id": "eo50uuvgxacjaumqfg1a939x7",
                "Ingress": true,
                "Internal": false,
                "Labels": null,
                "Name": "ingress",
                "Options": {
                    "com.docker.network.driver.overlay.vxlanid_list": "4096"
                },
                "Scope": "swarm"
            },
            {
                "Attachable": false,
                "ConfigFrom": {
                    "Network": ""
                },
                "ConfigOnly": false,
                "Containers": {},
                "Created": "2021-01-10T11:10:44.214462477+04:00",
                "Driver": "bridge",
                "EnableIPv6": false,
                "IPAM": {
                    "Config": [
                        {
                            "Gateway": "1.0.0.7",
                            "Subnet": "1.0.0.0/16"
                        }
                    ],
                    "Driver": "default",
                    "Options": null
                },
                "Id": "bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34",
                "Ingress": false,
                "Internal": false,
                "Labels": {},
                "Name": "bridge",
                "Options": {
                    "com.docker.network.bridge.default_bridge": "true",
                    "com.docker.network.bridge.enable_icc": "true",
                    "com.docker.network.bridge.enable_ip_masquerade": "true",
                    "com.docker.network.bridge.host_binding_ipv4": "0.0.0.0",
                    "com.docker.network.bridge.name": "docker0",
                    "com.docker.network.driver.mtu": "1500"
                },
                "Scope": "local"
            },
            {
                "Attachable": false,
                "ConfigFrom": {
                    "Network": ""
                },
                "ConfigOnly": false,
                "Containers": {},
                "Created": "2021-01-08T17:19:52.219528741+04:00",
                "Driver": "bridge",
                "EnableIPv6": false,
                "IPAM": {
                    "Config": [
                        {
                            "Gateway": "1.0.0.1",
                            "Subnet": "1.0.0.0/16"
                        }
                    ],
                    "Driver": "default",
                    "Options": null
                },
                "Id": "2fb46b676f23558562df9fc6d526b547c686c79ee85c4466e7dbbe30e7b4144e",
                "Ingress": false,
                "Internal": false,
                "Labels": {},
                "Name": "docker_gwbridge",
                "Options": {
                    "com.docker.network.bridge.enable_icc": "false",
                    "com.docker.network.bridge.enable_ip_masquerade": "true",
                    "com.docker.network.bridge.name": "docker_gwbridge"
                },
                "Scope": "local"
            },
            {
                "Attachable": false,
                "ConfigFrom": {
                    "Network": ""
                },
                "ConfigOnly": false,
                "Containers": {},
                "Created": "2020-12-21T17:20:47.098713019+04:00",
                "Driver": "bridge",
                "EnableIPv6": false,
                "IPAM": {
                    "Config": [
                        {
                            "Gateway": "1.0.0.5",
                            "Subnet": "1.0.0.5/16"
                        }
                    ],
                    "Driver": "default",
                    "Options": null
                },
                "Id": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86",
                "Ingress": false,
                "Internal": false,
                "Labels": {},
                "Name": "openctiv4_default",
                "Options": {},
                "Scope": "local"
            },
            {
                "Attachable": false,
                "ConfigFrom": {
                    "Network": ""
                },
                "ConfigOnly": false,
                "Containers": {},
                "Created": "2021-01-06T12:11:43.782971403+04:00",
                "Driver": "bridge",
                "EnableIPv6": false,
                "IPAM": {
                    "Config": [
                        {
                            "Gateway": "1.0.0.1",
                            "Subnet": "1.0.0.0/16"
                        }
                    ],
                    "Driver": "default",
                    "Options": null
                },
                "Id": "5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b",
                "Ingress": false,
                "Internal": false,
                "Labels": {},
                "Name": "mongodb_default",
                "Options": {},
                "Scope": "local"
            },
            {
                "Attachable": false,
                "ConfigFrom": {
                    "Network": ""
                },
                "ConfigOnly": false,
                "Containers": {},
                "Created": "2020-12-17T18:40:22.859629034+04:00",
                "Driver": "host",
                "EnableIPv6": false,
                "IPAM": {
                    "Config": [],
                    "Driver": "default",
                    "Options": null
                },
                "Id": "740d56a702e4f7237a054882bea8f5c9265f794a0ef2f6b2cdd31b7281b14002",
                "Ingress": false,
                "Internal": false,
                "Labels": {},
                "Name": "host",
                "Options": {},
                "Scope": "local"
            },
            {
                "Attachable": false,
                "ConfigFrom": {
                    "Network": ""
                },
                "ConfigOnly": false,
                "Containers": {},
                "Created": "2020-12-17T18:40:22.854126071+04:00",
                "Driver": "null",
                "EnableIPv6": false,
                "IPAM": {
                    "Config": [],
                    "Driver": "default",
                    "Options": null
                },
                "Id": "76788f94aa9d9e9868007abfc07e88e45bb0d86e2e5a97be30a027dd47c6490b",
                "Ingress": false,
                "Internal": false,
                "Labels": {},
                "Name": "none",
                "Options": {},
                "Scope": "local"
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|Attachable|ConfigFrom|ConfigOnly|Containers|Created|Driver|EnableIPv6|IPAM|Id|Ingress|Internal|Labels|Name|Options|Scope|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| false | Network:  | false |  | 2021-01-10T07:33:54.637849596Z | overlay | false | Driver: default<br/>Options: null<br/>Config: {'Subnet': '10.0.0.0/24', 'Gateway': '10.0.0.1'} | eo50uuvgxacjaumqfg1a939x7 | true | false |  | ingress | com.docker.network.driver.overlay.vxlanid_list: 4096 | swarm |
>| false | Network:  | false |  | 2021-01-10T11:10:44.214462477+04:00 | bridge | false | Driver: default<br/>Options: null<br/>Config: {'Subnet': '1.0.0.0/16', 'Gateway': '1.0.0.7'} | bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34 | false | false |  | bridge | com.docker.network.bridge.default_bridge: true<br/>com.docker.network.bridge.enable_icc: true<br/>com.docker.network.bridge.enable_ip_masquerade: true<br/>com.docker.network.bridge.host_binding_ipv4: 0.0.0.0<br/>com.docker.network.bridge.name: docker0<br/>com.docker.network.driver.mtu: 1500 | local |
>| false | Network:  | false |  | 2021-01-08T17:19:52.219528741+04:00 | bridge | false | Driver: default<br/>Options: null<br/>Config: {'Subnet': '1.0.0.0/16', 'Gateway': '1.0.0.1'} | 2fb46b676f23558562df9fc6d526b547c686c79ee85c4466e7dbbe30e7b4144e | false | false |  | docker_gwbridge | com.docker.network.bridge.enable_icc: false<br/>com.docker.network.bridge.enable_ip_masquerade: true<br/>com.docker.network.bridge.name: docker_gwbridge | local |
>| false | Network:  | false |  | 2020-12-21T17:20:47.098713019+04:00 | bridge | false | Driver: default<br/>Options: null<br/>Config: {'Subnet': '1.0.0.5/16', 'Gateway': '1.0.0.5'} | 51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86 | false | false |  | openctiv4_default |  | local |
>| false | Network:  | false |  | 2021-01-06T12:11:43.782971403+04:00 | bridge | false | Driver: default<br/>Options: null<br/>Config: {'Subnet': '1.0.0.0/16', 'Gateway': '1.0.0.1'} | 5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b | false | false |  | mongodb_default |  | local |
>| false | Network:  | false |  | 2020-12-17T18:40:22.859629034+04:00 | host | false | Driver: default<br/>Options: null<br/>Config:  | 740d56a702e4f7237a054882bea8f5c9265f794a0ef2f6b2cdd31b7281b14002 | false | false |  | host |  | local |
>| false | Network:  | false |  | 2020-12-17T18:40:22.854126071+04:00 | null | false | Driver: default<br/>Options: null<br/>Config:  | 76788f94aa9d9e9868007abfc07e88e45bb0d86e2e5a97be30a027dd47c6490b | false | false |  | none |  | local |


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

#### Command Example
```!docker-network-prune```

#### Context Example
```json
{
    "Docker": {
        "NetworkPruneResponse": {
            "NetworksDeleted": [
                "test-network1"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|NetworksDeleted|
>|---|
>| test-network1 |


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


#### Command Example
```!docker-node-inspect id="ihwbb8r17uj4zgk1ds427r06o"```

#### Context Example
```json
{
    "Docker": {
        "Node": {
            "message": "node ihwbb8r17uj4zgk1ds427r06o not found"
        }
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| node ihwbb8r17uj4zgk1ds427r06o not found |


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


#### Command Example
```!docker-node-list```

#### Context Example
```json
{
    "Docker": {
        "Node": [
            {
                "CreatedAt": "2021-01-10T07:33:54.637814818Z",
                "Description": {
                    "Engine": {
                        "EngineVersion": "20.10.1",
                        "Plugins": [
                            {
                                "Name": "awslogs",
                                "Type": "Log"
                            },
                            {
                                "Name": "fluentd",
                                "Type": "Log"
                            },
                            {
                                "Name": "gcplogs",
                                "Type": "Log"
                            },
                            {
                                "Name": "gelf",
                                "Type": "Log"
                            },
                            {
                                "Name": "journald",
                                "Type": "Log"
                            },
                            {
                                "Name": "json-file",
                                "Type": "Log"
                            },
                            {
                                "Name": "local",
                                "Type": "Log"
                            },
                            {
                                "Name": "logentries",
                                "Type": "Log"
                            },
                            {
                                "Name": "splunk",
                                "Type": "Log"
                            },
                            {
                                "Name": "syslog",
                                "Type": "Log"
                            },
                            {
                                "Name": "bridge",
                                "Type": "Network"
                            },
                            {
                                "Name": "host",
                                "Type": "Network"
                            },
                            {
                                "Name": "ipvlan",
                                "Type": "Network"
                            },
                            {
                                "Name": "macvlan",
                                "Type": "Network"
                            },
                            {
                                "Name": "null",
                                "Type": "Network"
                            },
                            {
                                "Name": "overlay",
                                "Type": "Network"
                            },
                            {
                                "Name": "local",
                                "Type": "Volume"
                            }
                        ]
                    },
                    "Hostname": "docker",
                    "Platform": {
                        "Architecture": "x86_64",
                        "OS": "linux"
                    },
                    "Resources": {
                        "MemoryBytes": 8143470592,
                        "NanoCPUs": 8000000000
                    },
                    "TLSInfo": {
                        "CertIssuerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELEuzulYmFOfxzSCYtsNqHSGFM8rRmbeT+xY1JXxNFw3xM65ZdJxSBjZPzskwpZ3ra+KBgdtWpvA6s6xLBwfNuQ==",
                        "CertIssuerSubject": "MBMxETAPBgNVBAMTCHN3YXJtLWNh",
                        "TrustRoot": "-----BEGIN CERTIFICATE-----\nMIIBazCCARCgAwIBAgIUOiN4v/EY6RXDOD/KhFdvH3brl7AwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAxMIc3dhcm0tY2EwHhcNMjEwMTEwMDcyOTAwWhcNNDEwMTA1MDcy\nOTAwWjATMREwDwYDVQQDEwhzd2FybS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABCxLs7pWJhTn8c0gmLbDah0hhTPK0Zm3k/sWNSV8TRcN8TOuWXScUgY2T87J\nMKWd62vigYHbVqbwOrOsSwcHzbmjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBS4aSrlzrksA4rV4dI/+VaVF6FPUDAKBggqhkjO\nPQQDAgNJADBGAiEA7XBazcswvm/Dl4z7OHI6LGodSFOS5Z8Zg1DFPmdoodoCIQCh\n2+H2IcBXUO50IAzFvKt754HImW+kpLNe6fOFtEj+kQ==\n-----END CERTIFICATE-----\n"
                    }
                },
                "ID": "cgj752x81xe8wbwhfr0chpa1n",
                "ManagerStatus": {
                    "Addr": "1.0.0.2:2377",
                    "Leader": true,
                    "Reachability": "reachable"
                },
                "Spec": {
                    "Availability": "active",
                    "Labels": {},
                    "Role": "manager"
                },
                "Status": {
                    "Addr": "1.0.0.2",
                    "State": "ready"
                },
                "UpdatedAt": "2021-01-10T07:33:55.240452056Z",
                "Version": {
                    "Index": 9
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|CreatedAt|Description|ID|ManagerStatus|Spec|Status|UpdatedAt|Version|
>|---|---|---|---|---|---|---|---|
>| 2021-01-10T07:33:54.637814818Z | Hostname: docker<br/>Platform: {"Architecture": "x86_64", "OS": "linux"}<br/>Resources: {"NanoCPUs": 8000000000, "MemoryBytes": 8143470592}<br/>Engine: {"EngineVersion": "20.10.1", "Plugins": [{"Type": "Log", "Name": "awslogs"}, {"Type": "Log", "Name": "fluentd"}, {"Type": "Log", "Name": "gcplogs"}, {"Type": "Log", "Name": "gelf"}, {"Type": "Log", "Name": "journald"}, {"Type": "Log", "Name": "json-file"}, {"Type": "Log", "Name": "local"}, {"Type": "Log", "Name": "logentries"}, {"Type": "Log", "Name": "splunk"}, {"Type": "Log", "Name": "syslog"}, {"Type": "Network", "Name": "bridge"}, {"Type": "Network", "Name": "host"}, {"Type": "Network", "Name": "ipvlan"}, {"Type": "Network", "Name": "macvlan"}, {"Type": "Network", "Name": "null"}, {"Type": "Network", "Name": "overlay"}, {"Type": "Volume", "Name": "local"}]}<br/>TLSInfo: {"TrustRoot": "-----BEGIN CERTIFICATE-----\nMIIBazCCARCgAwIBAgIUOiN4v/EY6RXDOD/KhFdvH3brl7AwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAxMIc3dhcm0tY2EwHhcNMjEwMTEwMDcyOTAwWhcNNDEwMTA1MDcy\nOTAwWjATMREwDwYDVQQDEwhzd2FybS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABCxLs7pWJhTn8c0gmLbDah0hhTPK0Zm3k/sWNSV8TRcN8TOuWXScUgY2T87J\nMKWd62vigYHbVqbwOrOsSwcHzbmjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBS4aSrlzrksA4rV4dI/+VaVF6FPUDAKBggqhkjO\nPQQDAgNJADBGAiEA7XBazcswvm/Dl4z7OHI6LGodSFOS5Z8Zg1DFPmdoodoCIQCh\n2+H2IcBXUO50IAzFvKt754HImW+kpLNe6fOFtEj+kQ==\n-----END CERTIFICATE-----\n", "CertIssuerSubject": "MBMxETAPBgNVBAMTCHN3YXJtLWNh", "CertIssuerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELEuzulYmFOfxzSCYtsNqHSGFM8rRmbeT+xY1JXxNFw3xM65ZdJxSBjZPzskwpZ3ra+KBgdtWpvA6s6xLBwfNuQ=="} | cgj752x81xe8wbwhfr0chpa1n | Leader: true<br/>Reachability: reachable<br/>Addr: 1.0.0.2:2377 | Labels: {}<br/>Role: manager<br/>Availability: active | State: ready<br/>Addr: 1.0.0.2 | 2021-01-10T07:33:55.240452056Z | Index: 9 |


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

#### Command Example
```!docker-secret-create secretspec_name="temp-secret1" secretspec_data="test"```

#### Context Example
```json
{
    "Docker": {
        "ID": "4ifl4ou479wz933pezt2t87u0"
    }
}
```

#### Human Readable Output

>### Results
>|ID|
>|---|
>| 4ifl4ou479wz933pezt2t87u0 |


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


#### Command Example
```!docker-secret-inspect id="2k3h2oy2qiiz2rc35zhgh3yvz"```

#### Context Example
```json
{
    "Docker": {
        "Secret": {
            "message": "secret 2k3h2oy2qiiz2rc35zhgh3yvz not found"
        }
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| secret 2k3h2oy2qiiz2rc35zhgh3yvz not found |


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


#### Command Example
```!docker-secret-list```

#### Context Example
```json
{
    "Docker": {
        "Secret": [
            {
                "CreatedAt": "2021-01-10T07:34:16.735786395Z",
                "ID": "4ifl4ou479wz933pezt2t87u0",
                "Spec": {
                    "Labels": {},
                    "Name": "temp-secret1"
                },
                "UpdatedAt": "2021-01-10T07:34:16.735786395Z",
                "Version": {
                    "Index": 12
                }
            }
        ]
    }
}
```

#### Human Readable Output

>### Results
>|CreatedAt|ID|Spec|UpdatedAt|Version|
>|---|---|---|---|---|
>| 2021-01-10T07:34:16.735786395Z | 4ifl4ou479wz933pezt2t87u0 | Name: temp-secret1<br/>Labels: {} | 2021-01-10T07:34:16.735786395Z | Index: 12 |


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

#### Command Example
```!docker-swarm-init listenaddr="1.0.0.2" advertiseaddr="1.0.0.2"```

#### Context Example
```json
{
    "Docker": {
        "Swarm": {
            "Token": {
                "Node ID": "cgj752x81xe8wbwhfr0chpa1n"
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|Node ID|
>|---|
>| cgj752x81xe8wbwhfr0chpa1n |


### docker-swarm-inspect
***
Inspect swarm


#### Base Command

`docker-swarm-inspect`
#### Input

There are no input arguments for this command.

#### Context Output

There is no context output for this command.

#### Command Example
```!docker-swarm-inspect```

#### Context Example
```json
{
    "Docker": {
        "Swarm": {
            "CreatedAt": "2021-01-10T07:33:54.637800661Z",
            "DataPathPort": 4789,
            "DefaultAddrPool": [
                "10.0.0.0/8"
            ],
            "ID": "vlnbrh88562b0zqkfznqxp3lo",
            "JoinTokens": {
                "Manager": "SWMTKN-1-5saqys3rd44qxyua8eq7ssa6o0k79sgwyjpcat8ocpz7jaq8ij-38lq63qd8ruxh0eabe5gmxqrz",
                "Worker": "SWMTKN-1-5saqys3rd44qxyua8eq7ssa6o0k79sgwyjpcat8ocpz7jaq8ij-aj3qmgg6e5zvn9bz2k71pu7pv"
            },
            "RootRotationInProgress": false,
            "Spec": {
                "CAConfig": {
                    "NodeCertExpiry": 7776000000000000
                },
                "Dispatcher": {
                    "HeartbeatPeriod": 5000000000
                },
                "EncryptionConfig": {
                    "AutoLockManagers": false
                },
                "Labels": {},
                "Name": "default",
                "Orchestration": {
                    "TaskHistoryRetentionLimit": 5
                },
                "Raft": {
                    "ElectionTick": 10,
                    "HeartbeatTick": 1,
                    "KeepOldSnapshots": 0,
                    "LogEntriesForSlowFollowers": 500,
                    "SnapshotInterval": 10000
                },
                "TaskDefaults": {}
            },
            "SubnetSize": 24,
            "TLSInfo": {
                "CertIssuerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELEuzulYmFOfxzSCYtsNqHSGFM8rRmbeT+xY1JXxNFw3xM65ZdJxSBjZPzskwpZ3ra+KBgdtWpvA6s6xLBwfNuQ==",
                "CertIssuerSubject": "MBMxETAPBgNVBAMTCHN3YXJtLWNh",
                "TrustRoot": "-----BEGIN CERTIFICATE-----\nMIIBazCCARCgAwIBAgIUOiN4v/EY6RXDOD/KhFdvH3brl7AwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAxMIc3dhcm0tY2EwHhcNMjEwMTEwMDcyOTAwWhcNNDEwMTA1MDcy\nOTAwWjATMREwDwYDVQQDEwhzd2FybS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABCxLs7pWJhTn8c0gmLbDah0hhTPK0Zm3k/sWNSV8TRcN8TOuWXScUgY2T87J\nMKWd62vigYHbVqbwOrOsSwcHzbmjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBS4aSrlzrksA4rV4dI/+VaVF6FPUDAKBggqhkjO\nPQQDAgNJADBGAiEA7XBazcswvm/Dl4z7OHI6LGodSFOS5Z8Zg1DFPmdoodoCIQCh\n2+H2IcBXUO50IAzFvKt754HImW+kpLNe6fOFtEj+kQ==\n-----END CERTIFICATE-----\n"
            },
            "UpdatedAt": "2021-01-10T07:33:55.245247885Z",
            "Version": {
                "Index": 10
            }
        }
    }
}
```

#### Human Readable Output

>### Results
>|CreatedAt|DataPathPort|DefaultAddrPool|ID|JoinTokens|RootRotationInProgress|Spec|SubnetSize|TLSInfo|UpdatedAt|Version|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 2021-01-10T07:33:54.637800661Z | 4789 | 10.0.0.0/8 | vlnbrh88562b0zqkfznqxp3lo | Worker: SWMTKN-1-5saqys3rd44qxyua8eq7ssa6o0k79sgwyjpcat8ocpz7jaq8ij-aj3qmgg6e5zvn9bz2k71pu7pv<br/>Manager: SWMTKN-1-5saqys3rd44qxyua8eq7ssa6o0k79sgwyjpcat8ocpz7jaq8ij-38lq63qd8ruxh0eabe5gmxqrz | false | Name: default<br/>Labels: {}<br/>Orchestration: {"TaskHistoryRetentionLimit": 5}<br/>Raft: {"SnapshotInterval": 10000, "KeepOldSnapshots": 0, "LogEntriesForSlowFollowers": 500, "ElectionTick": 10, "HeartbeatTick": 1}<br/>Dispatcher: {"HeartbeatPeriod": 5000000000}<br/>CAConfig: {"NodeCertExpiry": 7776000000000000}<br/>TaskDefaults: {}<br/>EncryptionConfig: {"AutoLockManagers": false} | 24 | TrustRoot: -----BEGIN CERTIFICATE-----<br/>MIIBazCCARCgAwIBAgIUOiN4v/EY6RXDOD/KhFdvH3brl7AwCgYIKoZIzj0EAwIw<br/>EzERMA8GA1UEAxMIc3dhcm0tY2EwHhcNMjEwMTEwMDcyOTAwWhcNNDEwMTA1MDcy<br/>OTAwWjATMREwDwYDVQQDEwhzd2FybS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEH<br/>A0IABCxLs7pWJhTn8c0gmLbDah0hhTPK0Zm3k/sWNSV8TRcN8TOuWXScUgY2T87J<br/>MKWd62vigYHbVqbwOrOsSwcHzbmjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB<br/>Af8EBTADAQH/MB0GA1UdDgQWBBS4aSrlzrksA4rV4dI/+VaVF6FPUDAKBggqhkjO<br/>PQQDAgNJADBGAiEA7XBazcswvm/Dl4z7OHI6LGodSFOS5Z8Zg1DFPmdoodoCIQCh<br/>2+H2IcBXUO50IAzFvKt754HImW+kpLNe6fOFtEj+kQ==<br/>-----END CERTIFICATE-----<br/><br/>CertIssuerSubject: MBMxETAPBgNVBAMTCHN3YXJtLWNh<br/>CertIssuerPublicKey: MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELEuzulYmFOfxzSCYtsNqHSGFM8rRmbeT+xY1JXxNFw3xM65ZdJxSBjZPzskwpZ3ra+KBgdtWpvA6s6xLBwfNuQ== | 2021-01-10T07:33:55.245247885Z | Index: 10 |


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

#### Command Example
```!docker-swarm-join```

#### Context Example
```json
{
    "Docker": {
        "message": "This node is already part of a swarm. Use \"docker swarm leave\" to leave this swarm and join another one."
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| This node is already part of a swarm. Use "docker swarm leave" to leave this swarm and join another one. |


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

#### Command Example
```!docker-swarm-leave force="True"```

#### Context Example
```json
{
    "Docker": {
        "message": "Swarm node left."
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| Swarm node left. |


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

#### Command Example
```!docker-swarm-unlock```

#### Context Example
```json
{
    "Docker": {
        "message": "swarm is not locked"
    }
}
```

#### Human Readable Output

>### Results
>|message|
>|---|
>| swarm is not locked |


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


#### Command Example
```!docker-swarm-unlockkey```

#### Context Example
```json
{
    "Docker": {
        "UnlockKeyResponse": {
            "UnlockKey": ""
        }
    }
}
```

#### Human Readable Output

>### Results
>|UnlockKey|
>|---|
>|  |


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


#### Command Example
```!docker-system-data-usage```

#### Context Example
```json
{
    "Docker": {
        "SystemDataUsageResponse": {
            "BuildCache": null,
            "BuilderSize": 0,
            "Containers": [
                {
                    "Command": "/hello",
                    "Created": 1610122922,
                    "HostConfig": {
                        "NetworkMode": "default"
                    },
                    "Id": "7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41",
                    "Image": "hello-world",
                    "ImageID": "sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b",
                    "Labels": {},
                    "Mounts": [],
                    "Names": [
                        "/hello-docker"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "bridge": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "",
                                "Gateway": "",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": null,
                                "IPAddress": "",
                                "IPPrefixLen": 0,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "",
                                "NetworkID": "b5b425aad28e5f4b9c9b118257ce214455d84a7901e5a90d79e3ae4f527f725e"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 13336,
                    "State": "exited",
                    "Status": "Exited (0) 39 hours ago"
                },
                {
                    "Command": "/hello",
                    "Created": 1610121618,
                    "HostConfig": {
                        "NetworkMode": "default"
                    },
                    "Id": "0caea4d0b099175e6d3d8c0f68d0ab6624fc4339ff3e88db7ec509efd5e3c6c3",
                    "Image": "hello-world",
                    "ImageID": "sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b",
                    "Labels": {},
                    "Mounts": [],
                    "Names": [
                        "/crazy_curran"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "bridge": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "",
                                "Gateway": "",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": null,
                                "IPAddress": "",
                                "IPPrefixLen": 0,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "",
                                "NetworkID": "b5b425aad28e5f4b9c9b118257ce214455d84a7901e5a90d79e3ae4f527f725e"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 13336,
                    "State": "exited",
                    "Status": "Exited (0) 40 hours ago"
                },
                {
                    "Command": "tini -- /docker-entrypoint.sh mongo-express",
                    "Created": 1609920735,
                    "HostConfig": {
                        "NetworkMode": "mongodb_default"
                    },
                    "Id": "57d49db83f2ced79c87e5c50d2b407bbb7bc33c3a95a03e142477f3a3b79ded5",
                    "Image": "mongo-express",
                    "ImageID": "sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e",
                    "Labels": {
                        "com.docker.compose.config-hash": "0a75befcc34f36ab677c5d8f09d2ee8063e8ad3d",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "mongodb",
                        "com.docker.compose.service": "mongo-express",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/mongodb-express"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "mongodb_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "2628f2ac3df2f3b5a8059fe3e736d9fe9da4d428c9da9220dad5d2eb100258fa",
                                "Gateway": "1.0.0.1",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.3",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:1a:00:03",
                                "NetworkID": "5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 8081,
                            "PublicPort": 8081,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 129389081,
                    "SizeRw": 169,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "docker-entrypoint.sh mongod",
                    "Created": 1609920723,
                    "HostConfig": {
                        "NetworkMode": "mongodb_default"
                    },
                    "Id": "161f9d908f5bc34a9638a496b492cce47a16cd47268ec61f04e10b1224dbd2a3",
                    "Image": "mongo",
                    "ImageID": "sha256:c97feb3412a387d4d3bbd8653b09ef26683263a192e0e8dc6554e65bfb637a86",
                    "Labels": {
                        "com.docker.compose.config-hash": "74e20e7feccade15ae2ce2378088081ae5726a05",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "mongodb",
                        "com.docker.compose.service": "mongo",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [
                        {
                            "Destination": "/data/configdb",
                            "Driver": "local",
                            "Mode": "",
                            "Name": "88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55",
                            "Propagation": "",
                            "RW": true,
                            "Source": "",
                            "Type": "volume"
                        },
                        {
                            "Destination": "/data/db",
                            "Driver": "local",
                            "Mode": "z",
                            "Name": "mongodb",
                            "Propagation": "",
                            "RW": true,
                            "Source": "/var/lib/docker/volumes/mongodb/_data",
                            "Type": "volume"
                        }
                    ],
                    "Names": [
                        "/mongodb"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "mongodb_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "2f478dd56c3bfa4b0bfb2a6bdfa5a7f95f20960dbc5045238567f4f7c2b5e46d",
                                "Gateway": "1.0.0.1",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.2",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:1a:00:02",
                                "NetworkID": "5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 27017,
                            "PublicPort": 27017,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 492934722,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/bin/sh -c 'java -XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap -Dcom.sun.management.jmxremote -noverify ${JAVA_OPTS} -jar taxii-server-micronaut-all.jar'",
                    "Created": 1609866461,
                    "HostConfig": {
                        "NetworkMode": "bridge"
                    },
                    "Id": "b2f4cb3dbb3656d62441ba4d6a718e1271df075781d8c56e85cf585841772ac9",
                    "Image": "taxiserver:latest",
                    "ImageID": "sha256:70d8624ce3a1f02008bcdb8ba2bf4001e178bcb0ab90bdfab0eb17fd4ea2ca7f",
                    "Labels": {},
                    "Mounts": [],
                    "Names": [
                        "/taxiserver"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "bridge": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "",
                                "Gateway": "",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "",
                                "IPPrefixLen": 0,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "",
                                "NetworkID": "ebc2e7e11094a2f780d8f41f7a2fffd1e36208d6e2939ec94770dfd6083a384d"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 298529298,
                    "State": "exited",
                    "Status": "Exited (143) 3 days ago"
                },
                {
                    "Command": "/entrypoint.sh /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000",
                    "Created": 1609863181,
                    "HostConfig": {
                        "NetworkMode": "bridge"
                    },
                    "Id": "04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94",
                    "Image": "eclecticiq/opentaxii:latest",
                    "ImageID": "sha256:aa50897f28e43c1110328f1b8740a2ad097031e8d2443266e562fe74be1a7a19",
                    "Labels": {
                        "maintainer": "EclecticIQ <opentaxii@eclecticiq.com>"
                    },
                    "Mounts": [
                        {
                            "Destination": "/input",
                            "Driver": "local",
                            "Mode": "z",
                            "Name": "opentaxii-input",
                            "Propagation": "",
                            "RW": true,
                            "Source": "/var/lib/docker/volumes/opentaxii-input/_data",
                            "Type": "volume"
                        },
                        {
                            "Destination": "/data",
                            "Driver": "local",
                            "Mode": "z",
                            "Name": "opentaxii-data",
                            "Propagation": "",
                            "RW": true,
                            "Source": "/var/lib/docker/volumes/opentaxii-data/_data",
                            "Type": "volume"
                        }
                    ],
                    "Names": [
                        "/test-taxii"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "bridge": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "3fccdab7ca5ad3f11ef72dd8d76044160c0cc66e005643d9584fbcb903500c1b",
                                "Gateway": "1.0.0.7",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.2",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:11:00:02",
                                "NetworkID": "bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 9000,
                            "PublicPort": 6000,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 188189407,
                    "SizeRw": 782,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608827060,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "14d3c9c9c306e427b8cd4a2e4d80ddd6ad38684936224f3e36440b6b6f08bc34",
                    "Image": "opencti/connector-ipinfo:4.0.3",
                    "ImageID": "sha256:cd608aa8a042cb46adf5aaa3c43ce92a85b3817c5254b8de0e53b49b7a729c6b",
                    "Labels": {
                        "com.docker.compose.config-hash": "3a9bd111dfb135ed1a839ad5e164068c78b2b630",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "connector-export-file-stix",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_connector-ipinfo"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "717ad998186f308ebefb4f0f71c04ae5fbc143e450bed9eba8570d9adc099624",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:08",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 94682341,
                    "SizeRw": 537027,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608564498,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "7ba5c18139e09bd2a34e7be27db70520c6901dad7db901dd073c1f96abfc9034",
                    "Image": "opencti/connector-import-file-pdf-observables:4.0.3",
                    "ImageID": "sha256:51afb662d3c993510447e431e3da8495140690cb9c1ca93c7cf19424a63ce223",
                    "Labels": {
                        "com.docker.compose.config-hash": "336a368bc6eb7eae69a090a9ac80f9614d02685e",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "connector-import-file-pdf-observables",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_connector-import-file-pdf-observables"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "e99d6307854d91785af35603157c0a82826a5ebe59b3072924770dd7e66be07c",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.2",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:02",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 115044111,
                    "SizeRw": 553305,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608564460,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "2aa24d29411d89e1d3fcd708b0dae10e32a84d53d9164a5998c217e054d31bd9",
                    "Image": "opencti/connector-import-file-stix:4.0.3",
                    "ImageID": "sha256:cfd88d87460e5c1e0d7c82ee58258208c80d8acbd9417afe2f7cea10bfef4dd9",
                    "Labels": {
                        "com.docker.compose.config-hash": "d39640557a02e44f4983eac94b75e00a8b975e07",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "connector-import-file-stix",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_connector-import-file-stix"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "5b5f7eef4e12eef95f1a28143b26a49d4edbc971592859348393be98a56320f8",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:07",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 66912727,
                    "SizeRw": 537027,
                    "State": "running",
                    "Status": "Up Less than a second"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608564417,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "5f92895691ca7eeb6c8bc3f4914cd6210a3d59a72e8e48890f336d352cbc9753",
                    "Image": "opencti/connector-export-file-csv:4.0.3",
                    "ImageID": "sha256:25500204dfbea42059fc77100177de2c5d92cd4219ca6437831bfc26c53b628c",
                    "Labels": {
                        "com.docker.compose.config-hash": "64d591ae3f975e1a79738447dd38d1e554486f44",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "connector-export-file-csv",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_connector-export-file-csv"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "91a3c7767104581ddb04f739c3cc313e7bfe0f6db5ad4c6865970d1e60bf99b7",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:09",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 66919911,
                    "SizeRw": 537027,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608564294,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "65ddee16a51d57e8b57f6b00acd7f9ae5b92152731276d6d4d497c2f979e2b1e",
                    "Image": "opencti/connector-export-file-stix:4.0.3",
                    "ImageID": "sha256:42efb539088b86558557e24c10d00810014e5e820f0d7ac8bb8d0fd3981a0bda",
                    "Labels": {
                        "com.docker.compose.config-hash": "3a9bd111dfb135ed1a839ad5e164068c78b2b630",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "connector-export-file-stix",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_connector-export-file-stix"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "8cd31e2f66b6df498962e8cc4df17f741b842546c4fd61ac9a79c2f6805f66bc",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:04",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 66914627,
                    "SizeRw": 537027,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608564112,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "c61e3108d286e07032f8ec44f3e5883bac00838a673972e871c31d970b75d155",
                    "Image": "opencti/connector-history:4.0.3",
                    "ImageID": "sha256:0257f00635aca1087fa630362c470f22c4661bc87d4e6e8c54c64f5795dfce1e",
                    "Labels": {
                        "com.docker.compose.config-hash": "6ac905cdbdc63d012688d34a06393c135d384c79",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "connector-history",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_connector-history"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "048b58a95cd8a27e6f640c844e9b5ea7c65c4fdcbdc5dfdc683986daf6813e4a",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:0d",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 69431220,
                    "SizeRw": 537027,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608563957,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "2220832cc2840320c53156993563fce5298d4e0317d71b42851067f02c762423",
                    "Image": "opencti/connector-alienvault:4.0.3",
                    "ImageID": "sha256:3e718135d5fb38c0af85c9c00b64160082a407722d929572a190d6092c604e15",
                    "Labels": {
                        "com.docker.compose.config-hash": "3a9bd111dfb135ed1a839ad5e164068c78b2b630",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "connector-export-file-stix",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_connector-alienvault"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "3a8b638639e908f26163f7271bb88eee017a3fc5cb253bf180e8b190ebca5a80",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:0c",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 67793705,
                    "SizeRw": 597000,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608562731,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "cc1743f3d83750f973796d0aaadba7ec5fb67361906666b2a48be0512d82a050",
                    "Image": "opencti/worker:4.0.3",
                    "ImageID": "sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473",
                    "Labels": {
                        "com.docker.compose.config-hash": "4f611b1efe20fd3b147a1b830afceff276398af1",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "worker",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_worker_2"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "03f052a4e86e16124c279fe9e593e4686fcc658b57d82b51c031163f2076cfc6",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:0e",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 130086647,
                    "SizeRw": 267877,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608561358,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "118fe891bacfe3328ad64677ac492f0568547740458090594600950613774fcf",
                    "Image": "opencti/worker:4.0.3",
                    "ImageID": "sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473",
                    "Labels": {
                        "com.docker.compose.config-hash": "4f611b1efe20fd3b147a1b830afceff276398af1",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "worker",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti_worker_1"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "ce7645ab046233a84fc7c2c9ce796a120edfd790280a52fb9df55f2066458141",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:0f",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [],
                    "SizeRootFs": 130086647,
                    "SizeRw": 267877,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "docker-entrypoint.sh redis-server",
                    "Created": 1608559382,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "4be1f8dec98809ec2cf360d1d882beb8c819a58111070a04affbc714a071d1a0",
                    "Image": "redis:6.0.9",
                    "ImageID": "sha256:ef47f3b6dc11e8f17fb39a6e46ecaf4efd47b3d374e92aeb9f2606896b751251",
                    "Labels": {
                        "com.docker.compose.config-hash": "daf5e1ad7b16619b8c479df88301daf432c5a564",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "redis",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [
                        {
                            "Destination": "/data",
                            "Driver": "local",
                            "Mode": "z",
                            "Name": "redisdata",
                            "Propagation": "",
                            "RW": true,
                            "Source": "/var/lib/docker/volumes/redisdata/_data",
                            "Type": "volume"
                        }
                    ],
                    "Names": [
                        "/redis"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "996d21e0ac5c57239c1622bba9c9a5d303a82cec1c15146a94c84766cd460966",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.3",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:03",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 6379,
                            "PublicPort": 6379,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 104252176,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/tini -- /usr/local/bin/docker-entrypoint.sh eswrapper",
                    "Created": 1608559270,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "5c3b991454ad1daa7d2f287cc0450d69f0c1e0a7778f8f55199b5201da3b5390",
                    "Image": "docker.elastic.co/elasticsearch/elasticsearch:7.10.1",
                    "ImageID": "sha256:558380375f1a36c20e67c3a0b7bf715c659d75520d0e688b066d5e708918d716",
                    "Labels": {
                        "com.docker.compose.config-hash": "6367ce3fdc8ac903d07574f97c9dc4a7208f3aef",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "elasticsearch",
                        "com.docker.compose.version": "1.5.0",
                        "org.label-schema.build-date": "2020-12-05T01:00:33.671820Z",
                        "org.label-schema.license": "Elastic-License",
                        "org.label-schema.name": "Elasticsearch",
                        "org.label-schema.schema-version": "1.0",
                        "org.label-schema.url": "https://www.elastic.co/products/elasticsearch",
                        "org.label-schema.usage": "https://www.elastic.co/guide/en/elasticsearch/reference/index.html",
                        "org.label-schema.vcs-ref": "1c34507e66d7db1211f66f3513706fdf548736aa",
                        "org.label-schema.vcs-url": "https://github.com/elastic/elasticsearch",
                        "org.label-schema.vendor": "Elastic",
                        "org.label-schema.version": "7.10.1",
                        "org.opencontainers.image.created": "2020-12-05T01:00:33.671820Z",
                        "org.opencontainers.image.documentation": "https://www.elastic.co/guide/en/elasticsearch/reference/index.html",
                        "org.opencontainers.image.licenses": "Elastic-License",
                        "org.opencontainers.image.revision": "1c34507e66d7db1211f66f3513706fdf548736aa",
                        "org.opencontainers.image.source": "https://github.com/elastic/elasticsearch",
                        "org.opencontainers.image.title": "Elasticsearch",
                        "org.opencontainers.image.url": "https://www.elastic.co/products/elasticsearch",
                        "org.opencontainers.image.vendor": "Elastic",
                        "org.opencontainers.image.version": "7.10.1"
                    },
                    "Mounts": [
                        {
                            "Destination": "/usr/share/elasticsearch/data",
                            "Driver": "local",
                            "Mode": "z",
                            "Name": "esdata",
                            "Propagation": "",
                            "RW": true,
                            "Source": "/var/lib/docker/volumes/esdata/_data",
                            "Type": "volume"
                        }
                    ],
                    "Names": [
                        "/elasticsearch"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "64904da59143266418038a1f64c1f7573d0a31f79ed0a32998ce94172ba49c88",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:06",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 9200,
                            "PublicPort": 9200,
                            "Type": "tcp"
                        },
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 9300,
                            "PublicPort": 9300,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 1108853726,
                    "SizeRw": 335097051,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "docker-entrypoint.sh rabbitmq-server",
                    "Created": 1608559125,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "93b8c8f3e5c5b959b5382b20ec3f441d1b960124419e809d86f0a34cee59d7c8",
                    "Image": "rabbitmq:3.8-management",
                    "ImageID": "sha256:1ecd87fb78edc5feada026b0f926bcf7458eb9c80db8100618e1df725645540e",
                    "Labels": {
                        "com.docker.compose.config-hash": "d18573c6a89abeacddfab591aca6e68b2921b90a",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "rabbitmq",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [
                        {
                            "Destination": "/var/lib/rabbitmq",
                            "Driver": "local",
                            "Mode": "z",
                            "Name": "amqpdata",
                            "Propagation": "",
                            "RW": true,
                            "Source": "/var/lib/docker/volumes/amqpdata/_data",
                            "Type": "volume"
                        }
                    ],
                    "Names": [
                        "/rabbitmq"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "2eb072c87b19c95fac0f6121af754ea0cec052a27cb4f2aee8755c2aec92dfce",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.1",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:0a",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "PrivatePort": 5672,
                            "Type": "tcp"
                        },
                        {
                            "PrivatePort": 15671,
                            "Type": "tcp"
                        },
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 15672,
                            "PublicPort": 15672,
                            "Type": "tcp"
                        },
                        {
                            "PrivatePort": 15691,
                            "Type": "tcp"
                        },
                        {
                            "PrivatePort": 15692,
                            "Type": "tcp"
                        },
                        {
                            "PrivatePort": 25672,
                            "Type": "tcp"
                        },
                        {
                            "PrivatePort": 4369,
                            "Type": "tcp"
                        },
                        {
                            "PrivatePort": 5671,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 197694194,
                    "SizeRw": 1101,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/entrypoint.sh",
                    "Created": 1608557349,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "0b7479a2f6abb93887cfb881dc8e4464e48df384887cb483c99a134cf894644b",
                    "Image": "opencti/platform:4.0.3",
                    "ImageID": "sha256:b03e4ab4fe4739d8ef6cd6a6639ccea8e09eaee8f6fb8842be9225c3719e27cd",
                    "Labels": {
                        "com.docker.compose.config-hash": "22687afb96da8b20f51629f9868dfd237ad601a6",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "opencti",
                        "com.docker.compose.version": "1.5.0"
                    },
                    "Mounts": [],
                    "Names": [
                        "/opencti"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "588234b49254b09744635401d2c95f092f7884bac7ae85e3e23e6cccab00abb7",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.1",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:0b",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 8080,
                            "PublicPort": 8080,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 1213991401,
                    "SizeRw": 495546664,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/usr/bin/docker-entrypoint.sh server /data",
                    "Created": 1608557040,
                    "HostConfig": {
                        "NetworkMode": "openctiv4_default"
                    },
                    "Id": "cddbc48191628fde8991adfed5d0e4c2704f4e09b9b79d96549be8baf608984d",
                    "Image": "minio/minio:RELEASE.2020-12-12T08-39-07Z",
                    "ImageID": "sha256:f1a30c1dd760a7927d12a559c55fcf6ccb7efbbe79295ecc9394b7e4fe21d216",
                    "Labels": {
                        "architecture": "x86_64",
                        "build-date": "2020-10-31T05:07:05.471303",
                        "com.docker.compose.config-hash": "da8a89d63690ae08df58294ad3685f61c201125e",
                        "com.docker.compose.container-number": "1",
                        "com.docker.compose.oneoff": "False",
                        "com.docker.compose.project": "openctiv4",
                        "com.docker.compose.service": "minio",
                        "com.docker.compose.version": "1.5.0",
                        "com.redhat.build-host": "cpt-1002.osbs.prod.upshift.rdu2.redhat.com",
                        "com.redhat.component": "ubi8-minimal-container",
                        "com.redhat.license_terms": "https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI",
                        "description": "MinIO object storage is fundamentally different. Designed for performance and the S3 API, it is 100% open-source. MinIO is ideal for large, private cloud environments with stringent security requirements and delivers mission-critical availability across a diverse range of workloads.",
                        "distribution-scope": "public",
                        "io.k8s.description": "The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.",
                        "io.k8s.display-name": "Red Hat Universal Base Image 8 Minimal",
                        "io.openshift.expose-services": "",
                        "io.openshift.tags": "minimal rhel8",
                        "maintainer": "MinIO Inc <dev@min.io>",
                        "name": "MinIO",
                        "release": "RELEASE.2020-11-25T22-36-25Z",
                        "summary": "MinIO is a High Performance Object Storage, API compatible with Amazon S3 cloud storage service.",
                        "url": "https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.3-201",
                        "vcs-ref": "f53dab37c7541dd0080f410727c5886e85c09ee7",
                        "vcs-type": "git",
                        "vendor": "MinIO Inc <dev@min.io>",
                        "version": "RELEASE.2020-11-25T22-36-25Z"
                    },
                    "Mounts": [
                        {
                            "Destination": "/data",
                            "Driver": "local",
                            "Mode": "z",
                            "Name": "s3data",
                            "Propagation": "",
                            "RW": true,
                            "Source": "/var/lib/docker/volumes/s3data/_data",
                            "Type": "volume"
                        }
                    ],
                    "Names": [
                        "/minio"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "openctiv4_default": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "b3d4562edf6ea434a58ac398ca2c179cb95740af5e4c3bf970499544413397a4",
                                "Gateway": "1.0.0.5",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": {},
                                "IPAddress": "1.0.0.5",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:18:00:05",
                                "NetworkID": "51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 9000,
                            "PublicPort": 5000,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 182261690,
                    "State": "running",
                    "Status": "Up 23 minutes"
                },
                {
                    "Command": "/portainer",
                    "Created": 1608307988,
                    "HostConfig": {
                        "NetworkMode": "default"
                    },
                    "Id": "63de66e6e323ae7e189aeeba070adc184b386456ffe0dde9e3a88b8da0660d54",
                    "Image": "portainer/portainer-ce",
                    "ImageID": "sha256:a0a227bf03ddc8b88bbb74b1b84a8a7220c8fa95b122cbde2a7444f32dc30659",
                    "Labels": {},
                    "Mounts": [
                        {
                            "Destination": "/data",
                            "Driver": "local",
                            "Mode": "z",
                            "Name": "portainer_data",
                            "Propagation": "",
                            "RW": true,
                            "Source": "/var/lib/docker/volumes/portainer_data/_data",
                            "Type": "volume"
                        },
                        {
                            "Destination": "/var/run/docker.sock",
                            "Mode": "",
                            "Propagation": "rprivate",
                            "RW": true,
                            "Source": "/var/run/docker.sock",
                            "Type": "bind"
                        }
                    ],
                    "Names": [
                        "/portainer"
                    ],
                    "NetworkSettings": {
                        "Networks": {
                            "bridge": {
                                "Aliases": null,
                                "DriverOpts": null,
                                "EndpointID": "338cd95d726c3fde9674c4e86a9754ad5041ed9f3ea67b533224d8d27f2203f8",
                                "Gateway": "1.0.0.7",
                                "GlobalIPv6Address": "",
                                "GlobalIPv6PrefixLen": 0,
                                "IPAMConfig": null,
                                "IPAddress": "1.0.0.3",
                                "IPPrefixLen": 16,
                                "IPv6Gateway": "",
                                "Links": null,
                                "MacAddress": "02:42:ac:11:00:03",
                                "NetworkID": "bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34"
                            }
                        }
                    },
                    "Ports": [
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 9000,
                            "PublicPort": 9000,
                            "Type": "tcp"
                        },
                        {
                            "IP": "0.0.0.0",
                            "PrivatePort": 8000,
                            "PublicPort": 8000,
                            "Type": "tcp"
                        }
                    ],
                    "SizeRootFs": 195546824,
                    "State": "running",
                    "Status": "Up 23 minutes"
                }
            ],
            "Images": [
                {
                    "Containers": 1,
                    "Created": 1609870186,
                    "Id": "sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "mongo-express@sha256:6ae44c697cd2381772f8ea8f0571008b62e36301305b113df7f35f2e683e8255"
                    ],
                    "RepoTags": [
                        "mongo-express:latest"
                    ],
                    "SharedSize": 0,
                    "Size": 129388912,
                    "VirtualSize": 129388912
                },
                {
                    "Containers": 1,
                    "Created": 1609866227,
                    "Id": "sha256:70d8624ce3a1f02008bcdb8ba2bf4001e178bcb0ab90bdfab0eb17fd4ea2ca7f",
                    "Labels": null,
                    "ParentId": "sha256:c6c592c10fd1c88676835629a4b9d19f3e1354ca7d927c2d829628a53b427b3c",
                    "RepoDigests": null,
                    "RepoTags": [
                        "taxiserver:latest"
                    ],
                    "SharedSize": 237380314,
                    "Size": 298529298,
                    "VirtualSize": 298529298
                },
                {
                    "Containers": 1,
                    "Created": 1609798872,
                    "Id": "sha256:c97feb3412a387d4d3bbd8653b09ef26683263a192e0e8dc6554e65bfb637a86",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "mongo@sha256:7722bd2778a299b6f4a62b93a0d2741c734ba7332a090131030ca28261a9a198"
                    ],
                    "RepoTags": [
                        "mongo:latest"
                    ],
                    "SharedSize": 63252300,
                    "Size": 492934722,
                    "VirtualSize": 492934722
                },
                {
                    "Containers": 2,
                    "Created": 1608474777,
                    "Id": "sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/worker@sha256:5eef44425b59c272135cb6460232891cd607ccc4b5557a441cce3120624b9538"
                    ],
                    "RepoTags": [
                        "opencti/worker:4.0.3"
                    ],
                    "SharedSize": 0,
                    "Size": 129818770,
                    "VirtualSize": 129818770
                },
                {
                    "Containers": 1,
                    "Created": 1608474717,
                    "Id": "sha256:b03e4ab4fe4739d8ef6cd6a6639ccea8e09eaee8f6fb8842be9225c3719e27cd",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/platform@sha256:19a610656b32bf6ff894e04a0dcf9064ce3e850b3fc2f497f5478a21598753e5"
                    ],
                    "RepoTags": [
                        "opencti/platform:4.0.3"
                    ],
                    "SharedSize": 80179887,
                    "Size": 718444737,
                    "VirtualSize": 718444737
                },
                {
                    "Containers": 1,
                    "Created": 1608473851,
                    "Id": "sha256:0257f00635aca1087fa630362c470f22c4661bc87d4e6e8c54c64f5795dfce1e",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/connector-history@sha256:a80726951eb8d10acb6700c1ba1a602178e672f52b72787ed23f79d473d588cc"
                    ],
                    "RepoTags": [
                        "opencti/connector-history:4.0.3"
                    ],
                    "SharedSize": 42359686,
                    "Size": 68894193,
                    "VirtualSize": 68894193
                },
                {
                    "Containers": 1,
                    "Created": 1608473623,
                    "Id": "sha256:cd608aa8a042cb46adf5aaa3c43ce92a85b3817c5254b8de0e53b49b7a729c6b",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/connector-ipinfo@sha256:ae818dcf18b0acf5bdd25279ada6feb7f05c9b1745c847d3930a1fdaee555c57"
                    ],
                    "RepoTags": [
                        "opencti/connector-ipinfo:4.0.3"
                    ],
                    "SharedSize": 42359686,
                    "Size": 94145314,
                    "VirtualSize": 94145314
                },
                {
                    "Containers": 1,
                    "Created": 1608472895,
                    "Id": "sha256:3e718135d5fb38c0af85c9c00b64160082a407722d929572a190d6092c604e15",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/connector-alienvault@sha256:417b9cf7ed4f8ab5ebb391c52a38decfa306ef89b5dbc1853a85280f75fdd78d"
                    ],
                    "RepoTags": [
                        "opencti/connector-alienvault:4.0.3"
                    ],
                    "SharedSize": 42359686,
                    "Size": 67196705,
                    "VirtualSize": 67196705
                },
                {
                    "Containers": 1,
                    "Created": 1608472820,
                    "Id": "sha256:25500204dfbea42059fc77100177de2c5d92cd4219ca6437831bfc26c53b628c",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/connector-export-file-csv@sha256:d36ba9933590e3ade436fefa790fe03918a561cc69a944b473fc8eac5ca580f0"
                    ],
                    "RepoTags": [
                        "opencti/connector-export-file-csv:4.0.3"
                    ],
                    "SharedSize": 42359686,
                    "Size": 66382884,
                    "VirtualSize": 66382884
                },
                {
                    "Containers": 1,
                    "Created": 1608472784,
                    "Id": "sha256:42efb539088b86558557e24c10d00810014e5e820f0d7ac8bb8d0fd3981a0bda",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/connector-export-file-stix@sha256:3f0d74c5c77295edff0e7bb8ff7fa67db496c9f851b52643d705a0044d0fd67b"
                    ],
                    "RepoTags": [
                        "opencti/connector-export-file-stix:4.0.3"
                    ],
                    "SharedSize": 42359686,
                    "Size": 66377600,
                    "VirtualSize": 66377600
                },
                {
                    "Containers": 1,
                    "Created": 1608472749,
                    "Id": "sha256:51afb662d3c993510447e431e3da8495140690cb9c1ca93c7cf19424a63ce223",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/connector-import-file-pdf-observables@sha256:1f778d9cfb81b3f1d7e4456b9123022dca285da4bd5431360035dd13ec23e9ca"
                    ],
                    "RepoTags": [
                        "opencti/connector-import-file-pdf-observables:4.0.3"
                    ],
                    "SharedSize": 42359686,
                    "Size": 114490806,
                    "VirtualSize": 114490806
                },
                {
                    "Containers": 1,
                    "Created": 1608472472,
                    "Id": "sha256:cfd88d87460e5c1e0d7c82ee58258208c80d8acbd9417afe2f7cea10bfef4dd9",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/connector-import-file-stix@sha256:2e43819b4d1ef5f4de3a74382e5334e52647100553ea1b411a5bad87fa9e2984"
                    ],
                    "RepoTags": [
                        "opencti/connector-import-file-stix:4.0.3"
                    ],
                    "SharedSize": 42359686,
                    "Size": 66375700,
                    "VirtualSize": 66375700
                },
                {
                    "Containers": 0,
                    "Created": 1608200626,
                    "Id": "sha256:dca5e1ed7218f3145b4414b6599a8aec9385857664bd6cc928ea9fba26febf3f",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "opencti/platform@sha256:183a3c085644615eab322d9d460d875c4d6b3f4c03bd5c4bac3e467771c79bdf"
                    ],
                    "RepoTags": [
                        "opencti/platform:4.0.2",
                        "opencti/platform:latest"
                    ],
                    "SharedSize": 80179887,
                    "Size": 718413368,
                    "VirtualSize": 718413368
                },
                {
                    "Containers": 1,
                    "Created": 1608165887,
                    "Id": "sha256:1ecd87fb78edc5feada026b0f926bcf7458eb9c80db8100618e1df725645540e",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "rabbitmq@sha256:849677f6903921038a4541dd907e48a7d0e64a4cea63302acd73f9ee208789ce"
                    ],
                    "RepoTags": [
                        "rabbitmq:3.8-management"
                    ],
                    "SharedSize": 63252300,
                    "Size": 197693093,
                    "VirtualSize": 197693093
                },
                {
                    "Containers": 0,
                    "Created": 1608160149,
                    "Id": "sha256:959fcab9b1e95d6d7ec1fc4c25491dd7e8cf43aed7346e089d2b564f83cbf58b",
                    "Labels": {
                        "maintainer": "ownCloud DevOps <devops@owncloud.com>",
                        "org.label-schema.build-date": "2020-12-16T23:07:14Z",
                        "org.label-schema.name": "ownCloud Server",
                        "org.label-schema.schema-version": "1.0",
                        "org.label-schema.vcs-ref": "6da3457d723a5ffee6bc0eea945e0ba3fdbd629b",
                        "org.label-schema.vcs-url": "https://github.com/owncloud-docker/server.git",
                        "org.label-schema.vendor": "ownCloud GmbH"
                    },
                    "ParentId": "",
                    "RepoDigests": [
                        "owncloud/server@sha256:e5be595c31734b25133c69aec27c32e87fe011201540b940f1acbd629f910691"
                    ],
                    "RepoTags": [
                        "owncloud/server:latest"
                    ],
                    "SharedSize": 0,
                    "Size": 1363203435,
                    "VirtualSize": 1363203435
                },
                {
                    "Containers": 1,
                    "Created": 1607763909,
                    "Id": "sha256:f1a30c1dd760a7927d12a559c55fcf6ccb7efbbe79295ecc9394b7e4fe21d216",
                    "Labels": {
                        "architecture": "x86_64",
                        "build-date": "2020-10-31T05:07:05.471303",
                        "com.redhat.build-host": "cpt-1002.osbs.prod.upshift.rdu2.redhat.com",
                        "com.redhat.component": "ubi8-minimal-container",
                        "com.redhat.license_terms": "https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI",
                        "description": "MinIO object storage is fundamentally different. Designed for performance and the S3 API, it is 100% open-source. MinIO is ideal for large, private cloud environments with stringent security requirements and delivers mission-critical availability across a diverse range of workloads.",
                        "distribution-scope": "public",
                        "io.k8s.description": "The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.",
                        "io.k8s.display-name": "Red Hat Universal Base Image 8 Minimal",
                        "io.openshift.expose-services": "",
                        "io.openshift.tags": "minimal rhel8",
                        "maintainer": "MinIO Inc <dev@min.io>",
                        "name": "MinIO",
                        "release": "RELEASE.2020-11-25T22-36-25Z",
                        "summary": "MinIO is a High Performance Object Storage, API compatible with Amazon S3 cloud storage service.",
                        "url": "https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.3-201",
                        "vcs-ref": "f53dab37c7541dd0080f410727c5886e85c09ee7",
                        "vcs-type": "git",
                        "vendor": "MinIO Inc <dev@min.io>",
                        "version": "RELEASE.2020-11-25T22-36-25Z"
                    },
                    "ParentId": "",
                    "RepoDigests": [
                        "minio/minio@sha256:a2eeb964863632a274f3eed08fc256b790ca83a020e164dd18e1e5f402d9f8d4"
                    ],
                    "RepoTags": [
                        "minio/minio:RELEASE.2020-12-12T08-39-07Z"
                    ],
                    "SharedSize": 0,
                    "Size": 182261690,
                    "VirtualSize": 182261690
                },
                {
                    "Containers": 1,
                    "Created": 1607703900,
                    "Id": "sha256:ef47f3b6dc11e8f17fb39a6e46ecaf4efd47b3d374e92aeb9f2606896b751251",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "redis@sha256:0f724af268d0d3f5fb1d6b33fc22127ba5cbca2d58523b286ed3122db0dc5381"
                    ],
                    "RepoTags": [
                        "redis:6.0.9"
                    ],
                    "SharedSize": 0,
                    "Size": 104252176,
                    "VirtualSize": 104252176
                },
                {
                    "Containers": 1,
                    "Created": 1607130473,
                    "Id": "sha256:558380375f1a36c20e67c3a0b7bf715c659d75520d0e688b066d5e708918d716",
                    "Labels": {
                        "org.label-schema.build-date": "2020-12-05T01:00:33.671820Z",
                        "org.label-schema.license": "Elastic-License",
                        "org.label-schema.name": "Elasticsearch",
                        "org.label-schema.schema-version": "1.0",
                        "org.label-schema.url": "https://www.elastic.co/products/elasticsearch",
                        "org.label-schema.usage": "https://www.elastic.co/guide/en/elasticsearch/reference/index.html",
                        "org.label-schema.vcs-ref": "1c34507e66d7db1211f66f3513706fdf548736aa",
                        "org.label-schema.vcs-url": "https://github.com/elastic/elasticsearch",
                        "org.label-schema.vendor": "Elastic",
                        "org.label-schema.version": "7.10.1",
                        "org.opencontainers.image.created": "2020-12-05T01:00:33.671820Z",
                        "org.opencontainers.image.documentation": "https://www.elastic.co/guide/en/elasticsearch/reference/index.html",
                        "org.opencontainers.image.licenses": "Elastic-License",
                        "org.opencontainers.image.revision": "1c34507e66d7db1211f66f3513706fdf548736aa",
                        "org.opencontainers.image.source": "https://github.com/elastic/elasticsearch",
                        "org.opencontainers.image.title": "Elasticsearch",
                        "org.opencontainers.image.url": "https://www.elastic.co/products/elasticsearch",
                        "org.opencontainers.image.vendor": "Elastic",
                        "org.opencontainers.image.version": "7.10.1"
                    },
                    "ParentId": "",
                    "RepoDigests": [
                        "docker.elastic.co/elasticsearch/elasticsearch@sha256:5d8f1962907ef60746a8cf61c8a7f2b8755510ee36bdee0f65417f90a38a0139"
                    ],
                    "RepoTags": [
                        "docker.elastic.co/elasticsearch/elasticsearch:7.10.1"
                    ],
                    "SharedSize": 0,
                    "Size": 773756675,
                    "VirtualSize": 773756675
                },
                {
                    "Containers": 1,
                    "Created": 1598864687,
                    "Id": "sha256:a0a227bf03ddc8b88bbb74b1b84a8a7220c8fa95b122cbde2a7444f32dc30659",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "portainer/portainer-ce@sha256:0ab9d25e9ac7b663a51afc6853875b2055d8812fcaf677d0013eba32d0bf0e0d"
                    ],
                    "RepoTags": [
                        "portainer/portainer-ce:latest"
                    ],
                    "SharedSize": 0,
                    "Size": 195546824,
                    "VirtualSize": 195546824
                },
                {
                    "Containers": 2,
                    "Created": 1578014497,
                    "Id": "sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "hello-world@sha256:1a523af650137b8accdaed439c17d684df61ee4d74feac151b5b337bd29e7eec"
                    ],
                    "RepoTags": [
                        "hello-world:latest"
                    ],
                    "SharedSize": 0,
                    "Size": 13336,
                    "VirtualSize": 13336
                },
                {
                    "Containers": 0,
                    "Created": 1573631696,
                    "Id": "sha256:3f6237885724af871088cfbb9d787ea4aebb37c0565e207e897c7f51ce0ad0ed",
                    "Labels": {
                        "maintainer": "Thomas Boerger <thomas@webhippie.de>",
                        "org.label-schema.build-date": "2019-11-13T07:54:28Z",
                        "org.label-schema.name": "MariaDB",
                        "org.label-schema.schema-version": "1.0",
                        "org.label-schema.vcs-ref": "1e1f1924a0477f837c8a4399467594a0a5c3bada",
                        "org.label-schema.vcs-url": "https://github.com/dockhippie/mariadb.git",
                        "org.label-schema.vendor": "Thomas Boerger",
                        "org.label-schema.version": "latest"
                    },
                    "ParentId": "",
                    "RepoDigests": [
                        "webhippie/mariadb@sha256:8a2c927529e5fd6238f08f79e3855d90a353e4475481574aa4bf0b90550b5db9"
                    ],
                    "RepoTags": [
                        "webhippie/mariadb:latest"
                    ],
                    "SharedSize": 57530959,
                    "Size": 656206898,
                    "VirtualSize": 656206898
                },
                {
                    "Containers": 0,
                    "Created": 1573631680,
                    "Id": "sha256:42ab00c664c227dce98aec279e4098cb569084d6597e562dd226c98df32dc058",
                    "Labels": {
                        "maintainer": "Thomas Boerger <thomas@webhippie.de>",
                        "org.label-schema.build-date": "2019-11-13T07:54:26Z",
                        "org.label-schema.name": "Redis",
                        "org.label-schema.schema-version": "1.0",
                        "org.label-schema.vcs-ref": "7b176b8e39cb973ed19aee8243ba63a6e75ffe60",
                        "org.label-schema.vcs-url": "https://github.com/dockhippie/redis.git",
                        "org.label-schema.vendor": "Thomas Boerger",
                        "org.label-schema.version": "latest"
                    },
                    "ParentId": "",
                    "RepoDigests": [
                        "webhippie/redis@sha256:42f6d51be6a7a5ef6fb672e98507824816566f0b1f89c19b2d585f54e26b2529"
                    ],
                    "RepoTags": [
                        "webhippie/redis:latest"
                    ],
                    "SharedSize": 57530959,
                    "Size": 59184716,
                    "VirtualSize": 59184716
                },
                {
                    "Containers": 1,
                    "Created": 1551262109,
                    "Id": "sha256:aa50897f28e43c1110328f1b8740a2ad097031e8d2443266e562fe74be1a7a19",
                    "Labels": {
                        "maintainer": "EclecticIQ <opentaxii@eclecticiq.com>"
                    },
                    "ParentId": "",
                    "RepoDigests": [
                        "eclecticiq/opentaxii@sha256:647b07724ae60b31accaf57a56fb8e7ee8f25506e3d283dce5ef6ca89002d662"
                    ],
                    "RepoTags": [
                        "eclecticiq/opentaxii:latest"
                    ],
                    "SharedSize": 0,
                    "Size": 188188625,
                    "VirtualSize": 188188625
                },
                {
                    "Containers": 0,
                    "Created": 1548789201,
                    "Id": "sha256:f3f4b8ddca6feca170e6239933cbf5139f52d8496737df497911850440f40a5a",
                    "Labels": null,
                    "ParentId": "",
                    "RepoDigests": [
                        "adoptopenjdk/openjdk11-openj9@sha256:60718fa9eb6b6bc4ab6fe7f3a9db31b8725fb63ebdda833a43f541c07792ff5c"
                    ],
                    "RepoTags": [
                        "adoptopenjdk/openjdk11-openj9:jdk-x.x.x.x-alpine-slim"
                    ],
                    "SharedSize": 237380314,
                    "Size": 237380314,
                    "VirtualSize": 237380314
                }
            ],
            "LayersSize": 6296579215,
            "Volumes": [
                {
                    "CreatedAt": "2021-01-10T11:33:47+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/mongodb/_data",
                    "Name": "mongodb",
                    "Options": {},
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 332256838
                    }
                },
                {
                    "CreatedAt": "2021-01-10T11:15:46+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/redisdata/_data",
                    "Name": "redisdata",
                    "Options": null,
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 44588590
                    }
                },
                {
                    "CreatedAt": "2021-01-05T20:13:01+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/opentaxii-input/_data",
                    "Name": "opentaxii-input",
                    "Options": {},
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 0
                    }
                },
                {
                    "CreatedAt": "2020-12-18T20:13:08+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/portainer_data/_data",
                    "Name": "portainer_data",
                    "Options": null,
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 202048
                    }
                },
                {
                    "CreatedAt": "2021-01-10T11:10:47+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/s3data/_data",
                    "Name": "s3data",
                    "Options": null,
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 503932
                    }
                },
                {
                    "CreatedAt": "2021-01-10T11:34:11+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/temp-volume/_data",
                    "Name": "temp-volume",
                    "Options": null,
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 0,
                        "Size": 0
                    }
                },
                {
                    "CreatedAt": "2021-01-06T12:12:03+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55/_data",
                    "Name": "88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55",
                    "Options": null,
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 0
                    }
                },
                {
                    "CreatedAt": "2020-12-18T20:33:49+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/amqpdata/_data",
                    "Name": "amqpdata",
                    "Options": null,
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 2775833149
                    }
                },
                {
                    "CreatedAt": "2020-12-18T20:33:46+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/esdata/_data",
                    "Name": "esdata",
                    "Options": null,
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 392439372
                    }
                },
                {
                    "CreatedAt": "2021-01-05T20:13:03+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/opentaxii-data/_data",
                    "Name": "opentaxii-data",
                    "Options": {},
                    "Scope": "local",
                    "UsageData": {
                        "RefCount": 1,
                        "Size": 98304
                    }
                }
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|BuildCache|BuilderSize|Containers|Images|LayersSize|Volumes|
>|---|---|---|---|---|---|
>|  | 0 | {'Id': '7997c8bd061e762bfdb105274af3f60e5f2254aaba2172744db1edfccc2b8a41', 'Names': ['/hello-docker'], 'Image': 'hello-world', 'ImageID': 'sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b', 'Command': '/hello', 'Created': 1610122922, 'Ports': [], 'SizeRootFs': 13336, 'Labels': {}, 'State': 'exited', 'Status': 'Exited (0) 39 hours ago', 'HostConfig': {'NetworkMode': 'default'}, 'NetworkSettings': {'Networks': {'bridge': {'IPAMConfig': None, 'Links': None, 'Aliases': None, 'NetworkID': 'b5b425aad28e5f4b9c9b118257ce214455d84a7901e5a90d79e3ae4f527f725e', 'EndpointID': '', 'Gateway': '', 'IPAddress': '', 'IPPrefixLen': 0, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '0caea4d0b099175e6d3d8c0f68d0ab6624fc4339ff3e88db7ec509efd5e3c6c3', 'Names': ['/crazy_curran'], 'Image': 'hello-world', 'ImageID': 'sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b', 'Command': '/hello', 'Created': 1610121618, 'Ports': [], 'SizeRootFs': 13336, 'Labels': {}, 'State': 'exited', 'Status': 'Exited (0) 40 hours ago', 'HostConfig': {'NetworkMode': 'default'}, 'NetworkSettings': {'Networks': {'bridge': {'IPAMConfig': None, 'Links': None, 'Aliases': None, 'NetworkID': 'b5b425aad28e5f4b9c9b118257ce214455d84a7901e5a90d79e3ae4f527f725e', 'EndpointID': '', 'Gateway': '', 'IPAddress': '', 'IPPrefixLen': 0, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '57d49db83f2ced79c87e5c50d2b407bbb7bc33c3a95a03e142477f3a3b79ded5', 'Names': ['/mongodb-express'], 'Image': 'mongo-express', 'ImageID': 'sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e', 'Command': 'tini -- /docker-entrypoint.sh mongo-express', 'Created': 1609920735, 'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 8081, 'PublicPort': 8081, 'Type': 'tcp'}], 'SizeRw': 169, 'SizeRootFs': 129389081, 'Labels': {'com.docker.compose.config-hash': '0a75befcc34f36ab677c5d8f09d2ee8063e8ad3d', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'mongodb', 'com.docker.compose.service': 'mongo-express', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'mongodb_default'}, 'NetworkSettings': {'Networks': {'mongodb_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b', 'EndpointID': '2628f2ac3df2f3b5a8059fe3e736d9fe9da4d428c9da9220dad5d2eb100258fa', 'Gateway': '1.0.0.1', 'IPAddress': '1.0.0.3', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:1a:00:03', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '161f9d908f5bc34a9638a496b492cce47a16cd47268ec61f04e10b1224dbd2a3', 'Names': ['/mongodb'], 'Image': 'mongo', 'ImageID': 'sha256:c97feb3412a387d4d3bbd8653b09ef26683263a192e0e8dc6554e65bfb637a86', 'Command': 'docker-entrypoint.sh mongod', 'Created': 1609920723, 'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 27017, 'PublicPort': 27017, 'Type': 'tcp'}], 'SizeRootFs': 492934722, 'Labels': {'com.docker.compose.config-hash': '74e20e7feccade15ae2ce2378088081ae5726a05', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'mongodb', 'com.docker.compose.service': 'mongo', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'mongodb_default'}, 'NetworkSettings': {'Networks': {'mongodb_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '5e04b0a7302ac9ce9c5fa3ba9d71c6bf173a9aaca5b3efc6c79b3bf01260371b', 'EndpointID': '2f478dd56c3bfa4b0bfb2a6bdfa5a7f95f20960dbc5045238567f4f7c2b5e46d', 'Gateway': '1.0.0.1', 'IPAddress': '1.0.0.2', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:1a:00:02', 'DriverOpts': None}}}, 'Mounts': [{'Type': 'volume', 'Name': '88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55', 'Source': '', 'Destination': '/data/configdb', 'Driver': 'local', 'Mode': '', 'RW': True, 'Propagation': ''}, {'Type': 'volume', 'Name': 'mongodb', 'Source': '/var/lib/docker/volumes/mongodb/_data', 'Destination': '/data/db', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''}]},<br/>{'Id': 'b2f4cb3dbb3656d62441ba4d6a718e1271df075781d8c56e85cf585841772ac9', 'Names': ['/taxiserver'], 'Image': 'taxiserver:latest', 'ImageID': 'sha256:70d8624ce3a1f02008bcdb8ba2bf4001e178bcb0ab90bdfab0eb17fd4ea2ca7f', 'Command': "/bin/sh -c 'java -XX:+UnlockExperimentalVMOptions -XX:+UseCGroupMemoryLimitForHeap -Dcom.sun.management.jmxremote -noverify ${JAVA_OPTS} -jar taxii-server-micronaut-all.jar'", 'Created': 1609866461, 'Ports': [], 'SizeRootFs': 298529298, 'Labels': {}, 'State': 'exited', 'Status': 'Exited (143) 3 days ago', 'HostConfig': {'NetworkMode': 'bridge'}, 'NetworkSettings': {'Networks': {'bridge': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': 'ebc2e7e11094a2f780d8f41f7a2fffd1e36208d6e2939ec94770dfd6083a384d', 'EndpointID': '', 'Gateway': '', 'IPAddress': '', 'IPPrefixLen': 0, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '04be62e20d33bf299865e26b657ec5516928641558ccff6a899407ab0b6b1d94', 'Names': ['/test-taxii'], 'Image': 'eclecticiq/opentaxii:latest', 'ImageID': 'sha256:aa50897f28e43c1110328f1b8740a2ad097031e8d2443266e562fe74be1a7a19', 'Command': '/entrypoint.sh /venv/bin/gunicorn opentaxii.http:app --workers=2 --log-level=info --log-file=- --timeout=300 --config=python:opentaxii.http --bind=0.0.0.0:9000', 'Created': 1609863181, 'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 9000, 'PublicPort': 6000, 'Type': 'tcp'}], 'SizeRw': 782, 'SizeRootFs': 188189407, 'Labels': {'maintainer': 'EclecticIQ <opentaxii@eclecticiq.com>'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'bridge'}, 'NetworkSettings': {'Networks': {'bridge': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': 'bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34', 'EndpointID': '3fccdab7ca5ad3f11ef72dd8d76044160c0cc66e005643d9584fbcb903500c1b', 'Gateway': '1.0.0.7', 'IPAddress': '1.0.0.2', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:11:00:02', 'DriverOpts': None}}}, 'Mounts': [{'Type': 'volume', 'Name': 'opentaxii-input', 'Source': '/var/lib/docker/volumes/opentaxii-input/_data', 'Destination': '/input', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''}, {'Type': 'volume', 'Name': 'opentaxii-data', 'Source': '/var/lib/docker/volumes/opentaxii-data/_data', 'Destination': '/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''}]},<br/>{'Id': '14d3c9c9c306e427b8cd4a2e4d80ddd6ad38684936224f3e36440b6b6f08bc34', 'Names': ['/opencti_connector-ipinfo'], 'Image': 'opencti/connector-ipinfo:4.0.3', 'ImageID': 'sha256:cd608aa8a042cb46adf5aaa3c43ce92a85b3817c5254b8de0e53b49b7a729c6b', 'Command': '/entrypoint.sh', 'Created': 1608827060, 'Ports': [], 'SizeRw': 537027, 'SizeRootFs': 94682341, 'Labels': {'com.docker.compose.config-hash': '3a9bd111dfb135ed1a839ad5e164068c78b2b630', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'connector-export-file-stix', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '717ad998186f308ebefb4f0f71c04ae5fbc143e450bed9eba8570d9adc099624', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.5', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:08', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '7ba5c18139e09bd2a34e7be27db70520c6901dad7db901dd073c1f96abfc9034', 'Names': ['/opencti_connector-import-file-pdf-observables'], 'Image': 'opencti/connector-import-file-pdf-observables:4.0.3', 'ImageID': 'sha256:51afb662d3c993510447e431e3da8495140690cb9c1ca93c7cf19424a63ce223', 'Command': '/entrypoint.sh', 'Created': 1608564498, 'Ports': [], 'SizeRw': 553305, 'SizeRootFs': 115044111, 'Labels': {'com.docker.compose.config-hash': '336a368bc6eb7eae69a090a9ac80f9614d02685e', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'connector-import-file-pdf-observables', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': 'e99d6307854d91785af35603157c0a82826a5ebe59b3072924770dd7e66be07c', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.2', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:02', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '2aa24d29411d89e1d3fcd708b0dae10e32a84d53d9164a5998c217e054d31bd9', 'Names': ['/opencti_connector-import-file-stix'], 'Image': 'opencti/connector-import-file-stix:4.0.3', 'ImageID': 'sha256:cfd88d87460e5c1e0d7c82ee58258208c80d8acbd9417afe2f7cea10bfef4dd9', 'Command': '/entrypoint.sh', 'Created': 1608564460, 'Ports': [], 'SizeRw': 537027, 'SizeRootFs': 66912727, 'Labels': {'com.docker.compose.config-hash': 'd39640557a02e44f4983eac94b75e00a8b975e07', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'connector-import-file-stix', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up Less than a second', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '5b5f7eef4e12eef95f1a28143b26a49d4edbc971592859348393be98a56320f8', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.5', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:07', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '5f92895691ca7eeb6c8bc3f4914cd6210a3d59a72e8e48890f336d352cbc9753', 'Names': ['/opencti_connector-export-file-csv'], 'Image': 'opencti/connector-export-file-csv:4.0.3', 'ImageID': 'sha256:25500204dfbea42059fc77100177de2c5d92cd4219ca6437831bfc26c53b628c', 'Command': '/entrypoint.sh', 'Created': 1608564417, 'Ports': [], 'SizeRw': 537027, 'SizeRootFs': 66919911, 'Labels': {'com.docker.compose.config-hash': '64d591ae3f975e1a79738447dd38d1e554486f44', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'connector-export-file-csv', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '91a3c7767104581ddb04f739c3cc313e7bfe0f6db5ad4c6865970d1e60bf99b7', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.5', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:09', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '65ddee16a51d57e8b57f6b00acd7f9ae5b92152731276d6d4d497c2f979e2b1e', 'Names': ['/opencti_connector-export-file-stix'], 'Image': 'opencti/connector-export-file-stix:4.0.3', 'ImageID': 'sha256:42efb539088b86558557e24c10d00810014e5e820f0d7ac8bb8d0fd3981a0bda', 'Command': '/entrypoint.sh', 'Created': 1608564294, 'Ports': [], 'SizeRw': 537027, 'SizeRootFs': 66914627, 'Labels': {'com.docker.compose.config-hash': '3a9bd111dfb135ed1a839ad5e164068c78b2b630', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'connector-export-file-stix', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '8cd31e2f66b6df498962e8cc4df17f741b842546c4fd61ac9a79c2f6805f66bc', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.5', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:04', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': 'c61e3108d286e07032f8ec44f3e5883bac00838a673972e871c31d970b75d155', 'Names': ['/opencti_connector-history'], 'Image': 'opencti/connector-history:4.0.3', 'ImageID': 'sha256:0257f00635aca1087fa630362c470f22c4661bc87d4e6e8c54c64f5795dfce1e', 'Command': '/entrypoint.sh', 'Created': 1608564112, 'Ports': [], 'SizeRw': 537027, 'SizeRootFs': 69431220, 'Labels': {'com.docker.compose.config-hash': '6ac905cdbdc63d012688d34a06393c135d384c79', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'connector-history', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '048b58a95cd8a27e6f640c844e9b5ea7c65c4fdcbdc5dfdc683986daf6813e4a', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.5', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:0d', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '2220832cc2840320c53156993563fce5298d4e0317d71b42851067f02c762423', 'Names': ['/opencti_connector-alienvault'], 'Image': 'opencti/connector-alienvault:4.0.3', 'ImageID': 'sha256:3e718135d5fb38c0af85c9c00b64160082a407722d929572a190d6092c604e15', 'Command': '/entrypoint.sh', 'Created': 1608563957, 'Ports': [], 'SizeRw': 597000, 'SizeRootFs': 67793705, 'Labels': {'com.docker.compose.config-hash': '3a9bd111dfb135ed1a839ad5e164068c78b2b630', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'connector-export-file-stix', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '3a8b638639e908f26163f7271bb88eee017a3fc5cb253bf180e8b190ebca5a80', 'Gateway': '1.2.0.1', 'IPAddress': '1.2.0.12', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:0c', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': 'cc1743f3d83750f973796d0aaadba7ec5fb67361906666b2a48be0512d82a050', 'Names': ['/opencti_worker_2'], 'Image': 'opencti/worker:4.0.3', 'ImageID': 'sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473', 'Command': '/entrypoint.sh', 'Created': 1608562731, 'Ports': [], 'SizeRw': 267877, 'SizeRootFs': 130086647, 'Labels': {'com.docker.compose.config-hash': '4f611b1efe20fd3b147a1b830afceff276398af1', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'worker', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '03f052a4e86e16124c279fe9e593e4686fcc658b57d82b51c031163f2076cfc6', 'Gateway': '1.2.0.1', 'IPAddress': '1.2.0.1', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:0e', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '118fe891bacfe3328ad64677ac492f0568547740458090594600950613774fcf', 'Names': ['/opencti_worker_1'], 'Image': 'opencti/worker:4.0.3', 'ImageID': 'sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473', 'Command': '/entrypoint.sh', 'Created': 1608561358, 'Ports': [], 'SizeRw': 267877, 'SizeRootFs': 130086647, 'Labels': {'com.docker.compose.config-hash': '4f611b1efe20fd3b147a1b830afceff276398af1', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'worker', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': 'ce7645ab046233a84fc7c2c9ce796a120edfd790280a52fb9df55f2066458141', 'Gateway': '1.2.0.1', 'IPAddress': '1.0.0.5', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:0f', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': '4be1f8dec98809ec2cf360d1d882beb8c819a58111070a04affbc714a071d1a0', 'Names': ['/redis'], 'Image': 'redis:6.0.9', 'ImageID': 'sha256:ef47f3b6dc11e8f17fb39a6e46ecaf4efd47b3d374e92aeb9f2606896b751251', 'Command': 'docker-entrypoint.sh redis-server', 'Created': 1608559382, 'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 6379, 'PublicPort': 6379, 'Type': 'tcp'}], 'SizeRootFs': 104252176, 'Labels': {'com.docker.compose.config-hash': 'daf5e1ad7b16619b8c479df88301daf432c5a564', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'redis', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '996d21e0ac5c57239c1622bba9c9a5d303a82cec1c15146a94c84766cd460966', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.3', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:03', 'DriverOpts': None}}}, 'Mounts': [{'Type': 'volume', 'Name': 'redisdata', 'Source': '/var/lib/docker/volumes/redisdata/_data', 'Destination': '/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''}]},<br/>{'Id': '5c3b991454ad1daa7d2f287cc0450d69f0c1e0a7778f8f55199b5201da3b5390', 'Names': ['/elasticsearch'], 'Image': 'docker.elastic.co/elasticsearch/elasticsearch:7.10.1', 'ImageID': 'sha256:558380375f1a36c20e67c3a0b7bf715c659d75520d0e688b066d5e708918d716', 'Command': '/tini -- /usr/local/bin/docker-entrypoint.sh eswrapper', 'Created': 1608559270, 'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 9200, 'PublicPort': 9200, 'Type': 'tcp'}, {'IP': '0.0.0.0', 'PrivatePort': 9300, 'PublicPort': 9300, 'Type': 'tcp'}], 'SizeRw': 335097051, 'SizeRootFs': 1108853726, 'Labels': {'com.docker.compose.config-hash': '6367ce3fdc8ac903d07574f97c9dc4a7208f3aef', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'elasticsearch', 'com.docker.compose.version': '1.5.0', 'org.label-schema.build-date': '2020-12-05T01:00:33.671820Z', 'org.label-schema.license': 'Elastic-License', 'org.label-schema.name': 'Elasticsearch', 'org.label-schema.schema-version': '1.0', 'org.label-schema.url': 'https://www.elastic.co/products/elasticsearch', 'org.label-schema.usage': 'https://www.elastic.co/guide/en/elasticsearch/reference/index.html', 'org.label-schema.vcs-ref': '1c34507e66d7db1211f66f3513706fdf548736aa', 'org.label-schema.vcs-url': 'https://github.com/elastic/elasticsearch', 'org.label-schema.vendor': 'Elastic', 'org.label-schema.version': '7.10.1', 'org.opencontainers.image.created': '2020-12-05T01:00:33.671820Z', 'org.opencontainers.image.documentation': 'https://www.elastic.co/guide/en/elasticsearch/reference/index.html', 'org.opencontainers.image.licenses': 'Elastic-License', 'org.opencontainers.image.revision': '1c34507e66d7db1211f66f3513706fdf548736aa', 'org.opencontainers.image.source': 'https://github.com/elastic/elasticsearch', 'org.opencontainers.image.title': 'Elasticsearch', 'org.opencontainers.image.url': 'https://www.elastic.co/products/elasticsearch', 'org.opencontainers.image.vendor': 'Elastic', 'org.opencontainers.image.version': '7.10.1'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '64904da59143266418038a1f64c1f7573d0a31f79ed0a32998ce94172ba49c88', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.5', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:06', 'DriverOpts': None}}}, 'Mounts': [{'Type': 'volume', 'Name': 'esdata', 'Source': '/var/lib/docker/volumes/esdata/_data', 'Destination': '/usr/share/elasticsearch/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''}]},<br/>{'Id': '93b8c8f3e5c5b959b5382b20ec3f441d1b960124419e809d86f0a34cee59d7c8', 'Names': ['/rabbitmq'], 'Image': 'rabbitmq:3.8-management', 'ImageID': 'sha256:1ecd87fb78edc5feada026b0f926bcf7458eb9c80db8100618e1df725645540e', 'Command': 'docker-entrypoint.sh rabbitmq-server', 'Created': 1608559125, 'Ports': [{'PrivatePort': 5672, 'Type': 'tcp'}, {'PrivatePort': 15671, 'Type': 'tcp'}, {'IP': '0.0.0.0', 'PrivatePort': 15672, 'PublicPort': 15672, 'Type': 'tcp'}, {'PrivatePort': 15691, 'Type': 'tcp'}, {'PrivatePort': 15692, 'Type': 'tcp'}, {'PrivatePort': 25672, 'Type': 'tcp'}, {'PrivatePort': 4369, 'Type': 'tcp'}, {'PrivatePort': 5671, 'Type': 'tcp'}], 'SizeRw': 1101, 'SizeRootFs': 197694194, 'Labels': {'com.docker.compose.config-hash': 'd18573c6a89abeacddfab591aca6e68b2921b90a', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'rabbitmq', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '2eb072c87b19c95fac0f6121af754ea0cec052a27cb4f2aee8755c2aec92dfce', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.1', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:0a', 'DriverOpts': None}}}, 'Mounts': [{'Type': 'volume', 'Name': 'amqpdata', 'Source': '/var/lib/docker/volumes/amqpdata/_data', 'Destination': '/var/lib/rabbitmq', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''}]},<br/>{'Id': '0b7479a2f6abb93887cfb881dc8e4464e48df384887cb483c99a134cf894644b', 'Names': ['/opencti'], 'Image': 'opencti/platform:4.0.3', 'ImageID': 'sha256:b03e4ab4fe4739d8ef6cd6a6639ccea8e09eaee8f6fb8842be9225c3719e27cd', 'Command': '/entrypoint.sh', 'Created': 1608557349, 'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 8080, 'PublicPort': 8080, 'Type': 'tcp'}], 'SizeRw': 495546664, 'SizeRootFs': 1213991401, 'Labels': {'com.docker.compose.config-hash': '22687afb96da8b20f51629f9868dfd237ad601a6', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'opencti', 'com.docker.compose.version': '1.5.0'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': '588234b49254b09744635401d2c95f092f7884bac7ae85e3e23e6cccab00abb7', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.1', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:0b', 'DriverOpts': None}}}, 'Mounts': []},<br/>{'Id': 'cddbc48191628fde8991adfed5d0e4c2704f4e09b9b79d96549be8baf608984d', 'Names': ['/minio'], 'Image': 'minio/minio:RELEASE.2020-12-12T08-39-07Z', 'ImageID': 'sha256:f1a30c1dd760a7927d12a559c55fcf6ccb7efbbe79295ecc9394b7e4fe21d216', 'Command': '/usr/bin/docker-entrypoint.sh server /data', 'Created': 1608557040, 'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 9000, 'PublicPort': 5000, 'Type': 'tcp'}], 'SizeRootFs': 182261690, 'Labels': {'architecture': 'x86_64', 'build-date': '2020-10-31T05:07:05.471303', 'com.docker.compose.config-hash': 'da8a89d63690ae08df58294ad3685f61c201125e', 'com.docker.compose.container-number': '1', 'com.docker.compose.oneoff': 'False', 'com.docker.compose.project': 'openctiv4', 'com.docker.compose.service': 'minio', 'com.docker.compose.version': '1.5.0', 'com.redhat.build-host': 'cpt-1002.osbs.prod.upshift.rdu2.redhat.com', 'com.redhat.component': 'ubi8-minimal-container', 'com.redhat.license_terms': 'https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI', 'description': 'MinIO object storage is fundamentally different. Designed for performance and the S3 API, it is 100% open-source. MinIO is ideal for large, private cloud environments with stringent security requirements and delivers mission-critical availability across a diverse range of workloads.', 'distribution-scope': 'public', 'io.k8s.description': 'The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.', 'io.k8s.display-name': 'Red Hat Universal Base Image 8 Minimal', 'io.openshift.expose-services': '', 'io.openshift.tags': 'minimal rhel8', 'maintainer': 'MinIO Inc <dev@min.io>', 'name': 'MinIO', 'release': 'RELEASE.2020-11-25T22-36-25Z', 'summary': 'MinIO is a High Performance Object Storage, API compatible with Amazon S3 cloud storage service.', 'url': 'https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.3-201', 'vcs-ref': 'f53dab37c7541dd0080f410727c5886e85c09ee7', 'vcs-type': 'git', 'vendor': 'MinIO Inc <dev@min.io>', 'version': 'RELEASE.2020-11-25T22-36-25Z'}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'openctiv4_default'}, 'NetworkSettings': {'Networks': {'openctiv4_default': {'IPAMConfig': {}, 'Links': None, 'Aliases': None, 'NetworkID': '51bdffad4912288c4232bdc10e4e0c54a029b1291db71e3034c6b6353fb10a86', 'EndpointID': 'b3d4562edf6ea434a58ac398ca2c179cb95740af5e4c3bf970499544413397a4', 'Gateway': '1.0.0.5', 'IPAddress': '1.0.0.5', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:18:00:05', 'DriverOpts': None}}}, 'Mounts': [{'Type': 'volume', 'Name': 's3data', 'Source': '/var/lib/docker/volumes/s3data/_data', 'Destination': '/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''}]},<br/>{'Id': '63de66e6e323ae7e189aeeba070adc184b386456ffe0dde9e3a88b8da0660d54', 'Names': ['/portainer'], 'Image': 'portainer/portainer-ce', 'ImageID': 'sha256:a0a227bf03ddc8b88bbb74b1b84a8a7220c8fa95b122cbde2a7444f32dc30659', 'Command': '/portainer', 'Created': 1608307988, 'Ports': [{'IP': '0.0.0.0', 'PrivatePort': 9000, 'PublicPort': 9000, 'Type': 'tcp'}, {'IP': '0.0.0.0', 'PrivatePort': 8000, 'PublicPort': 8000, 'Type': 'tcp'}], 'SizeRootFs': 195546824, 'Labels': {}, 'State': 'running', 'Status': 'Up 23 minutes', 'HostConfig': {'NetworkMode': 'default'}, 'NetworkSettings': {'Networks': {'bridge': {'IPAMConfig': None, 'Links': None, 'Aliases': None, 'NetworkID': 'bd9761f59994adf640e4728dfdf92856d8292a649e4cf6b102ddbed672445a34', 'EndpointID': '338cd95d726c3fde9674c4e86a9754ad5041ed9f3ea67b533224d8d27f2203f8', 'Gateway': '1.0.0.7', 'IPAddress': '1.0.0.3', 'IPPrefixLen': 16, 'IPv6Gateway': '', 'GlobalIPv6Address': '', 'GlobalIPv6PrefixLen': 0, 'MacAddress': '02:42:ac:11:00:03', 'DriverOpts': None}}}, 'Mounts': [{'Type': 'volume', 'Name': 'portainer_data', 'Source': '/var/lib/docker/volumes/portainer_data/_data', 'Destination': '/data', 'Driver': 'local', 'Mode': 'z', 'RW': True, 'Propagation': ''}, {'Type': 'bind', 'Source': '/var/run/docker.sock', 'Destination': '/var/run/docker.sock', 'Mode': '', 'RW': True, 'Propagation': 'rprivate'}]} | {'Containers': 1, 'Created': 1609870186, 'Id': 'sha256:05bf9d904cd0953ee1ad647a61abfb0ab1470062f8baa70495b4b068e95a514e', 'Labels': None, 'ParentId': '', 'RepoDigests': ['mongo-express@sha256:6ae44c697cd2381772f8ea8f0571008b62e36301305b113df7f35f2e683e8255'], 'RepoTags': ['mongo-express:latest'], 'SharedSize': 0, 'Size': 129388912, 'VirtualSize': 129388912},<br/>{'Containers': 1, 'Created': 1609866227, 'Id': 'sha256:70d8624ce3a1f02008bcdb8ba2bf4001e178bcb0ab90bdfab0eb17fd4ea2ca7f', 'Labels': None, 'ParentId': 'sha256:c6c592c10fd1c88676835629a4b9d19f3e1354ca7d927c2d829628a53b427b3c', 'RepoDigests': None, 'RepoTags': ['taxiserver:latest'], 'SharedSize': 237380314, 'Size': 298529298, 'VirtualSize': 298529298},<br/>{'Containers': 1, 'Created': 1609798872, 'Id': 'sha256:c97feb3412a387d4d3bbd8653b09ef26683263a192e0e8dc6554e65bfb637a86', 'Labels': None, 'ParentId': '', 'RepoDigests': ['mongo@sha256:7722bd2778a299b6f4a62b93a0d2741c734ba7332a090131030ca28261a9a198'], 'RepoTags': ['mongo:latest'], 'SharedSize': 63252300, 'Size': 492934722, 'VirtualSize': 492934722},<br/>{'Containers': 2, 'Created': 1608474777, 'Id': 'sha256:670872e9f7dbae235172cb2b7c732b0ea05283aeb45fcaa4616673826f9c4473', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/worker@sha256:5eef44425b59c272135cb6460232891cd607ccc4b5557a441cce3120624b9538'], 'RepoTags': ['opencti/worker:4.0.3'], 'SharedSize': 0, 'Size': 129818770, 'VirtualSize': 129818770},<br/>{'Containers': 1, 'Created': 1608474717, 'Id': 'sha256:b03e4ab4fe4739d8ef6cd6a6639ccea8e09eaee8f6fb8842be9225c3719e27cd', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/platform@sha256:19a610656b32bf6ff894e04a0dcf9064ce3e850b3fc2f497f5478a21598753e5'], 'RepoTags': ['opencti/platform:4.0.3'], 'SharedSize': 80179887, 'Size': 718444737, 'VirtualSize': 718444737},<br/>{'Containers': 1, 'Created': 1608473851, 'Id': 'sha256:0257f00635aca1087fa630362c470f22c4661bc87d4e6e8c54c64f5795dfce1e', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/connector-history@sha256:a80726951eb8d10acb6700c1ba1a602178e672f52b72787ed23f79d473d588cc'], 'RepoTags': ['opencti/connector-history:4.0.3'], 'SharedSize': 42359686, 'Size': 68894193, 'VirtualSize': 68894193},<br/>{'Containers': 1, 'Created': 1608473623, 'Id': 'sha256:cd608aa8a042cb46adf5aaa3c43ce92a85b3817c5254b8de0e53b49b7a729c6b', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/connector-ipinfo@sha256:ae818dcf18b0acf5bdd25279ada6feb7f05c9b1745c847d3930a1fdaee555c57'], 'RepoTags': ['opencti/connector-ipinfo:4.0.3'], 'SharedSize': 42359686, 'Size': 94145314, 'VirtualSize': 94145314},<br/>{'Containers': 1, 'Created': 1608472895, 'Id': 'sha256:3e718135d5fb38c0af85c9c00b64160082a407722d929572a190d6092c604e15', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/connector-alienvault@sha256:417b9cf7ed4f8ab5ebb391c52a38decfa306ef89b5dbc1853a85280f75fdd78d'], 'RepoTags': ['opencti/connector-alienvault:4.0.3'], 'SharedSize': 42359686, 'Size': 67196705, 'VirtualSize': 67196705},<br/>{'Containers': 1, 'Created': 1608472820, 'Id': 'sha256:25500204dfbea42059fc77100177de2c5d92cd4219ca6437831bfc26c53b628c', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/connector-export-file-csv@sha256:d36ba9933590e3ade436fefa790fe03918a561cc69a944b473fc8eac5ca580f0'], 'RepoTags': ['opencti/connector-export-file-csv:4.0.3'], 'SharedSize': 42359686, 'Size': 66382884, 'VirtualSize': 66382884},<br/>{'Containers': 1, 'Created': 1608472784, 'Id': 'sha256:42efb539088b86558557e24c10d00810014e5e820f0d7ac8bb8d0fd3981a0bda', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/connector-export-file-stix@sha256:3f0d74c5c77295edff0e7bb8ff7fa67db496c9f851b52643d705a0044d0fd67b'], 'RepoTags': ['opencti/connector-export-file-stix:4.0.3'], 'SharedSize': 42359686, 'Size': 66377600, 'VirtualSize': 66377600},<br/>{'Containers': 1, 'Created': 1608472749, 'Id': 'sha256:51afb662d3c993510447e431e3da8495140690cb9c1ca93c7cf19424a63ce223', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/connector-import-file-pdf-observables@sha256:1f778d9cfb81b3f1d7e4456b9123022dca285da4bd5431360035dd13ec23e9ca'], 'RepoTags': ['opencti/connector-import-file-pdf-observables:4.0.3'], 'SharedSize': 42359686, 'Size': 114490806, 'VirtualSize': 114490806},<br/>{'Containers': 1, 'Created': 1608472472, 'Id': 'sha256:cfd88d87460e5c1e0d7c82ee58258208c80d8acbd9417afe2f7cea10bfef4dd9', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/connector-import-file-stix@sha256:2e43819b4d1ef5f4de3a74382e5334e52647100553ea1b411a5bad87fa9e2984'], 'RepoTags': ['opencti/connector-import-file-stix:4.0.3'], 'SharedSize': 42359686, 'Size': 66375700, 'VirtualSize': 66375700},<br/>{'Containers': 0, 'Created': 1608200626, 'Id': 'sha256:dca5e1ed7218f3145b4414b6599a8aec9385857664bd6cc928ea9fba26febf3f', 'Labels': None, 'ParentId': '', 'RepoDigests': ['opencti/platform@sha256:183a3c085644615eab322d9d460d875c4d6b3f4c03bd5c4bac3e467771c79bdf'], 'RepoTags': ['opencti/platform:4.0.2', 'opencti/platform:latest'], 'SharedSize': 80179887, 'Size': 718413368, 'VirtualSize': 718413368},<br/>{'Containers': 1, 'Created': 1608165887, 'Id': 'sha256:1ecd87fb78edc5feada026b0f926bcf7458eb9c80db8100618e1df725645540e', 'Labels': None, 'ParentId': '', 'RepoDigests': ['rabbitmq@sha256:849677f6903921038a4541dd907e48a7d0e64a4cea63302acd73f9ee208789ce'], 'RepoTags': ['rabbitmq:3.8-management'], 'SharedSize': 63252300, 'Size': 197693093, 'VirtualSize': 197693093},<br/>{'Containers': 0, 'Created': 1608160149, 'Id': 'sha256:959fcab9b1e95d6d7ec1fc4c25491dd7e8cf43aed7346e089d2b564f83cbf58b', 'Labels': {'maintainer': 'ownCloud DevOps <devops@owncloud.com>', 'org.label-schema.build-date': '2020-12-16T23:07:14Z', 'org.label-schema.name': 'ownCloud Server', 'org.label-schema.schema-version': '1.0', 'org.label-schema.vcs-ref': '6da3457d723a5ffee6bc0eea945e0ba3fdbd629b', 'org.label-schema.vcs-url': 'https://github.com/owncloud-docker/server.git', 'org.label-schema.vendor': 'ownCloud GmbH'}, 'ParentId': '', 'RepoDigests': ['owncloud/server@sha256:e5be595c31734b25133c69aec27c32e87fe011201540b940f1acbd629f910691'], 'RepoTags': ['owncloud/server:latest'], 'SharedSize': 0, 'Size': 1363203435, 'VirtualSize': 1363203435},<br/>{'Containers': 1, 'Created': 1607763909, 'Id': 'sha256:f1a30c1dd760a7927d12a559c55fcf6ccb7efbbe79295ecc9394b7e4fe21d216', 'Labels': {'architecture': 'x86_64', 'build-date': '2020-10-31T05:07:05.471303', 'com.redhat.build-host': 'cpt-1002.osbs.prod.upshift.rdu2.redhat.com', 'com.redhat.component': 'ubi8-minimal-container', 'com.redhat.license_terms': 'https://www.redhat.com/en/about/red-hat-end-user-license-agreements#UBI', 'description': 'MinIO object storage is fundamentally different. Designed for performance and the S3 API, it is 100% open-source. MinIO is ideal for large, private cloud environments with stringent security requirements and delivers mission-critical availability across a diverse range of workloads.', 'distribution-scope': 'public', 'io.k8s.description': 'The Universal Base Image Minimal is a stripped down image that uses microdnf as a package manager. This base image is freely redistributable, but Red Hat only supports Red Hat technologies through subscriptions for Red Hat products. This image is maintained by Red Hat and updated regularly.', 'io.k8s.display-name': 'Red Hat Universal Base Image 8 Minimal', 'io.openshift.expose-services': '', 'io.openshift.tags': 'minimal rhel8', 'maintainer': 'MinIO Inc <dev@min.io>', 'name': 'MinIO', 'release': 'RELEASE.2020-11-25T22-36-25Z', 'summary': 'MinIO is a High Performance Object Storage, API compatible with Amazon S3 cloud storage service.', 'url': 'https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.3-201', 'vcs-ref': 'f53dab37c7541dd0080f410727c5886e85c09ee7', 'vcs-type': 'git', 'vendor': 'MinIO Inc <dev@min.io>', 'version': 'RELEASE.2020-11-25T22-36-25Z'}, 'ParentId': '', 'RepoDigests': ['minio/minio@sha256:a2eeb964863632a274f3eed08fc256b790ca83a020e164dd18e1e5f402d9f8d4'], 'RepoTags': ['minio/minio:RELEASE.2020-12-12T08-39-07Z'], 'SharedSize': 0, 'Size': 182261690, 'VirtualSize': 182261690},<br/>{'Containers': 1, 'Created': 1607703900, 'Id': 'sha256:ef47f3b6dc11e8f17fb39a6e46ecaf4efd47b3d374e92aeb9f2606896b751251', 'Labels': None, 'ParentId': '', 'RepoDigests': ['redis@sha256:0f724af268d0d3f5fb1d6b33fc22127ba5cbca2d58523b286ed3122db0dc5381'], 'RepoTags': ['redis:6.0.9'], 'SharedSize': 0, 'Size': 104252176, 'VirtualSize': 104252176},<br/>{'Containers': 1, 'Created': 1607130473, 'Id': 'sha256:558380375f1a36c20e67c3a0b7bf715c659d75520d0e688b066d5e708918d716', 'Labels': {'org.label-schema.build-date': '2020-12-05T01:00:33.671820Z', 'org.label-schema.license': 'Elastic-License', 'org.label-schema.name': 'Elasticsearch', 'org.label-schema.schema-version': '1.0', 'org.label-schema.url': 'https://www.elastic.co/products/elasticsearch', 'org.label-schema.usage': 'https://www.elastic.co/guide/en/elasticsearch/reference/index.html', 'org.label-schema.vcs-ref': '1c34507e66d7db1211f66f3513706fdf548736aa', 'org.label-schema.vcs-url': 'https://github.com/elastic/elasticsearch', 'org.label-schema.vendor': 'Elastic', 'org.label-schema.version': '7.10.1', 'org.opencontainers.image.created': '2020-12-05T01:00:33.671820Z', 'org.opencontainers.image.documentation': 'https://www.elastic.co/guide/en/elasticsearch/reference/index.html', 'org.opencontainers.image.licenses': 'Elastic-License', 'org.opencontainers.image.revision': '1c34507e66d7db1211f66f3513706fdf548736aa', 'org.opencontainers.image.source': 'https://github.com/elastic/elasticsearch', 'org.opencontainers.image.title': 'Elasticsearch', 'org.opencontainers.image.url': 'https://www.elastic.co/products/elasticsearch', 'org.opencontainers.image.vendor': 'Elastic', 'org.opencontainers.image.version': '7.10.1'}, 'ParentId': '', 'RepoDigests': ['docker.elastic.co/elasticsearch/elasticsearch@sha256:5d8f1962907ef60746a8cf61c8a7f2b8755510ee36bdee0f65417f90a38a0139'], 'RepoTags': ['docker.elastic.co/elasticsearch/elasticsearch:7.10.1'], 'SharedSize': 0, 'Size': 773756675, 'VirtualSize': 773756675},<br/>{'Containers': 1, 'Created': 1598864687, 'Id': 'sha256:a0a227bf03ddc8b88bbb74b1b84a8a7220c8fa95b122cbde2a7444f32dc30659', 'Labels': None, 'ParentId': '', 'RepoDigests': ['portainer/portainer-ce@sha256:0ab9d25e9ac7b663a51afc6853875b2055d8812fcaf677d0013eba32d0bf0e0d'], 'RepoTags': ['portainer/portainer-ce:latest'], 'SharedSize': 0, 'Size': 195546824, 'VirtualSize': 195546824},<br/>{'Containers': 2, 'Created': 1578014497, 'Id': 'sha256:bf756fb1ae65adf866bd8c456593cd24beb6a0a061dedf42b26a993176745f6b', 'Labels': None, 'ParentId': '', 'RepoDigests': ['hello-world@sha256:1a523af650137b8accdaed439c17d684df61ee4d74feac151b5b337bd29e7eec'], 'RepoTags': ['hello-world:latest'], 'SharedSize': 0, 'Size': 13336, 'VirtualSize': 13336},<br/>{'Containers': 0, 'Created': 1573631696, 'Id': 'sha256:3f6237885724af871088cfbb9d787ea4aebb37c0565e207e897c7f51ce0ad0ed', 'Labels': {'maintainer': 'Thomas Boerger <thomas@webhippie.de>', 'org.label-schema.build-date': '2019-11-13T07:54:28Z', 'org.label-schema.name': 'MariaDB', 'org.label-schema.schema-version': '1.0', 'org.label-schema.vcs-ref': '1e1f1924a0477f837c8a4399467594a0a5c3bada', 'org.label-schema.vcs-url': 'https://github.com/dockhippie/mariadb.git', 'org.label-schema.vendor': 'Thomas Boerger', 'org.label-schema.version': 'latest'}, 'ParentId': '', 'RepoDigests': ['webhippie/mariadb@sha256:8a2c927529e5fd6238f08f79e3855d90a353e4475481574aa4bf0b90550b5db9'], 'RepoTags': ['webhippie/mariadb:latest'], 'SharedSize': 57530959, 'Size': 656206898, 'VirtualSize': 656206898},<br/>{'Containers': 0, 'Created': 1573631680, 'Id': 'sha256:42ab00c664c227dce98aec279e4098cb569084d6597e562dd226c98df32dc058', 'Labels': {'maintainer': 'Thomas Boerger <thomas@webhippie.de>', 'org.label-schema.build-date': '2019-11-13T07:54:26Z', 'org.label-schema.name': 'Redis', 'org.label-schema.schema-version': '1.0', 'org.label-schema.vcs-ref': '7b176b8e39cb973ed19aee8243ba63a6e75ffe60', 'org.label-schema.vcs-url': 'https://github.com/dockhippie/redis.git', 'org.label-schema.vendor': 'Thomas Boerger', 'org.label-schema.version': 'latest'}, 'ParentId': '', 'RepoDigests': ['webhippie/redis@sha256:42f6d51be6a7a5ef6fb672e98507824816566f0b1f89c19b2d585f54e26b2529'], 'RepoTags': ['webhippie/redis:latest'], 'SharedSize': 57530959, 'Size': 59184716, 'VirtualSize': 59184716},<br/>{'Containers': 1, 'Created': 1551262109, 'Id': 'sha256:aa50897f28e43c1110328f1b8740a2ad097031e8d2443266e562fe74be1a7a19', 'Labels': {'maintainer': 'EclecticIQ <opentaxii@eclecticiq.com>'}, 'ParentId': '', 'RepoDigests': ['eclecticiq/opentaxii@sha256:647b07724ae60b31accaf57a56fb8e7ee8f25506e3d283dce5ef6ca89002d662'], 'RepoTags': ['eclecticiq/opentaxii:latest'], 'SharedSize': 0, 'Size': 188188625, 'VirtualSize': 188188625},<br/>{'Containers': 0, 'Created': 1548789201, 'Id': 'sha256:f3f4b8ddca6feca170e6239933cbf5139f52d8496737df497911850440f40a5a', 'Labels': None, 'ParentId': '', 'RepoDigests': ['adoptopenjdk/openjdk11-openj9@sha256:60718fa9eb6b6bc4ab6fe7f3a9db31b8725fb63ebdda833a43f541c07792ff5c'], 'RepoTags': ['adoptopenjdk/openjdk11-openj9:jdk-x.x.x.x-alpine-slim'], 'SharedSize': 237380314, 'Size': 237380314, 'VirtualSize': 237380314} | 6296579215 | {'CreatedAt': '2021-01-10T11:33:47+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/mongodb/_data', 'Name': 'mongodb', 'Options': {}, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 332256838}},<br/>{'CreatedAt': '2021-01-10T11:15:46+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/redisdata/_data', 'Name': 'redisdata', 'Options': None, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 44588590}},<br/>{'CreatedAt': '2021-01-05T20:13:01+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/opentaxii-input/_data', 'Name': 'opentaxii-input', 'Options': {}, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 0}},<br/>{'CreatedAt': '2020-12-18T20:13:08+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/portainer_data/_data', 'Name': 'portainer_data', 'Options': None, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 202048}},<br/>{'CreatedAt': '2021-01-10T11:10:47+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/s3data/_data', 'Name': 's3data', 'Options': None, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 503932}},<br/>{'CreatedAt': '2021-01-10T11:34:11+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/temp-volume/_data', 'Name': 'temp-volume', 'Options': None, 'Scope': 'local', 'UsageData': {'RefCount': 0, 'Size': 0}},<br/>{'CreatedAt': '2021-01-06T12:12:03+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55/_data', 'Name': '88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55', 'Options': None, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 0}},<br/>{'CreatedAt': '2020-12-18T20:33:49+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/amqpdata/_data', 'Name': 'amqpdata', 'Options': None, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 2775833149}},<br/>{'CreatedAt': '2020-12-18T20:33:46+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/esdata/_data', 'Name': 'esdata', 'Options': None, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 392439372}},<br/>{'CreatedAt': '2021-01-05T20:13:03+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/opentaxii-data/_data', 'Name': 'opentaxii-data', 'Options': {}, 'Scope': 'local', 'UsageData': {'RefCount': 1, 'Size': 98304}} |


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
| Docker.SystemInfo.OSType | String | Generic type of the operating system of the host, as returned by the Go runtime \(\`GOOS\`\).  Currently returned values are "linux" and "windows". A full list of possible values can be found in the \[Go documentation\]\(https://golang.org/doc/install/source#environment\).  | 
| Docker.SystemInfo.Architecture | String | Hardware architecture of the host, as returned by the Go runtime \(\`GOARCH\`\).  A full list of possible values can be found in the \[Go documentation\]\(https://golang.org/doc/install/source#environment\).  | 
| Docker.SystemInfo.NCPU | Number | The number of logical CPUs usable by the daemon.  The number of available CPUs is checked by querying the operating system when the daemon starts. Changes to operating system CPU allocation after the daemon is started are not reflected.  | 
| Docker.SystemInfo.MemTotal | Number | Total amount of physical memory available on the host, in bytes.  | 
| Docker.SystemInfo.IndexServerAddress | String | Address / URL of the index server that is used for image search, and as a default for user authentication for Docker Hub and Docker Cloud.  | 
| Docker.SystemInfo.HttpProxy | String | HTTP-proxy configured for the daemon. This value is obtained from the \[\`HTTP_PROXY\`\]\(https://www.gnu.org/software/wget/manual/html_node/Proxies.html\) environment variable. Credentials \(\[user info component\]\(https://tools.ietf.org/html/rfc3986#section-3.2.1\)\) in the proxy URL are masked in the API response.  Containers do not automatically inherit this configuration.  | 
| Docker.SystemInfo.HttpsProxy | String | HTTPS-proxy configured for the daemon. This value is obtained from the \[\`HTTPS_PROXY\`\]\(https://www.gnu.org/software/wget/manual/html_node/Proxies.html\) environment variable. Credentials \(\[user info component\]\(https://tools.ietf.org/html/rfc3986#section-3.2.1\)\) in the proxy URL are masked in the API response.  Containers do not automatically inherit this configuration.  | 
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


#### Command Example
```!docker-system-info```

#### Context Example
```json
{
    "Docker": {
        "SystemInfo": {
            "Architecture": "x86_64",
            "BridgeNfIp6tables": true,
            "BridgeNfIptables": true,
            "CPUSet": true,
            "CPUShares": true,
            "CgroupDriver": "cgroupfs",
            "CgroupVersion": "1",
            "ContainerdCommit": {
                "Expected": "269548fa27e0089a8b8278fc4fc781d7f65a939b",
                "ID": "269548fa27e0089a8b8278fc4fc781d7f65a939b"
            },
            "Containers": 21,
            "ContainersPaused": 0,
            "ContainersRunning": 18,
            "ContainersStopped": 3,
            "CpuCfsPeriod": true,
            "CpuCfsQuota": true,
            "Debug": false,
            "DefaultRuntime": "runc",
            "DockerRootDir": "/var/lib/docker",
            "Driver": "overlay2",
            "DriverStatus": [
                [
                    "Backing Filesystem",
                    "xfs"
                ],
                [
                    "Supports d_type",
                    "true"
                ],
                [
                    "Native Overlay Diff",
                    "true"
                ]
            ],
            "ExperimentalBuild": false,
            "GenericResources": null,
            "HttpProxy": "",
            "HttpsProxy": "",
            "ID": "5PJK:E7MV:OVJT:2VTA:F55W:MUFB:D3XC:242O:7VO6:D6FJ:ST5I:EI3V",
            "IPv4Forwarding": true,
            "Images": 26,
            "IndexServerAddress": "https://index.docker.io/v1/",
            "InitBinary": "docker-init",
            "InitCommit": {
                "Expected": "de40ad0",
                "ID": "de40ad0"
            },
            "Isolation": "",
            "KernelMemory": true,
            "KernelMemoryTCP": true,
            "KernelVersion": "4.18.0-240.1.1.el8_3.x86_64",
            "Labels": [],
            "LiveRestoreEnabled": false,
            "LoggingDriver": "json-file",
            "MemTotal": 8143470592,
            "MemoryLimit": true,
            "NCPU": 8,
            "NEventsListener": 0,
            "NFd": 179,
            "NGoroutines": 252,
            "Name": "docker",
            "NoProxy": "",
            "OSType": "linux",
            "OSVersion": "8",
            "OomKillDisable": true,
            "OperatingSystem": "CentOS Linux 8",
            "PidsLimit": true,
            "Plugins": {
                "Authorization": null,
                "Log": [
                    "awslogs",
                    "fluentd",
                    "gcplogs",
                    "gelf",
                    "journald",
                    "json-file",
                    "local",
                    "logentries",
                    "splunk",
                    "syslog"
                ],
                "Network": [
                    "bridge",
                    "host",
                    "ipvlan",
                    "macvlan",
                    "null",
                    "overlay"
                ],
                "Volume": [
                    "local"
                ]
            },
            "RegistryConfig": {
                "AllowNondistributableArtifactsCIDRs": [],
                "AllowNondistributableArtifactsHostnames": [],
                "IndexConfigs": {
                    "docker.io": {
                        "Mirrors": [],
                        "Name": "docker.io",
                        "Official": true,
                        "Secure": true
                    }
                },
                "InsecureRegistryCIDRs": [
                    "127.0.0.0/8"
                ],
                "Mirrors": []
            },
            "RuncCommit": {
                "Expected": "ff819c7e9184c13b7c2607fe6c30ae19403a7aff",
                "ID": "ff819c7e9184c13b7c2607fe6c30ae19403a7aff"
            },
            "Runtimes": {
                "io.containerd.runc.v2": {
                    "path": "runc"
                },
                "io.containerd.runtime.v1.linux": {
                    "path": "runc"
                },
                "runc": {
                    "path": "runc"
                }
            },
            "SecurityOptions": [
                "name=seccomp,profile=default"
            ],
            "ServerVersion": "20.10.1",
            "SwapLimit": true,
            "Swarm": {
                "Cluster": {
                    "CreatedAt": "2021-01-10T07:33:54.637800661Z",
                    "DataPathPort": 4789,
                    "DefaultAddrPool": [
                        "10.0.0.0/8"
                    ],
                    "ID": "vlnbrh88562b0zqkfznqxp3lo",
                    "RootRotationInProgress": false,
                    "Spec": {
                        "CAConfig": {
                            "NodeCertExpiry": 7776000000000000
                        },
                        "Dispatcher": {
                            "HeartbeatPeriod": 5000000000
                        },
                        "EncryptionConfig": {
                            "AutoLockManagers": false
                        },
                        "Labels": {},
                        "Name": "default",
                        "Orchestration": {
                            "TaskHistoryRetentionLimit": 5
                        },
                        "Raft": {
                            "ElectionTick": 10,
                            "HeartbeatTick": 1,
                            "KeepOldSnapshots": 0,
                            "LogEntriesForSlowFollowers": 500,
                            "SnapshotInterval": 10000
                        },
                        "TaskDefaults": {}
                    },
                    "SubnetSize": 24,
                    "TLSInfo": {
                        "CertIssuerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELEuzulYmFOfxzSCYtsNqHSGFM8rRmbeT+xY1JXxNFw3xM65ZdJxSBjZPzskwpZ3ra+KBgdtWpvA6s6xLBwfNuQ==",
                        "CertIssuerSubject": "MBMxETAPBgNVBAMTCHN3YXJtLWNh",
                        "TrustRoot": "-----BEGIN CERTIFICATE-----\nMIIBazCCARCgAwIBAgIUOiN4v/EY6RXDOD/KhFdvH3brl7AwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAxMIc3dhcm0tY2EwHhcNMjEwMTEwMDcyOTAwWhcNNDEwMTA1MDcy\nOTAwWjATMREwDwYDVQQDEwhzd2FybS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABCxLs7pWJhTn8c0gmLbDah0hhTPK0Zm3k/sWNSV8TRcN8TOuWXScUgY2T87J\nMKWd62vigYHbVqbwOrOsSwcHzbmjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBS4aSrlzrksA4rV4dI/+VaVF6FPUDAKBggqhkjO\nPQQDAgNJADBGAiEA7XBazcswvm/Dl4z7OHI6LGodSFOS5Z8Zg1DFPmdoodoCIQCh\n2+H2IcBXUO50IAzFvKt754HImW+kpLNe6fOFtEj+kQ==\n-----END CERTIFICATE-----\n"
                    },
                    "UpdatedAt": "2021-01-10T07:33:55.245247885Z",
                    "Version": {
                        "Index": 10
                    }
                },
                "ControlAvailable": true,
                "Error": "",
                "LocalNodeState": "active",
                "Managers": 1,
                "NodeAddr": "1.0.0.1",
                "NodeID": "cgj752x81xe8wbwhfr0chpa1n",
                "Nodes": 1,
                "RemoteManagers": [
                    {
                        "Addr": "1.0.0.1:1337",
                        "NodeID": "cgj752x81xe8wbwhfr0chpa1n"
                    }
                ]
            },
            "SystemTime": "2021-01-10T11:34:15.475287531+04:00",
            "Warnings": [
                "WARNING: No blkio weight support",
                "WARNING: No blkio weight_device support"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|Architecture|BridgeNfIp6tables|BridgeNfIptables|CPUSet|CPUShares|CgroupDriver|CgroupVersion|ContainerdCommit|Containers|ContainersPaused|ContainersRunning|ContainersStopped|CpuCfsPeriod|CpuCfsQuota|Debug|DefaultRuntime|DockerRootDir|Driver|DriverStatus|ExperimentalBuild|GenericResources|HttpProxy|HttpsProxy|ID|IPv4Forwarding|Images|IndexServerAddress|InitBinary|InitCommit|Isolation|KernelMemory|KernelMemoryTCP|KernelVersion|Labels|LiveRestoreEnabled|LoggingDriver|MemTotal|MemoryLimit|NCPU|NEventsListener|NFd|NGoroutines|Name|NoProxy|OSType|OSVersion|OomKillDisable|OperatingSystem|PidsLimit|Plugins|RegistryConfig|RuncCommit|Runtimes|SecurityOptions|ServerVersion|SwapLimit|Swarm|SystemTime|Warnings|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| x86_64 | true | true | true | true | cgroupfs | 1 | ID: 269548fa27e0089a8b8278fc4fc781d7f65a939b<br/>Expected: 269548fa27e0089a8b8278fc4fc781d7f65a939b | 21 | 0 | 18 | 3 | true | true | false | runc | /var/lib/docker | overlay2 | ['Backing Filesystem', 'xfs'],<br/>['Supports d_type', 'true'],<br/>['Native Overlay Diff', 'true'] | false |  |  |  | 5PJK:E7MV:OVJT:2VTA:F55W:MUFB:D3XC:242O:7VO6:D6FJ:ST5I:EI3V | true | 26 | https://index.docker.io/v1/ | docker-init | ID: de40ad0<br/>Expected: de40ad0 |  | true | true | 4.18.0-240.1.1.el8_3.x86_64 |  | false | json-file | 8143470592 | true | 8 | 0 | 179 | 252 | docker |  | linux | 8 | true | CentOS Linux 8 | true | Volume: local<br/>Network: bridge,<br/>host,<br/>ipvlan,<br/>macvlan,<br/>null,<br/>overlay<br/>Authorization: null<br/>Log: awslogs,<br/>fluentd,<br/>gcplogs,<br/>gelf,<br/>journald,<br/>json-file,<br/>local,<br/>logentries,<br/>splunk,<br/>syslog | AllowNondistributableArtifactsCIDRs: <br/>AllowNondistributableArtifactsHostnames: <br/>InsecureRegistryCIDRs: 127.0.0.0/8<br/>IndexConfigs: {"docker.io": {"Name": "docker.io", "Mirrors": [], "Secure": true, "Official": true}}<br/>Mirrors:  | ID: ff819c7e9184c13b7c2607fe6c30ae19403a7aff<br/>Expected: ff819c7e9184c13b7c2607fe6c30ae19403a7aff | io.containerd.runc.v2: {"path": "runc"}<br/>io.containerd.runtime.v1.linux: {"path": "runc"}<br/>runc: {"path": "runc"} | name=seccomp,profile=default | 20.10.1 | true | NodeID: cgj752x81xe8wbwhfr0chpa1n<br/>NodeAddr: 1.0.0.1<br/>LocalNodeState: active<br/>ControlAvailable: true<br/>Error: <br/>RemoteManagers: {'NodeID': 'cgj752x81xe8wbwhfr0chpa1n', 'Addr': '1.0.0.1:1337'}<br/>Nodes: 1<br/>Managers: 1<br/>Cluster: {"ID": "vlnbrh88562b0zqkfznqxp3lo", "Version": {"Index": 10}, "CreatedAt": "2021-01-10T07:33:54.637800661Z", "UpdatedAt": "2021-01-10T07:33:55.245247885Z", "Spec": {"Name": "default", "Labels": {}, "Orchestration": {"TaskHistoryRetentionLimit": 5}, "Raft": {"SnapshotInterval": 10000, "KeepOldSnapshots": 0, "LogEntriesForSlowFollowers": 500, "ElectionTick": 10, "HeartbeatTick": 1}, "Dispatcher": {"HeartbeatPeriod": 5000000000}, "CAConfig": {"NodeCertExpiry": 7776000000000000}, "TaskDefaults": {}, "EncryptionConfig": {"AutoLockManagers": false}}, "TLSInfo": {"TrustRoot": "-----BEGIN CERTIFICATE-----\nMIIBazCCARCgAwIBAgIUOiN4v/EY6RXDOD/KhFdvH3brl7AwCgYIKoZIzj0EAwIw\nEzERMA8GA1UEAxMIc3dhcm0tY2EwHhcNMjEwMTEwMDcyOTAwWhcNNDEwMTA1MDcy\nOTAwWjATMREwDwYDVQQDEwhzd2FybS1jYTBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABCxLs7pWJhTn8c0gmLbDah0hhTPK0Zm3k/sWNSV8TRcN8TOuWXScUgY2T87J\nMKWd62vigYHbVqbwOrOsSwcHzbmjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBS4aSrlzrksA4rV4dI/+VaVF6FPUDAKBggqhkjO\nPQQDAgNJADBGAiEA7XBazcswvm/Dl4z7OHI6LGodSFOS5Z8Zg1DFPmdoodoCIQCh\n2+H2IcBXUO50IAzFvKt754HImW+kpLNe6fOFtEj+kQ==\n-----END CERTIFICATE-----\n", "CertIssuerSubject": "MBMxETAPBgNVBAMTCHN3YXJtLWNh", "CertIssuerPublicKey": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAELEuzulYmFOfxzSCYtsNqHSGFM8rRmbeT+xY1JXxNFw3xM65ZdJxSBjZPzskwpZ3ra+KBgdtWpvA6s6xLBwfNuQ=="}, "RootRotationInProgress": false, "DefaultAddrPool": ["10.0.0.0/8"], "SubnetSize": 24, "DataPathPort": 4789} | 2021-01-10T11:34:15.475287531+04:00 | WARNING: No blkio weight support,<br/>WARNING: No blkio weight_device support |


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


#### Command Example
```!docker-system-version```

#### Context Example
```json
{
    "Docker": {
        "SystemVersion": {
            "ApiVersion": "1.41",
            "Arch": "amd64",
            "BuildTime": "2020-12-15T04:32:21.000000000+00:00",
            "Components": [
                {
                    "Details": {
                        "ApiVersion": "1.41",
                        "Arch": "amd64",
                        "BuildTime": "2020-12-15T04:32:21.000000000+00:00",
                        "Experimental": "false",
                        "GitCommit": "f001486",
                        "GoVersion": "go1.13.15",
                        "KernelVersion": "4.18.0-240.1.1.el8_3.x86_64",
                        "MinAPIVersion": "1.12",
                        "Os": "linux"
                    },
                    "Name": "Engine",
                    "Version": "20.10.1"
                },
                {
                    "Details": {
                        "GitCommit": "269548fa27e0089a8b8278fc4fc781d7f65a939b"
                    },
                    "Name": "containerd",
                    "Version": "1.4.3"
                },
                {
                    "Details": {
                        "GitCommit": "ff819c7e9184c13b7c2607fe6c30ae19403a7aff"
                    },
                    "Name": "runc",
                    "Version": "1.0.0-rc92"
                },
                {
                    "Details": {
                        "GitCommit": "de40ad0"
                    },
                    "Name": "docker-init",
                    "Version": "0.19.0"
                }
            ],
            "GitCommit": "f001486",
            "GoVersion": "go1.13.15",
            "KernelVersion": "4.18.0-240.1.1.el8_3.x86_64",
            "MinAPIVersion": "1.12",
            "Os": "linux",
            "Platform": {
                "Name": "Docker Engine - Community"
            },
            "Version": "20.10.1"
        }
    }
}
```

#### Human Readable Output

>### Results
>|ApiVersion|Arch|BuildTime|Components|GitCommit|GoVersion|KernelVersion|MinAPIVersion|Os|Platform|Version|
>|---|---|---|---|---|---|---|---|---|---|---|
>| 1.41 | amd64 | 2020-12-15T04:32:21.000000000+00:00 | {'Name': 'Engine', 'Version': '20.10.1', 'Details': {'ApiVersion': '1.41', 'Arch': 'amd64', 'BuildTime': '2020-12-15T04:32:21.000000000+00:00', 'Experimental': 'false', 'GitCommit': 'f001486', 'GoVersion': 'go1.13.15', 'KernelVersion': '4.18.0-240.1.1.el8_3.x86_64', 'MinAPIVersion': '1.12', 'Os': 'linux'}},<br/>{'Name': 'containerd', 'Version': '1.4.3', 'Details': {'GitCommit': '269548fa27e0089a8b8278fc4fc781d7f65a939b'}},<br/>{'Name': 'runc', 'Version': '1.0.0-rc92', 'Details': {'GitCommit': 'ff819c7e9184c13b7c2607fe6c30ae19403a7aff'}},<br/>{'Name': 'docker-init', 'Version': '0.19.0', 'Details': {'GitCommit': 'de40ad0'}} | f001486 | go1.13.15 | 4.18.0-240.1.1.el8_3.x86_64 | 1.12 | linux | Name: Docker Engine - Community | 20.10.1 |


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


#### Command Example
```!docker-task-list```

#### Context Example
```json
{}
```

#### Human Readable Output

>null

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

#### Command Example
```!docker-volume-create volumeconfig_name="temp-volume"```

#### Context Example
```json
{
    "Docker": {
        "CreatedAt": "2021-01-10T11:34:11+04:00",
        "Driver": "local",
        "Labels": null,
        "Mountpoint": "/var/lib/docker/volumes/temp-volume/_data",
        "Name": "temp-volume",
        "Options": null,
        "Scope": "local"
    }
}
```

#### Human Readable Output

>### Results
>|CreatedAt|Driver|Labels|Mountpoint|Name|Options|Scope|
>|---|---|---|---|---|---|---|
>| 2021-01-10T11:34:11+04:00 | local |  | /var/lib/docker/volumes/temp-volume/_data | temp-volume |  | local |


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


#### Command Example
```!docker-volume-inspect name="temp-volume"```

#### Context Example
```json
{
    "Docker": {
        "Volume": {
            "CreatedAt": "2021-01-10T11:34:11+04:00",
            "Driver": "local",
            "Labels": null,
            "Mountpoint": "/var/lib/docker/volumes/temp-volume/_data",
            "Name": "temp-volume",
            "Options": null,
            "Scope": "local"
        }
    }
}
```

#### Human Readable Output

>### Results
>|CreatedAt|Driver|Labels|Mountpoint|Name|Options|Scope|
>|---|---|---|---|---|---|---|
>| 2021-01-10T11:34:11+04:00 | local |  | /var/lib/docker/volumes/temp-volume/_data | temp-volume |  | local |


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


#### Command Example
```!docker-volume-list```

#### Context Example
```json
{
    "Docker": {
        "VolumeListResponse": {
            "Volumes": [
                {
                    "CreatedAt": "2021-01-10T11:33:47+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/mongodb/_data",
                    "Name": "mongodb",
                    "Options": {},
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2021-01-10T11:15:46+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/redisdata/_data",
                    "Name": "redisdata",
                    "Options": null,
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2020-12-18T20:33:46+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/esdata/_data",
                    "Name": "esdata",
                    "Options": null,
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2021-01-05T20:13:03+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/opentaxii-data/_data",
                    "Name": "opentaxii-data",
                    "Options": {},
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2021-01-05T20:13:01+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/opentaxii-input/_data",
                    "Name": "opentaxii-input",
                    "Options": {},
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2020-12-18T20:13:08+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/portainer_data/_data",
                    "Name": "portainer_data",
                    "Options": null,
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2021-01-10T11:10:47+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/s3data/_data",
                    "Name": "s3data",
                    "Options": null,
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2021-01-10T11:14:49+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/temp-volume/_data",
                    "Name": "temp-volume",
                    "Options": null,
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2021-01-06T12:12:03+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55/_data",
                    "Name": "88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55",
                    "Options": null,
                    "Scope": "local"
                },
                {
                    "CreatedAt": "2020-12-18T20:33:49+04:00",
                    "Driver": "local",
                    "Labels": null,
                    "Mountpoint": "/var/lib/docker/volumes/amqpdata/_data",
                    "Name": "amqpdata",
                    "Options": null,
                    "Scope": "local"
                }
            ],
            "Warnings": null
        }
    }
}
```

#### Human Readable Output

>### Results
>|Volumes|Warnings|
>|---|---|
>| {'CreatedAt': '2021-01-10T11:33:47+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/mongodb/_data', 'Name': 'mongodb', 'Options': {}, 'Scope': 'local'},<br/>{'CreatedAt': '2021-01-10T11:15:46+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/redisdata/_data', 'Name': 'redisdata', 'Options': None, 'Scope': 'local'},<br/>{'CreatedAt': '2020-12-18T20:33:46+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/esdata/_data', 'Name': 'esdata', 'Options': None, 'Scope': 'local'},<br/>{'CreatedAt': '2021-01-05T20:13:03+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/opentaxii-data/_data', 'Name': 'opentaxii-data', 'Options': {}, 'Scope': 'local'},<br/>{'CreatedAt': '2021-01-05T20:13:01+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/opentaxii-input/_data', 'Name': 'opentaxii-input', 'Options': {}, 'Scope': 'local'},<br/>{'CreatedAt': '2020-12-18T20:13:08+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/portainer_data/_data', 'Name': 'portainer_data', 'Options': None, 'Scope': 'local'},<br/>{'CreatedAt': '2021-01-10T11:10:47+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/s3data/_data', 'Name': 's3data', 'Options': None, 'Scope': 'local'},<br/>{'CreatedAt': '2021-01-10T11:14:49+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/temp-volume/_data', 'Name': 'temp-volume', 'Options': None, 'Scope': 'local'},<br/>{'CreatedAt': '2021-01-06T12:12:03+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55/_data', 'Name': '88b259421004c4300e96dc6d2ec2685b243dea9f5007bfebf881a7d6ae0a6b55', 'Options': None, 'Scope': 'local'},<br/>{'CreatedAt': '2020-12-18T20:33:49+04:00', 'Driver': 'local', 'Labels': None, 'Mountpoint': '/var/lib/docker/volumes/amqpdata/_data', 'Name': 'amqpdata', 'Options': None, 'Scope': 'local'} |  |


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


#### Command Example
```!docker-volume-prune```

#### Context Example
```json
{
    "Docker": {
        "VolumePruneResponse": {
            "SpaceReclaimed": 0,
            "VolumesDeleted": [
                "temp-volume"
            ]
        }
    }
}
```

#### Human Readable Output

>### Results
>|SpaceReclaimed|VolumesDeleted|
>|---|---|
>| 0 | temp-volume |
