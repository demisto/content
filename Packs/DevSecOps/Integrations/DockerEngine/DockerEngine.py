import urllib3

from CommonServerPython import *


class Client:
    def __init__(self, server_url, verify, proxy, headers, client_cert, client_key):
        self._base_url = server_url
        self._verify = verify
        self._proxy = proxy
        self._headers = headers
        self._client_cert = client_cert
        self._client_key = client_key

    def _http_request(self, method, url_suffix='', full_url=None, params=None, headers=None, data=None, json_data=None):
        address = full_url if full_url else urljoin(self._base_url, url_suffix)
        headers = headers if headers else self._headers
        client_cert_path = None
        client_key_path = None
        if self._client_cert:
            client_cert_path = 'client.cert'
            with open(client_cert_path, 'wb') as file:
                file.write(self._client_cert.encode())
        if self._client_key:
            client_key_path = 'client_key.key'
            with open(client_key_path, 'wb') as file:
                file.write(self._client_key.encode())
        response = requests.session().request(
            method,
            address,
            verify=self._verify,
            params=params,
            data=data,
            json=json_data,
            headers=headers,
            cert=(client_cert_path, client_key_path),
            timeout=2,

        )
        if response.headers.get('Content-Type') == 'application/json':
            return json.loads(response.content)
        else:
            return response.content

    def test_request(self):
        response = self._http_request('get', 'version')

        return response

    def build_prune_request(self, keep_storage, prune_all, filters):
        params = assign_params(keep_storage=keep_storage, prune_all=prune_all, filters=filters)

        headers = self._headers

        response = self._http_request('post', 'build/prune', params=params, headers=headers)

        return response

    def config_create_request(self, configspec_name, configspec_labels,
                              configspec_data, configspec_templating):
        data = assign_params(Name=configspec_name, Labels=configspec_labels,
                             Data=configspec_data, Templating=configspec_templating)

        headers = self._headers

        response = self._http_request('post', 'configs/create', json_data=data, headers=headers)

        return response

    def config_inspect_request(self, id_):

        headers = self._headers

        response = self._http_request('get', f'configs/{id_}', headers=headers)

        return response

    def config_list_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('get', 'configs', params=params, headers=headers)

        return response

    def container_changes_request(self, id_):

        headers = self._headers

        response = self._http_request('get', f'containers/{id_}/changes', headers=headers)

        return response

    def container_create_request(self, name, containerconfig_hostname,
                                 containerconfig_domainname, containerconfig_user,
                                 containerconfig_attachstdin, containerconfig_attachstdout,
                                 containerconfig_attachstderr, containerconfig_exposedports,
                                 containerconfig_tty, containerconfig_openstdin, containerconfig_stdinonce,
                                 containerconfig_env, containerconfig_cmd, containerconfig_healthcheck,
                                 containerconfig_argsescaped, containerconfig_image, containerconfig_volumes,
                                 containerconfig_workingdir, containerconfig_entrypoint,
                                 containerconfig_networkdisabled, containerconfig_macaddress,
                                 containerconfig_onbuild, containerconfig_labels,
                                 containerconfig_stopsignal, containerconfig_stoptimeout,
                                 containerconfig_shell, hostconfig_binds, hostconfig_containeridfile,
                                 hostconfig_logconfig, hostconfig_networkmode, hostconfig_portbindings,
                                 hostconfig_restartpolicy, hostconfig_autoremove, hostconfig_volumedriver,
                                 hostconfig_volumesfrom, hostconfig_mounts, hostconfig_capadd,
                                 hostconfig_capdrop, hostconfig_cgroupnsmode, hostconfig_dns,
                                 hostconfig_dnsoptions, hostconfig_dnssearch, hostconfig_extrahosts,
                                 hostconfig_groupadd, hostconfig_ipcmode, hostconfig_cgroup, hostconfig_links,
                                 hostconfig_oomscoreadj, hostconfig_pidmode, hostconfig_privileged,
                                 hostconfig_publishallports, hostconfig_readonlyrootfs, hostconfig_securityopt,
                                 hostconfig_storageopt, hostconfig_tmpfs, hostconfig_utsmode,
                                 hostconfig_usernsmode, hostconfig_shmsize, hostconfig_sysctls,
                                 hostconfig_runtime, hostconfig_consolesize, hostconfig_isolation,
                                 hostconfig_maskedpaths, hostconfig_readonlypaths,
                                 networkingconfig_endpointsconfig):
        params = assign_params(name=name)
        data = assign_params(Hostname=containerconfig_hostname, Domainname=containerconfig_domainname,
                             User=containerconfig_user, AttachStdin=containerconfig_attachstdin,
                             AttachStdout=containerconfig_attachstdout, AttachStderr=containerconfig_attachstderr,
                             ExposedPorts=containerconfig_exposedports, Tty=containerconfig_tty,
                             OpenStdin=containerconfig_openstdin, StdinOnce=containerconfig_stdinonce,
                             Env=containerconfig_env, Cmd=containerconfig_cmd,
                             Healthcheck=containerconfig_healthcheck, ArgsEscaped=containerconfig_argsescaped,
                             Image=containerconfig_image, Volumes=containerconfig_volumes,
                             WorkingDir=containerconfig_workingdir, Entrypoint=containerconfig_entrypoint,
                             NetworkDisabled=containerconfig_networkdisabled,
                             MacAddress=containerconfig_macaddress, OnBuild=containerconfig_onbuild,
                             Labels=containerconfig_labels, StopSignal=containerconfig_stopsignal,
                             StopTimeout=containerconfig_stoptimeout, Shell=containerconfig_shell,
                             Binds=hostconfig_binds, ContainerIDFile=hostconfig_containeridfile,
                             LogConfig=hostconfig_logconfig, NetworkMode=hostconfig_networkmode,
                             PortBindings=hostconfig_portbindings, RestartPolicy=hostconfig_restartpolicy,
                             AutoRemove=hostconfig_autoremove, VolumeDriver=hostconfig_volumedriver,
                             VolumesFrom=hostconfig_volumesfrom, Mounts=hostconfig_mounts,
                             CapAdd=hostconfig_capadd, CapDrop=hostconfig_capdrop,
                             CgroupnsMode=hostconfig_cgroupnsmode, Dns=hostconfig_dns,
                             DnsOptions=hostconfig_dnsoptions, DnsSearch=hostconfig_dnssearch,
                             ExtraHosts=hostconfig_extrahosts, GroupAdd=hostconfig_groupadd,
                             IpcMode=hostconfig_ipcmode, Cgroup=hostconfig_cgroup,
                             Links=hostconfig_links, OomScoreAdj=hostconfig_oomscoreadj,
                             PidMode=hostconfig_pidmode, Privileged=hostconfig_privileged,
                             PublishAllPorts=hostconfig_publishallports,
                             ReadonlyRootfs=hostconfig_readonlyrootfs, SecurityOpt=hostconfig_securityopt,
                             StorageOpt=hostconfig_storageopt, Tmpfs=hostconfig_tmpfs,
                             UTSMode=hostconfig_utsmode, UsernsMode=hostconfig_usernsmode,
                             ShmSize=hostconfig_shmsize, Sysctls=hostconfig_sysctls,
                             Runtime=hostconfig_runtime, ConsoleSize=hostconfig_consolesize,
                             Isolation=hostconfig_isolation, MaskedPaths=hostconfig_maskedpaths,
                             ReadonlyPaths=hostconfig_readonlypaths,
                             EndpointsConfig=networkingconfig_endpointsconfig)

        headers = self._headers

        response = self._http_request('post', 'containers/create', params=params, json_data=data, headers=headers)

        return response

    def container_delete_request(self, id_, v, force, link):
        params = assign_params(v=v, force=force, link=link)

        headers = self._headers

        response = self._http_request('delete', f'containers/{id_}', params=params, headers=headers)

        return response

    def container_exec_request(self, execconfig_attachstdin, execconfig_attachstdout, execconfig_attachstderr,
                               execconfig_detachkeys, execconfig_tty, execconfig_env,
                               execconfig_cmd, execconfig_privileged, execconfig_user,
                               execconfig_workingdir, id_):
        data = assign_params(AttachStdin=execconfig_attachstdin, AttachStdout=execconfig_attachstdout,
                             AttachStderr=execconfig_attachstderr, detach_keys=execconfig_detachkeys,
                             Tty=execconfig_tty, Env=execconfig_env, Cmd=execconfig_cmd,
                             Privileged=execconfig_privileged, User=execconfig_user,
                             WorkingDir=execconfig_workingdir)

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/exec', json_data=data, headers=headers)

        return response

    def container_export_request(self, id_):

        headers = self._headers
        headers['Accept'] = 'application/octet-stream'

        response = self._http_request('get', f'containers/{id_}/export', headers=headers)

        return response

    def container_inspect_request(self, id_, size):
        params = assign_params(size=size)

        headers = self._headers

        response = self._http_request('get', f'containers/{id_}/json', params=params, headers=headers)

        return response

    def container_kill_request(self, id_, signal):
        params = assign_params(signal=signal)

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/kill', params=params, headers=headers)

        return response

    def container_list_request(self, list_all, limit, size, filters):
        params = assign_params(list_all=list_all, limit=limit, size=size, filters=filters)

        headers = self._headers

        response = self._http_request('get', 'containers/json', params=params, headers=headers)

        return response

    def container_logs_request(self, id_, follow, stdout, stderr, since, until, timestamps, tail):
        params = assign_params(follow=follow, stdout=stdout, stderr=stderr, since=since, until=until,
                               timestamps=timestamps, tail=tail)

        headers = self._headers

        response = self._http_request('get', f'containers/{id_}/logs', params=params, headers=headers)

        return response

    def container_pause_request(self, id_):

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/pause', headers=headers)

        return response

    def container_prune_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('post', 'containers/prune', params=params, headers=headers)

        return response

    def container_rename_request(self, id_, name):
        params = assign_params(name=name)

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/rename', params=params, headers=headers)

        return response

    def container_resize_request(self, id_, h, w):
        params = assign_params(h=h, w=w)

        headers = self._headers
        headers['Content-Type'] = 'application/octet-stream' 
        headers['Accept'] = 'text/plain'

        response = self._http_request('post', f'containers/{id_}/resize', params=params, headers=headers)

        return response

    def container_restart_request(self, id_, t):
        params = assign_params(t=t)

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/restart', params=params, headers=headers)

        return response

    def container_start_request(self, id_, detach_keys):
        params = assign_params(detach_keys=detach_keys)

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/start', params=params, headers=headers)

        return response

    def container_stats_request(self, id_, stream, one_shot):
        params = assign_params(stream=stream, one_shot=one_shot)

        headers = self._headers

        response = self._http_request('get', f'containers/{id_}/stats', params=params, headers=headers)

        return response

    def container_stop_request(self, id_, t):
        params = assign_params(t=t)

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/stop', params=params, headers=headers)

        return response

    def container_top_request(self, id_, ps_args):
        params = assign_params(ps_args=ps_args)

        headers = self._headers

        response = self._http_request('get', f'containers/{id_}/top', params=params, headers=headers)

        return response

    def container_unpause_request(self, id_):

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/unpause', headers=headers)

        return response

    def container_update_request(self, id_, resources_cpushares, resources_memory, resources_cgroupparent,
                                 resources_blkioweight, resources_blkioweightdevice, resources_blkiodevicereadbps,
                                 resources_blkiodevicewritebps, resources_blkiodevicereadiops,
                                 resources_blkiodevicewriteiops, resources_cpuperiod, resources_cpuquota,
                                 resources_cpurealtimeperiod, resources_cpurealtimeruntime, resources_cpusetcpus,
                                 resources_cpusetmems, resources_devices, resources_devicecgrouprules,
                                 resources_devicerequests, resources_kernelmemory, resources_kernelmemorytcp,
                                 resources_memoryreservation, resources_memoryswap, resources_memoryswappiness,
                                 resources_nanocpus, resources_oomkilldisable, resources_init, resources_pidslimit,
                                 resources_ulimits, resources_cpucount, resources_cpupercent, resources_iomaximumiops,
                                 resources_iomaximumbandwidth, restartpolicy_name, restartpolicy_maximumretrycount):
        data = assign_params(CpuShares=resources_cpushares, Memory=resources_memory,
                             CgroupParent=resources_cgroupparent, BlkioWeight=resources_blkioweight,
                             BlkioWeightDevice=resources_blkioweightdevice,
                             BlkioDeviceReadBps=resources_blkiodevicereadbps,
                             BlkioDeviceWriteBps=resources_blkiodevicewritebps,
                             BlkioDeviceReadIOps=resources_blkiodevicereadiops,
                             BlkioDeviceWriteIOps=resources_blkiodevicewriteiops,
                             CpuPeriod=resources_cpuperiod, CpuQuota=resources_cpuquota,
                             CpuRealtimePeriod=resources_cpurealtimeperiod,
                             CpuRealtimeRuntime=resources_cpurealtimeruntime,
                             CpusetCpus=resources_cpusetcpus, CpusetMems=resources_cpusetmems,
                             Devices=resources_devices,
                             DeviceCgroupRules=resources_devicecgrouprules,
                             DeviceRequests=resources_devicerequests,
                             KernelMemory=resources_kernelmemory,
                             KernelMemoryTCP=resources_kernelmemorytcp,
                             MemoryReservation=resources_memoryreservation,
                             MemorySwap=resources_memoryswap,
                             MemorySwappiness=resources_memoryswappiness,
                             NanoCPUs=resources_nanocpus, OomKillDisable=resources_oomkilldisable,
                             Init=resources_init, PidsLimit=resources_pidslimit,
                             Ulimits=resources_ulimits, CpuCount=resources_cpucount,
                             CpuPercent=resources_cpupercent, IOMaximumIOps=resources_iomaximumiops,
                             IOMaximumBandwidth=resources_iomaximumbandwidth,
                             Name=restartpolicy_name,
                             MaximumRetryCount=restartpolicy_maximumretrycount)

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/update', json_data=data, headers=headers)

        return response

    def container_wait_request(self, id_, condition):
        params = assign_params(condition=condition)

        headers = self._headers

        response = self._http_request('post', f'containers/{id_}/wait', params=params, headers=headers)

        return response

    def distribution_inspect_request(self, name):

        headers = self._headers

        response = self._http_request('get', f'distribution/{name}/json', headers=headers)

        return response

    def exec_inspect_request(self, id_):

        headers = self._headers

        response = self._http_request('get', f'exec/{id_}/json', headers=headers)

        return response

    def exec_resize_request(self, id_, h, w):
        params = assign_params(h=h, w=w)

        headers = self._headers

        response = self._http_request('post', f'exec/{id_}/resize', params=params, headers=headers)

        return response

    def exec_start_request(self, execstartconfig_detach, execstartconfig_tty, id_):
        data = assign_params(Detach=execstartconfig_detach, Tty=execstartconfig_tty)

        headers = self._headers
        headers['Accept'] = 'application/vnd.docker.raw-stream'

        response = self._http_request('post', f'exec/{id_}/start', json_data=data, headers=headers)

        return response

    def image_build_request(self, input_stream, dockerfile, t, extrahosts, remote, q, nocache, cachefrom, pull, rm,
                            forcerm, memory, memswap, cpushares, cpusetcpus, cpuperiod, cpuquota, buildargs, shmsize,
                            squash, labels, networkmode, platform, target, outputs):
        params = assign_params(dockerfile=dockerfile, t=t, extrahosts=extrahosts, remote=remote, q=q, nocache=nocache,
                               cachefrom=cachefrom, pull=pull, rm=rm, forcerm=forcerm, memory=memory, memswap=memswap,
                               cpushares=cpushares, cpusetcpus=cpusetcpus, cpuperiod=cpuperiod, cpuquota=cpuquota,
                               buildargs=buildargs, shmsize=shmsize, squash=squash, labels=labels,
                               networkmode=networkmode, platform=platform, target=target, outputs=outputs)
        data = assign_params(input_stream=input_stream)

        headers = self._headers
        headers['Content-Type'] = 'application/octet-stream'

        response = self._http_request('post', 'build', params=params, json_data=data, headers=headers)

        return response

    def image_commit_request(self, containerconfig_hostname, containerconfig_domainname, containerconfig_user,
                             containerconfig_attachstdin, containerconfig_attachstdout, containerconfig_attachstderr,
                             containerconfig_exposedports, containerconfig_tty, containerconfig_openstdin,
                             containerconfig_stdinonce, containerconfig_env, containerconfig_cmd,
                             containerconfig_healthcheck, containerconfig_argsescaped, containerconfig_image,
                             containerconfig_volumes, containerconfig_workingdir, containerconfig_entrypoint,
                             containerconfig_networkdisabled, containerconfig_macaddress, containerconfig_onbuild,
                             containerconfig_labels, containerconfig_stopsignal, containerconfig_stoptimeout,
                             containerconfig_shell, container, repo, tag, comment, author, pause, changes):
        params = assign_params(container=container, repo=repo, tag=tag, comment=comment, author=author, pause=pause,
                               changes=changes)
        data = assign_params(Hostname=containerconfig_hostname, Domainname=containerconfig_domainname,
                             User=containerconfig_user, AttachStdin=containerconfig_attachstdin,
                             AttachStdout=containerconfig_attachstdout, AttachStderr=containerconfig_attachstderr,
                             ExposedPorts=containerconfig_exposedports, Tty=containerconfig_tty,
                             OpenStdin=containerconfig_openstdin, StdinOnce=containerconfig_stdinonce,
                             Env=containerconfig_env, Cmd=containerconfig_cmd,
                             Healthcheck=containerconfig_healthcheck,
                             ArgsEscaped=containerconfig_argsescaped,
                             Image=containerconfig_image, Volumes=containerconfig_volumes,
                             WorkingDir=containerconfig_workingdir, Entrypoint=containerconfig_entrypoint,
                             NetworkDisabled=containerconfig_networkdisabled,
                             MacAddress=containerconfig_macaddress, OnBuild=containerconfig_onbuild,
                             Labels=containerconfig_labels, StopSignal=containerconfig_stopsignal,
                             StopTimeout=containerconfig_stoptimeout, Shell=containerconfig_shell)

        headers = self._headers

        response = self._http_request('post', 'commit', params=params, json_data=data, headers=headers)

        return response

    def image_create_request(self, from_image, from_src, repo, tag, message, input_image, platform):
        params = assign_params(from_image=from_image, from_src=from_src, repo=repo, tag=tag, message=message,
                               platform=platform)
        data = assign_params(input_image=input_image)

        headers = self._headers
        headers['Content-Type'] = 'text/plain'

        response = self._http_request('post', 'images/create', params=params, json_data=data, headers=headers)

        return response

    def image_delete_request(self, name, force, noprune):
        params = assign_params(force=force, noprune=noprune)

        headers = self._headers

        response = self._http_request('delete', f'images/{name}', params=params, headers=headers)

        return response

    def image_get_request(self, name):

        headers = self._headers
        headers['Accept'] = 'application/x-tar'

        response = self._http_request('get', f'images/{name}/get', headers=headers)

        return response

    def image_get_all_request(self, names):
        params = assign_params(names=names)

        headers = self._headers
        headers['Accept'] = 'application/x-tar'

        response = self._http_request('get', 'images/get', params=params, headers=headers)

        return response

    def image_history_request(self, name):

        headers = self._headers

        response = self._http_request('get', f'images/{name}/history', headers=headers)

        return response

    def image_inspect_request(self, name):

        headers = self._headers

        response = self._http_request('get', f'images/{name}/json', headers=headers)

        return response

    def image_list_request(self, prune_all, filters, digests):
        params = assign_params(prune_all=prune_all, filters=filters, digests=digests)

        headers = self._headers

        response = self._http_request('get', 'images/json', params=params, headers=headers)

        return response

    def image_load_request(self, images_tarball, quiet):
        params = assign_params(quiet=quiet)
        data = assign_params(images_tarball=images_tarball)

        headers = self._headers
        headers['Content-Type'] = 'application/x-tar'

        response = self._http_request('post', 'images/load', params=params, json_data=data, headers=headers)

        return response

    def image_prune_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('post', 'images/prune', params=params, headers=headers)

        return response

    def image_push_request(self, name, tag):
        params = assign_params(tag=tag)

        headers = self._headers
        headers['Content-Type'] = 'application/octet-stream'

        response = self._http_request('post', f'images/{name}/push', params=params, headers=headers)

        return response

    def image_search_request(self, term, limit, filters):
        params = assign_params(term=term, limit=limit, filters=filters)

        headers = self._headers

        response = self._http_request('get', 'images/search', params=params, headers=headers)

        return response

    def image_tag_request(self, name, repo, tag):
        params = assign_params(repo=repo, tag=tag)

        headers = self._headers

        response = self._http_request('post', f'images/{name}/tag', params=params, headers=headers)

        return response

    def network_connect_request(self, id_, container_container, container_endpointconfig):
        data = assign_params(Container=container_container, EndpointConfig=container_endpointconfig)

        headers = self._headers

        response = self._http_request('post', f'networks/{id_}/connect', json_data=data, headers=headers)

        return response

    def network_create_request(self, networkconfig_name, networkconfig_checkduplicate, networkconfig_driver,
                               networkconfig_internal, networkconfig_attachable, networkconfig_ingress,
                               networkconfig_ipam, networkconfig_enableipv6, networkconfig_options,
                               networkconfig_labels):
        data = assign_params(Name=networkconfig_name, CheckDuplicate=networkconfig_checkduplicate,
                             Driver=networkconfig_driver, Internal=networkconfig_internal,
                             Attachable=networkconfig_attachable, Ingress=networkconfig_ingress,
                             IPAM=networkconfig_ipam, EnableIPv6=networkconfig_enableipv6,
                             Options=networkconfig_options, Labels=networkconfig_labels)

        headers = self._headers

        response = self._http_request('post', 'networks/create', json_data=data, headers=headers)

        return response

    def network_delete_request(self, id_):

        headers = self._headers

        response = self._http_request('delete', f'networks/{id_}', headers=headers)

        return response

    def network_disconnect_request(self, id_, container, force):
        data = assign_params(Container=container, Force=force)

        headers = self._headers

        response = self._http_request('post', f'networks/{id_}/disconnect', json_data=data, headers=headers)

        return response

    def network_inspect_request(self, id_, verbose, scope):
        params = assign_params(verbose=verbose, scope=scope)

        headers = self._headers

        response = self._http_request('get', f'networks/{id_}', params=params, headers=headers)

        return response

    def network_list_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('get', 'networks', params=params, headers=headers)

        return response

    def network_prune_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('post', 'networks/prune', params=params, headers=headers)

        return response

    def node_delete_request(self, id_, force):
        params = assign_params(force=force)

        headers = self._headers

        response = self._http_request('delete', f'nodes/{id_}', params=params, headers=headers)

        return response

    def node_inspect_request(self, id_):

        headers = self._headers

        response = self._http_request('get', f'nodes/{id_}', headers=headers)

        return response

    def node_list_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('get', 'nodes', params=params, headers=headers)

        return response

    def node_update_request(self, id_, nodespec_name, nodespec_labels, nodespec_role, nodespec_availability, version):
        params = assign_params(version=version)
        data = assign_params(Name=nodespec_name, Labels=nodespec_labels, Role=nodespec_role,
                             Availability=nodespec_availability)

        headers = self._headers

        response = self._http_request('post', f'nodes/{id_}/update', params=params, json_data=data, headers=headers)

        return response

    def secret_create_request(self, secretspec_name, secretspec_labels, secretspec_data, secretspec_driver,
                              secretspec_templating):
        data = assign_params(Name=secretspec_name, Labels=secretspec_labels, Data=secretspec_data,
                             Driver=secretspec_driver, Templating=secretspec_templating)

        headers = self._headers

        response = self._http_request('post', 'secrets/create', json_data=data, headers=headers)

        return response

    def secret_delete_request(self, id_):

        headers = self._headers

        response = self._http_request('delete', f'secrets/{id_}', headers=headers)

        return response

    def secret_inspect_request(self, id_):

        headers = self._headers

        response = self._http_request('get', f'secrets/{id_}', headers=headers)

        return response

    def secret_list_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('get', 'secrets', params=params, headers=headers)

        return response

    def secret_update_request(self, id_, secretspec_name, secretspec_labels, secretspec_data, secretspec_driver,
                              secretspec_templating, version):
        params = assign_params(version=version)
        data = assign_params(Name=secretspec_name, Labels=secretspec_labels, Data=secretspec_data,
                             Driver=secretspec_driver, Templating=secretspec_templating)

        headers = self._headers

        response = self._http_request('post', f'secrets/{id_}/update', params=params, json_data=data, headers=headers)

        return response

    def service_create_request(self, servicespec_name, servicespec_labels, servicespec_tasktemplate, servicespec_mode,
                               servicespec_updateconfig, servicespec_rollbackconfig, servicespec_networks,
                               servicespec_endpointspec):
        data = assign_params(Name=servicespec_name, Labels=servicespec_labels, TaskTemplate=servicespec_tasktemplate,
                             Mode=servicespec_mode, UpdateConfig=servicespec_updateconfig,
                             RollbackConfig=servicespec_rollbackconfig, Networks=servicespec_networks,
                             EndpointSpec=servicespec_endpointspec)

        headers = self._headers

        response = self._http_request('post', 'services/create', json_data=data, headers=headers)

        return response

    def service_delete_request(self, id_):

        headers = self._headers

        response = self._http_request('delete', f'services/{id_}', headers=headers)

        return response

    def service_inspect_request(self, id_, insert_defaults):
        params = assign_params(insert_defaults=insert_defaults)

        headers = self._headers

        response = self._http_request('get', f'services/{id_}', params=params, headers=headers)

        return response

    def service_list_request(self, filters, status):
        params = assign_params(filters=filters, status=status)

        headers = self._headers

        response = self._http_request('get', 'services', params=params, headers=headers)

        return response

    def service_logs_request(self, id_, details, follow, stdout, stderr, since, timestamps, tail):
        params = assign_params(details=details, follow=follow, stdout=stdout, stderr=stderr, since=since,
                               timestamps=timestamps, tail=tail)

        headers = self._headers

        response = self._http_request('get', f'services/{id_}/logs', params=params, headers=headers)

        return response

    def service_update_request(self, id_, servicespec_name, servicespec_labels, servicespec_tasktemplate,
                               servicespec_mode, servicespec_updateconfig, servicespec_rollbackconfig,
                               servicespec_networks, servicespec_endpointspec, version, registery_auth_from, rollback):
        params = assign_params(version=version, registery_auth_from=registery_auth_from, rollback=rollback)
        data = assign_params(Name=servicespec_name, Labels=servicespec_labels, TaskTemplate=servicespec_tasktemplate,
                             Mode=servicespec_mode, UpdateConfig=servicespec_updateconfig,
                             RollbackConfig=servicespec_rollbackconfig, Networks=servicespec_networks,
                             EndpointSpec=servicespec_endpointspec)

        headers = self._headers

        response = self._http_request('post', f'services/{id_}/update', params=params, json_data=data, headers=headers)

        return response

    def session_request(self):

        headers = self._headers
        headers['Accept'] = 'application/vnd.docker.raw-stream'

        response = self._http_request('post', 'session', headers=headers)

        return response

    def swarm_init_request(self, listenaddr, advertiseaddr, datapathaddr, datapathport,
                           defaultaddrpool, forcenewcluster, subnetsize, spec):
        data = assign_params(ListenAddr=listenaddr, AdvertiseAddr=advertiseaddr,
                             DataPathAddr=datapathaddr, DataPathPort=datapathport,
                             DefaultAddrPool=defaultaddrpool, ForceNewCluster=forcenewcluster,
                             SubnetSize=subnetsize, Spec=spec)

        headers = self._headers

        response = self._http_request('post', 'swarm/init', json_data=data, headers=headers)

        return response

    def swarm_inspect_request(self):

        headers = self._headers

        response = self._http_request('get', 'swarm', headers=headers)

        return response

    def swarm_join_request(self, listenaddr, advertiseaddr, datapathaddr, remoteaddrs,
                           jointoken):
        data = assign_params(ListenAddr=listenaddr, AdvertiseAddr=advertiseaddr,
                             DataPathAddr=datapathaddr, RemoteAddrs=remoteaddrs,
                             JoinToken=jointoken)

        headers = self._headers

        response = self._http_request('post', 'swarm/join', json_data=data, headers=headers)

        return response

    def swarm_leave_request(self, force):
        params = assign_params(force=force)
        headers = self._headers

        response = self._http_request('post', 'swarm/leave', params=params, headers=headers)

        return response

    def swarm_unlock_request(self, unlockkey):
        data = assign_params(UnlockKey=unlockkey)

        headers = self._headers

        response = self._http_request('post', 'swarm/unlock', json_data=data, headers=headers)

        return response

    def swarm_unlockkey_request(self):

        headers = self._headers

        response = self._http_request('get', 'swarm/unlockkey', headers=headers)

        return response

    def system_auth_request(self, authconfig_username, authconfig_password, authconfig_email, authconfig_serveraddress):
        data = assign_params(username=authconfig_username, password=authconfig_password, email=authconfig_email,
                             serveraddress=authconfig_serveraddress)

        headers = self._headers

        response = self._http_request('post', 'auth', json_data=data, headers=headers)

        return response

    def system_data_usage_request(self):

        headers = self._headers

        response = self._http_request('get', 'system/df', headers=headers)

        return response

    def system_events_request(self, since, until, filters):
        params = assign_params(since=since, until=until, filters=filters)

        headers = self._headers

        response = self._http_request('get', 'events', params=params, headers=headers)

        return response

    def system_info_request(self):

        headers = self._headers

        response = self._http_request('get', 'info', headers=headers)

        return response

    def system_ping_request(self):

        headers = self._headers
        headers['Accept'] = 'text/plain'

        response = self._http_request('get', '_ping', headers=headers)

        return response

    def system_ping_head_request(self):

        headers = self._headers
        headers['Accept'] = 'text/plain'

        response = self._http_request('head', '_ping', headers=headers)

        return response

    def system_version_request(self):

        headers = self._headers

        response = self._http_request('get', 'version', headers=headers)

        return response

    def task_inspect_request(self, id_):

        headers = self._headers

        response = self._http_request('get', f'tasks/{id_}', headers=headers)

        return response

    def task_list_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('get', 'tasks', params=params, headers=headers)

        return response

    def task_logs_request(self, id_, details, follow, stdout, stderr, since, timestamps, tail):
        params = assign_params(details=details, follow=follow, stdout=stdout, stderr=stderr, since=since,
                               timestamps=timestamps, tail=tail)

        headers = self._headers

        response = self._http_request('get', f'tasks/{id_}/logs', params=params, headers=headers)

        return response

    def volume_create_request(self, volumeconfig_name, volumeconfig_driver, volumeconfig_driveropts,
                              volumeconfig_labels):
        data = assign_params(Name=volumeconfig_name, Driver=volumeconfig_driver, DriverOpts=volumeconfig_driveropts,
                             Labels=volumeconfig_labels)

        headers = self._headers

        response = self._http_request('post', 'volumes/create', json_data=data, headers=headers)

        return response

    def volume_delete_request(self, name, force):
        params = assign_params(force=force)

        headers = self._headers

        response = self._http_request('delete', f'volumes/{name}', params=params, headers=headers)

        return response

    def volume_inspect_request(self, name):

        headers = self._headers

        response = self._http_request('get', f'volumes/{name}', headers=headers)

        return response

    def volume_list_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('get', 'volumes', params=params, headers=headers)

        return response

    def volume_prune_request(self, filters):
        params = assign_params(filters=filters)

        headers = self._headers

        response = self._http_request('post', 'volumes/prune', params=params, headers=headers)

        return response


def build_prune_command(client, args):
    keep_storage = args.get('keep_storage', None)
    prune_all = argToBoolean(args.get('prune_all', False))
    filters = str(args.get('filters', ''))

    response = client.build_prune_request(keep_storage, prune_all, filters)
    command_results = CommandResults(
        outputs_prefix='Docker.BuildPruneResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def config_create_command(client, args):
    configspec_name = str(args.get('configspec_name', ''))
    configspec_labels = str(args.get('configspec_labels', ''))
    configspec_data = str(args.get('configspec_data', ''))
    configspec_templating_name = str(args.get('configspec_templating_name', ''))
    configspec_templating_options = str(args.get('configspec_templating_options', ''))
    configspec_templating = assign_params(Name=configspec_templating_name, Options=configspec_templating_options)

    response = client.config_create_request(configspec_name, configspec_labels, configspec_data, configspec_templating)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def config_inspect_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.config_inspect_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker.Config',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def config_list_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.config_list_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.Config',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_changes_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.container_changes_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker.ContainerChangeResponseItem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_create_command(client, args):
    name = str(args.get('name', ''))
    containerconfig_hostname = str(args.get('containerconfig_hostname', ''))
    containerconfig_domainname = str(args.get('containerconfig_domainname', ''))
    containerconfig_user = str(args.get('containerconfig_user', ''))
    containerconfig_attachstdin = argToBoolean(args.get('containerconfig_attachstdin', False))
    containerconfig_attachstdout = argToBoolean(args.get('containerconfig_attachstdout', False))
    containerconfig_attachstderr = argToBoolean(args.get('containerconfig_attachstderr', False))
    containerconfig_exposedports = str(args.get('containerconfig_exposedports', ''))
    containerconfig_tty = argToBoolean(args.get('containerconfig_tty', False))
    containerconfig_openstdin = argToBoolean(args.get('containerconfig_openstdin', False))
    containerconfig_stdinonce = argToBoolean(args.get('containerconfig_stdinonce', False))
    containerconfig_env = argToList(args.get('containerconfig_env', []))
    containerconfig_cmd = argToList(args.get('containerconfig_cmd', []))
    containerconfig_healthcheck_test = str(args.get('containerconfig_healthcheck_test', ''))
    containerconfig_healthcheck_interval = args.get('containerconfig_healthcheck_interval', None)
    containerconfig_healthcheck_timeout = args.get('containerconfig_healthcheck_timeout', None)
    containerconfig_healthcheck_retries = args.get('containerconfig_healthcheck_retries', None)
    containerconfig_healthcheck_startperiod = args.get('containerconfig_healthcheck_startperiod', None)
    containerconfig_healthcheck = assign_params(Test=containerconfig_healthcheck_test,
                                                Interval=containerconfig_healthcheck_interval,
                                                Timeout=containerconfig_healthcheck_timeout,
                                                Retries=containerconfig_healthcheck_retries,
                                                StartPeriod=containerconfig_healthcheck_startperiod)
    containerconfig_argsescaped = argToBoolean(args.get('containerconfig_argsescaped', False))
    containerconfig_image = str(args.get('containerconfig_image', ''))
    containerconfig_volumes = str(args.get('containerconfig_volumes', ''))
    containerconfig_workingdir = str(args.get('containerconfig_workingdir', ''))
    containerconfig_entrypoint = argToList(args.get('containerconfig_entrypoint', []))
    containerconfig_networkdisabled = argToBoolean(args.get('containerconfig_networkdisabled', False))
    containerconfig_macaddress = str(args.get('containerconfig_macaddress', ''))
    containerconfig_onbuild = argToList(args.get('containerconfig_onbuild', []))
    containerconfig_labels = str(args.get('containerconfig_labels', ''))
    containerconfig_stopsignal = str(args.get('containerconfig_stopsignal', 'SIGTERM'))
    containerconfig_stoptimeout = args.get('containerconfig_stoptimeout', None)
    containerconfig_shell = argToList(args.get('containerconfig_shell', []))
    hostconfig_binds = argToList(args.get('hostconfig_binds', []))
    hostconfig_containeridfile = str(args.get('hostconfig_containeridfile', ''))
    hostconfig_logconfig_type = str(args.get('hostconfig_logconfig_type', ''))
    hostconfig_logconfig_config = str(args.get('hostconfig_logconfig_config', ''))
    hostconfig_logconfig = assign_params(Type=hostconfig_logconfig_type, Config=hostconfig_logconfig_config)
    hostconfig_networkmode = str(args.get('hostconfig_networkmode', ''))
    hostconfig_portbindings = str(args.get('hostconfig_portbindings', ''))
    hostconfig_restartpolicy_name = str(args.get('hostconfig_restartpolicy_name', ''))
    hostconfig_restartpolicy_maximumretrycount = args.get('hostconfig_restartpolicy_maximumretrycount', None)
    hostconfig_restartpolicy = assign_params(Name=hostconfig_restartpolicy_name,
                                             MaximumRetryCount=hostconfig_restartpolicy_maximumretrycount)
    hostconfig_autoremove = argToBoolean(args.get('hostconfig_autoremove', False))
    hostconfig_volumedriver = str(args.get('hostconfig_volumedriver', ''))
    hostconfig_volumesfrom = argToList(args.get('hostconfig_volumesfrom', []))
    hostconfig_mounts = argToList(args.get('hostconfig_mounts', []))
    hostconfig_capadd = argToList(args.get('hostconfig_capadd', []))
    hostconfig_capdrop = argToList(args.get('hostconfig_capdrop', []))
    hostconfig_cgroupnsmode = str(args.get('hostconfig_cgroupnsmode', ''))
    hostconfig_dns = argToList(args.get('hostconfig_dns', []))
    hostconfig_dnsoptions = argToList(args.get('hostconfig_dnsoptions', []))
    hostconfig_dnssearch = argToList(args.get('hostconfig_dnssearch', []))
    hostconfig_extrahosts = argToList(args.get('hostconfig_extrahosts', []))
    hostconfig_groupadd = argToList(args.get('hostconfig_groupadd', []))
    hostconfig_ipcmode = str(args.get('hostconfig_ipcmode', ''))
    hostconfig_cgroup = str(args.get('hostconfig_cgroup', ''))
    hostconfig_links = argToList(args.get('hostconfig_links', []))
    hostconfig_oomscoreadj = args.get('hostconfig_oomscoreadj', None)
    hostconfig_pidmode = str(args.get('hostconfig_pidmode', ''))
    hostconfig_privileged = argToBoolean(args.get('hostconfig_privileged', False))
    hostconfig_publishallports = argToBoolean(args.get('hostconfig_publishallports', False))
    hostconfig_readonlyrootfs = argToBoolean(args.get('hostconfig_readonlyrootfs', False))
    hostconfig_securityopt = argToList(args.get('hostconfig_securityopt', []))
    hostconfig_storageopt = str(args.get('hostconfig_storageopt', ''))
    hostconfig_tmpfs = str(args.get('hostconfig_tmpfs', ''))
    hostconfig_utsmode = str(args.get('hostconfig_utsmode', ''))
    hostconfig_usernsmode = str(args.get('hostconfig_usernsmode', ''))
    hostconfig_shmsize = args.get('hostconfig_shmsize', None)
    hostconfig_sysctls = str(args.get('hostconfig_sysctls', ''))
    hostconfig_runtime = str(args.get('hostconfig_runtime', ''))
    hostconfig_consolesize = argToList(args.get('hostconfig_consolesize', []))
    hostconfig_isolation = str(args.get('hostconfig_isolation', ''))
    hostconfig_maskedpaths = argToList(args.get('hostconfig_maskedpaths', []))
    hostconfig_readonlypaths = argToList(args.get('hostconfig_readonlypaths', []))
    networkingconfig_endpointsconfig = str(args.get('networkingconfig_endpointsconfig', ''))

    response = client.container_create_request(name, containerconfig_hostname, containerconfig_domainname,
                                               containerconfig_user,
                                               containerconfig_attachstdin,
                                               containerconfig_attachstdout,
                                               containerconfig_attachstderr,
                                               containerconfig_exposedports,
                                               containerconfig_tty,
                                               containerconfig_openstdin,
                                               containerconfig_stdinonce,
                                               containerconfig_env,
                                               containerconfig_cmd,
                                               containerconfig_healthcheck,
                                               containerconfig_argsescaped,
                                               containerconfig_image,
                                               containerconfig_volumes,
                                               containerconfig_workingdir,
                                               containerconfig_entrypoint,
                                               containerconfig_networkdisabled,
                                               containerconfig_macaddress,
                                               containerconfig_onbuild,
                                               containerconfig_labels,
                                               containerconfig_stopsignal,
                                               containerconfig_stoptimeout,
                                               containerconfig_shell,
                                               hostconfig_binds,
                                               hostconfig_containeridfile,
                                               hostconfig_logconfig,
                                               hostconfig_networkmode,
                                               hostconfig_portbindings,
                                               hostconfig_restartpolicy,
                                               hostconfig_autoremove,
                                               hostconfig_volumedriver,
                                               hostconfig_volumesfrom,
                                               hostconfig_mounts,
                                               hostconfig_capadd,
                                               hostconfig_capdrop,
                                               hostconfig_cgroupnsmode,
                                               hostconfig_dns,
                                               hostconfig_dnsoptions,
                                               hostconfig_dnssearch,
                                               hostconfig_extrahosts,
                                               hostconfig_groupadd,
                                               hostconfig_ipcmode,
                                               hostconfig_cgroup,
                                               hostconfig_links,
                                               hostconfig_oomscoreadj,
                                               hostconfig_pidmode,
                                               hostconfig_privileged,
                                               hostconfig_publishallports,
                                               hostconfig_readonlyrootfs,
                                               hostconfig_securityopt,
                                               hostconfig_storageopt,
                                               hostconfig_tmpfs,
                                               hostconfig_utsmode,
                                               hostconfig_usernsmode,
                                               hostconfig_shmsize,
                                               hostconfig_sysctls,
                                               hostconfig_runtime,
                                               hostconfig_consolesize,
                                               hostconfig_isolation,
                                               hostconfig_maskedpaths,
                                               hostconfig_readonlypaths,
                                               networkingconfig_endpointsconfig)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_delete_command(client, args):
    id_ = str(args.get('id', ''))
    v = argToBoolean(args.get('v', False))
    force = argToBoolean(args.get('force', False))
    link = argToBoolean(args.get('link', False))

    response = client.container_delete_request(id_, v, force, link)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_exec_command(client, args):
    execconfig_attachstdin = argToBoolean(args.get('execconfig_attachstdin', False))
    execconfig_attachstdout = argToBoolean(args.get('execconfig_attachstdout', False))
    execconfig_attachstderr = argToBoolean(args.get('execconfig_attachstderr', False))
    execconfig_detachkeys = str(args.get('execconfig_detachkeys', ''))
    execconfig_tty = argToBoolean(args.get('execconfig_tty', False))
    execconfig_env = argToList(args.get('execconfig_env', []))
    execconfig_cmd = argToList(args.get('execconfig_cmd', []))
    execconfig_privileged = argToBoolean(args.get('execconfig_privileged', False))
    execconfig_user = str(args.get('execconfig_user', ''))
    execconfig_workingdir = str(args.get('execconfig_workingdir', ''))
    id_ = str(args.get('id', ''))

    response = client.container_exec_request(execconfig_attachstdin, execconfig_attachstdout, execconfig_attachstderr,
                                             execconfig_detachkeys, execconfig_tty,
                                             execconfig_env, execconfig_cmd,
                                             execconfig_privileged, execconfig_user,
                                             execconfig_workingdir, id_)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_export_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.container_export_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_inspect_command(client, args):
    id_ = str(args.get('id', ''))
    size = argToBoolean(args.get('size', False))

    response = client.container_inspect_request(id_, size)
    command_results = CommandResults(
        outputs_prefix='Docker.ContainerInspectResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_kill_command(client, args):
    id_ = str(args.get('id', ''))
    signal = str(args.get('signal', 'SIGKILL'))

    response = client.container_kill_request(id_, signal)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_list_command(client, args):
    list_all = argToBoolean(args.get('list_all', False))
    limit = args.get('limit', None)
    size = argToBoolean(args.get('size', False))
    filters = str(args.get('filters', ''))

    response = client.container_list_request(list_all, limit, size, filters)
    command_results = CommandResults(
        outputs_prefix='Docker.ContainerSummary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_logs_command(client, args):
    id_ = str(args.get('id', ''))
    follow = argToBoolean(args.get('follow', False))
    stdout = argToBoolean(args.get('stdout', False))
    stderr = argToBoolean(args.get('stderr', False))
    since = int(args.get('since', 0))
    until = int(args.get('until', 0))
    timestamps = argToBoolean(args.get('timestamps', False))
    tail = str(args.get('tail', 'all'))

    response = client.container_logs_request(id_, follow, stdout, stderr, since, until, timestamps, tail)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_pause_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.container_pause_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_prune_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.container_prune_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.ContainerPruneResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_rename_command(client, args):
    id_ = str(args.get('id', ''))
    name = str(args.get('name', ''))

    response = client.container_rename_request(id_, name)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_resize_command(client, args):
    id_ = str(args.get('id', ''))
    h = args.get('h', None)
    w = args.get('w', None)

    response = client.container_resize_request(id_, h, w)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_restart_command(client, args):
    id_ = str(args.get('id', ''))
    t = args.get('t', None)

    response = client.container_restart_request(id_, t)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_start_command(client, args):
    id_ = str(args.get('id', ''))
    detach_keys = str(args.get('detach_keys', ''))

    response = client.container_start_request(id_, detach_keys)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_stats_command(client, args):
    id_ = str(args.get('id', ''))
    stream = argToBoolean(args.get('stream', False))
    one_shot = argToBoolean(args.get('one_shot', False))

    response = client.container_stats_request(id_, stream, one_shot)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_stop_command(client, args):
    id_ = str(args.get('id', ''))
    t = args.get('t', None)

    response = client.container_stop_request(id_, t)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_top_command(client, args):
    id_ = str(args.get('id', ''))
    ps_args = str(args.get('ps_args', '-ef'))

    response = client.container_top_request(id_, ps_args)
    command_results = CommandResults(
        outputs_prefix='Docker.ContainerTopResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_unpause_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.container_unpause_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_update_command(client, args):
    id_ = str(args.get('id', ''))
    resources_cpushares = args.get('resources_cpushares', None)
    resources_memory = int(args.get('resources_memory', 0))
    resources_cgroupparent = str(args.get('resources_cgroupparent', ''))
    resources_blkioweight = args.get('resources_blkioweight', None)
    resources_blkioweightdevice = argToList(args.get('resources_blkioweightdevice', []))
    resources_blkiodevicereadbps = argToList(args.get('resources_blkiodevicereadbps', []))
    resources_blkiodevicewritebps = argToList(args.get('resources_blkiodevicewritebps', []))
    resources_blkiodevicereadiops = argToList(args.get('resources_blkiodevicereadiops', []))
    resources_blkiodevicewriteiops = argToList(args.get('resources_blkiodevicewriteiops', []))
    resources_cpuperiod = args.get('resources_cpuperiod', None)
    resources_cpuquota = args.get('resources_cpuquota', None)
    resources_cpurealtimeperiod = args.get('resources_cpurealtimeperiod', None)
    resources_cpurealtimeruntime = args.get('resources_cpurealtimeruntime', None)
    resources_cpusetcpus = str(args.get('resources_cpusetcpus', ''))
    resources_cpusetmems = str(args.get('resources_cpusetmems', ''))
    resources_devices = argToList(args.get('resources_devices', []))
    resources_devicecgrouprules = argToList(args.get('resources_devicecgrouprules', []))
    resources_devicerequests = argToList(args.get('resources_devicerequests', []))
    resources_kernelmemory = args.get('resources_kernelmemory', None)
    resources_kernelmemorytcp = args.get('resources_kernelmemorytcp', None)
    resources_memoryreservation = args.get('resources_memoryreservation', None)
    resources_memoryswap = args.get('resources_memoryswap', None)
    resources_memoryswappiness = args.get('resources_memoryswappiness', None)
    resources_nanocpus = args.get('resources_nanocpus', None)
    resources_oomkilldisable = argToBoolean(args.get('resources_oomkilldisable', False))
    resources_init = argToBoolean(args.get('resources_init', False))
    resources_pidslimit = args.get('resources_pidslimit', None)
    resources_ulimits = argToList(args.get('resources_ulimits', []))
    resources_cpucount = args.get('resources_cpucount', None)
    resources_cpupercent = args.get('resources_cpupercent', None)
    resources_iomaximumiops = args.get('resources_iomaximumiops', None)
    resources_iomaximumbandwidth = args.get('resources_iomaximumbandwidth', None)
    restartpolicy_name = str(args.get('restartpolicy_name', ''))
    restartpolicy_maximumretrycount = args.get('restartpolicy_maximumretrycount', None)

    response = client.container_update_request(id_, resources_cpushares, resources_memory, resources_cgroupparent,
                                               resources_blkioweight,
                                               resources_blkioweightdevice,
                                               resources_blkiodevicereadbps,
                                               resources_blkiodevicewritebps,
                                               resources_blkiodevicereadiops,
                                               resources_blkiodevicewriteiops,
                                               resources_cpuperiod,
                                               resources_cpuquota,
                                               resources_cpurealtimeperiod,
                                               resources_cpurealtimeruntime,
                                               resources_cpusetcpus,
                                               resources_cpusetmems,
                                               resources_devices,
                                               resources_devicecgrouprules,
                                               resources_devicerequests,
                                               resources_kernelmemory,
                                               resources_kernelmemorytcp,
                                               resources_memoryreservation,
                                               resources_memoryswap,
                                               resources_memoryswappiness,
                                               resources_nanocpus,
                                               resources_oomkilldisable,
                                               resources_init, resources_pidslimit,
                                               resources_ulimits, resources_cpucount,
                                               resources_cpupercent,
                                               resources_iomaximumiops,
                                               resources_iomaximumbandwidth,
                                               restartpolicy_name,
                                               restartpolicy_maximumretrycount)
    command_results = CommandResults(
        outputs_prefix='Docker.ContainerUpdateResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def container_wait_command(client, args):
    id_ = str(args.get('id', ''))
    condition = str(args.get('condition', 'not-running'))

    response = client.container_wait_request(id_, condition)
    command_results = CommandResults(
        outputs_prefix='Docker.ContainerWaitResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def distribution_inspect_command(client, args):
    name = str(args.get('name', ''))

    response = client.distribution_inspect_request(name)
    command_results = CommandResults(
        outputs_prefix='Docker.DistributionInspectResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def exec_inspect_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.exec_inspect_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker.ExecInspectResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def exec_resize_command(client, args):
    id_ = str(args.get('id', ''))
    h = args.get('h', None)
    w = args.get('w', None)

    response = client.exec_resize_request(id_, h, w)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def exec_start_command(client, args):
    execstartconfig_detach = argToBoolean(args.get('execstartconfig_detach', False))
    execstartconfig_tty = argToBoolean(args.get('execstartconfig_tty', False))
    id_ = str(args.get('id', ''))

    response = client.exec_start_request(execstartconfig_detach, execstartconfig_tty, id_)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def get_plugin_privileges_command(client, args):
    remote = str(args.get('remote', ''))

    response = client.get_plugin_privileges_request(remote)
    command_results = CommandResults(
        outputs_prefix='Docker.PluginPrivilegeItem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_build_command(client, args):
    input_stream = str(args.get('input_stream', ''))
    dockerfile = str(args.get('dockerfile', 'Dockerfile'))
    t = str(args.get('t', ''))
    extrahosts = str(args.get('extrahosts', ''))
    remote = str(args.get('remote', ''))
    q = argToBoolean(args.get('q', False))
    nocache = argToBoolean(args.get('nocache', False))
    cachefrom = str(args.get('cachefrom', ''))
    pull = str(args.get('pull', ''))
    rm = argToBoolean(args.get('rm', False))
    forcerm = argToBoolean(args.get('forcerm', False))
    memory = args.get('memory', None)
    memswap = args.get('memswap', None)
    cpushares = args.get('cpushares', None)
    cpusetcpus = str(args.get('cpusetcpus', ''))
    cpuperiod = args.get('cpuperiod', None)
    cpuquota = args.get('cpuquota', None)
    buildargs = str(args.get('buildargs', ''))
    shmsize = args.get('shmsize', None)
    squash = argToBoolean(args.get('squash', False))
    labels = str(args.get('labels', ''))
    networkmode = str(args.get('networkmode', ''))
    platform = str(args.get('platform', ''))
    target = str(args.get('target', ''))
    outputs = str(args.get('outputs', ''))

    response = client.image_build_request(input_stream, dockerfile, t, extrahosts, remote, q, nocache, cachefrom, pull,
                                          rm, forcerm, memory, memswap, cpushares,
                                          cpusetcpus, cpuperiod, cpuquota, buildargs,
                                          shmsize, squash, labels, networkmode,
                                          platform, target, outputs)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_commit_command(client, args):
    containerconfig_hostname = str(args.get('containerconfig_hostname', ''))
    containerconfig_domainname = str(args.get('containerconfig_domainname', ''))
    containerconfig_user = str(args.get('containerconfig_user', ''))
    containerconfig_attachstdin = argToBoolean(args.get('containerconfig_attachstdin', False))
    containerconfig_attachstdout = argToBoolean(args.get('containerconfig_attachstdout', False))
    containerconfig_attachstderr = argToBoolean(args.get('containerconfig_attachstderr', False))
    containerconfig_exposedports = str(args.get('containerconfig_exposedports', ''))
    containerconfig_tty = argToBoolean(args.get('containerconfig_tty', False))
    containerconfig_openstdin = argToBoolean(args.get('containerconfig_openstdin', False))
    containerconfig_stdinonce = argToBoolean(args.get('containerconfig_stdinonce', False))
    containerconfig_env = argToList(args.get('containerconfig_env', []))
    containerconfig_cmd = argToList(args.get('containerconfig_cmd', []))
    containerconfig_healthcheck_test = str(args.get('containerconfig_healthcheck_test', ''))
    containerconfig_healthcheck_interval = args.get('containerconfig_healthcheck_interval', None)
    containerconfig_healthcheck_timeout = args.get('containerconfig_healthcheck_timeout', None)
    containerconfig_healthcheck_retries = args.get('containerconfig_healthcheck_retries', None)
    containerconfig_healthcheck_startperiod = args.get('containerconfig_healthcheck_startperiod', None)
    containerconfig_healthcheck = assign_params(Test=containerconfig_healthcheck_test,
                                                Interval=containerconfig_healthcheck_interval,
                                                Timeout=containerconfig_healthcheck_timeout,
                                                Retries=containerconfig_healthcheck_retries,
                                                StartPeriod=containerconfig_healthcheck_startperiod)
    containerconfig_argsescaped = argToBoolean(args.get('containerconfig_argsescaped', False))
    containerconfig_image = str(args.get('containerconfig_image', ''))
    containerconfig_volumes = str(args.get('containerconfig_volumes', ''))
    containerconfig_workingdir = str(args.get('containerconfig_workingdir', ''))
    containerconfig_entrypoint = argToList(args.get('containerconfig_entrypoint', []))
    containerconfig_networkdisabled = argToBoolean(args.get('containerconfig_networkdisabled', False))
    containerconfig_macaddress = str(args.get('containerconfig_macaddress', ''))
    containerconfig_onbuild = argToList(args.get('containerconfig_onbuild', []))
    containerconfig_labels = str(args.get('containerconfig_labels', ''))
    containerconfig_stopsignal = str(args.get('containerconfig_stopsignal', 'SIGTERM'))
    containerconfig_stoptimeout = args.get('containerconfig_stoptimeout', None)
    containerconfig_shell = argToList(args.get('containerconfig_shell', []))
    container = str(args.get('container', ''))
    repo = str(args.get('repo', ''))
    tag = str(args.get('tag', ''))
    comment = str(args.get('comment', ''))
    author = str(args.get('author', ''))
    pause = argToBoolean(args.get('pause', False))
    changes = str(args.get('changes', ''))

    response = client.image_commit_request(containerconfig_hostname, containerconfig_domainname, containerconfig_user,
                                           containerconfig_attachstdin,
                                           containerconfig_attachstdout,
                                           containerconfig_attachstderr,
                                           containerconfig_exposedports,
                                           containerconfig_tty,
                                           containerconfig_openstdin,
                                           containerconfig_stdinonce,
                                           containerconfig_env,
                                           containerconfig_cmd,
                                           containerconfig_healthcheck,
                                           containerconfig_argsescaped,
                                           containerconfig_image,
                                           containerconfig_volumes,
                                           containerconfig_workingdir,
                                           containerconfig_entrypoint,
                                           containerconfig_networkdisabled,
                                           containerconfig_macaddress,
                                           containerconfig_onbuild,
                                           containerconfig_labels,
                                           containerconfig_stopsignal,
                                           containerconfig_stoptimeout,
                                           containerconfig_shell, container,
                                           repo, tag, comment, author, pause, changes)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_create_command(client, args):
    from_image = str(args.get('from_image', ''))
    from_src = str(args.get('from_src', ''))
    repo = str(args.get('repo', ''))
    tag = str(args.get('tag', ''))
    message = str(args.get('message', ''))
    input_image = str(args.get('input_image', ''))
    platform = str(args.get('platform', ''))

    response = client.image_create_request(from_image, from_src, repo, tag, message, input_image, platform)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_delete_command(client, args):
    name = str(args.get('name', ''))
    force = argToBoolean(args.get('force', False))
    noprune = argToBoolean(args.get('noprune', False))

    response = client.image_delete_request(name, force, noprune)
    command_results = CommandResults(
        outputs_prefix='Docker.ImageDeleteResponseItem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_get_command(client, args):
    name = str(args.get('name', ''))

    response = client.image_get_request(name)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_get_all_command(client, args):
    names = argToList(args.get('names', []))

    response = client.image_get_all_request(names)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_history_command(client, args):
    name = str(args.get('name', ''))

    response = client.image_history_request(name)
    command_results = CommandResults(
        outputs_prefix='Docker.HistoryResponseItem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_inspect_command(client, args):
    name = str(args.get('name', ''))

    response = client.image_inspect_request(name)
    command_results = CommandResults(
        outputs_prefix='Docker.Image',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_list_command(client, args):
    list_all = argToBoolean(args.get('list_all', False))
    filters = str(args.get('filters', ''))
    digests = argToBoolean(args.get('digests', False))

    response = client.image_list_request(list_all, filters, digests)
    command_results = CommandResults(
        outputs_prefix='Docker.ImageSummary',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_load_command(client, args):
    images_tarball = str(args.get('images_tarball', ''))
    quiet = argToBoolean(args.get('quiet', False))

    response = client.image_load_request(images_tarball, quiet)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_prune_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.image_prune_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.ImagePruneResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_push_command(client, args):
    name = str(args.get('name', ''))
    tag = str(args.get('tag', ''))

    response = client.image_push_request(name, tag)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_search_command(client, args):
    term = str(args.get('term', ''))
    limit = args.get('limit', None)
    filters = str(args.get('filters', ''))

    response = client.image_search_request(term, limit, filters)
    command_results = CommandResults(
        outputs_prefix='Docker.ImageSearchResponseItem',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def image_tag_command(client, args):
    name = str(args.get('name', ''))
    repo = str(args.get('repo', ''))
    tag = str(args.get('tag', ''))

    response = client.image_tag_request(name, repo, tag)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def network_connect_command(client, args):
    id_ = str(args.get('id', ''))
    container_container = str(args.get('container_container', ''))
    container_endpointconfig_ipamconfig = str(args.get('container_endpointconfig_ipamconfig', ''))
    container_endpointconfig_links = str(args.get('container_endpointconfig_links', ''))
    container_endpointconfig_aliases = str(args.get('container_endpointconfig_aliases', ''))
    container_endpointconfig_networkid = str(args.get('container_endpointconfig_networkid', ''))
    container_endpointconfig_endpointid = str(args.get('container_endpointconfig_endpointid', ''))
    container_endpointconfig_gateway = str(args.get('container_endpointconfig_gateway', ''))
    container_endpointconfig_ipaddress = str(args.get('container_endpointconfig_ipaddress', ''))
    container_endpointconfig_ipprefixlen = args.get('container_endpointconfig_ipprefixlen', None)
    container_endpointconfig_ipv6gateway = str(args.get('container_endpointconfig_ipv6gateway', ''))
    container_endpointconfig_globalipv6address = str(args.get('container_endpointconfig_globalipv6address', ''))
    container_endpointconfig_globalipv6prefixlen = args.get('container_endpointconfig_globalipv6prefixlen', None)
    container_endpointconfig_macaddress = str(args.get('container_endpointconfig_macaddress', ''))
    container_endpointconfig_driveropts = str(args.get('container_endpointconfig_driveropts', ''))
    container_endpointconfig = assign_params(IPAMConfig=container_endpointconfig_ipamconfig,
                                             Links=container_endpointconfig_links,
                                             Aliases=container_endpointconfig_aliases,
                                             NetworkID=container_endpointconfig_networkid,
                                             EndpointID=container_endpointconfig_endpointid,
                                             Gateway=container_endpointconfig_gateway,
                                             IPAddress=container_endpointconfig_ipaddress,
                                             IPPrefixLen=container_endpointconfig_ipprefixlen,
                                             IPv6Gateway=container_endpointconfig_ipv6gateway,
                                             GlobalIPv6Address=container_endpointconfig_globalipv6address,
                                             GlobalIPv6PrefixLen=container_endpointconfig_globalipv6prefixlen,
                                             MacAddress=container_endpointconfig_macaddress,
                                             DriverOpts=container_endpointconfig_driveropts)

    response = client.network_connect_request(id_, container_container, container_endpointconfig)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def network_create_command(client, args):
    networkconfig_name = str(args.get('networkconfig_name', ''))
    networkconfig_checkduplicate = argToBoolean(args.get('networkconfig_checkduplicate', False))
    networkconfig_driver = str(args.get('networkconfig_driver', 'bridge'))
    networkconfig_internal = argToBoolean(args.get('networkconfig_internal', False))
    networkconfig_attachable = argToBoolean(args.get('networkconfig_attachable', False))
    networkconfig_ingress = argToBoolean(args.get('networkconfig_ingress', False))
    networkconfig_ipam_driver = str(args.get('networkconfig_ipam_driver', ''))
    networkconfig_ipam_config = str(args.get('networkconfig_ipam_config', ''))
    networkconfig_ipam_options = str(args.get('networkconfig_ipam_options', ''))
    networkconfig_ipam = assign_params(Driver=networkconfig_ipam_driver, Config=networkconfig_ipam_config,
                                       Options=networkconfig_ipam_options)
    networkconfig_enableipv6 = argToBoolean(args.get('networkconfig_enableipv6', False))
    networkconfig_options = str(args.get('networkconfig_options', ''))
    networkconfig_labels = str(args.get('networkconfig_labels', ''))

    response = client.network_create_request(networkconfig_name, networkconfig_checkduplicate, networkconfig_driver,
                                             networkconfig_internal, networkconfig_attachable, networkconfig_ingress,
                                             networkconfig_ipam, networkconfig_enableipv6, networkconfig_options,
                                             networkconfig_labels)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def network_delete_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.network_delete_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def network_disconnect_command(client, args):
    id_ = str(args.get('id', ''))
    container = str(args.get('container', ''))
    force = argToBoolean(args.get('force', False))

    response = client.network_disconnect_request(id_, container, force)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def network_inspect_command(client, args):
    id_ = str(args.get('id', ''))
    verbose = argToBoolean(args.get('verbose', False))
    scope = str(args.get('scope', ''))

    response = client.network_inspect_request(id_, verbose, scope)
    command_results = CommandResults(
        outputs_prefix='Docker.Network',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def network_list_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.network_list_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.Network',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def network_prune_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.network_prune_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.NetworkPruneResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def node_delete_command(client, args):
    id_ = str(args.get('id', ''))
    force = argToBoolean(args.get('force', False))

    response = client.node_delete_request(id_, force)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def node_inspect_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.node_inspect_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker.Node',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def node_list_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.node_list_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.Node',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def node_update_command(client, args):
    id_ = str(args.get('id', ''))
    nodespec_name = str(args.get('nodespec_name', ''))
    nodespec_labels = str(args.get('nodespec_labels', ''))
    nodespec_role = str(args.get('nodespec_role', ''))
    nodespec_availability = str(args.get('nodespec_availability', ''))
    version = args.get('version', None)

    response = client.node_update_request(id_, nodespec_name, nodespec_labels, nodespec_role, nodespec_availability,
                                          version)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def secret_create_command(client, args):
    secretspec_name = str(args.get('secretspec_name', ''))
    secretspec_labels = str(args.get('secretspec_labels', ''))
    secretspec_data = str(args.get('secretspec_data', ''))
    secretspec_driver_name = str(args.get('secretspec_driver_name', ''))
    secretspec_driver_options = str(args.get('secretspec_driver_options', ''))
    secretspec_driver = assign_params(Name=secretspec_driver_name, Options=secretspec_driver_options)
    secretspec_templating_name = str(args.get('secretspec_templating_name', ''))
    secretspec_templating_options = str(args.get('secretspec_templating_options', ''))
    secretspec_templating = assign_params(Name=secretspec_templating_name, Options=secretspec_templating_options)

    response = client.secret_create_request(secretspec_name, secretspec_labels, secretspec_data, secretspec_driver,
                                            secretspec_templating)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def secret_delete_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.secret_delete_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def secret_inspect_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.secret_inspect_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker.Secret',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def secret_list_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.secret_list_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.Secret',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def secret_update_command(client, args):
    id_ = str(args.get('id', ''))
    secretspec_name = str(args.get('secretspec_name', ''))
    secretspec_labels = str(args.get('secretspec_labels', ''))
    secretspec_data = str(args.get('secretspec_data', ''))
    secretspec_driver_name = str(args.get('secretspec_driver_name', ''))
    secretspec_driver_options = str(args.get('secretspec_driver_options', ''))
    secretspec_driver = assign_params(Name=secretspec_driver_name, Options=secretspec_driver_options)
    secretspec_templating_name = str(args.get('secretspec_templating_name', ''))
    secretspec_templating_options = str(args.get('secretspec_templating_options', ''))
    secretspec_templating = assign_params(Name=secretspec_templating_name, Options=secretspec_templating_options)
    version = args.get('version', None)

    response = client.secret_update_request(id_, secretspec_name, secretspec_labels, secretspec_data, secretspec_driver,
                                            secretspec_templating, version)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def service_create_command(client, args):
    servicespec_name = str(args.get('servicespec_name', ''))
    servicespec_labels = str(args.get('servicespec_labels', ''))
    servicespec_tasktemplate_pluginspec = str(args.get('servicespec_tasktemplate_pluginspec', ''))
    servicespec_tasktemplate_containerspec = str(args.get('servicespec_tasktemplate_containerspec', ''))
    servicespec_tasktemplate_networkattachmentspec = str(args.get('servicespec_tasktemplate_networkattachmentspec', ''))
    servicespec_tasktemplate_resources = str(args.get('servicespec_tasktemplate_resources', ''))
    servicespec_tasktemplate_restartpolicy = str(args.get('servicespec_tasktemplate_restartpolicy', ''))
    servicespec_tasktemplate_placement = str(args.get('servicespec_tasktemplate_placement', ''))
    servicespec_tasktemplate_forceupdate = args.get('servicespec_tasktemplate_forceupdate', None)
    servicespec_tasktemplate_runtime = str(args.get('servicespec_tasktemplate_runtime', ''))
    servicespec_tasktemplate_networks = str(args.get('servicespec_tasktemplate_networks', ''))
    servicespec_tasktemplate_logdriver = str(args.get('servicespec_tasktemplate_logdriver', ''))
    servicespec_tasktemplate = assign_params(PluginSpec=servicespec_tasktemplate_pluginspec,
                                             ContainerSpec=servicespec_tasktemplate_containerspec,
                                             NetworkAttachmentSpec=servicespec_tasktemplate_networkattachmentspec,
                                             Resources=servicespec_tasktemplate_resources,
                                             RestartPolicy=servicespec_tasktemplate_restartpolicy,
                                             Placement=servicespec_tasktemplate_placement,
                                             ForceUpdate=servicespec_tasktemplate_forceupdate,
                                             Runtime=servicespec_tasktemplate_runtime,
                                             Networks=servicespec_tasktemplate_networks,
                                             LogDriver=servicespec_tasktemplate_logdriver)
    servicespec_mode_replicated = str(args.get('servicespec_mode_replicated', ''))
    servicespec_mode_global = str(args.get('servicespec_mode_global', ''))
    servicespec_mode_replicatedjob = str(args.get('servicespec_mode_replicatedjob', ''))
    servicespec_mode_globaljob = str(args.get('servicespec_mode_globaljob', ''))
    servicespec_mode = assign_params(Replicated=servicespec_mode_replicated, Global=servicespec_mode_global,
                                     ReplicatedJob=servicespec_mode_replicatedjob,
                                     GlobalJob=servicespec_mode_globaljob)
    servicespec_updateconfig_parallelism = args.get('servicespec_updateconfig_parallelism', None)
    servicespec_updateconfig_delay = args.get('servicespec_updateconfig_delay', None)
    servicespec_updateconfig_failureaction = str(args.get('servicespec_updateconfig_failureaction', ''))
    servicespec_updateconfig_monitor = args.get('servicespec_updateconfig_monitor', None)
    servicespec_updateconfig_maxfailureratio = str(args.get('servicespec_updateconfig_maxfailureratio', ''))
    servicespec_updateconfig_order = str(args.get('servicespec_updateconfig_order', ''))
    servicespec_updateconfig = assign_params(Parallelism=servicespec_updateconfig_parallelism,
                                             Delay=servicespec_updateconfig_delay,
                                             FailureAction=servicespec_updateconfig_failureaction,
                                             Monitor=servicespec_updateconfig_monitor,
                                             MaxFailureRatio=servicespec_updateconfig_maxfailureratio,
                                             Order=servicespec_updateconfig_order)
    servicespec_rollbackconfig_parallelism = args.get('servicespec_rollbackconfig_parallelism', None)
    servicespec_rollbackconfig_delay = args.get('servicespec_rollbackconfig_delay', None)
    servicespec_rollbackconfig_failureaction = str(args.get('servicespec_rollbackconfig_failureaction', ''))
    servicespec_rollbackconfig_monitor = args.get('servicespec_rollbackconfig_monitor', None)
    servicespec_rollbackconfig_maxfailureratio = str(args.get('servicespec_rollbackconfig_maxfailureratio', ''))
    servicespec_rollbackconfig_order = str(args.get('servicespec_rollbackconfig_order', ''))
    servicespec_rollbackconfig = assign_params(Parallelism=servicespec_rollbackconfig_parallelism,
                                               Delay=servicespec_rollbackconfig_delay,
                                               FailureAction=servicespec_rollbackconfig_failureaction,
                                               Monitor=servicespec_rollbackconfig_monitor,
                                               MaxFailureRatio=servicespec_rollbackconfig_maxfailureratio,
                                               Order=servicespec_rollbackconfig_order)
    servicespec_networks = argToList(args.get('servicespec_networks', []))
    servicespec_endpointspec_mode = str(args.get('servicespec_endpointspec_mode', ''))
    servicespec_endpointspec_ports = str(args.get('servicespec_endpointspec_ports', ''))
    servicespec_endpointspec = assign_params(Mode=servicespec_endpointspec_mode, Ports=servicespec_endpointspec_ports)

    response = client.service_create_request(servicespec_name, servicespec_labels, servicespec_tasktemplate,
                                             servicespec_mode, servicespec_updateconfig,
                                             servicespec_rollbackconfig, servicespec_networks,
                                             servicespec_endpointspec)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def service_delete_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.service_delete_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def service_inspect_command(client, args):
    id_ = str(args.get('id', ''))
    insert_defaults = argToBoolean(args.get('insert_defaults', False))

    response = client.service_inspect_request(id_, insert_defaults)
    command_results = CommandResults(
        outputs_prefix='Docker.Service',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def service_list_command(client, args):
    filters = str(args.get('filters', ''))
    status = argToBoolean(args.get('status', False))

    response = client.service_list_request(filters, status)
    command_results = CommandResults(
        outputs_prefix='Docker.Service',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def service_logs_command(client, args):
    id_ = str(args.get('id', ''))
    details = argToBoolean(args.get('details', False))
    follow = argToBoolean(args.get('follow', False))
    stdout = argToBoolean(args.get('stdout', False))
    stderr = argToBoolean(args.get('stderr', False))
    since = int(args.get('since', 0))
    timestamps = argToBoolean(args.get('timestamps', False))
    tail = str(args.get('tail', 'all'))

    response = client.service_logs_request(id_, details, follow, stdout, stderr, since, timestamps, tail)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def service_update_command(client, args):
    id_ = str(args.get('id', ''))
    servicespec_name = str(args.get('servicespec_name', ''))
    servicespec_labels = str(args.get('servicespec_labels', ''))
    servicespec_tasktemplate_pluginspec = str(args.get('servicespec_tasktemplate_pluginspec', ''))
    servicespec_tasktemplate_containerspec = str(args.get('servicespec_tasktemplate_containerspec', ''))
    servicespec_tasktemplate_networkattachmentspec = str(args.get('servicespec_tasktemplate_networkattachmentspec', ''))
    servicespec_tasktemplate_resources = str(args.get('servicespec_tasktemplate_resources', ''))
    servicespec_tasktemplate_restartpolicy = str(args.get('servicespec_tasktemplate_restartpolicy', ''))
    servicespec_tasktemplate_placement = str(args.get('servicespec_tasktemplate_placement', ''))
    servicespec_tasktemplate_forceupdate = args.get('servicespec_tasktemplate_forceupdate', None)
    servicespec_tasktemplate_runtime = str(args.get('servicespec_tasktemplate_runtime', ''))
    servicespec_tasktemplate_networks = str(args.get('servicespec_tasktemplate_networks', ''))
    servicespec_tasktemplate_logdriver = str(args.get('servicespec_tasktemplate_logdriver', ''))
    servicespec_tasktemplate = assign_params(PluginSpec=servicespec_tasktemplate_pluginspec,
                                             ContainerSpec=servicespec_tasktemplate_containerspec,
                                             NetworkAttachmentSpec=servicespec_tasktemplate_networkattachmentspec,
                                             Resources=servicespec_tasktemplate_resources,
                                             RestartPolicy=servicespec_tasktemplate_restartpolicy,
                                             Placement=servicespec_tasktemplate_placement,
                                             ForceUpdate=servicespec_tasktemplate_forceupdate,
                                             Runtime=servicespec_tasktemplate_runtime,
                                             Networks=servicespec_tasktemplate_networks,
                                             LogDriver=servicespec_tasktemplate_logdriver)
    servicespec_mode_replicated = str(args.get('servicespec_mode_replicated', ''))
    servicespec_mode_global = str(args.get('servicespec_mode_global', ''))
    servicespec_mode_replicatedjob = str(args.get('servicespec_mode_replicatedjob', ''))
    servicespec_mode_globaljob = str(args.get('servicespec_mode_globaljob', ''))
    servicespec_mode = assign_params(Replicated=servicespec_mode_replicated, Global=servicespec_mode_global,
                                     ReplicatedJob=servicespec_mode_replicatedjob,
                                     GlobalJob=servicespec_mode_globaljob)
    servicespec_updateconfig_parallelism = args.get('servicespec_updateconfig_parallelism', None)
    servicespec_updateconfig_delay = args.get('servicespec_updateconfig_delay', None)
    servicespec_updateconfig_failureaction = str(args.get('servicespec_updateconfig_failureaction', ''))
    servicespec_updateconfig_monitor = args.get('servicespec_updateconfig_monitor', None)
    servicespec_updateconfig_maxfailureratio = str(args.get('servicespec_updateconfig_maxfailureratio', ''))
    servicespec_updateconfig_order = str(args.get('servicespec_updateconfig_order', ''))
    servicespec_updateconfig = assign_params(Parallelism=servicespec_updateconfig_parallelism,
                                             Delay=servicespec_updateconfig_delay,
                                             FailureAction=servicespec_updateconfig_failureaction,
                                             Monitor=servicespec_updateconfig_monitor,
                                             MaxFailureRatio=servicespec_updateconfig_maxfailureratio,
                                             Order=servicespec_updateconfig_order)
    servicespec_rollbackconfig_parallelism = args.get('servicespec_rollbackconfig_parallelism', None)
    servicespec_rollbackconfig_delay = args.get('servicespec_rollbackconfig_delay', None)
    servicespec_rollbackconfig_failureaction = str(args.get('servicespec_rollbackconfig_failureaction', ''))
    servicespec_rollbackconfig_monitor = args.get('servicespec_rollbackconfig_monitor', None)
    servicespec_rollbackconfig_maxfailureratio = str(args.get('servicespec_rollbackconfig_maxfailureratio', ''))
    servicespec_rollbackconfig_order = str(args.get('servicespec_rollbackconfig_order', ''))
    servicespec_rollbackconfig = assign_params(Parallelism=servicespec_rollbackconfig_parallelism,
                                               Delay=servicespec_rollbackconfig_delay,
                                               FailureAction=servicespec_rollbackconfig_failureaction,
                                               Monitor=servicespec_rollbackconfig_monitor,
                                               MaxFailureRatio=servicespec_rollbackconfig_maxfailureratio,
                                               Order=servicespec_rollbackconfig_order)
    servicespec_networks = argToList(args.get('servicespec_networks', []))
    servicespec_endpointspec_mode = str(args.get('servicespec_endpointspec_mode', ''))
    servicespec_endpointspec_ports = str(args.get('servicespec_endpointspec_ports', ''))
    servicespec_endpointspec = assign_params(Mode=servicespec_endpointspec_mode, Ports=servicespec_endpointspec_ports)
    version = args.get('version', None)
    registery_auth_from = str(args.get('registery_auth_from', 'spec'))
    rollback = str(args.get('rollback', ''))

    response = client.service_update_request(id_, servicespec_name, servicespec_labels, servicespec_tasktemplate,
                                             servicespec_mode,
                                             servicespec_updateconfig,
                                             servicespec_rollbackconfig,
                                             servicespec_networks,
                                             servicespec_endpointspec,
                                             version, registery_auth_from, rollback)
    command_results = CommandResults(
        outputs_prefix='Docker.ServiceUpdateResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def session_command(client, args):

    response = client.session_request()
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def swarm_init_command(client, args):
    listenaddr = str(args.get('listenaddr', ''))
    advertiseaddr = str(args.get('advertiseaddr', ''))
    datapathaddr = str(args.get('datapathaddr', ''))
    datapathport = args.get('datapathport', None)
    defaultaddrpool = argToList(args.get('defaultaddrpool', []))
    forcenewcluster = argToBoolean(args.get('forcenewcluster', False))
    subnetsize = args.get('subnetsize', None)
    spec_name = str(args.get('spec_name', ''))
    spec_labels = str(args.get('spec_labels', ''))
    spec_orchestration = str(args.get('spec_orchestration', ''))
    spec_raft = str(args.get('spec_raft', ''))
    spec_dispatcher = str(args.get('spec_dispatcher', ''))
    spec_caconfig = str(args.get('spec_caconfig', ''))
    spec_encryptionconfig = str(args.get('spec_encryptionconfig', ''))
    spec_taskdefaults = str(args.get('spec_taskdefaults', ''))
    spec = assign_params(Name=spec_name, Labels=spec_labels,
                         Orchestration=spec_orchestration,
                         Raft=spec_raft,
                         Dispatcher=spec_dispatcher,
                         CAConfig=spec_caconfig,
                         EncryptionConfig=spec_encryptionconfig,
                         TaskDefaults=spec_taskdefaults)

    response = client.swarm_init_request(listenaddr, advertiseaddr, datapathaddr,
                                         datapathport, defaultaddrpool, forcenewcluster,
                                         subnetsize, spec)
    if type(response) == str:
        response = {
            "Node ID": response
        }
        command_results = CommandResults(
            outputs_prefix='Docker.Swarm.Token',
            outputs_key_field='',
            outputs=response,
            raw_response=response
        )
    else:
        command_results = CommandResults(
            outputs_prefix='Docker.Swarm.Token',
            outputs_key_field='',
            outputs=response,
            raw_response=response
        )
    return command_results


def swarm_inspect_command(client, args):

    response = client.swarm_inspect_request()
    command_results = CommandResults(
        outputs_prefix='Docker.Swarm',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def swarm_join_command(client, args):
    listenaddr = str(args.get('listenaddr', ''))
    advertiseaddr = str(args.get('advertiseaddr', ''))
    datapathaddr = str(args.get('datapathaddr', ''))
    remoteaddrs = argToList(args.get('remoteaddrs', []))
    jointoken = str(args.get('jointoken', ''))

    response = client.swarm_join_request(listenaddr, advertiseaddr, datapathaddr,
                                         remoteaddrs, jointoken)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def swarm_leave_command(client, args):
    force = argToBoolean(args.get('force', False))

    response = client.swarm_leave_request(force)

    if type(response) == dict:
        command_results = CommandResults(
            outputs_prefix='Docker',
            outputs_key_field='',
            outputs=response,
            raw_response=response
        )
    else:
        response = {
            "message": "Swarm node left."
        }
        command_results = CommandResults(
            outputs_prefix='Docker',
            outputs_key_field='',
            outputs=response,
            raw_response=response
        )

    return command_results


def swarm_unlock_command(client, args):
    unlockkey = str(args.get('unlockkey', ''))

    response = client.swarm_unlock_request(unlockkey)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def swarm_unlockkey_command(client, args):

    response = client.swarm_unlockkey_request()
    command_results = CommandResults(
        outputs_prefix='Docker.UnlockKeyResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def system_auth_command(client, args):
    authconfig_username = str(args.get('authconfig_username', ''))
    authconfig_password = str(args.get('authconfig_password', ''))
    authconfig_email = str(args.get('authconfig_email', ''))
    authconfig_serveraddress = str(args.get('authconfig_serveraddress', ''))

    response = client.system_auth_request(authconfig_username, authconfig_password, authconfig_email,
                                          authconfig_serveraddress)
    command_results = CommandResults(
        outputs_prefix='Docker.SystemAuthResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def system_data_usage_command(client, args):

    response = client.system_data_usage_request()
    command_results = CommandResults(
        outputs_prefix='Docker.SystemDataUsageResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def system_events_command(client, args):
    since = str(args.get('since', ''))
    until = str(args.get('until', ''))
    filters = str(args.get('filters', ''))

    response = client.system_events_request(since, until, filters)
    command_results = CommandResults(
        outputs_prefix='Docker.SystemEventsResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def system_info_command(client, args):

    response = client.system_info_request()
    command_results = CommandResults(
        outputs_prefix='Docker.SystemInfo',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def system_ping_command(client, args):

    response = client.system_ping_request()
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def system_ping_head_command(client, args):

    response = client.system_ping_head_request()
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def system_version_command(client, args):

    response = client.system_version_request()
    command_results = CommandResults(
        outputs_prefix='Docker.SystemVersion',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def task_inspect_command(client, args):
    id_ = str(args.get('id', ''))

    response = client.task_inspect_request(id_)
    command_results = CommandResults(
        outputs_prefix='Docker.Task',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def task_list_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.task_list_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.Task',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def task_logs_command(client, args):
    id_ = str(args.get('id', ''))
    details = argToBoolean(args.get('details', False))
    follow = argToBoolean(args.get('follow', False))
    stdout = argToBoolean(args.get('stdout', False))
    stderr = argToBoolean(args.get('stderr', False))
    since = int(args.get('since', 0))
    timestamps = argToBoolean(args.get('timestamps', False))
    tail = str(args.get('tail', 'all'))

    response = client.task_logs_request(id_, details, follow, stdout, stderr, since, timestamps, tail)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def volume_create_command(client, args):
    volumeconfig_name = str(args.get('volumeconfig_name', ''))
    volumeconfig_driver = str(args.get('volumeconfig_driver', 'local'))
    volumeconfig_driveropts = str(args.get('volumeconfig_driveropts', ''))
    volumeconfig_labels = str(args.get('volumeconfig_labels', ''))

    response = client.volume_create_request(volumeconfig_name, volumeconfig_driver, volumeconfig_driveropts,
                                            volumeconfig_labels)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def volume_delete_command(client, args):
    name = str(args.get('name', ''))
    force = argToBoolean(args.get('force', False))

    response = client.volume_delete_request(name, force)
    command_results = CommandResults(
        outputs_prefix='Docker',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def volume_inspect_command(client, args):
    name = str(args.get('name', ''))

    response = client.volume_inspect_request(name)
    command_results = CommandResults(
        outputs_prefix='Docker.Volume',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def volume_list_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.volume_list_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.VolumeListResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def volume_prune_command(client, args):
    filters = str(args.get('filters', ''))

    response = client.volume_prune_request(filters)
    command_results = CommandResults(
        outputs_prefix='Docker.VolumePruneResponse',
        outputs_key_field='',
        outputs=response,
        raw_response=response
    )

    return command_results


def test_module(client):
    # Test functions here
    response = client.test_request()
    if response.get('Platform'):
        demisto.results('ok')
    else:
        demisto.results(response)


def main():

    params = demisto.params()
    args = demisto.args()
    url = params.get('url')
    client_cert = params.get('client_certificate')
    client_key = params.get('client_key')
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)

    command = demisto.command()
    LOG(f'Command being called is {command}')

    try:
        urllib3.disable_warnings()
        client = Client(urljoin(url, "/v1.41"), verify_certificate, proxy, headers=None,
                        client_cert=client_cert, client_key=client_key)
        commands = {
            'docker-build-prune': build_prune_command,
            'docker-config-create': config_create_command,
            'docker-config-inspect': config_inspect_command,
            'docker-config-list': config_list_command,
            'docker-container-changes': container_changes_command,
            'docker-container-create': container_create_command,
            'docker-container-delete': container_delete_command,
            'docker-container-exec': container_exec_command,
            'docker-container-export': container_export_command,
            'docker-container-inspect': container_inspect_command,
            'docker-container-kill': container_kill_command,
            'docker-container-list': container_list_command,
            'docker-container-logs': container_logs_command,
            'docker-container-pause': container_pause_command,
            'docker-container-prune': container_prune_command,
            'docker-container-rename': container_rename_command,
            'docker-container-resize': container_resize_command,
            'docker-container-restart': container_restart_command,
            'docker-container-start': container_start_command,
            'docker-container-stats': container_stats_command,
            'docker-container-stop': container_stop_command,
            'docker-container-top': container_top_command,
            'docker-container-unpause': container_unpause_command,
            'docker-container-update': container_update_command,
            'docker-container-wait': container_wait_command,
            'docker-distribution-inspect': distribution_inspect_command,
            'docker-exec-inspect': exec_inspect_command,
            'docker-exec-resize': exec_resize_command,
            'docker-exec-start': exec_start_command,
            'docker-image-build': image_build_command,
            'docker-image-commit': image_commit_command,
            'docker-image-create': image_create_command,
            'docker-image-delete': image_delete_command,
            'docker-image-get': image_get_command,
            'docker-image-get-all': image_get_all_command,
            'docker-image-history': image_history_command,
            'docker-image-inspect': image_inspect_command,
            'docker-image-list': image_list_command,
            'docker-image-load': image_load_command,
            'docker-image-prune': image_prune_command,
            'docker-image-push': image_push_command,
            'docker-image-search': image_search_command,
            'docker-image-tag': image_tag_command,
            'docker-network-connect': network_connect_command,
            'docker-network-create': network_create_command,
            'docker-network-delete': network_delete_command,
            'docker-network-disconnect': network_disconnect_command,
            'docker-network-inspect': network_inspect_command,
            'docker-network-list': network_list_command,
            'docker-network-prune': network_prune_command,
            'docker-node-delete': node_delete_command,
            'docker-node-inspect': node_inspect_command,
            'docker-node-list': node_list_command,
            'docker-node-update': node_update_command,
            'docker-secret-create': secret_create_command,
            'docker-secret-delete': secret_delete_command,
            'docker-secret-inspect': secret_inspect_command,
            'docker-secret-list': secret_list_command,
            'docker-secret-update': secret_update_command,
            'docker-service-create': service_create_command,
            'docker-service-delete': service_delete_command,
            'docker-service-inspect': service_inspect_command,
            'docker-service-list': service_list_command,
            'docker-service-logs': service_logs_command,
            'docker-service-update': service_update_command,
            'docker-session': session_command,
            'docker-swarm-init': swarm_init_command,
            'docker-swarm-inspect': swarm_inspect_command,
            'docker-swarm-join': swarm_join_command,
            'docker-swarm-leave': swarm_leave_command,
            'docker-swarm-unlock': swarm_unlock_command,
            'docker-swarm-unlockkey': swarm_unlockkey_command,
            'docker-system-auth': system_auth_command,
            'docker-system-data-usage': system_data_usage_command,
            'docker-system-events': system_events_command,
            'docker-system-info': system_info_command,
            'docker-system-ping': system_ping_command,
            'docker-system-ping-head': system_ping_head_command,
            'docker-system-version': system_version_command,
            'docker-task-inspect': task_inspect_command,
            'docker-task-list': task_list_command,
            'docker-task-logs': task_logs_command,
            'docker-volume-create': volume_create_command,
            'docker-volume-delete': volume_delete_command,
            'docker-volume-inspect': volume_inspect_command,
            'docker-volume-list': volume_list_command,
            'docker-volume-prune': volume_prune_command,
        }

        if command == 'test-module':
            test_module(client)
        else:
            return_results(commands[command](client, args))

    except Exception as e:
        return_error(str(e))


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
