import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pylint: disable=no-member
# pylint: disable=no-name-in-module
import ssl
import urllib3
import pyVim.task
import dateparser  # type: ignore
from io import StringIO
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl  # type: ignore
from vmware.vapi.vsphere.client import create_vsphere_client


REDIRECT_STD_OUT = argToBoolean(demisto.params().get('redirect_std_out', 'false'))
real_demisto_info = demisto.info
real_demisto_debug = demisto.debug


def use_demisto_debug(msg):  # pragma: no cover
    if REDIRECT_STD_OUT:
        temp = sys.stdout
        sys.stdout = sys.__stdout__
        real_demisto_debug(msg)
        sys.stdout = temp
    else:
        real_demisto_debug(msg)


def use_demisto_info(msg):  # pragma: no cover
    if REDIRECT_STD_OUT:
        temp = sys.stdout
        sys.stdout = sys.__stdout__
        real_demisto_info(msg)
        sys.stdout = temp
    else:
        real_demisto_info(msg)


demisto.info = use_demisto_info  # type: ignore
demisto.debug = use_demisto_debug  # type: ignore


def parse_params(params):
    full_url = params['url']
    url_arr = full_url.rsplit(':', 1)
    url = url_arr[0]
    port = str(url_arr[1])
    user_name = params.get('credentials').get('identifier')
    password = params.get('credentials').get('password')
    return full_url, url, port, user_name, password


def get_limit(args):
    """
    Args:
        args: Args input for command, this function uses limit, page and page_size

    Returns:
        - limit - how many items to request from AWS - IAM API.
        - is_manual - whether manual pagination is active (using page and page_size)
        - page_size - used when manual pagination is active, to bring the relevant number of results from the data.

    """
    limit = arg_to_number(str(args.get("limit"))) if "limit" in args else None
    page = arg_to_number(str(args.get("page"))) if "page" in args else None
    page_size = arg_to_number(str(args.get("page_size"))) if "page_size" in args else None

    if limit is None:
        if page is not None and page_size is not None:
            if page <= 0:
                raise Exception('Chosen page number must be greater than 0')
            limit = page_size * page
            return limit, True, page_size
        else:
            limit = 50
    return limit, False, page_size


def login(params):  # pragma: no cover
    full_url, url, port, user_name, password = parse_params(params)

    # Preparations for SDKs connections
    s = ssl.SSLContext(ssl.PROTOCOL_TLS)
    s.verify_mode = ssl.CERT_NONE

    # Connect to a vCenter Server using username and password
    try:
        si = SmartConnect(host=url,
                          user=user_name,
                          pwd=password,
                          port=port)
    except Exception:
        si = SmartConnect(host=url,
                          user=user_name,
                          pwd=password,
                          port=port,
                          sslContext=s)

    return si


def logout(si):  # pragma: no cover
    Disconnect(si)


def get_vm(si, uuid):
    vm = si.content.searchIndex.FindByUuid(None, uuid, True, True)  # type: ignore
    if vm is None:
        raise Exception('Unable to locate Virtual Machine.')
    return vm


def get_tag(vsphere_client, args):
    relevant_category = None
    relevant_tag = None
    categories = vsphere_client.tagging.Category.list()
    for category in categories:
        cat_details = vsphere_client.tagging.Category.get(category)
        if cat_details.name == args.get('category'):
            relevant_category = cat_details.id
            break
    if not relevant_category:
        raise Exception("The category {} was not found".format(args.get('category')))
    tags = vsphere_client.tagging.Tag.list_tags_for_category(relevant_category)
    for tag in tags:
        tag_details = vsphere_client.tagging.Tag.get(tag)
        if tag_details.name == args.get('tag'):
            relevant_tag = tag_details.id
            break
    return relevant_tag


def search_for_obj(content, vim_type, name, folder=None, recurse=True):
    if folder is None:
        folder = content.rootFolder
    if not name:
        return None
    obj = None
    container = content.viewManager.CreateContainerView(folder, vim_type, recurse)

    for managed_object_ref in container.view:
        if managed_object_ref.name == name:
            obj = managed_object_ref
            break
    container.Destroy()
    if not obj:
        raise RuntimeError("Managed Object " + name + " not found.")
    return obj


def create_vm_config_creator(host, args):
    spec = vim.vm.ConfigSpec()  # type: ignore
    files = vim.vm.FileInfo()  # type: ignore
    files.vmPathName = "[" + host.datastore[0].name + "]" + args.get('name')
    resource_allocation_spec = vim.ResourceAllocationInfo()  # type: ignore
    resource_allocation_info = vim.ResourceAllocationInfo()  # type: ignore
    resource_allocation_spec.limit = arg_to_number(args.get('cpu-allocation'))
    resource_allocation_info.limit = arg_to_number(args.get('memory'))
    spec.name = args.get('name')
    spec.numCPUs = arg_to_number(args.get('cpu-num'))  # type: ignore[assignment]
    spec.cpuAllocation = resource_allocation_spec
    spec.memoryAllocation = resource_allocation_info
    spec.memoryMB = arg_to_number(args.get('virtual-memory'))
    spec.files = files
    if args.get('guest_id'):
        spec.guestId = args.get('guest_id')
    return spec


def create_rellocation_locator_spec(vm, datastore):
    template_disks = []
    disk_locators = []
    # collect template disks
    for device in vm.config.hardware.device:
        if type(device).__name__ == "vim.vm.device.VirtualDisk" and hasattr(device.backing, 'fileName'):
            template_disks.append(device)

    # construct locator for the disks
    for disk in template_disks:
        locator = vim.vm.RelocateSpec.DiskLocator()  # type: ignore
        locator.diskBackingInfo = disk.backing  # Backing information for the virtual disk at the destination
        locator.diskId = int(disk.key)
        locator.datastore = datastore  # Destination datastore
        disk_locators.append(locator)

    return disk_locators


def apply_get_vms_filters(args, vm_summery):
    ips = argToList(args.get('ip'))
    names = argToList(args.get('vm_name'))
    uuids = argToList(args.get('uuid'))

    ip = not args.get('ip') or (vm_summery.guest.ipAddress and vm_summery.guest.ipAddress in ips)
    hostname = not args.get('hostname') or (vm_summery.guest.hostName and vm_summery.guest.hostName == args.get(
        'hostname'))
    name = not args.get('vm_name') or vm_summery.config.name in names
    uuid = not args.get('uuid') or vm_summery.config.instanceUuid in uuids

    return ip and hostname and name and uuid


def get_priority(priority):
    if priority == 'highPriority':
        return vim.VirtualMachine.MovePriority().highPriority  # type: ignore[call-arg] # pylint: disable=no-value-for-parameter
    elif priority == 'lowPriority':
        return vim.VirtualMachine.MovePriority().lowPriority  # type: ignore[call-arg] # pylint: disable=no-value-for-parameter
    else:
        return vim.VirtualMachine.MovePriority().defaultPriority  # type: ignore # pylint: disable=no-value-for-parameter


def get_vms(si, args):
    data = []
    content = si.RetrieveContent()  # type: ignore
    container = content.rootFolder
    view_type = [vim.VirtualMachine]
    recursive = True
    container_view = content.viewManager.CreateContainerView(container, view_type, recursive)
    children = container_view.view
    limit, is_manual, page_size = get_limit(args)

    for child in children:
        summary = child.summary
        snapshot_create_date = datetime_to_string(
            child.snapshot.currentSnapshot.config.createDate) if child.snapshot else None
        snapshot_uuid = child.snapshot.currentSnapshot.config.uuid if child.snapshot else None
        if apply_get_vms_filters(args, summary):
            mac_address = ''
            try:
                for dev in child.config.hardware.device:
                    if isinstance(dev, vim.vm.device.VirtualEthernetCard):  # type: ignore
                        mac_address = dev.macAddress
                        break
            except Exception:  # noqa
                pass

            data.append({
                'Name': summary.config.name,
                'Template': summary.config.template,
                'Path': summary.config.vmPathName,
                'Guest': summary.config.guestFullName,
                'UUID': summary.config.instanceUuid,
                'IP': summary.guest.ipAddress if summary.guest.ipAddress else None,
                'State': summary.runtime.powerState,
                'HostName': summary.guest.hostName if summary.guest.hostName else None,
                'MACAddress': mac_address,
                'SnapshotCreateDate': snapshot_create_date,
                'SnapshotUUID': snapshot_uuid,
                'Deleted': False
            })
            if len(data) == limit:
                break

    # Return the correct amount of data
    if is_manual and page_size and len(data) > page_size:
        data = data[-1 * page_size:]

    ec = {
        'VMWare(val.UUID && val.UUID === obj.UUID)': data
    }
    return create_entry(data, ec)


def create_entry(data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': createContext(data, removeNull=True),
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Virtual Machines', data, headers=['Name', 'Template', 'Path', 'Guest', 'UUID',
                                                                            'IP', 'State', 'HostName', 'MACAddress',
                                                                            'SnapshotCreateDate',
                                                                            'SnapshotUUID',
                                                                            'Deleted'], removeNull=True) if data
        else 'No result were found',
        'EntryContext': ec
    }


def power_on(si, uuid):
    vm = get_vm(si, uuid)

    if vm.runtime.powerState == 'poweredOn':
        raise Exception('Virtual Machine is already powered on.')
    task = vm.PowerOn()
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:  # type: ignore
        time.sleep(1)
    if task.info.state == 'success':
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': {
                'UUID': uuid,
                'State': 'poweredOn'
            }
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': ec,
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Virtual Machine was powered on successfully.',
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise Exception('Error occurred while trying to power on Virtual Machine.')
    return None


def power_off(si, uuid):
    vm = get_vm(si, uuid)
    if vm.runtime.powerState == 'poweredOff':
        raise Exception('Virtual Machine is already powered off.')
    task = vm.PowerOff()
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:  # type: ignore
        time.sleep(1)
    if task.info.state == 'success':
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': {
                'UUID': uuid,
                'State': 'poweredOff'
            }
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': ec,
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Virtual Machine was powered off successfully.',
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise Exception('Error occured while trying to power off Virtual Machine.')
    return None


def suspend(si, uuid):
    vm = get_vm(si, uuid)
    if vm.runtime.powerState == 'suspended':
        raise Exception('Virtual Machine is already suspended.')
    task = vm.Suspend()
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:  # type: ignore
        time.sleep(1)
    if task.info.state == 'success':
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': {
                'UUID': uuid,
                'State': 'suspended'
            }
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': ec,
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Virtual Machine was suspended successfully.',
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise Exception('Error occured while trying to power on Virtual Machine.')
    return None


def hard_reboot(si, uuid):
    vm = get_vm(si, uuid)
    task = vm.ResetVM_Task()
    wait_for_tasks(si, [task])
    if task.info.state == 'success':
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': {
                'UUID': uuid,
                'State': 'HardRebooted'
            }
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': ec,
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Virtual Machine was rebooted successfully.',
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise Exception('Error occured while trying to reboot Virtual Machine.')
    return None


def wait_for_tasks(si, tasks):
    propertyCollector = si.content.propertyCollector
    taskList = [str(task) for task in tasks]
    objSpecs = [vmodl.query.PropertyCollector.ObjectSpec(obj=task) for task in tasks]  # type: ignore
    propertySpec = vmodl.query.PropertyCollector.PropertySpec(type=vim.Task, pathSet=[], all=True)  # type: ignore
    filterSpec = vmodl.query.PropertyCollector.FilterSpec()
    filterSpec.objectSet = objSpecs
    filterSpec.propSet = [propertySpec]
    pcfilter = propertyCollector.CreateFilter(filterSpec, True)
    try:
        version, state = None, None
        while len(taskList):
            update = propertyCollector.WaitForUpdates(version)
            for filter_set in update.filterSet:
                for obj_set in filter_set.objectSet:
                    task = obj_set.obj
                    for change in obj_set.changeSet:
                        if change.name == 'info':
                            state = change.val.state
                        elif change.name == 'info.state':
                            state = change.val
                        else:
                            continue
                        if str(task) not in taskList:
                            continue
                        if state == vim.TaskInfo.State.success:  # type: ignore
                            taskList.remove(str(task))
                        elif state == vim.TaskInfo.State.error:  # type: ignore
                            raise task.info.error
            version = update.version
    finally:
        if pcfilter:
            pcfilter.Destroy()


def soft_reboot(si, uuid):
    vm = get_vm(si, uuid)
    vm.RebootGuest()
    return 'A request to reboot the guest has been sent.'


def create_snapshot(si, args):
    uuid = args['vm-uuid']
    vm = get_vm(si, uuid)
    d = str(datetime.now())
    if args['memory'] == 'True':
        mem = True
    else:
        mem = False
    if args['quiesce'] == 'True':
        qui = True
    else:
        qui = False
    name = args.get('name', uuid + ' snapshot ' + d)
    desc = args.get('description', 'Snapshot of VM UUID ' + uuid + ' taken on ' + d)
    pyVim.task.WaitForTask(vm.CreateSnapshot(name=name, description=desc, memory=mem, quiesce=qui))
    return 'Snapshot ' + name + ' completed.'


def revert_snapshot(si, name, uuid):
    vm = get_vm(si, uuid)
    snapObj = get_snapshots(vm.snapshot.rootSnapshotList, name)
    if len(snapObj) == 1:
        snapObj = snapObj[0].snapshot
        pyVim.task.WaitForTask(snapObj.RevertToSnapshot_Task())
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': {
                'UUID': uuid,
                'Snapshot': 'Reverted to ' + name
            }
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': ec,
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Reverted to snapshot ' + name + ' successfully.',
            'EntryContext': ec
        }
    else:
        return 'No snapshots found with name: ' + name + ' on VM: ' + uuid


def get_snapshots(snapshots, snapname):
    snapObj = []
    for snapshot in snapshots:
        if snapshot.name == snapname:
            snapObj.append(snapshot)
        else:
            snapObj = snapObj + get_snapshots(snapshot.childSnapshotList, snapname)
    return snapObj


def get_events(si, args):
    vm = get_vm(si, args.get('vm-uuid'))
    hr = []
    content = si.RetrieveServiceContent()  # type: ignore
    eventManager = content.eventManager
    limit, is_manual, page_size = get_limit(args)

    time = vim.event.EventFilterSpec.ByTime()  # type: ignore
    time.beginTime = dateparser.parse(args.get('start_date', ''))  # type: ignore
    time.endTime = dateparser.parse(args.get('end_date', ''))  # type: ignore
    if (args.get('start_date') and not time.beginTime) or (args.get('end_date') and not time.endTime):  # type: ignore
        raise Exception("Dates given in a wrong format.")
    by_user_name = vim.event.EventFilterSpec.ByUsername()  # type: ignore
    by_user_name.userList = args.get('user', '').split(',') or None  # type: ignore[assignment]
    filter = vim.event.EventFilterSpec.ByEntity(entity=vm, recursion="self")  # type: ignore
    ids = args.get('event-type').split(',')

    filterSpec = vim.event.EventFilterSpec()
    filterSpec.eventTypeId = ids  # type: ignore
    filterSpec.entity = filter  # type: ignore
    filterSpec.time = time
    filterSpec.userName = by_user_name  # type: ignore
    filterSpec.maxCount = limit  # type: ignore

    eventRes = eventManager.QueryEvents(filterSpec)
    for e in eventRes:
        hr.append({
            'id': e.key,
            'Event': e.fullFormattedMessage,
            'CreatedTime': e.createdTime.strftime("%Y-%m-%d %H:%M:%S"),
            'UserName': e.userName,
        })
    # Return the correct amount of data
    if is_manual and page_size and len(hr) > page_size:
        hr = hr[-1 * page_size:]
    ec = {'VMWareEvenet(val.UUID && val.UUID === obj.UUID)': hr}
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': hr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('VM ' + vm.summary.config.name + ' Events',
                                         hr, removeNull=True) if hr else 'No result were found',
        'EntryContext': ec
    }


def change_nic_state(si, args):  # pragma: no cover
    uuid = args['vm-uuid']
    new_nic_state = args['nic-state']
    nic_number = args['nic-number']
    vm = get_vm(si, uuid)
    nic_prefix_header = "Network adapter "
    nic_label = nic_prefix_header + str(nic_number)
    virtual_nic_device = None
    for dev in vm.config.hardware.device:
        if isinstance(dev, vim.vm.device.VirtualEthernetCard) and dev.deviceInfo.label == nic_label:  # type: ignore
            virtual_nic_device = dev
    if not virtual_nic_device:
        raise Exception(f"Virtual {nic_label} could not be found.")

    virtual_nic_spec = vim.vm.device.VirtualDeviceSpec()  # type: ignore
    if new_nic_state == 'delete':
        virtual_nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove  # type: ignore
    else:
        virtual_nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit  # type: ignore
    virtual_nic_spec.device = virtual_nic_device
    virtual_nic_spec.device.key = virtual_nic_device.key
    virtual_nic_spec.device.macAddress = virtual_nic_device.macAddress
    virtual_nic_spec.device.backing = virtual_nic_device.backing
    virtual_nic_spec.device.wakeOnLanEnabled = virtual_nic_device.wakeOnLanEnabled
    connectable = vim.vm.device.VirtualDevice.ConnectInfo()  # type: ignore
    if new_nic_state == 'connect':
        connectable.connected = True
        connectable.startConnected = True
    elif new_nic_state == 'disconnect':
        connectable.connected = False
        connectable.startConnected = False
    else:
        connectable = virtual_nic_device.connectable
    virtual_nic_spec.device.connectable = connectable
    dev_changes = []
    dev_changes.append(virtual_nic_spec)
    spec = vim.vm.ConfigSpec()  # type: ignore
    spec.deviceChange = dev_changes
    task = vm.ReconfigVM_Task(spec=spec)
    wait_for_tasks(si, [task])

    res_new_nic_state = (new_nic_state + "ed").replace("eed", "ed")

    if task.info.state == 'success':
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': {
                'UUID': uuid,
                'NICState': res_new_nic_state
            }
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': ec,
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': f'Virtual Machine\'s NIC was {res_new_nic_state} successfully.',
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise Exception('Error occurred while trying to clone VM.')
    return None


def list_vms_by_tag(vsphere_client, args):
    relevant_tag = get_tag(vsphere_client, args)
    # Added this condition to avoid 'vsphere_client.tagging.TagAssociation.list_attached_objects' errors
    if not relevant_tag:
        raise Exception("The tag {} was not found".format(args.get('tag')))
    vms = vsphere_client.tagging.TagAssociation.list_attached_objects(relevant_tag)
    vms = [vm for vm in vms if vm.type == 'VirtualMachine']
    vms_details = []
    # This filter isn't needed if vms are empty, when you send an empty vms list - it returns all vms
    if vms:
        vms_details = vsphere_client.vcenter.VM.list(
            vsphere_client.vcenter.VM.FilterSpec(vms={str(vm.id) for vm in vms}))
    data = []
    for vm in vms_details:
        data.append({
            'TagName': args.get('tag'),
            'Category': args.get('category'),
            'VM': vm.name
        })
    data = createContext(data, removeNull=True)
    ec = {
        'VMWareTag(val.TagName && val.Category && val.TagName == obj.TagName && va.Category == obj.Category)': data
    }
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Virtual Machines with Tag {}'.format(args.get('tag')), data, removeNull=True),
        'EntryContext': ec
    }


def create_vm(si, args):
    content = si.RetrieveContent()
    folder = search_for_obj(content, [vim.Folder], args.get('folder'))
    host = search_for_obj(content, [vim.HostSystem], args.get('host'))
    if not host:
        raise Exception('The host provided is not valid.')
    pool = host.parent.resourcePool
    spec = create_vm_config_creator(host, args)

    task = folder.CreateVM_Task(config=spec, pool=pool, host=host)
    wait_for_tasks(si, [task])

    if task.info.state == 'success':
        mac_address = ''
        summary = task.info.result.summary

        try:
            for dev in task.info.result.config.hardware.device:
                if isinstance(dev, vim.vm.device.VirtualEthernetCard):  # type: ignore
                    mac_address = dev.macAddress
                    break
        except Exception:  # noqa
            pass

        data = {
            'Name': summary.config.name,
            'Template': summary.config.template,
            'Path': summary.config.vmPathName,
            'Guest': summary.config.guestFullName,
            'UUID': summary.config.instanceUuid,
            'IP': summary.guest.ipAddress if summary.guest.ipAddress else None,
            'State': summary.runtime.powerState,
            'HostName': summary.guest.hostName if summary.guest.hostName else None,
            'MACAddress': mac_address,
            'Snapshot': task.info.result.snapshot.currentSnapshot if task.info.result.snapshot else None,
            'SnapshotCreateDate': '',
            'SnapshotUUID': '',
            'Deleted': False
        }
        data = createContext(data, removeNull=True)
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': data
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': data,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Virtual Machine', data,
                                             headers=['Name', 'Template', 'Path', 'Guest', 'UUID',
                                                      'IP', 'State', 'HostName', 'MACAddress', 'SnapshotCreateDate',
                                                      'SnapshotUUID', 'Deleted'], removeNull=True),
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise Exception('Error occurred while trying to create a VM.')
    return None


def clone_vm(si, args):
    vm = get_vm(si, args.get('uuid'))
    content = si.RetrieveContent()
    spec = vim.vm.CloneSpec()  # type: ignore
    relocate_spec = vim.vm.RelocateSpec()  # type: ignore
    relocate_spec.datastore = search_for_obj(content, [vim.Datastore], args.get('datastore'))
    relocate_spec.host = search_for_obj(content, [vim.HostSystem], args.get('host'))
    relocate_spec.pool = search_for_obj(content, [vim.ResourcePool], args.get('pool'))  # type: ignore
    spec.location = relocate_spec
    spec.template = argToBoolean(args.get('template', False))
    spec.powerOn = argToBoolean(args.get('powerOn'))

    folder = search_for_obj(content, [vim.Folder], args.get('folder'))
    task = vm.CloneVM_Task(folder=folder, name=args.get('name'), spec=spec)
    wait_for_tasks(si, [task])

    if task.info.state == 'success':
        mac_address = ''
        summary = task.info.result.summary
        try:
            for dev in task.info.result.config.hardware.device:
                if isinstance(dev, vim.vm.device.VirtualEthernetCard):  # type: ignore
                    mac_address = dev.macAddress
                    break
        except Exception:  # noqa
            pass

        data = {
            'Name': summary.config.name,
            'Template': summary.config.template,
            'Path': summary.config.vmPathName,
            'Guest': summary.config.guestFullName,
            'UUID': summary.config.instanceUuid,
            'IP': summary.guest.ipAddress if summary.guest.ipAddress else None,
            'State': summary.runtime.powerState,
            'HostName': summary.guest.hostName if summary.guest.hostName else None,
            'MACAddress': mac_address,
            'SnapshotCreateDate': '',
            'SnapshotUUID': '',
            'Deleted': False
        }
        data = createContext(data, removeNull=True)
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': data
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': data,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Virtual Machine', data,
                                             headers=['Name', 'Template', 'Path', 'Guest', 'UUID',
                                                      'IP', 'State', 'HostName', 'MACAddress', 'SnapshotCreateDate',
                                                      'SnapshotUUID', 'Deleted'], removeNull=True),
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise Exception('Error occurred while trying to clone VM.')
    return None


def relocate_vm(si, args):
    content = si.RetrieveContent()
    vm = get_vm(si, args.get('uuid'))

    priority = get_priority(args.get('priority'))
    spec = vim.VirtualMachineRelocateSpec()  # type: ignore
    spec.folder = search_for_obj(content, [vim.Folder], args.get('folder'))
    spec.host = search_for_obj(content, [vim.HostSystem], args.get('host'))
    spec.pool = search_for_obj(content, [vim.ResourcePool], args.get('pool'))  # type: ignore
    datastore = search_for_obj(content, [vim.Datastore], args.get('datastore'))

    if datastore:
        spec.datastore = datastore
        spec.disks = create_rellocation_locator_spec(vm, datastore)
    task = vm.RelocateVM_Task(spec, priority)
    wait_for_tasks(si, [task])

    if task.info.state == 'success':
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': {},
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Virtual Machine was relocated successfully.',
            'EntryContext': {}
        }
    elif task.info.state == 'error':
        raise Exception('Error occurred while trying to relocate VM.')
    return None


def delete_vm(si, args):
    vm = get_vm(si, args.get('uuid'))
    if vm.runtime.powerState == 'poweredOn':
        raise Exception("Virtual Machine should be powered off before deleting.")
    task = vm.Destroy_Task()
    wait_for_tasks(si, [task])
    if task.info.state == 'success':
        data = {
            'UUID': args.get('uuid'),
            'Deleted': True
        }
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': data
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': {},
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Virtual Machine was deleted successfully.',
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise Exception('Error occurred while trying to delete VM.')
    return None


def register_vm(si, args):
    content = si.RetrieveContent()
    folder = search_for_obj(content, [vim.Folder], args.get('folder'))
    host = search_for_obj(content, [vim.HostSystem], args.get('host'))
    pool = host.parent.resourcePool

    task = folder.RegisterVM_Task(path=args.get('path'), name=args.get('name'),
                                  asTemplate=argToBoolean(args.get('as_template')), pool=pool, host=host)
    wait_for_tasks(si, [task])
    if task.info.state == 'success':
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': {},
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Virtual Machine was registered successfully.',
            'EntryContext': {}
        }
    elif task.info.state == 'error':
        raise Exception('Error occurred while trying to register VM.')
    return None


def unregister_vm(si, args):
    vm = get_vm(si, args.get('uuid'))
    vm.UnregisterVM()
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': {},
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Virtual Machine was unregistered successfully.',
        'EntryContext': {}
    }


def test_module(si):
    get_vms(si, {'limit': '1'})
    return 'ok'


def vsphare_client_login(params):
    full_url, url, port, user_name, password = parse_params(params)

    session = requests.session()
    session.verify = not params.get('insecure', False)
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Connect to Vsphere automation sdk using username and password
    return create_vsphere_client(server=full_url, username=user_name, password=password, session=session)


def main():  # pragma: no cover
    if REDIRECT_STD_OUT:
        sys.stdout = StringIO()
    res = []
    si = None
    result: Any
    try:
        si = login(demisto.params())
        if demisto.command() == 'test-module':
            result = test_module(si)
        if demisto.command() == 'vmware-get-vms':
            result = get_vms(si, demisto.args())
        if demisto.command() == 'vmware-poweron':
            result = power_on(si, demisto.args()['vm-uuid'])
        if demisto.command() == 'vmware-poweroff':
            result = power_off(si, demisto.args()['vm-uuid'])
        if demisto.command() == 'vmware-hard-reboot':
            result = hard_reboot(si, demisto.args()['vm-uuid'])
        if demisto.command() == 'vmware-suspend':
            result = suspend(si, demisto.args()['vm-uuid'])
        if demisto.command() == 'vmware-soft-reboot':
            result = soft_reboot(si, demisto.args()['vm-uuid'])
        if demisto.command() == 'vmware-create-snapshot':
            result = create_snapshot(si, demisto.args())
        if demisto.command() == 'vmware-revert-snapshot':
            result = revert_snapshot(si, demisto.args()['snapshot-name'], demisto.args()['vm-uuid'])
        if demisto.command() == 'vmware-get-events':
            result = get_events(si, demisto.args())
        if demisto.command() == 'vmware-change-nic-state':
            result = change_nic_state(si, demisto.args())
        if demisto.command() == 'vmware-list-vms-by-tag':
            vsphere_client = vsphare_client_login(demisto.params())
            result = list_vms_by_tag(vsphere_client, demisto.args())
        if demisto.command() == 'vmware-create-vm':
            result = create_vm(si, demisto.args())
        if demisto.command() == 'vmware-clone-vm':
            result = clone_vm(si, demisto.args())
        if demisto.command() == 'vmware-relocate-vm':
            result = relocate_vm(si, demisto.args())
        if demisto.command() == 'vmware-delete-vm':
            result = delete_vm(si, demisto.args())
        if demisto.command() == 'vmware-register-vm':
            result = register_vm(si, demisto.args())
        if demisto.command() == 'vmware-unregister-vm':
            result = unregister_vm(si, demisto.args())
        res.append(result)
    except Exception as ex:
        if hasattr(ex, 'msg') and ex.msg:  # type: ignore
            message = ex.msg  # type: ignore
        else:
            message = ex
        res.append(
            {"Type": entryTypes["error"], "ContentsFormat": formats["text"],
             "Contents": str(message)})  # type: ignore

    try:
        logout(si)
    except Exception as ex:
        res.append({  # type: ignore
            "Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": "Logout failed. " + str(ex)})

    sys.stdout = sys.__stdout__
    demisto.results(res)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
