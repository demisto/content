# pylint: disable=no-member
# pylint: disable=no-name-in-module

import enum
import ssl
from cStringIO import StringIO
import urllib3
from pyvim.connect import Disconnect, SmartConnect
from pyvim.task import WaitForTask
from pyVmomi import vim, vmodl
from vmware.vapi.vsphere.client import create_vsphere_client
from com.vmware.vapi.std_client import DynamicID

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

FULL_URL_ARR = demisto.params()['url'].split(':')
FULL_URL = demisto.params()['url']
URL = FULL_URL_ARR[0]
USERNAME = demisto.params()['credentials']['identifier']
PASSWORD = demisto.params()['credentials']['password']
PORT = str(FULL_URL_ARR[1])


def login():
    s = ssl.SSLContext(ssl.PROTOCOL_TLS)
    s.verify_mode = ssl.CERT_NONE
    session = requests.session()
    session.verify = False
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Connect to a vCenter Server using username and password
    vsphere_client = create_vsphere_client(server=FULL_URL, username=USERNAME, password=PASSWORD, session=session)

    try:
        si = SmartConnect(host=URL,
                          user=USERNAME,
                          pwd=PASSWORD,
                          port=PORT)
    except Exception:
        si = SmartConnect(host=URL,
                          user=USERNAME,
                          pwd=PASSWORD,
                          port=PORT,
                          sslContext=s)
    return si, vsphere_client


def logout(si):
    Disconnect(si)


def get_vm(uuid):
    vm = si.content.searchIndex.FindByUuid(None, uuid, True, True)  # type: ignore
    if vm is None:
        raise SystemExit('Unable to locate Virtual Machine.')
    return vm


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
    spec = vim.vm.ConfigSpec()
    files = vim.vm.FileInfo()
    files.vmPathName = "["+host.datastore[0].name+"]" + args.get('name')
    resource_allocation_spec = vim.ResourceAllocationInfo()
    resource_allocation_info = vim.ResourceAllocationInfo()
    resource_allocation_spec.limit = arg_to_number(args.get('cpu-allocation'))
    resource_allocation_info.limit = arg_to_number(args.get('memory'))
    spec.name = args.get('name')
    spec.numCPUs = arg_to_number(args.get('cpu-num'))
    spec.cpuAllocation = resource_allocation_spec
    spec.memoryAllocation = resource_allocation_info
    spec.memoryMB = arg_to_number(args.get('virtual-memory'))
    # spec.guestId = args.get('guestId')
    spec.files=files
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
        locator = vim.vm.RelocateSpec.DiskLocator()
        locator.diskBackingInfo = disk.backing  # Backing information for the virtual disk at the destination
        locator.diskId = int(disk.key)
        locator.datastore = datastore # Destination datastore
        disk_locators.append(locator)

    return disk_locators


def apply_get_vms_filters(args, vm_summery):
    ips = argToList(args.get('ip'))
    names = argToList(args.get('name'))
    uuids = argToList(args.get('uuid'))

    ip = not vm_summery.guest.ipAddress or not args.get('ip') or vm_summery.guest.ipAddress in ips
    hostname = not vm_summery.guest.hostName or not args.get('hostname') or vm_summery.guest.ipAddress == args.get('hostName')
    name = not args.get('name') or vm_summery.config.name in names
    uuid = not args.get('uuid') or vm_summery.config.instanceUuid in uuids

    return ip and hostname and name and uuid


def get_vms(args):
    data = []
    content = si.RetrieveContent()  # type: ignore
    container = content.rootFolder
    view_type = [vim.VirtualMachine]
    recursive = True
    container_view = content.viewManager.CreateContainerView(container, view_type, recursive)
    children = container_view.view
    
    for child in children:
        summary = child.summary
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
                'IP': summary.guest.ipAddress if summary.guest.ipAddress else ' ',
                'State': summary.runtime.powerState,
                'HostName': summary.guest.hostName if summary.guest.hostName else ' ',
                'MACAddress': mac_address,
                'Deleted': 'False'
            })
    ec = {
        'VMWare(val.UUID && val.UUID === obj.UUID)': data
    }
    return create_entry(data, ec)


def create_entry(data, ec):
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': data,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('Virtual Machines', data) if data else 'No result were found',
        'EntryContext': ec
    }


def power_on(uuid):
    vm = get_vm(uuid)

    if vm.runtime.powerState == 'poweredOn':
        raise SystemExit('Virtual Machine is already powered on.')
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
        raise SystemExit('Error occured while trying to power on Virtual Machine.')


def power_off(uuid):
    vm = get_vm(uuid)
    if vm.runtime.powerState == 'poweredOff':
        raise SystemExit('Virtual Machine is already powered off.')
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
        raise SystemExit('Error occured while trying to power off Virtual Machine.')


def suspend(uuid):
    vm = get_vm(uuid)
    if vm.runtime.powerState == 'suspended':
        raise SystemExit('Virtual Machine is already suspended.')
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
        raise SystemExit('Error occured while trying to power on Virtual Machine.')


def hard_reboot(uuid):
    vm = get_vm(uuid)
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
        raise SystemExit('Error occured while trying to reboot Virtual Machine.')


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
                        if not str(task) in taskList:
                            continue
                        if state == vim.TaskInfo.State.success:  # type: ignore
                            taskList.remove(str(task))
                        elif state == vim.TaskInfo.State.error:  # type: ignore
                            raise task.info.error
            version = update.version
    finally:
        if pcfilter:
            pcfilter.Destroy()


def soft_reboot(uuid):
    vm = get_vm(uuid)
    vm.RebootGuest()
    return 'A request to reboot the guest has been sent.'


def create_snapshot(args):
    uuid = args['vm-uuid']
    vm = get_vm(uuid)
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
    WaitForTask(vm.CreateSnapshot(name=name, description=desc, memory=mem, quiesce=qui))
    return 'Snapshot ' + name + ' completed.'


def revert_snapshot(name, uuid):
    vm = get_vm(uuid)
    snapObj = get_snapshots(vm.snapshot.rootSnapshotList, name)
    if len(snapObj) == 1:
        snapObj = snapObj[0].snapshot
        WaitForTask(snapObj.RevertToSnapshot_Task())
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


def get_events(uuid, event_type):
    vm = get_vm(uuid)
    hr = []
    content = si.RetrieveServiceContent()  # type: ignore
    eventManager = content.eventManager
    filter = vim.event.EventFilterSpec.ByEntity(entity=vm, recursion="self")  # type: ignore
    filterSpec = vim.event.EventFilterSpec()
    ids = event_type.split(',')
    filterSpec.eventTypeId = ids  # type: ignore
    filterSpec.entity = filter  # type: ignore
    eventRes = eventManager.QueryEvents(filterSpec)
    for e in eventRes:
        hr.append({
            'Event': e.fullFormattedMessage,
            'Created Time': e.createdTime.strftime("%Y-%m-%d %H:%M:%S")
        })
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': hr,
        'ReadableContentsFormat': formats['markdown'],
        'HumanReadable': tableToMarkdown('VM ' + vm.summary.config.name + ' Events',
                                         hr) if hr else 'No result were found'
    }


def change_nic_state(args):
    uuid = args['vm-uuid']
    new_nic_state = args['nic-state']
    nic_number = args['nic-number']
    vm = get_vm(uuid)
    nic_prefix_header = "Network adapter "
    nic_label = nic_prefix_header + str(nic_number)
    virtual_nic_device = None
    for dev in vm.config.hardware.device:
        if isinstance(dev, vim.vm.device.VirtualEthernetCard) and dev.deviceInfo.label == nic_label:  # type: ignore
            virtual_nic_device = dev
    if not virtual_nic_device:
        raise SystemExit("Virtual {} could not be found.".format(nic_label))

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
            'HumanReadable': 'Virtual Machine\'s NIC was {} successfully.'.format(res_new_nic_state),
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise SystemExit('Error occurred while trying to clone VM.')


def list_vm_tags(uuid, parent_category_name):
    dynamic_id = DynamicID(type='VirtualMachine', id=uuid)
    tags = vsphere_client.tagging.TagAssociation.list_attached_tags(dynamic_id)


def create_vm(args):
    content = si.RetrieveContent()
    folder = search_for_obj(content, [vim.Folder], args.get('folder'))
    host = search_for_obj(content, [vim.HostSystem], args.get('host'))
    pool = search_for_obj(content, [vim.ResourcePool], args.get('pool'))
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
            'IP': summary.guest.ipAddress if summary.guest.ipAddress else ' ',
            'State': summary.runtime.powerState,
            'HostName': summary.guest.hostName if summary.guest.hostName else ' ',
            'MACAddress': mac_address,
        }
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': data
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': data,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Virtual Machine', data),
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise SystemExit('Error occurred while trying to create a VM.')


def clone_vm(args):
    vm = get_vm(args.get('uuid'))
    content = si.RetrieveContent()
    spec = vim.vm.CloneSpec()
    relocate_spec = vim.vm.RelocateSpec()
    relocate_spec.datastore = search_for_obj(content, [vim.Datastore], args.get('datastore'))
    relocate_spec.host = search_for_obj(content, [vim.HostSystem], args.get('host'))
    relocate_spec.pool = search_for_obj(content, [vim.ResourcePool], args.get('pool'))
    spec.location = relocate_spec
    spec.template = args.get('template', False)
    spec.powerOn = args.get('powerOn', False)

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
            'IP': summary.guest.ipAddress if summary.guest.ipAddress else ' ',
            'State': summary.runtime.powerState,
            'HostName': summary.guest.hostName if summary.guest.hostName else ' ',
            'MACAddress': mac_address,
        }
        ec = {
            'VMWare(val.UUID && val.UUID === obj.UUID)': data
        }
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': data,
            'ReadableContentsFormat': formats['markdown'],
            'HumanReadable': tableToMarkdown('Virtual Machine', data),
            'EntryContext': ec
        }
    elif task.info.state == 'error':
        raise SystemExit('Error occurred while trying to clone VM.')


def relocate_vm(args):
    vm = get_vm(args.get('args'))
    content = si.RetrieveContent()
    priority = vim.VirtualMachine.MovePriority()
    service = vim.ServiceLocator()
    service.sslThumbprint = args.get('service')
    spec = vim.vm.RelocateSpec()
    spec.folder = search_for_obj(content, [vim.Folder], args.get('folder'))
    spec.host = search_for_obj(content, [vim.HostSystem], args.get('host'))
    spec.pool = search_for_obj(content, [vim.ResourcePool], args.get('pool'))
    spec.service = service
    datastore =  search_for_obj(content, [vim.Datastore], args.get('datastore'))
    if datastore:
        spec.datastore = datastore
        spec.disks = create_rellocation_locator_spec(vm, datastore)

    # spec.profile = args.get('profile')  todo

    task = vm.RelocateVM_Task(spec, priority.args.get('priority'))
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
        raise SystemExit('Error occurred while trying to relocate VM.')


def delete_vm(args):
    vm = get_vm(args.get('uuid'))
    task = vm.Destroy_Task()
    wait_for_tasks(si, [task])
    if task.info.state == 'success':
        return {
            'ContentsFormat': formats['json'],
            'Type': entryTypes['note'],
            'Contents': {},
            'ReadableContentsFormat': formats['text'],
            'HumanReadable': 'Virtual Machine was deleted successfully.',
            'EntryContext': {}
        }
    elif task.info.state == 'error':
        raise SystemExit('Error occurred while trying to delete VM.')


def register_vm(args):
    content = si.RetrieveContent()
    folder = search_for_obj(content, [vim.Folder], args.get('folder'))
    host = search_for_obj(content, [vim.HostSystem], args.get('host'))
    pool = search_for_obj(content, [vim.ResourcePool], args.get('pool'))

    task = folder.RegisterVM_Task(path=args.get('path'), name=args.get('name'),
                                  asTemplate=args.get('asTemplaet', False), pool=pool, host=host)
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
        raise SystemExit('Error occurred while trying to register VM.')


def unregister_vm(args):
    vm = get_vm(args.get('uuisd'))
    vm.UnregisterVM()
    return {
        'ContentsFormat': formats['json'],
        'Type': entryTypes['note'],
        'Contents': {},
        'ReadableContentsFormat': formats['text'],
        'HumanReadable': 'Virtual Machine was unregistered successfully.',
        'EntryContext': {}
    }


sout = sys.stdout
sys.stdout = StringIO()
res = []
si = None
vsphere_client = None
try:

    si, vsphere_client = login()

    if demisto.command() == 'test-module':
        result = 'ok'
    if demisto.command() == 'vmware-get-vms':
        result = get_vms(demisto.args())
    if demisto.command() == 'vmware-poweron':
        result = power_on(demisto.args()['vm-uuid'])
    if demisto.command() == 'vmware-poweroff':
        result = power_off(demisto.args()['vm-uuid'])
    if demisto.command() == 'vmware-hard-reboot':
        result = hard_reboot(demisto.args()['vm-uuid'])
    if demisto.command() == 'vmware-suspend':
        result = suspend(demisto.args()['vm-uuid'])
    if demisto.command() == 'vmware-soft-reboot':
        result = soft_reboot(demisto.args()['vm-uuid'])
    if demisto.command() == 'vmware-create-snapshot':
        result = create_snapshot(demisto.args())
    if demisto.command() == 'vmware-revert-snapshot':
        result = revert_snapshot(demisto.args()['snapshot-name'], demisto.args()['vm-uuid'])
    if demisto.command() == 'vmware-get-events':
        result = get_events(demisto.args()['uuid'], demisto.args()['event-type'])
    if demisto.command() == 'vmware-change-nic-state':
        result = change_nic_state(demisto.args())
    if demisto.command() == 'vmware-list-vm-tags':
        result = list_vm_tags(demisto.args()['uuid'], demisto.args()['parent-category-name'])
    if demisto.command() == 'vmware-add-tag':
        result = list_vm_tags(demisto.args()['vm-uuid'], demisto.args()['parent-category-name'])
    if demisto.command() == 'vmware-create-vm':
        result = create_vm(demisto.args())
    if demisto.command() == 'vmware-clone-vm':
        result = clone_vm(demisto.args())
    if demisto.command() == 'vmware-relocate-vm':
        # result = relocate_vm(demisto.args())
        pass
    if demisto.command() == 'vmware-delete-vm':
        result = delete_vm(demisto.args())
    if demisto.command() == 'vmware-register-vm':
        result = register_vm(demisto.args())
    if demisto.command() == 'vmware-unregister-vm':
        result = unregister_vm(demisto.args())
    res.append(result)
except Exception as ex:
    res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": str(ex)})  # type: ignore

try:
    logout(si)
except Exception as ex:
    res.append({  # type: ignore
        "Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": "Logout failed. " + str(ex)})

sys.stdout = sout
demisto.results(res)
sys.exit(0)
