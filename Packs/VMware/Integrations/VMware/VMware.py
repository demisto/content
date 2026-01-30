# pylint: disable=no-member
# pylint: disable=no-name-in-module
import ssl
from io import StringIO

import dateparser  # type: ignore
import demistomock as demisto  # noqa: F401
import pyVim.task
from CommonServerPython import *  # noqa: F401
from pyVim.connect import Disconnect, SmartConnect
from pyVmomi import vim, vmodl  # type: ignore

REDIRECT_STD_OUT = argToBoolean(demisto.params().get("redirect_std_out", "false"))
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
    full_url = params["url"]
    url_arr = full_url.rsplit(":", 1)
    url = url_arr[0]
    port = str(url_arr[1])
    user_name = params.get("credentials").get("identifier")
    password = params.get("credentials").get("password")
    return full_url, url, port, user_name, password


class Client(BaseClient):
    def __init__(self, full_url: str, user_name: str, password: str, verify: bool = False, proxy: bool = False):
        self.user_name = user_name
        self.password = password
        super().__init__(base_url=f"https://{full_url}", verify=verify, proxy=proxy)
        demisto.debug("Getting session ID using username and password.")
        self.session_id = self._get_session_id()
        self._headers = {"vmware-api-session-id": self.session_id, "Content-Type": "application/json"}
        demisto.debug(f"Created new client instance using {full_url=}, {verify=}, {proxy=}.")

    def _get_session_id(self) -> str:
        """Authenticates and returns a session ID."""
        # https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/session/post/
        auth = (self.user_name, self.password)
        session_id_response = self._http_request(method="POST", url_suffix="/api/session", auth=auth, resp_type="text")
        demisto.debug(f"Got {session_id_response=}.")
        session_id = session_id_response.replace('"', "")
        if not session_id:
            raise DemistoException("Failed to obtain session ID. Check credentials and VCENTER_HOST.")
        return session_id

    def logout(self):
        """Closes the session and returns HTTP 204 with empty response object."""
        # https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/session/delete/
        self._http_request(method="DELETE", url_suffix="/api/session", resp_type="response")

    def get_category_id(self, category_name: str) -> str:
        """Get the ID of the category by its name."""
        # https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/cis/tagging/category/get/
        category_list_response = self._http_request(method="GET", url_suffix="/api/cis/tagging/category")
        # The response is a list of category IDs, not objects with names. We must iterate and get details for each.
        demisto.debug(f"Got {category_list_response=}.")
        for category_id in category_list_response:
            # https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/cis/tagging/category/categoryId/get/
            category_details_response = self._http_request(method="GET", url_suffix=f"/api/cis/tagging/category/{category_id}")
            demisto.debug(f"For {category_id=}, got {category_details_response=}.")
            if category_details_response.get("name") == category_name:
                return category_id
        raise DemistoException(f"Category '{category_name}' not found.")

    def get_tag_id(self, tag_name: str, category_id: str) -> str:
        """Get the ID of the tag by its name, filtered by category ID."""
        # https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/cis/tagging/tag__action=list-tags-for-category/post/
        tag_list_response = self._http_request(
            method="POST",
            url_suffix="/api/cis/tagging/tag?action=list-tags-for-category",
            json_data={"category_id": category_id},
        )
        # The response is a list of tag IDs, not objects with names. We must iterate and get details for each.
        demisto.debug(f"Got {tag_list_response=}.")
        for tag_id in tag_list_response:
            # https://developer.broadcom.com/xapis/vsphere-automation-api/latest/api/cis/tagging/tag/tagId/get/
            tag_details_response = self._http_request(method="GET", url_suffix=f"/api/cis/tagging/tag/{tag_id}")
            demisto.debug(f"For {tag_id=}, got {tag_details_response=}.")
            if tag_details_response.get("name") == tag_name:
                return tag_id
        raise DemistoException(f"Tag '{tag_name}' not found in the specified category.")

    def list_associated_objects(self, tag_id: str) -> list:
        """Get all objects associated with the Tag ID."""
        # https://developer.broadcom.com/xapis/vsphere-automation-api/9.0/api/cis/tagging/tag-association/tagId__action=list-attached-objects/post/
        tag_associated_objects_response = self._http_request(
            method="POST",
            url_suffix=f"/api/cis/tagging/tag-association/{tag_id}?action=list-attached-objects",
        )
        demisto.debug(f"Got {tag_associated_objects_response=}.")
        return tag_associated_objects_response

    def list_vms(self, vm_ids: list) -> list:
        """List VMs filtered by VM IDs."""
        # https://developer.broadcom.com/xapis/vsphere-automation-api/v7.0u3/vcenter/api/vcenter/vm/get/index
        filtered_vms_response = self._http_request(method="GET", url_suffix="/api/vcenter/vm", params={"vms": vm_ids})
        demisto.debug(f"Got {filtered_vms_response=}.")
        return filtered_vms_response


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
                raise Exception("Chosen page number must be greater than 0")
            limit = page_size * page
            return limit, True, page_size
        else:
            limit = 50
    return limit, False, page_size


def login(url: str, port: int, user_name: str, password: str):  # pragma: no cover
    # Preparations for SDKs connections
    s = ssl.SSLContext(ssl.PROTOCOL_TLS)
    s.verify_mode = ssl.CERT_NONE

    # Connect to a vCenter Server using username and password
    try:
        si = SmartConnect(host=url, user=user_name, pwd=password, port=port)
    except Exception:
        si = SmartConnect(host=url, user=user_name, pwd=password, port=port, sslContext=s)

    return si


def logout(si):  # pragma: no cover
    Disconnect(si)


def get_vm(si, uuid):
    vm = si.content.searchIndex.FindByUuid(None, uuid, True, True)  # type: ignore
    if vm is None:
        raise Exception("Unable to locate Virtual Machine.")
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
    spec = vim.vm.ConfigSpec()  # type: ignore
    files = vim.vm.FileInfo()  # type: ignore
    files.vmPathName = "[" + host.datastore[0].name + "]" + args.get("name")
    resource_allocation_spec = vim.ResourceAllocationInfo()  # type: ignore
    resource_allocation_info = vim.ResourceAllocationInfo()  # type: ignore
    resource_allocation_spec.limit = arg_to_number(args.get("cpu-allocation"))
    resource_allocation_info.limit = arg_to_number(args.get("memory"))
    spec.name = args.get("name")
    spec.numCPUs = arg_to_number(args.get("cpu-num"))  # type: ignore[assignment]
    spec.cpuAllocation = resource_allocation_spec
    spec.memoryAllocation = resource_allocation_info
    spec.memoryMB = arg_to_number(args.get("virtual-memory"))
    spec.files = files
    if args.get("guest_id"):
        spec.guestId = args.get("guest_id")
    return spec


def create_rellocation_locator_spec(vm, datastore):
    template_disks = []
    disk_locators = []
    # collect template disks
    for device in vm.config.hardware.device:
        if type(device).__name__ == "vim.vm.device.VirtualDisk" and hasattr(device.backing, "fileName"):
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
    ips = argToList(args.get("ip"))
    names = argToList(args.get("vm_name"))
    uuids = argToList(args.get("uuid"))

    ip = not args.get("ip") or (vm_summery.guest.ipAddress and vm_summery.guest.ipAddress in ips)
    hostname = not args.get("hostname") or (vm_summery.guest.hostName and vm_summery.guest.hostName == args.get("hostname"))
    name = not args.get("vm_name") or vm_summery.config.name in names
    uuid = not args.get("uuid") or vm_summery.config.instanceUuid in uuids

    return ip and hostname and name and uuid


def get_priority(priority):
    if priority == "highPriority":
        return vim.VirtualMachine.MovePriority().highPriority  # type: ignore[call-arg] # pylint: disable=no-value-for-parameter
    elif priority == "lowPriority":
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
        snapshot_create_date = datetime_to_string(child.snapshot.currentSnapshot.config.createDate) if child.snapshot else None
        snapshot_uuid = child.snapshot.currentSnapshot.config.uuid if child.snapshot else None
        if apply_get_vms_filters(args, summary):
            mac_address: str | None = ""
            try:
                for dev in child.config.hardware.device:
                    if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                        mac_address = dev.macAddress
                        break
            except Exception:  # noqa
                pass

            data.append(
                {
                    "Name": summary.config.name,
                    "Template": summary.config.template,
                    "Path": summary.config.vmPathName,
                    "Guest": summary.config.guestFullName,
                    "UUID": summary.config.instanceUuid,
                    "IP": summary.guest.ipAddress if summary.guest.ipAddress else None,
                    "State": summary.runtime.powerState,
                    "HostName": summary.guest.hostName if summary.guest.hostName else None,
                    "MACAddress": mac_address,
                    "SnapshotCreateDate": snapshot_create_date,
                    "SnapshotUUID": snapshot_uuid,
                    "Deleted": False,
                }
            )
            if len(data) == limit:
                break

    # Return the correct amount of data
    if is_manual and page_size and len(data) > page_size:
        data = data[-1 * page_size :]

    ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": data}
    return create_entry(data, ec)


def create_entry(data, ec):
    return {
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": createContext(data, removeNull=True),
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown(
            "Virtual Machines",
            data,
            headers=[
                "Name",
                "Template",
                "Path",
                "Guest",
                "UUID",
                "IP",
                "State",
                "HostName",
                "MACAddress",
                "SnapshotCreateDate",
                "SnapshotUUID",
                "Deleted",
            ],
            removeNull=True,
        )
        if data
        else "No result were found",
        "EntryContext": ec,
    }


def power_on(si, uuid):
    vm = get_vm(si, uuid)

    if vm.runtime.powerState == "poweredOn":
        raise Exception("Virtual Machine is already powered on.")
    task = vm.PowerOn()
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:  # type: ignore
        time.sleep(1)
    if task.info.state == "success":
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": {"UUID": uuid, "State": "poweredOn"}}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": ec,
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": "Virtual Machine was powered on successfully.",
            "EntryContext": ec,
        }
    elif task.info.state == "error":
        raise Exception("Error occurred while trying to power on Virtual Machine.")
    return None


def power_off(si, uuid):
    vm = get_vm(si, uuid)
    if vm.runtime.powerState == "poweredOff":
        raise Exception("Virtual Machine is already powered off.")
    task = vm.PowerOff()
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:  # type: ignore
        time.sleep(1)
    if task.info.state == "success":
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": {"UUID": uuid, "State": "poweredOff"}}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": ec,
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": "Virtual Machine was powered off successfully.",
            "EntryContext": ec,
        }
    elif task.info.state == "error":
        raise Exception("Error occured while trying to power off Virtual Machine.")
    return None


def suspend(si, uuid):
    vm = get_vm(si, uuid)
    if vm.runtime.powerState == "suspended":
        raise Exception("Virtual Machine is already suspended.")
    task = vm.Suspend()
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:  # type: ignore
        time.sleep(1)
    if task.info.state == "success":
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": {"UUID": uuid, "State": "suspended"}}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": ec,
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": "Virtual Machine was suspended successfully.",
            "EntryContext": ec,
        }
    elif task.info.state == "error":
        raise Exception("Error occured while trying to power on Virtual Machine.")
    return None


def hard_reboot(si, uuid):
    vm = get_vm(si, uuid)
    task = vm.ResetVM_Task()
    wait_for_tasks(si, [task])
    if task.info.state == "success":
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": {"UUID": uuid, "State": "HardRebooted"}}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": ec,
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": "Virtual Machine was rebooted successfully.",
            "EntryContext": ec,
        }
    elif task.info.state == "error":
        raise Exception("Error occured while trying to reboot Virtual Machine.")
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
                        if change.name == "info":
                            state = change.val.state
                        elif change.name == "info.state":
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
    return "A request to reboot the guest has been sent."


def create_snapshot(si, args):
    uuid = args["vm-uuid"]
    vm = get_vm(si, uuid)
    d = str(datetime.now())
    if args["memory"] == "True":
        mem = True
    else:
        mem = False
    if args["quiesce"] == "True":
        qui = True
    else:
        qui = False
    name = args.get("name", uuid + " snapshot " + d)
    desc = args.get("description", "Snapshot of VM UUID " + uuid + " taken on " + d)
    pyVim.task.WaitForTask(vm.CreateSnapshot(name=name, description=desc, memory=mem, quiesce=qui))
    return "Snapshot " + name + " completed."


def revert_snapshot(si, name, uuid):
    vm = get_vm(si, uuid)
    snapObj = get_snapshots(vm.snapshot.rootSnapshotList, name)
    if len(snapObj) == 1:
        snapObj = snapObj[0].snapshot
        pyVim.task.WaitForTask(snapObj.RevertToSnapshot_Task())
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": {"UUID": uuid, "Snapshot": "Reverted to " + name}}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": ec,
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": "Reverted to snapshot " + name + " successfully.",
            "EntryContext": ec,
        }
    else:
        return "No snapshots found with name: " + name + " on VM: " + uuid


def get_snapshots(snapshots, snapname):
    snapObj = []
    for snapshot in snapshots:
        if snapshot.name == snapname:
            snapObj.append(snapshot)
        else:
            snapObj = snapObj + get_snapshots(snapshot.childSnapshotList, snapname)
    return snapObj


def get_events(si, args):
    vm = get_vm(si, args.get("vm-uuid"))
    hr = []
    content = si.RetrieveServiceContent()  # type: ignore
    eventManager = content.eventManager
    limit, is_manual, page_size = get_limit(args)

    time = vim.event.EventFilterSpec.ByTime()  # type: ignore
    time.beginTime = dateparser.parse(args.get("start_date", ""))  # type: ignore
    time.endTime = dateparser.parse(args.get("end_date", ""))  # type: ignore
    if (args.get("start_date") and not time.beginTime) or (args.get("end_date") and not time.endTime):  # type: ignore
        raise Exception("Dates given in a wrong format.")
    by_user_name = vim.event.EventFilterSpec.ByUsername()  # type: ignore
    by_user_name.userList = args.get("user", "").split(",") if args.get("user") else None  # type: ignore[assignment]
    filter = vim.event.EventFilterSpec.ByEntity(entity=vm, recursion="self")  # type: ignore
    ids = args.get("event-type").split(",")

    filterSpec = vim.event.EventFilterSpec()
    filterSpec.eventTypeId = ids  # type: ignore
    filterSpec.entity = filter  # type: ignore
    filterSpec.time = time
    filterSpec.userName = by_user_name  # type: ignore
    filterSpec.maxCount = limit  # type: ignore

    eventRes = eventManager.QueryEvents(filterSpec)
    for e in eventRes:
        hr.append(
            {
                "id": e.key,
                "Event": e.fullFormattedMessage,
                "CreatedTime": e.createdTime.strftime("%Y-%m-%d %H:%M:%S"),
                "UserName": e.userName,
            }
        )
    # Return the correct amount of data
    if is_manual and page_size and len(hr) > page_size:
        hr = hr[-1 * page_size :]
    ec = {"VMWareEvenet(val.UUID && val.UUID === obj.UUID)": hr}
    return {
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": hr,
        "ReadableContentsFormat": formats["markdown"],
        "HumanReadable": tableToMarkdown("VM " + vm.summary.config.name + " Events", hr, removeNull=True)
        if hr
        else "No result were found",
        "EntryContext": ec,
    }


def change_nic_state(si, args):  # pragma: no cover
    uuid = args["vm-uuid"]
    new_nic_state = args["nic-state"]
    nic_number = args["nic-number"]
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
    if new_nic_state == "delete":
        virtual_nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove  # type: ignore
    else:
        virtual_nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.edit  # type: ignore
    virtual_nic_spec.device = virtual_nic_device
    virtual_nic_spec.device.key = virtual_nic_device.key
    virtual_nic_spec.device.macAddress = virtual_nic_device.macAddress
    virtual_nic_spec.device.backing = virtual_nic_device.backing
    virtual_nic_spec.device.wakeOnLanEnabled = virtual_nic_device.wakeOnLanEnabled
    connectable = vim.vm.device.VirtualDevice.ConnectInfo()  # type: ignore
    if new_nic_state == "connect":
        connectable.connected = True
        connectable.startConnected = True
    elif new_nic_state == "disconnect":
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

    if task.info.state == "success":
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": {"UUID": uuid, "NICState": res_new_nic_state}}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": ec,
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": f"Virtual Machine's NIC was {res_new_nic_state} successfully.",
            "EntryContext": ec,
        }
    elif task.info.state == "error":
        raise Exception("Error occurred while trying to clone VM.")
    return None


def list_vms_by_tag(client: Client, args: dict) -> CommandResults:
    """Lists VMs by tag using the REST API Client."""
    category_name = args["category"]
    tag_name = args["tag"]

    # STEP 1 - Get category ID by category name
    category_id = client.get_category_id(category_name)
    demisto.debug(f"Got {category_id=} using {category_name=}.")

    # STEP 2 - Get tag ID by tag name and category ID
    tag_id = client.get_tag_id(tag_name, category_id)
    demisto.debug(f"Got {tag_id=} using {tag_name=} and {category_id=}.")

    # STEP 3 - Get objects associated with tag ID
    associated_objects = client.list_associated_objects(tag_id)
    demisto.debug(f"Got {len(associated_objects)} objects associated with {tag_id=}.")

    # STEP 4 - Filter VMs for list of associated objects
    vm_ids = [vm.get("id") for vm in associated_objects if vm.get("type") == "VirtualMachine"]
    demisto.debug(f"Got {len(vm_ids)} VM IDs associated with {tag_id=}.")

    # STEP 5 - Get VM names by VM IDs
    associated_vms = client.list_vms(vm_ids) if vm_ids else []
    demisto.debug(f"Got {len(associated_vms)} VMs associated with {tag_id=}.")

    context_output = [{"VM": vm.get("name"), "TagName": tag_name, "Category": category_name} for vm in associated_vms]

    return CommandResults(
        readable_output=tableToMarkdown(f"VMs with category: {category_name!r} and tag: {tag_name!r}", associated_vms),
        outputs=context_output,
        outputs_prefix="VMwareTag",
        outputs_key_field=["VM", "TagName", "Category"],
    )


def create_vm(si, args):
    content = si.RetrieveContent()
    folder = search_for_obj(content, [vim.Folder], args.get("folder"))
    host = search_for_obj(content, [vim.HostSystem], args.get("host"))
    if not host:
        raise Exception("The host provided is not valid.")
    pool = host.parent.resourcePool
    spec = create_vm_config_creator(host, args)

    task = folder.CreateVM_Task(config=spec, pool=pool, host=host)
    wait_for_tasks(si, [task])

    if task.info.state == "success":
        mac_address: str | None = ""
        summary = task.info.result.summary

        try:
            for dev in task.info.result.config.hardware.device:
                if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                    mac_address = dev.macAddress
                    break
        except Exception:  # noqa
            pass

        data = {
            "Name": summary.config.name,
            "Template": summary.config.template,
            "Path": summary.config.vmPathName,
            "Guest": summary.config.guestFullName,
            "UUID": summary.config.instanceUuid,
            "IP": summary.guest.ipAddress if summary.guest.ipAddress else None,
            "State": summary.runtime.powerState,
            "HostName": summary.guest.hostName if summary.guest.hostName else None,
            "MACAddress": mac_address,
            "Snapshot": task.info.result.snapshot.currentSnapshot if task.info.result.snapshot else None,
            "SnapshotCreateDate": "",
            "SnapshotUUID": "",
            "Deleted": False,
        }
        data = createContext(data, removeNull=True)
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": data}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": data,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "Virtual Machine",
                data,
                headers=[
                    "Name",
                    "Template",
                    "Path",
                    "Guest",
                    "UUID",
                    "IP",
                    "State",
                    "HostName",
                    "MACAddress",
                    "SnapshotCreateDate",
                    "SnapshotUUID",
                    "Deleted",
                ],
                removeNull=True,
            ),
            "EntryContext": ec,
        }
    elif task.info.state == "error":
        raise Exception("Error occurred while trying to create a VM.")
    return None


def clone_vm(si, args):
    vm = get_vm(si, args.get("uuid"))
    content = si.RetrieveContent()
    spec = vim.vm.CloneSpec()  # type: ignore
    relocate_spec = vim.vm.RelocateSpec()  # type: ignore
    relocate_spec.datastore = search_for_obj(content, [vim.Datastore], args.get("datastore"))
    relocate_spec.host = search_for_obj(content, [vim.HostSystem], args.get("host"))
    relocate_spec.pool = search_for_obj(content, [vim.ResourcePool], args.get("pool"))  # type: ignore
    spec.location = relocate_spec
    spec.template = argToBoolean(args.get("template", False))
    spec.powerOn = argToBoolean(args.get("powerOn"))

    folder = search_for_obj(content, [vim.Folder], args.get("folder"))
    task = vm.CloneVM_Task(folder=folder, name=args.get("name"), spec=spec)
    wait_for_tasks(si, [task])

    if task.info.state == "success":
        mac_address: str | None = ""
        summary = task.info.result.summary
        try:
            for dev in task.info.result.config.hardware.device:
                if isinstance(dev, vim.vm.device.VirtualEthernetCard):
                    mac_address = dev.macAddress
                    break
        except Exception:  # noqa
            pass

        data = {
            "Name": summary.config.name,
            "Template": summary.config.template,
            "Path": summary.config.vmPathName,
            "Guest": summary.config.guestFullName,
            "UUID": summary.config.instanceUuid,
            "IP": summary.guest.ipAddress if summary.guest.ipAddress else None,
            "State": summary.runtime.powerState,
            "HostName": summary.guest.hostName if summary.guest.hostName else None,
            "MACAddress": mac_address,
            "SnapshotCreateDate": "",
            "SnapshotUUID": "",
            "Deleted": False,
        }
        data = createContext(data, removeNull=True)
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": data}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": data,
            "ReadableContentsFormat": formats["markdown"],
            "HumanReadable": tableToMarkdown(
                "Virtual Machine",
                data,
                headers=[
                    "Name",
                    "Template",
                    "Path",
                    "Guest",
                    "UUID",
                    "IP",
                    "State",
                    "HostName",
                    "MACAddress",
                    "SnapshotCreateDate",
                    "SnapshotUUID",
                    "Deleted",
                ],
                removeNull=True,
            ),
            "EntryContext": ec,
        }
    elif task.info.state == "error":
        raise Exception("Error occurred while trying to clone VM.")
    return None


def relocate_vm(si, args):
    content = si.RetrieveContent()
    vm = get_vm(si, args.get("uuid"))

    priority = get_priority(args.get("priority"))
    spec = vim.VirtualMachineRelocateSpec()  # type: ignore
    spec.folder = search_for_obj(content, [vim.Folder], args.get("folder"))
    spec.host = search_for_obj(content, [vim.HostSystem], args.get("host"))
    spec.pool = search_for_obj(content, [vim.ResourcePool], args.get("pool"))  # type: ignore
    datastore = search_for_obj(content, [vim.Datastore], args.get("datastore"))

    if datastore:
        spec.datastore = datastore
        spec.disks = create_rellocation_locator_spec(vm, datastore)
    task = vm.RelocateVM_Task(spec, priority)
    wait_for_tasks(si, [task])

    if task.info.state == "success":
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": {},
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": "Virtual Machine was relocated successfully.",
            "EntryContext": {},
        }
    elif task.info.state == "error":
        raise Exception("Error occurred while trying to relocate VM.")
    return None


def delete_vm(si, args):
    vm = get_vm(si, args.get("uuid"))
    if vm.runtime.powerState == "poweredOn":
        raise Exception("Virtual Machine should be powered off before deleting.")
    task = vm.Destroy_Task()
    wait_for_tasks(si, [task])
    if task.info.state == "success":
        data = {"UUID": args.get("uuid"), "Deleted": True}
        ec = {"VMWare(val.UUID && val.UUID === obj.UUID)": data}
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": {},
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": "Virtual Machine was deleted successfully.",
            "EntryContext": ec,
        }
    elif task.info.state == "error":
        raise Exception("Error occurred while trying to delete VM.")
    return None


def register_vm(si, args):
    content = si.RetrieveContent()
    folder = search_for_obj(content, [vim.Folder], args.get("folder"))
    host = search_for_obj(content, [vim.HostSystem], args.get("host"))
    pool = host.parent.resourcePool

    task = folder.RegisterVM_Task(
        path=args.get("path"), name=args.get("name"), asTemplate=argToBoolean(args.get("as_template")), pool=pool, host=host
    )
    wait_for_tasks(si, [task])
    if task.info.state == "success":
        return {
            "ContentsFormat": formats["json"],
            "Type": entryTypes["note"],
            "Contents": {},
            "ReadableContentsFormat": formats["text"],
            "HumanReadable": "Virtual Machine was registered successfully.",
            "EntryContext": {},
        }
    elif task.info.state == "error":
        raise Exception("Error occurred while trying to register VM.")
    return None


def unregister_vm(si, args):
    vm = get_vm(si, args.get("uuid"))
    vm.UnregisterVM()
    return {
        "ContentsFormat": formats["json"],
        "Type": entryTypes["note"],
        "Contents": {},
        "ReadableContentsFormat": formats["text"],
        "HumanReadable": "Virtual Machine was unregistered successfully.",
        "EntryContext": {},
    }


def test_module(si):
    get_vms(si, {"limit": "1"})
    return "ok"


def main():  # pragma: no cover
    params = demisto.params()
    command = demisto.command()
    args = demisto.args()

    full_url, url, port, user_name, password = parse_params(params)
    verify = not params.get("insecure", False)
    proxy = params.get("proxy", False)

    if REDIRECT_STD_OUT:
        sys.stdout = StringIO()
    res = []
    si = None
    client = None
    result: Any = None
    try:
        si = login(url, port, user_name, password)
        if command == "test-module":
            result = test_module(si)
        if command == "vmware-get-vms":
            result = get_vms(si, args)
        if command == "vmware-poweron":
            result = power_on(si, args["vm-uuid"])
        if command == "vmware-poweroff":
            result = power_off(si, args["vm-uuid"])
        if command == "vmware-hard-reboot":
            result = hard_reboot(si, args["vm-uuid"])
        if command == "vmware-suspend":
            result = suspend(si, args["vm-uuid"])
        if command == "vmware-soft-reboot":
            result = soft_reboot(si, args["vm-uuid"])
        if command == "vmware-create-snapshot":
            result = create_snapshot(si, args)
        if command == "vmware-revert-snapshot":
            result = revert_snapshot(si, args["snapshot-name"], args["vm-uuid"])
        if command == "vmware-get-events":
            result = get_events(si, args)
        if command == "vmware-change-nic-state":
            result = change_nic_state(si, args)
        if command == "vmware-list-vms-by-tag":
            client = Client(full_url, user_name, password, verify=verify, proxy=proxy)
            return_results(list_vms_by_tag(client, args))
        if command == "vmware-create-vm":
            result = create_vm(si, args)
        if command == "vmware-clone-vm":
            result = clone_vm(si, args)
        if command == "vmware-relocate-vm":
            result = relocate_vm(si, args)
        if command == "vmware-delete-vm":
            result = delete_vm(si, args)
        if command == "vmware-register-vm":
            result = register_vm(si, args)
        if command == "vmware-unregister-vm":
            result = unregister_vm(si, args)
        if result is not None:
            res.append(result)
    except Exception as ex:
        if hasattr(ex, "msg") and ex.msg:  # type: ignore
            message = ex.msg  # type: ignore
        else:
            message = ex
        res.append({"Type": entryTypes["error"], "ContentsFormat": formats["text"], "Contents": str(message)})  # type: ignore

    try:
        logout(si)
        if client:
            client.logout()
    except Exception as ex:
        res.append(
            {  # type: ignore
                "Type": entryTypes["error"],
                "ContentsFormat": formats["text"],
                "Contents": "Logout failed. " + str(ex),
            }
        )

    sys.stdout = sys.__stdout__
    demisto.results(res)


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
