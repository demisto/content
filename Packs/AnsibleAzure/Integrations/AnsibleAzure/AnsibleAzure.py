import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import ssh_agent_setup

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = "local"

# MAIN FUNCTION


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # SSH Key integration requires ssh_agent to be running in the background
    ssh_agent_setup.setup()

    # Common Inputs
    command = demisto.command()
    args = demisto.args()
    int_params = demisto.params()
    creds_mapping = {"identifier": "client_id", "password": "secret"}

    try:
        if command == "test-module":
            # This is the call made when pressing the integration Test button.
            result = generic_ansible("Azure", "azure_rm_resource_info", args, int_params, host_type, creds_mapping)

            if result:
                return_results("ok")
            else:
                return_results(result)

        elif command == "azure-rm-autoscale":
            return_results(generic_ansible("Azure", "azure_rm_autoscale", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-autoscale-info":
            return_results(generic_ansible("Azure", "azure_rm_autoscale_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-availabilityset":
            return_results(generic_ansible("Azure", "azure_rm_availabilityset", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-availabilityset-info":
            return_results(generic_ansible("Azure", "azure_rm_availabilityset_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-deployment":
            return_results(generic_ansible("Azure", "azure_rm_deployment", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-deployment-info":
            return_results(generic_ansible("Azure", "azure_rm_deployment_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-functionapp":
            return_results(generic_ansible("Azure", "azure_rm_functionapp", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-functionapp-info":
            return_results(generic_ansible("Azure", "azure_rm_functionapp_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-gallery":
            return_results(generic_ansible("Azure", "azure_rm_gallery", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-gallery-info":
            return_results(generic_ansible("Azure", "azure_rm_gallery_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-galleryimage":
            return_results(generic_ansible("Azure", "azure_rm_galleryimage", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-galleryimage-info":
            return_results(generic_ansible("Azure", "azure_rm_galleryimage_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-galleryimageversion":
            return_results(generic_ansible("Azure", "azure_rm_galleryimageversion", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-galleryimageversion-info":
            return_results(
                generic_ansible("Azure", "azure_rm_galleryimageversion_info", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-image":
            return_results(generic_ansible("Azure", "azure_rm_image", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-image-info":
            return_results(generic_ansible("Azure", "azure_rm_image_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-loadbalancer":
            return_results(generic_ansible("Azure", "azure_rm_loadbalancer", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-loadbalancer-info":
            return_results(generic_ansible("Azure", "azure_rm_loadbalancer_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-manageddisk":
            return_results(generic_ansible("Azure", "azure_rm_manageddisk", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-manageddisk-info":
            return_results(generic_ansible("Azure", "azure_rm_manageddisk_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-resource-info":
            return_results(generic_ansible("Azure", "azure_rm_resource_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-resourcegroup":
            return_results(generic_ansible("Azure", "azure_rm_resourcegroup", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-resourcegroup-info":
            return_results(generic_ansible("Azure", "azure_rm_resourcegroup_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-snapshot":
            return_results(generic_ansible("Azure", "azure_rm_snapshot", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-virtualmachine":
            return_results(generic_ansible("Azure", "azure_rm_virtualmachine", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-virtualmachine-info":
            return_results(generic_ansible("Azure", "azure_rm_virtualmachine_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-virtualmachineextension":
            return_results(
                generic_ansible("Azure", "azure_rm_virtualmachineextension", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-virtualmachineextension-info":
            return_results(
                generic_ansible("Azure", "azure_rm_virtualmachineextension_info", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-virtualmachineimage-info":
            return_results(
                generic_ansible("Azure", "azure_rm_virtualmachineimage_info", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-virtualmachinescaleset":
            return_results(
                generic_ansible("Azure", "azure_rm_virtualmachinescaleset", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-virtualmachinescaleset-info":
            return_results(
                generic_ansible("Azure", "azure_rm_virtualmachinescaleset_info", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-virtualmachinescalesetextension":
            return_results(
                generic_ansible("Azure", "azure_rm_virtualmachinescalesetextension", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-virtualmachinescalesetextension-info":
            return_results(
                generic_ansible(
                    "Azure", "azure_rm_virtualmachinescalesetextension_info", args, int_params, host_type, creds_mapping
                )
            )
        elif command == "azure-rm-virtualmachinescalesetinstance":
            return_results(
                generic_ansible("Azure", "azure_rm_virtualmachinescalesetinstance", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-virtualmachinescalesetinstance-info":
            return_results(
                generic_ansible(
                    "Azure", "azure_rm_virtualmachinescalesetinstance_info", args, int_params, host_type, creds_mapping
                )
            )
        elif command == "azure-rm-webapp":
            return_results(generic_ansible("Azure", "azure_rm_webapp", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-webapp-info":
            return_results(generic_ansible("Azure", "azure_rm_webapp_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-webappslot":
            return_results(generic_ansible("Azure", "azure_rm_webappslot", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-azurefirewall":
            return_results(generic_ansible("Azure", "azure_rm_azurefirewall", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-azurefirewall-info":
            return_results(generic_ansible("Azure", "azure_rm_azurefirewall_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-virtualnetwork":
            return_results(generic_ansible("Azure", "azure_rm_virtualnetwork", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-virtualnetwork-info":
            return_results(generic_ansible("Azure", "azure_rm_virtualnetwork_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-virtualnetworkgateway":
            return_results(generic_ansible("Azure", "azure_rm_virtualnetworkgateway", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-virtualnetworkpeering":
            return_results(generic_ansible("Azure", "azure_rm_virtualnetworkpeering", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-virtualnetworkpeering-info":
            return_results(
                generic_ansible("Azure", "azure_rm_virtualnetworkpeering_info", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-subnet":
            return_results(generic_ansible("Azure", "azure_rm_subnet", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-subnet-info":
            return_results(generic_ansible("Azure", "azure_rm_subnet_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-trafficmanagerendpoint":
            return_results(
                generic_ansible("Azure", "azure_rm_trafficmanagerendpoint", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-trafficmanagerendpoint-info":
            return_results(
                generic_ansible("Azure", "azure_rm_trafficmanagerendpoint_info", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-trafficmanagerprofile":
            return_results(generic_ansible("Azure", "azure_rm_trafficmanagerprofile", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-trafficmanagerprofile-info":
            return_results(
                generic_ansible("Azure", "azure_rm_trafficmanagerprofile_info", args, int_params, host_type, creds_mapping)
            )
        elif command == "azure-rm-networkinterface":
            return_results(generic_ansible("Azure", "azure_rm_networkinterface", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-networkinterface-info":
            return_results(generic_ansible("Azure", "azure_rm_networkinterface_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-publicipaddress":
            return_results(generic_ansible("Azure", "azure_rm_publicipaddress", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-publicipaddress-info":
            return_results(generic_ansible("Azure", "azure_rm_publicipaddress_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-route":
            return_results(generic_ansible("Azure", "azure_rm_route", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-routetable":
            return_results(generic_ansible("Azure", "azure_rm_routetable", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-routetable-info":
            return_results(generic_ansible("Azure", "azure_rm_routetable_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-securitygroup":
            return_results(generic_ansible("Azure", "azure_rm_securitygroup", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-securitygroup-info":
            return_results(generic_ansible("Azure", "azure_rm_securitygroup_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-dnsrecordset":
            return_results(generic_ansible("Azure", "azure_rm_dnsrecordset", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-dnsrecordset-info":
            return_results(generic_ansible("Azure", "azure_rm_dnsrecordset_info", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-dnszone":
            return_results(generic_ansible("Azure", "azure_rm_dnszone", args, int_params, host_type, creds_mapping))
        elif command == "azure-rm-dnszone-info":
            return_results(generic_ansible("Azure", "azure_rm_dnszone_info", args, int_params, host_type, creds_mapping))
    # Log exceptions and return errors
    except Exception as e:
        return_error(f"Failed to execute {command} command.\nError:\n{str(e)}")


# ENTRY POINT


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
