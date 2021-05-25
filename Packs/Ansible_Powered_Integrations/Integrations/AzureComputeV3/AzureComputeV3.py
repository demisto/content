import traceback
import ssh_agent_setup
import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# Import Generated code
from AnsibleApiModule import *  # noqa: E402

host_type = 'local'

# MAIN FUNCTION


def main() -> None:
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # SSH Key integration requires ssh_agent to be running in the background
    ssh_agent_setup.setup()

    try:

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            return_results('ok')
        elif demisto.command() == 'azure-rm-autoscale':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_autoscale', demisto.args()))
        elif demisto.command() == 'azure-rm-autoscale-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_autoscale_info', demisto.args()))
        elif demisto.command() == 'azure-rm-availabilityset':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_availabilityset', demisto.args()))
        elif demisto.command() == 'azure-rm-availabilityset-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_availabilityset_info', demisto.args()))
        elif demisto.command() == 'azure-rm-deployment':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_deployment', demisto.args()))
        elif demisto.command() == 'azure-rm-deployment-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_deployment_info', demisto.args()))
        elif demisto.command() == 'azure-rm-functionapp':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_functionapp', demisto.args()))
        elif demisto.command() == 'azure-rm-functionapp-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_functionapp_info', demisto.args()))
        elif demisto.command() == 'azure-rm-gallery':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_gallery', demisto.args()))
        elif demisto.command() == 'azure-rm-gallery-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_gallery_info', demisto.args()))
        elif demisto.command() == 'azure-rm-galleryimage':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_galleryimage', demisto.args()))
        elif demisto.command() == 'azure-rm-galleryimage-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_galleryimage_info', demisto.args()))
        elif demisto.command() == 'azure-rm-galleryimageversion':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_galleryimageversion', demisto.args()))
        elif demisto.command() == 'azure-rm-galleryimageversion-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_galleryimageversion_info', demisto.args()))
        elif demisto.command() == 'azure-rm-image':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_image', demisto.args()))
        elif demisto.command() == 'azure-rm-image-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_image_info', demisto.args()))
        elif demisto.command() == 'azure-rm-loadbalancer':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_loadbalancer', demisto.args()))
        elif demisto.command() == 'azure-rm-loadbalancer-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_loadbalancer_info', demisto.args()))
        elif demisto.command() == 'azure-rm-manageddisk':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_manageddisk', demisto.args()))
        elif demisto.command() == 'azure-rm-manageddisk-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_manageddisk_info', demisto.args()))
        elif demisto.command() == 'azure-rm-resource':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_resource', demisto.args()))
        elif demisto.command() == 'azure-rm-resource-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_resource_info', demisto.args()))
        elif demisto.command() == 'azure-rm-resourcegroup':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_resourcegroup', demisto.args()))
        elif demisto.command() == 'azure-rm-resourcegroup-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_resourcegroup_info', demisto.args()))
        elif demisto.command() == 'azure-rm-snapshot':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_snapshot', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachine':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachine', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachine-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachine_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachineextension':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachineextension', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachineextension-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachineextension_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachineimage-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachineimage_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescaleset':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescaleset', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescaleset-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescaleset_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescalesetextension':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescalesetextension', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescalesetextension-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescalesetextension_info', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescalesetinstance':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescalesetinstance', demisto.args()))
        elif demisto.command() == 'azure-rm-virtualmachinescalesetinstance-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_virtualmachinescalesetinstance_info', demisto.args()))
        elif demisto.command() == 'azure-rm-webapp':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_webapp', demisto.args()))
        elif demisto.command() == 'azure-rm-webapp-info':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_webapp_info', demisto.args()))
        elif demisto.command() == 'azure-rm-webappslot':
            return_results(generic_ansible('azurecomputev3', 'azure_rm_webappslot', demisto.args()))
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


# ENTRY POINT


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
