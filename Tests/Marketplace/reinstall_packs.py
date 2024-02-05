import argparse
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import demisto_client
from Tests.Marketplace.configure_and_install_packs import search_and_install_packs_and_their_dependencies
from Tests.Marketplace.search_and_uninstall_pack import uninstall_pack
from Tests.configure_and_test_integration_instances import CloudBuild, get_custom_user_agent
from Tests.scripts.utils import logging_wrapper as logging
from Tests.scripts.utils.log_util import install_logging


def options_handler() -> argparse.Namespace:
    """
    Returns: options parsed from input arguments.
    """
    parser = argparse.ArgumentParser(description='Utility for testing re-installation XSIAM packs.')
    parser.add_argument('--cloud_machine', help='cloud machine to use, if it is cloud build.')
    parser.add_argument('--cloud_servers_path', help='Path to secret cloud server metadata file.')
    parser.add_argument('--cloud_servers_api_keys', help='Path to the file with cloud Servers api keys.')
    parser.add_argument('--non-removable-packs', help='List of packs that cant be removed.')
    parser.add_argument('--build-number', help='CI job number where the instances were created', required=True)
    parser.add_argument('--packs_to_reinstall', help='List of packs to check its re-installation.', required=True)

    options = parser.parse_args()

    return options


def reinstall_packs(options: argparse.Namespace, cloud_machine: str) -> bool:
    """
    Packs re-installation test. Uninstall and then install packs from options.packs_to_reinstall list.

    Args:
        options: Script arguments.
        cloud_machine (str): Cloud machine name to test on.

    Returns:
        Boolean - If the operation succeeded.
    """
    success = True
    api_key, _, base_url, xdr_auth_id = CloudBuild.get_cloud_configuration(cloud_machine,
                                                                           options.cloud_servers_path,
                                                                           options.cloud_servers_api_keys)

    client = demisto_client.configure(base_url=base_url,
                                      verify_ssl=False,
                                      api_key=api_key,
                                      auth_id=xdr_auth_id)

    client.api_client.user_agent = get_custom_user_agent(options.build_number)
    host = client.api_client.configuration.host.replace('https://api-', 'https://')  # disable-secrets-detection

    logging.debug(f'Setting user agent on client to: {client.api_client.user_agent}')

    non_removable_packs = options.non_removable_packs.split(',')
    packs_to_reinstall_path = Path(options.packs_to_reinstall)
    packs_to_reinstall = packs_to_reinstall_path.read_text().split('\n')

    for pack in packs_to_reinstall:
        if pack in non_removable_packs:
            continue
        successful_uninstall, _ = uninstall_pack(client, pack)
        _, successful_install = search_and_install_packs_and_their_dependencies(
            pack_ids=[pack],
            client=client,
            hostname=host,
            install_packs_in_batches=True,
            production_bucket=False
        )
        success &= successful_uninstall & successful_install

    return success


def main():
    install_logging('reinstall_packs_check.log', logger=logging)

    # In Cloud, We don't use demisto username
    os.environ.pop('DEMISTO_USERNAME', None)

    options = options_handler()
    logging.info(f'Starting reinstall test for CLOUD servers:{options.cloud_machine}.')
    cloud_machines: list[str] = list(filter(None, options.cloud_machine.split(',')))
    success = True
    with ThreadPoolExecutor(max_workers=len(cloud_machines), thread_name_prefix='clean-machine') as executor:
        futures = [
            executor.submit(reinstall_packs, options, cloud_machine)
            for cloud_machine in cloud_machines
        ]
        for future in as_completed(futures):
            try:
                success &= future.result()
            except Exception as ex:
                logging.exception(f'Failed to run reinstall packs test. Additional info: {str(ex)}')
                success = False

    if not success:
        logging.error('Failed to reinstall packs.')
        sys.exit(2)
    logging.info('Finished reinstall packs test successfully.')


if __name__ == '__main__':
    main()
