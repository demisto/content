import demistomock as demisto
from CommonServerPython import *

from packaging.version import parse, Version

SCRIPT_NAME = 'ContentPackInstaller'


class ContentPackInstaller:
    """A class that handles all marketplace packs' installation process.
    """
    PACK_ID_VERSION_FORMAT = '{}::{}'

    def __init__(self, instance_name: str = None):
        self.installed_packs: Dict[str, Version] = {}
        self.newly_installed_packs: Dict[str, Version] = {}
        self.already_on_machine_packs: Dict[str, Version] = {}
        self.packs_data: Dict[str, Dict[str, str]] = {}
        self.packs_dependencies: Dict[str, Dict[str, Dict[str, str]]] = {}
        self.packs_failed: Dict[str, str] = {}
        self.instance_name: Optional[str] = instance_name

        self.get_installed_packs()

    def _call_execute_command(self, command, args):
        if self.instance_name:
            args['using'] = self.instance_name

        status, res = execute_command(
            command,
            args,
            fail_on_error=False,
        )

        if not status:
            error_message = f'{SCRIPT_NAME} - {res}'
            demisto.debug(error_message)
        if type(res) is list:
            res = res[0]
        return status, res

    def get_installed_packs(self) -> None:
        """Gets the current installed packs on the machine.
        """
        demisto.debug(f'{SCRIPT_NAME} - Fetching installed packs from marketplace.')

        args = {'uri': '/contentpacks/metadata/installed'}

        status, res = self._call_execute_command('core-api-get', args)
        if not status:
            return

        packs_data: List[Dict[str, str]] = res.get('response', [])
        for pack in packs_data:
            self.installed_packs[pack['id']] = parse(pack['currentVersion'])
            self.already_on_machine_packs[pack['id']] = parse(pack['currentVersion'])

    def get_pack_data_from_marketplace(self, pack_id: str) -> Dict[str, str]:
        """Returns the marketplace's data for a specific pack.

        Args:
            pack_id (str): The pack ID for which to get the data.

        Returns:
            Dict[str, str]. The pack's data from marketplace.
        """
        if pack_id in self.packs_data:
            demisto.debug(f'{SCRIPT_NAME} - Using cached data of {pack_id} that already been fetched.')
            return self.packs_data[pack_id]

        demisto.debug(f'{SCRIPT_NAME} - Fetching {pack_id} data from marketplace.')

        args = {'uri': f'/contentpacks/marketplace/{pack_id}'}

        _, res = self._call_execute_command('core-api-get', args)

        self.packs_data[pack_id] = res

        return res

    def get_pack_dependencies_from_marketplace(self, pack_data: Dict[str, str]) -> Dict[str, Dict[str, str]]:
        """Returns the dependencies of the pack from marketplace's data.

        Args:
            pack_data (Dict[str, str]): Packs' data for installation.

        Returns:
            Dict[str, Dict]. The pack's dependencies data from marketplace.
        """
        pack_key = self.PACK_ID_VERSION_FORMAT.format(pack_data['id'], pack_data['version'])

        if pack_key in self.packs_dependencies:
            demisto.debug(f'{SCRIPT_NAME} - Using cached dependencies data of {pack_key} that already been fetched.')
            return self.packs_dependencies[pack_key]

        demisto.debug(f'{SCRIPT_NAME} - Fetching {pack_key} dependencies data from marketplace.')

        args = {'uri': '/contentpacks/marketplace/search/dependencies',
                'body': [pack_data]
                }

        _, res = self._call_execute_command('core-api-post', args)

        try:
            self.packs_dependencies[pack_key] = res.get('response', {}).get('packs', [])[0] \
                .get('extras', {}).get('pack', {}).get('dependencies')
        except Exception as e:
            demisto.debug(f'{SCRIPT_NAME} - Unable to parse {pack_data["id"]} pack dependencies from response.\n{e}')
            return {}

        return self.packs_dependencies[pack_key]

    def get_latest_version_for_pack(self, pack_id: str) -> str:
        """Gets the latest version of the pack from the marketplace data.

        Args:
            pack_id (str): The pack name for which to get the data.

        Returns:
            str. The latest version of the pack.
        """
        try:
            res = self.get_pack_data_from_marketplace(pack_id)
            demisto.debug(f'raw pack_data_from_marketplace: {res}')
            return res.get('response', {}).get('currentVersion')  # type: ignore[call-overload, union-attr]
        except AttributeError as e:
            demisto.debug(f'error trying to get {pack_id=}. {e}')
            raise ValueError(f'Error while fetching {pack_id} from the marketplace. '
                             f'Make sure the Core REST API integration is properly configured and {pack_id} exists. '
                             f'Try running `!core-api-get uri=/contentpacks/marketplace/{pack_id}` in the playground. '
                             f'Raw Response:\n{res}')

    def get_packs_data_for_installation(self, packs_to_install: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """Creates a list of packs' data for the installation request.

        Args:
            packs_to_install (List[Dict[str, str]]): The packs to get data for.

        Returns:
            List[Dict[str, str]]. Updated list of data objects per pack, which hasn't been installed it.
        """
        latest_version_packs_to_install = []

        for pack in packs_to_install:
            latest_version = self.get_latest_version_for_pack(pack['id'])

            if parse(latest_version) > self.installed_packs.get(pack['id'], parse('1.0.0')):
                pack['version'] = latest_version
                latest_version_packs_to_install.append(pack)

        return latest_version_packs_to_install

    def install_packs(self, packs_to_install: List[Dict[str, str]]) -> None:
        """Sends the request to install the packs in the machine.

        Args:
            packs_to_install (List[Dict[str, str]]): The packs data to be used for the installation.

        """
        if not packs_to_install:
            demisto.debug(f'{SCRIPT_NAME} - No packs were sent for installation.')
            return

        # make the pack installation request
        packs_names_versions = {pack['id']: parse(pack['version']) for pack in packs_to_install}
        demisto.debug(f'{SCRIPT_NAME} - Sending installation request for: {packs_names_versions}')

        for pack in packs_to_install:
            pack_id = pack['id']
            pack_payload = json.dumps([{pack_id: pack['version']}])

            args = {'packs_to_install': str(pack_payload)}

            status, res = self._call_execute_command('core-api-install-packs', args)

            if not status:
                demisto.error(f'{SCRIPT_NAME} - Failed to install the pack {pack_id} - {str(res)}')
                self.packs_failed[pack_id] = str(pack['version'])
            else:
                self.installed_packs[pack_id] = packs_names_versions[pack_id]
                self.newly_installed_packs[pack_id] = packs_names_versions[pack_id]  # type: ignore

    def get_dependencies_for_pack(self, pack_data: Dict[str, str]) -> List[Dict[str, str]]:
        """Retrieves the packs' dependencies from the marketplace data.

        Args:
            pack_data (Dict[str, str]): Packs' data for installation.

        Returns:
            List[Dict[str, str]]. List of the packs' dependencies.
        """
        dependencies_to_install = []

        pack_dependencies = self.get_pack_dependencies_from_marketplace(pack_data)

        for dependency_id, dependency_data in pack_dependencies.items():
            if dependency_data.get('mandatory'):
                dependency_version = dependency_data.get('minVersion', '1.0.0')

                if parse(dependency_version) > self.installed_packs.get(dependency_id, parse('1.0.0')):
                    dependencies_to_install.append({
                        'id': dependency_id,
                        'version': dependency_version
                    })

        pack_key = self.PACK_ID_VERSION_FORMAT.format(pack_data['id'], pack_data['version'])
        demisto.debug(f'{SCRIPT_NAME} - Dependencies found for {pack_key}: {dependencies_to_install}')

        return dependencies_to_install

    def is_pack_already_installed(self, pack_data: Dict[str, str]) -> bool:
        """Returns whether the pack is already installed on the machine or not.

        Args:
            pack_data (Dict[str, str]): Packs' data for installation.

        Returns:
            bool. Whether the pack is already installed.
        """
        if pack_data['id'] not in self.installed_packs:
            return False

        try:
            if pack_data['version'] in ['latest', '*']:
                return parse(self.get_latest_version_for_pack(pack_data['id'])) == self.installed_packs[pack_data['id']]

            return parse(pack_data['version']) == self.installed_packs[pack_data['id']]
        except Exception:
            return parse(self.get_latest_version_for_pack(pack_data['id'])) == self.installed_packs[pack_data['id']]

    def install_pack_and_its_dependencies(self, pack_data: Dict[str, str], install_dependencies: bool) -> None:
        """Method for installing a pack and it's prerequisites in order.

        Args:
            pack_data (Dict[str, str]): Packs' data for installation.
            install_dependencies (bool): Whether to install the pack dependencies.

        """
        if self.is_pack_already_installed(pack_data):
            pack_info_for_message = self.PACK_ID_VERSION_FORMAT.format(pack_data['id'], pack_data['version'])
            demisto.debug(f'{SCRIPT_NAME} - pack "{pack_info_for_message}" is already installed')
            return

        demisto.debug(f'{SCRIPT_NAME} - Initiating installation process for pack {pack_data["id"]}')
        if pack_data['version'] == 'latest':
            pack_data = self.get_packs_data_for_installation([pack_data])[0]

        if install_dependencies:
            dependencies_to_install = self.get_dependencies_for_pack(pack_data)
            demisto.debug(f'{SCRIPT_NAME} - Updated dependencies for {pack_data["id"]}: {dependencies_to_install}')
            self.install_packs(dependencies_to_install)

        self.install_packs([pack_data])


def format_packs_data_for_installation(args: Dict) -> List[Dict[str, str]]:
    """Creates the body of the installation request from the raw data.

    Returns:
        List[Dict[str, str]]: Installable objects list.
    """
    packs_data = argToList(args.get('packs_data', []))

    id_key = args.get('pack_id_key')
    version_key = args.get('pack_version_key')

    try:
        return [
            {
                'id': pack[id_key],
                'version': pack[version_key],
            }
            for pack in packs_data
        ]
    except KeyError as e:
        raise DemistoException(f'The following key does not exist in the pack data: {e}.') from e
    except Exception as e:
        raise DemistoException(f'Unknown error occurred while processing the packs data.\n{e}') from e


def create_context(packs_to_install: List[Dict[str, str]], content_packs_installer: ContentPackInstaller) \
        -> List[Dict[str, str]]:
    """Creates context entry including all relevant data.

    Args:
        packs_to_install (List[Dict[str, str]]): The list of packs that should have been installed.
        content_packs_installer (ContentPackInstaller): The content packs installer.

    Returns:
        List[Dict[str, str]]. Formatted context data after installation processes.
    """
    context_data = []
    requested_packs_ids = [pack['id'] for pack in packs_to_install]

    for pack_id, pack_version in content_packs_installer.newly_installed_packs.items():
        content_installed = {
            'packid': pack_id,
            'packversion': str(pack_version),
            'installationstatus': 'Success.' if pack_id in requested_packs_ids else 'Installed as requirement.',
        }
        context_data.append(content_installed)

    for pack_id in requested_packs_ids:
        if pack_id in content_packs_installer.already_on_machine_packs:
            content_installed = {
                'packid': pack_id,
                'packversion': str(content_packs_installer.installed_packs[pack_id]),
                'installationstatus': 'Already Installed on the machine.',
            }
            context_data.append(content_installed)

        if pack_id in content_packs_installer.packs_failed:
            packs_failed = {
                'packid': pack_id,
                'packversion': content_packs_installer.packs_failed[pack_id],
                'installationstatus': 'Failed to install.',
            }
            context_data.append(packs_failed)

    return context_data


def main():
    try:
        args = demisto.args()
        instance_name = args.get('using')
        installer = ContentPackInstaller(instance_name)
        packs_to_install = format_packs_data_for_installation(args)
        install_dependencies = argToBoolean(args.get('install_dependencies', 'true'))

        for pack in packs_to_install:
            installer.install_pack_and_its_dependencies(pack, install_dependencies)

        return_results(
            CommandResults(
                outputs_prefix='ConfigurationSetup.MarketplacePacks',
                outputs_key_field='packid',
                outputs=create_context(packs_to_install, installer),
            )
        )

    except Exception as e:
        demisto.debug(f'error occured during script execution {e}')
        return_error(f'{SCRIPT_NAME} - Error occurred while setting up machine.\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
