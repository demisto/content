import demistomock as demisto
from CommonServerPython import *

SCRIPT_NAME = 'ConfigurationSetup'


class Pack:
    """Pack object for the configuration file.

    Args:
        id_ (str): Pack ID.
        version (str): Version of the pack to install.
    """

    def __init__(self, id_: str, version: str = '', url: str = ''):
        self.id = id_
        self._version = version
        self.url = url

    @property
    def version(self) -> str:
        """The getter method for the version variable.
        """
        if self._version == '*':
            return 'latest'
        return self._version

    @property
    def installation_object(self) -> Dict[str, str]:
        """Creates the layout of an installation object in marketplace for the pack.
        """
        return {
            'id': self.id,
            'version': self.version
        }


class IntegrationInstance:
    """Integration instance object for the configuration file.

    Args:
        brand_name (str): Integration name to be configured.
        instance_name (str): Instance name to be configured.
    """
    INSTANCES_KEYWORDS_LIST = ['use_cases', 'brand_name', 'instance_name']

    def __init__(self, brand_name: str, instance_name: str):
        self.brand_name = brand_name
        self.instance_name = instance_name

    @property
    def params(self) -> Dict:
        """Getter for the instance parameters.

        Returns:
            Dict. {param_name: param_value} for each configured parameter.
        """
        return {param_name: param_value for param_name, param_value in self.__dict__.items() if
                param_name not in IntegrationInstance.INSTANCES_KEYWORDS_LIST}

    def add_param(self, name: str, value: Any):
        self.__dict__[name] = value

    def get_param(self, param_name: str, default_value: Any = None) -> Any:
        """Get the parameter for the instance by name.

        Args:
            param_name (str): The name of the parameter to get it's value.
            default_value (Any): The fallback value for the case where the parameter is not configured.

        Returns:
            Any. The value of the parameter.

        Notes:
            In the case where the parameter is not configured, will return the default value. or None if not supplied.
        """
        try:
            return self.__dict__[param_name]
        except KeyError:
            return default_value


class Job:
    """Job object for the configuration file.

    Args:
        job_name (str): Job name to be configured.
    """
    JOBS_KEYWORDS_LIST = ['use_cases', 'job_name']

    def __init__(self, job_name: str):
        self.job_name = job_name

    @property
    def params(self) -> Dict:
        """Getter for the instance parameters.

        Returns:
            Dict. {param_name: param_value} for each configured parameter.
        """
        return {
            param_name: param_value
            for param_name, param_value in self.__dict__.items() if
            param_name not in Job.JOBS_KEYWORDS_LIST
        }

    def add_param(self, name: str, value: Any):
        self.__dict__[name] = value

    def get_param(self, param_name: str, default_value: Any = None) -> Any:
        """Get the parameter for the instance by name.

        Args:
            param_name (str): The name of the parameter to get it's value.
            default_value (Any): The fallback value for the case where the parameter is not configured.

        Returns:
            Any. The value of the parameter.

        Notes:
            In the case where the parameter is not configured, will return the default value. or None if not supplied.
        """
        try:
            return self.__dict__[param_name]
        except KeyError:
            return default_value


class Configuration:
    def __init__(self, configuration_data: Dict):
        """Configuration object for the configuration file.

        Args:
            configuration_data (Dict): The configuration data parsed from the configuration file.
        """
        self.config = configuration_data

        # Variables
        self.sections = list(self.config.keys())

        # Objects Variables
        self.jobs: Dict[str, Job] = {}
        self.lists: Dict[str, str] = {}
        self.custom_packs: Dict[str, Pack] = {}
        self.marketplace_packs: Dict[str, Pack] = {}
        self.integration_instances: Dict[str, IntegrationInstance] = {}

        # Load and create Objects
        self.load_jobs()
        self.load_lists()
        self.load_custom_packs()
        self.load_marketplace_packs()
        self.load_integration_instances()

    def load_custom_packs(self) -> None:
        """Iterates through the Packs sections and creates a Pack object for each custom pack.
        """
        if 'custom_packs' in self.sections:
            for pack in self.config['custom_packs']:
                pack_id = pack.get('id')
                pack_url = pack.get('url')
                if pack_url:
                    new_pack = Pack(pack_id, url=pack_url)
                    self.custom_packs[pack_id] = new_pack

    def load_marketplace_packs(self) -> None:
        """Iterates through the Packs sections and creates a Pack object for each marketplace pack.
        """
        if 'marketplace_packs' in self.sections:
            for pack in self.config['marketplace_packs']:
                pack_id = pack.get('id')
                pack_version = pack.get('version')
                if pack_version:
                    new_pack = Pack(pack_id, version=pack_version)
                    self.marketplace_packs[pack_id] = new_pack

    def load_integration_instances(self) -> None:
        """Iterates through the instances sections, creates IntegrationInstance object for each instance.
        """
        if 'instances' in self.sections:
            for instance in self.config['instances']:
                brand_name = instance.get('brand_name')
                instance_name = instance.get('instance_name')
                new_instance = IntegrationInstance(brand_name, instance_name)

                for param_name, param_value in instance.items():
                    new_instance.add_param(param_name, param_value)

                self.integration_instances[instance_name] = new_instance

    def load_jobs(self) -> None:
        """Iterates through the jobs sections, creates Job object for each job.
        """
        if 'jobs' in self.sections:
            for job in self.config['jobs']:
                job_name = job.get('name')
                new_job = Job(job_name)

                for param_name, param_value in job.items():
                    new_job.add_param(param_name, param_value)

                self.jobs[job_name] = new_job

    def load_lists(self) -> None:
        """Iterates through the lists sections, creates Dict object for each list.
        """
        if 'lists' in self.sections:
            for _list in self.config['lists']:
                list_name = _list.get('name')
                list_value = _list.get('value')

                self.lists[list_name] = list_value


def create_context(full_configuration: Configuration) -> Dict[str, List[Dict[str, str]]]:
    custom_packs = [
        {
            'packid': pack.id,
            'packurl': pack.url,
        }
        for _, pack in full_configuration.custom_packs.items()
    ]

    marketplace_packs = [
        {
            'packid': pack.id,
            'packversion': str(pack.version),
        }
        for _, pack in full_configuration.marketplace_packs.items()
    ]

    jobs = [
        job.params for _, job in full_configuration.jobs.items()
    ]

    lists = [
        {
            'listname': list_name,
            'listdata': list_data,
        }
        for list_name, list_data in full_configuration.lists.items()
    ]

    return {
        'Jobs': jobs,
        'Lists': lists,
        'CustomPacks': custom_packs,
        'MarketplacePacks': marketplace_packs,
    }


def get_data_from_war_room_file(entry_id):
    """Retrieves the content of a file from the war-room.

    Args:
        entry_id (str): The entry ID of the configuration file from the war-room.

    Returns:
        str. The content of the configuration file.
    """
    res = execute_command(
        'getFilePath',
        {'id': entry_id},
    )

    file_path = res['path']

    with open(file_path, 'rb') as file:
        file_content = file.read()

    return file_content


def get_config_data(args: Dict) -> Dict:
    """Gets the configuration data from Git or from a file entry in the war room..

    Returns:
        Dict. The parsed configuration file.
    """
    configuration_file_entry_id = args.get('configuration_file_entry_id')

    config_data = get_data_from_war_room_file(configuration_file_entry_id)

    try:
        return json.loads(config_data)
    except json.JSONDecodeError:
        raise DemistoException('Configuration file is not a valid JSON structure.')


def main():
    try:
        args = demisto.args()
        config_data = get_config_data(args)
        config = Configuration(config_data)

        return_results(
            CommandResults(
                outputs_prefix='ConfigurationSetup',
                outputs=create_context(config),
            )
        )

    except Exception as e:
        return_error(f'{SCRIPT_NAME} - Error occurred while setting up machine.\n{e}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
