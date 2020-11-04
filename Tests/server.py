import demisto_client
from Tests.tools import update_server_configuration
from Tests.configure_and_test_integration_instances import SimpleSSH
from Tests.build import Build


class Server:

    def __init__(self, host, user_name, password):
        self.__ssh_client = None
        self.__client = None
        self.host = host
        self.user_name = user_name
        self.password = password

    def __str__(self):
        return self.host

    @property
    def client(self):
        if self.__client is None:
            self.__client = demisto_client.configure(self.host, verify_ssl=False, username=self.user_name,
                                                     password=self.password)
        return self.__client

    def add_server_configuration(self, config_dict, error_msg, restart=False):
        update_server_configuration(self.client, config_dict, error_msg)

        if restart:
            self.exec_command('sudo systemctl restart demisto')

    def exec_command(self, command):
        if self.__ssh_client is None:
            self.__init_ssh()
        self.__ssh_client.exec_command(command)

    def __init_ssh(self):
        self.__ssh_client = SimpleSSH(host=self.host.replace('https://', '').replace('http://', ''),
                                      key_file_path=Build.key_file_path, user='ec2-user')
