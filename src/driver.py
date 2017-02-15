from cloudshell.api.cloudshell_api import CloudShellAPISession
from cloudshell.cli.cli import CLI
from cloudshell.cli.command_mode import CommandMode
from cloudshell.cli.session.ssh_session import SSHSession
from cloudshell.cli.session.telnet_session import TelnetSession
from cloudshell.shell.core.context import AutoLoadDetails
from cloudshell.shell.core.resource_driver_interface import ResourceDriverInterface
from log_helper import LogHelper
from re import sub


class GenericResourceDriver(ResourceDriverInterface):
    class UnImplementedCliConnectionType(Exception):
        pass

    class UnSupportedCliConnectionType(Exception):
        pass

    def cleanup(self):
        """
        Destroy the driver session, this function is called everytime a driver instance is destroyed
        This is a good place to close any open sessions, finish writing to log files
        """
        pass

    def __init__(self):
        self.address = None
        self.cli = None
        self.cli_connection_type = None
        self.cli_prompt_regex = None
        self.cli_session = None
        self.cs_session = None
        self.mode = None
        self.password_hash = None
        self.session_types = None
        self.user = None

    def initialize(self, context):
        self.cli = CLI()

    def get_inventory(self, context):
        self.run_command(context, 'hostname')

        return AutoLoadDetails()

    def run_command(self, context, command):
        logger = LogHelper.get_logger(context)
        self._cli_session_handler(context)

        with self.cli.get_session(self.session_types, self.mode, logger) as default_session:
            output = default_session.send_command(command)

        return sub(self.cli_prompt_regex, '', output)

    def _cs_session_handler(self, context):
        self.address = context.resource.address
        self.user = context.resource.attributes['User']
        self.password_hash = context.resource.attributes['Password']

        domain = None
        try:
            domain = context.reservation.domain
        except AttributeError:
            domain = 'Global'

        self.cs_session = CloudShellAPISession(host=context.connectivity.server_address,
                                               token_id=context.connectivity.admin_auth_token,
                                               domain=domain)

    def _cli_session_handler(self, context):
        self._cs_session_handler(context)
        logger = LogHelper.get_logger(context)

        self.cli_connection_type = context.resource.attributes['CLI Connection Type']
        self.cli_prompt_regex = context.resource.attributes['CLI Prompt Regular Expression']
        self.mode = CommandMode(self.cli_prompt_regex)
        self.session_types = None

        logger.info('CLI Connection Type: "%s"' % self.cli_connection_type)
        logger.info('CLI Prompt Regular Expression: "%s"' % self.cli_prompt_regex)

        if self.cli_connection_type == 'Auto':
            self.session_types = [SSHSession(host=self.address,
                                             username=self.user,
                                             password=self.cs_session.DecryptPassword(self.password_hash).Value),
                                  TelnetSession(host=self.address,
                                                username=self.user,
                                                password=self.cs_session.DecryptPassword(self.password_hash).Value)]
        elif self.cli_connection_type == 'Console':
            message = 'Unimplemented CLI Connection Type: "%s"' % self.cli_connection_type
            logger.error(message)
            raise GenericResourceDriver.UnImplementedCliConnectionType(message)
        elif self.cli_connection_type == 'SSH':
            self.session_types = [SSHSession(host=self.address,
                                             username=self.user,
                                             password=self.cs_session.DecryptPassword(self.password_hash).Value)]
        elif self.cli_connection_type == 'TCP':
            message = 'Unimplemented CLI Connection Type: "%s"' % self.cli_connection_type
            logger.error(message)
            raise GenericResourceDriver.UnImplementedCliConnectionType(message)
        elif self.cli_connection_type == 'Telnet':
            self.session_types = [TelnetSession(host=self.address,
                                                username=self.user,
                                                password=self.cs_session.DecryptPassword(self.password_hash).Value)]
        else:
            message = 'Unsupported CLI Connection Type: "%s"' % self.cli_connection_type
            logger.error(message)
            raise GenericResourceDriver.UnSupportedCliConnectionType(message)
