from __future__ import print_function


class DemistoWrapper(Demisto):
    """Wrapper class to interface with the Demisto server via stdin, stdout"""
    # INTEGRATION = 'Integration'
    # SCRIPT = 'Script'

    def __init__(self, context):
        super().__init__(context)
        # self.is_integration = self.callingContext['integration']
        # self.item_type = self.INTEGRATION if self.is_integration else self.SCRIPT
        # self.info(f"init wrapper: {self.item_type=}")

    # def raise_exception_if_not_implemented(self, implemented_item_type, function_name):
    #     """
    #
    #     :param implemented_item_type: Integration or Script, type that te function works with
    #     :param function_name: The calling function name
    #
    #     :return:
    #     """
    #     if self.item_type != implemented_item_type:
    #         raise Exception('Demisto object has no function `{function_name}` for {item_type}.'.format(
    #             function_name=function_name, item_type=self.item_type))

    def incidents(self, incidents):
        # self.raise_exception_if_not_implemented(self.INTEGRATION, 'incidents')
        if incidents:
            self.debug("Wrapper Class: Creating {num_incidents} incidents.".format(num_incidents=len(incidents)))
        super().incidents(incidents)

    def getFilePath(self, id):
        # self.raise_exception_if_not_implemented(self.SCRIPT, 'getFilePath')
        return super().getFilePath(id)

    def command(self):
        self.debug("calling command - darya")
        # self.raise_exception_if_not_implemented(self.INTEGRATION, 'command')
        return super().command()


try:
    # try except for CommonServerPython tests.
    # demisto._heartbeat_enabled = False
    # demisto._heartbeat_thread.join()
    demisto.__class__ = DemistoWrapper
    # demisto = DemistoWrapper(context)  # type:ignore [name-defined] # noqa: F821 # pylint: disable=E0602
except NameError:
    pass
