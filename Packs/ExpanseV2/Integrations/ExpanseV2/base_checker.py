import os

from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

# You can find documentation about adding new checker here:
# http://pylint.pycqa.org/en/latest/how_tos/custom_checkers.html#write-a-checker

base_msg = {
    "E9002": ("Print is found, Please remove all prints from the code.", "print-exists",
              "Please remove all prints from the code.",),
    "E9003": ("Sleep is found, Please remove all sleep statements from the code.", "sleep-exists",
              "Please remove all sleep statements from the code.",),
    "E9004": ("exit is found, Please remove all exit() statements from the code.", "exit-exists",
              "Please remove all exit() statements from the code.",),
    "E9005": ("quit is found, Please remove all quit() statements from the code.", "quit-exists",
              "Please remove all quit statements from the code.",),
    "E9006": ("Invalid CommonServerPython import was found. Please change the import to: "
              "from CommonServerPython import *", "invalid-import-common-server-python",
              "Please change the import to: from CommonServerPython import *")
}


# -------------------------------------------- Messages for all linters ------------------------------------------------


class CustomBaseChecker(BaseChecker):
    __implements__ = IAstroidChecker
    name = "base-checker"
    priority = -1
    msgs = base_msg

    def __init__(self, linter=None):
        super(CustomBaseChecker, self).__init__(linter)

    def visit_call(self, node):
        self._print_checker(node)
        self._sleep_checker(node)
        self._quit_checker(node)
        self._exit_checker(node)

    def visit_importfrom(self, node):
        self._common_server_import(node)

    # Print statment for Python2 only.
    def visit_print(self, node):
        self.add_message("print-exists", node=node)

    # -------------------------------------------- Validations--------------------------------------------------

    def _print_checker(self, node):
        try:
            if node.func.name == 'print':
                self.add_message("print-exists", node=node)
        except Exception:
            pass

    def _sleep_checker(self, node):
        if not os.getenv('LONGRUNNING'):
            try:
                if node.func.attrname == 'sleep' and node.func.expr.name == 'time' and node and int(
                        node.args[0].value) > 10:
                    self.add_message("sleep-exists", node=node)
            except Exception as exp:
                if str(exp) == "'Name' object has no attribute 'value'":
                    self.add_message("sleep-exists", node=node)
                else:
                    try:
                        if node.func.name == 'sleep' and int(node.args[0].value) > 10:
                            self.add_message("sleep-exists", node=node)
                    except AttributeError as e:
                        if str(e) == "'Name' object has no attribute 'value'":
                            self.add_message("sleep-exists", node=node)
                        else:
                            pass

    def _exit_checker(self, node):
        try:
            if node.func.name == 'exit':
                self.add_message("exit-exists", node=node)
        except Exception:
            pass

    def _quit_checker(self, node):
        try:
            if node.func.name == 'quit':
                self.add_message("quit-exists", node=node)
        except Exception:
            pass

    def _common_server_import(self, node):
        try:
            if node.modname == 'CommonServerPython' and not node.names[0][0] == '*':
                self.add_message("invalid-import-common-server-python", node=node)
        except Exception:
            pass


def register(linter):
    linter.register_checker(CustomBaseChecker(linter))
