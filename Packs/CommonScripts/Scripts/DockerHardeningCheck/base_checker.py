import os

import astroid
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
              "Please change the import to: from CommonServerPython import *"),
    "E9007": ("Invalid usage of indicators key in CommandResults was found, Please use indicator key instead.",
              "commandresults-indicators-exists",
              "Invalid usage of indicators key in CommandResults was found, Please use indicator key instead."),
    "E9010": ("Some commands from yml file are not implemented in the python file, Please make sure that every "
              "command is implemented in your code. The commands that are not implemented are %s",
              "unimplemented-commands-exist",
              "Some commands from yml file are not implemented in the python file, Please make sure that every "
              "command is implemented in your code.")
}


# -------------------------------------------- Messages for all linters ------------------------------------------------


class CustomBaseChecker(BaseChecker):
    __implements__ = IAstroidChecker
    name = "base-checker"
    priority = -1
    msgs = base_msg

    def __init__(self, linter=None):
        super(CustomBaseChecker, self).__init__(linter)
        self.commands = os.getenv('commands', '').split(',') if os.getenv('commands') else []

    def visit_call(self, node):
        self._print_checker(node)
        self._sleep_checker(node)
        self._quit_checker(node)
        self._exit_checker(node)
        self._commandresults_indicator_check(node)

    def visit_importfrom(self, node):
        self._common_server_import(node)
        self._api_module_import_checker(node)

    # Print statment for Python2 only.
    def visit_print(self, node):
        self.add_message("print-exists", node=node)

    def visit_dict(self, node):
        self._commands_in_dict_keys_checker(node)

    def visit_if(self, node):
        self._commands_in_if_statment_checker(node)

    def leave_module(self, node):
        self._all_commands_implemented(node)

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

    def _commands_in_dict_keys_checker(self, node):
        # for py2
        if os.getenv('PY2'):
            try:
                for item in node.items:
                    commands = self._infer_name(item[0])
                    for command in commands:
                        if command in self.commands:
                            self.commands.remove(command)
            except Exception:
                pass
        # for py3
        else:
            try:
                for sub_node in node.itered():
                    commands = self._infer_name(sub_node)
                    for command in commands:
                        if command in self.commands:
                            self.commands.remove(command)
            except Exception:
                pass

    def _commands_in_if_statment_checker(self, node):
        def _check_if(comp_with):
            # for regular if 'command' == command with inference mechanize
            commands = self._infer_name(comp_with)
            for command in commands:
                if command in self.commands:
                    self.commands.remove(command)

            # for if command in ['command1','command2'] or for if command in {'command1','command2'}
            if isinstance(comp_with, astroid.List) or isinstance(comp_with, astroid.Set):
                for var_lst in comp_with.itered():
                    commands = self._infer_name(var_lst)
                    for command in commands:
                        if command in self.commands:
                            self.commands.remove(command)

            # for if command in ('command1','command2')
            elif isinstance(comp_with, astroid.Tuple):
                for var_lst in comp_with.elts:
                    commands = self._infer_name(var_lst)
                    for command in commands:
                        if command in self.commands:
                            self.commands.remove(command)

        try:
            # for if command == 'command1' or command == 'commands2'
            if isinstance(node.test, astroid.BoolOp):
                for value in node.test.values:
                    _check_if(value.ops[0][1])
            # for regular if
            _check_if(node.test.ops[0][1])
            # for elif clause
            for elif_clause in node.orelse:
                _check_if(elif_clause.test.ops[0][1])
        except Exception:
            pass

    def _all_commands_implemented(self, node):
        if self.commands:
            self.add_message("unimplemented-commands-exist",
                             args=str(self.commands), node=node)

    def _api_module_import_checker(self, node):
        try:
            # for feeds which use api module -> the feed required params are implemented in the api module code.
            # as a result we will remove them from param list.
            if 'ApiModule' in node.modname:
                self.commands = []
        except Exception:
            pass

    def _commandresults_indicator_check(self, node):
        try:
            if node.func.name == 'CommandResults':
                for keyword in node.keywords:
                    if keyword.arg == 'indicators':
                        self.add_message("commandresults-indicators-exists", node=node)
        except Exception:
            pass

    #  --------------------------------------- Helper Function ----------------------------------------------------

    def _infer_name(self, comp_with):

        def _infer_single_var(var):
            var_infered = []
            try:
                for inference in var.infer():
                    var_infered.append(inference.value)
            except astroid.InferenceError:
                pass
            return var_infered

        infered = []
        if isinstance(comp_with, astroid.JoinedStr):
            for value in comp_with.values:
                if isinstance(value, astroid.FormattedValue):
                    infered.extend(_infer_single_var(value.value))
                elif isinstance(value, astroid.Const):
                    infered.append(value.value)
            infered = [''.join(infered)]
        elif isinstance(comp_with, astroid.Name):
            infered = _infer_single_var(comp_with)
        elif isinstance(comp_with, astroid.Const):
            infered = [comp_with.value]
        return infered


def register(linter):
    linter.register_checker(CustomBaseChecker(linter))
