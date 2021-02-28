import astroid
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

partner_msg = {
    "W9010": (
        "try and except statements were not found in main function. Please add them", "try-except-main-doesnt-exists",
        "Ensure to not try except in the main function.",),
    "W9011": (
        "return_error used too many times, should be used only once in the code, in main function. Please remove "
        "other usages.",
        "too-many-return-error",
        "return.error should be used only once in the code",),
    "W9012": ("return_error should be used in main function. Please add it.",
              "return-error-does-not-exist-in-main",
              "return_error should be used in main function",),
}


class PartnerChecker(BaseChecker):
    __implements__ = IAstroidChecker
    name = "partner-checker"
    priority = -1
    msgs = partner_msg

    def __init__(self, linter=None):
        super(PartnerChecker, self).__init__(linter)
        self.return_error_count = 0

    def visit_call(self, node):
        self._return_error_function_count(node)

    def visit_functiondef(self, node):
        self._try_except_in_main(node)
        self._return_error_in_main_checker(node)

    def leave_module(self, node):
        self._return_error_count_checker(node)

    # -------------------------------------------- Validations--------------------------------------------------

    def _try_except_in_main(self, node):
        if node.name == 'main':
            try_except_exists = False
            for child in node.get_children():
                if isinstance(child, astroid.TryExcept) or isinstance(child, astroid.TryFinally):
                    try_except_exists = True
            if not try_except_exists:
                self.add_message("try-except-main-doesnt-exists", node=node)

    def _return_error_in_main_checker(self, node):
        try:
            if node.name == 'main':
                return_error_exists = False
                for child in self._inner_search_return_error(node):
                    if isinstance(child, astroid.Call):
                        try:
                            if child.func.name == 'return_error':
                                return_error_exists = True
                        except AttributeError:
                            pass
                if not return_error_exists:
                    self.add_message("return-error-does-not-exist-in-main", node=node)
        except AttributeError:
            pass

    def _return_error_function_count(self, node):
        try:
            if node.func.name == 'return_error':
                self.return_error_count = self.return_error_count + 1
        except AttributeError:
            pass

    def _return_error_count_checker(self, node):
        if self.return_error_count > 1:
            self.add_message("too-many-return-error", node=node)

    def _inner_search_return_error(self, node):
        try:
            for subnode in list(node.get_children()):
                yield subnode
                for sub in self._inner_search_return_error(subnode):
                    yield sub

        except AttributeError:
            yield node

        except TypeError:
            yield node


def register(linter):
    linter.register_checker(PartnerChecker(linter))
