import os

import astroid
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

xsoar_msg = {
    "W9014": (
        "Function arguments are missing type annotations. Please add type annotations",
        "missing-arg-type-annoation",
        "Function arguments are missing type annotations. Please add type annotations",),
    "W9018": (
        "It is best practice for Integrations to raise a NotImplementedError when receiving a command which is not "
        "recognized. "
        "exception",
        "not-implemented-error-doesnt-exist",
        "It is best practice for Integrations to raise a NotImplementedError when receiving a command which is not "
        "recognized.",),
    "W9019": (
        "It is best practice to use .get when accessing the arg/params dict object rather then direct access.",
        "direct-access-args-params-dict-exist",
        "It is best practice to use .get when accessing the arg/params dict object rather then direct access.",),

}


class XsoarChecker(BaseChecker):
    __implements__ = IAstroidChecker
    name = "xsoar-checker"
    priority = -1
    msgs = xsoar_msg

    def __init__(self, linter=None):
        super(XsoarChecker, self).__init__(linter)
        self.is_script = True if os.getenv('is_script') == 'True' else False
        self.common_args_params = ['args', 'dargs', 'arguments', 'd_args', 'data_args', 'params', 'PARAMS',
                                   'integration_parameters']

    def visit_functiondef(self, node):
        self._type_annotations_checker(node)
        self._not_implemented_error_in_main(node)

    def visit_subscript(self, node):
        self._direct_access_dict_checker(node)

    # -------------------------------------------- Validations--------------------------------------------------

    def _type_annotations_checker(self, node):
        try:
            if not os.getenv('PY2'):
                annotation = True
                for ann, args in zip(node.args.annotations, node.args.args):
                    if not ann and args.name != 'self':
                        annotation = False
                if not annotation and node.name not in ['main', '__init__']:
                    self.add_message("missing-arg-type-annoation", node=node)
        except Exception:
            pass

    def _not_implemented_error_in_main(self, node):
        try:
            if not self.is_script:
                if node.name == 'main':
                    not_implemented_error_exist = False
                    for child in self._inner_search_return_error(node):
                        if isinstance(child, astroid.If):
                            else_cluse = child.orelse
                            for line in else_cluse:
                                if isinstance(line, astroid.Raise) and line.exc.func.name == "NotImplementedError":
                                    not_implemented_error_exist = True
                    if not not_implemented_error_exist:
                        self.add_message("not-implemented-error-doesnt-exist", node=node)
        except Exception:
            pass

    def _direct_access_dict_checker(self, node):
        try:
            # for demisto.args()[] implementation or for demisto.params()[]
            if isinstance(node.parent, astroid.Assign) and node not in node.parent.targets:
                if node.value.func.expr.name == 'demisto' and node.value.func.attrname == 'args':
                    self.add_message("direct-access-args-params-dict-exist", node=node)
                elif node.value.func.expr.name == 'demisto' and node.value.func.attrname == 'params':
                    self.add_message("direct-access-args-params-dict-exist", node=node)
        except Exception:
            try:
                if isinstance(node.parent, astroid.Assign) and node not in node.parent.targets:
                    # for args[]/params[] implementation
                    if node.value.name in self.common_args_params:
                        self.add_message("direct-access-args-params-dict-exist", node=node)
            except Exception:
                pass

    def _inner_search_return_error(self, node):
        try:
            for subnode in list(node.get_children()):
                yield subnode
                for sub in self._inner_search_return_error(subnode):
                    yield sub

        except (AttributeError, TypeError):
            yield node


def register(linter):
    linter.register_checker(XsoarChecker(linter))
