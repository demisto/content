import os

from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

xsoar_msg = {
    "W9014": (
        "Function arguments are missing type annotations. Please add type annotations",
        "missing-arg-type-annoation",
        "Function arguments are missing type annotations. Please add type annotations",),
}


class XsoarChecker(BaseChecker):
    __implements__ = IAstroidChecker
    name = "xsoar-checker"
    priority = -1
    msgs = xsoar_msg

    def __init__(self, linter=None):
        super(XsoarChecker, self).__init__(linter)

    def visit_functiondef(self, node):
        self._type_annotations_checker(node)

    # -------------------------------------------- Validations--------------------------------------------------

    def _type_annotations_checker(self, node):
        if not os.getenv('PY2'):
            annotation = True
            for ann, args in zip(node.args.annotations, node.args.args):
                if not ann and args.name != 'self':
                    annotation = False
            if not annotation and node.name not in ['main', '__init__']:
                self.add_message("missing-arg-type-annoation", node=node)


def register(linter):
    linter.register_checker(XsoarChecker(linter))
