from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

community_msg = {}  # type: ignore


class CommunityChecker(BaseChecker):
    __implements__ = IAstroidChecker
    name = "community-checker"
    priority = -1
    msgs = community_msg

    def __init__(self, linter=None):
        super(CommunityChecker, self).__init__(linter)

    # -------------------------------------------- Validations--------------------------------------------------


def register(linter):
    linter.register_checker(CommunityChecker(linter))
