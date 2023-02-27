import datetime
from unittest.mock import MagicMock
import pytest as pytest
from Utils.github_workflow_scripts.autobump_rn import LastModifiedCondition, LabelCondition


class PullRequest:

    def __init__(self,
                 updated_at=None,
                 labels=None,
                 files=None,
                 ):
        self.number = 1
        self.updated_at = updated_at or datetime.datetime.now()
        if labels:
            labels = []
        self.labels = labels or []
        self.files = files or []
        self.head = MagicMock()
        self.head.ref = 'branch'

    def get_files(self):
        return self.files

    def create_issue_comment(self):
        pass


class Repo:

    def __init__(self):
        self.git = MagicMock()


# @pytest.fixture
# def pr(mocker):
#     mocker.patch.object(demisto, 'getLicenseID', return_value='test')
#     pr = PullRequest()
#
#     return pr
#
#
# @pytest.fixture
# def git_repo(mocker):
#     mocker.patch.object(demisto, 'getLicenseID', return_value='test')
#     return git_repo

# labels=['ignore-auto-bump-version']
@pytest.mark.parametrize('condition_obj, pr_args, should_skip_reason_res, should_skip_res',
                         [
                             (LastModifiedCondition,
                              {
                                  'updated_at': datetime.datetime.now() - datetime.timedelta(days=20),
                               },
                              'The PR was not updated in last 14 days. PR last update time:',
                              True),
                             (LastModifiedCondition,
                              {
                                  'updated_at': datetime.datetime.now() - datetime.timedelta(days=1),
                              },
                              '',
                              False),
                             (LabelCondition,
                              {
                                  'labels': ['ignore-auto-bump-version', 'label1']
                              },
                              'Label "ignore-auto-bump-version" exist in this PR. PR labels: ',
                              True),
                             (LabelCondition,
                              {'labels': ['label1', 'label2']},
                              '',
                              False),
                         ])
def test_base_conditions(condition_obj, pr_args, should_skip_reason_res, should_skip_res):
    pr = PullRequest(**pr_args)
    cond = condition_obj(pr=pr, git_repo=Repo())
    res = cond.check()
    assert res.should_skip == should_skip_res
    assert should_skip_reason_res in res.reason


