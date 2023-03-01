import datetime
import json
from pathlib import Path
from packaging.version import Version
from typing import Optional
from unittest.mock import MagicMock
import pytest as pytest
from Utils.github_workflow_scripts.autobump_rn import LastModifiedCondition, \
    LabelCondition, AddedRNFilesCondition, HasConflictOnAllowedFilesCondition, PackSupportCondition, \
    MajorChangeCondition, MaxVersionCondition, OnlyVersionChangedCondition, OnlyOneRNPerPackCondition, \
    SameRNMetadataVersionCondition, ConditionResult, AllowedBumpCondition, UpdateType, PackAutoBumper
from git import GitCommandError
from demisto_sdk.commands.common.git_util import GitUtil
from demisto_sdk.commands.update_release_notes.update_rn import UpdateRN


MERGE_STDOUT = "stdout: '\n Auto-merging {}\n failed.\n Auto-merging {}\n failed.\n"


class Label:
    def __init__(self, name):
        self.name = name


class File:
    def __init__(self, path=None, status=None):
        self.filename = path or 'Packs/MyPack/some_file.py'
        self.status = status or 'added'


class PullRequest:

    def __init__(self,
                 updated_at=None,
                 labels: Optional[Label] = None,
                 files: Optional[File] = None,
                 branch_name: str = 'branch'
                 ):
        self.number = 1
        self.updated_at = updated_at or datetime.datetime.now()
        self.labels = labels or []
        self.files = files or []
        self.head = MagicMock()
        self.head.ref = branch_name

    def get_files(self):
        return self.files

    def create_issue_comment(self):
        pass


class Repo:

    def __init__(self, files=None):
        self.git = Git(files=files)


class Git:
    def __init__(self, files=None):
        self.files = files or []
        self.rn_file = [f.filename for f in self.files if f.status == 'added' and 'ReleaseNotes' in
                        Path(f.filename).parts]
        self.changed_metadata_files = [f.filename for f in self.files if 'pack_metadata.json' in Path(f.filename).parts]
        self.additional_files = [f.filename for f in self.files if 'ReleaseNotes' not in
                                 Path(f.filename).parts and 'pack_metadata.json' not in Path(f.filename).parts]

    def merge(self, *args):
        if '--abort' in args:
            pass
        elif '--no-commit' in args:
            if 'not-allowed-conflicts' in args[0]:
                raise GitCommandError(command='merge', stdout=MERGE_STDOUT.format(self.additional_files[0],
                                                                                  self.rn_file[0]))
            elif 'allowed-conflicts' in args[0]:
                raise GitCommandError(command='merge', stdout=MERGE_STDOUT.format(self.rn_file[0],
                                                                                  self.changed_metadata_files[0]))
            else:
                pass

    def add(self):
        pass

    def commit(self):
        pass

    def push(self):
        pass

    def log(self):
        pass


CHANGED_FILES = [File(path='Packs/MyPack/Integrations/MyIntegration/MyIntegration.py'),
                 File(path='Packs/MyPack/pack_metadata.json', status='modified'),
                 File(path='Packs/MyPack/ReleaseNotes/1_0_1.md', status='added')]


@pytest.mark.parametrize('cond_obj, pr_args, condition_result_attributes, cond_kwargs, prev_res', [
    (LastModifiedCondition,
     {
         'updated_at': datetime.datetime.now() - datetime.timedelta(days=20),
     },
     {'should_skip': True}, {}, None),
    (LastModifiedCondition,
     {
         'updated_at': datetime.datetime.now() - datetime.timedelta(days=1),
     },
     {'should_skip': False}, {}, None,
     ),
    (LabelCondition,
     {
         'labels': [Label('ignore-auto-bump-version'), Label('label1')]
     },
     {'reason': 'Label "ignore-auto-bump-version" exist in this PR. PR labels: ignore-auto-bump-version, label1.',
      'should_skip': True},
     {}, None,),
    (LabelCondition,
     {'labels': [Label('label1'), Label('label2')]},
     {'should_skip': False}, {}, None,),
    (AddedRNFilesCondition,
     {
         'files': [File(path='Packs/MyPack/Integrations/MyIntegration/MyIntegration.py'),
                   File(path='Packs/MyPack/Integrations/MyIntegration/MyIntegration.yml'),
                   File(path='Packs/MyPack/ReleaseNotes/1_0_1.md', status='modified')]
     },
     {'reason': 'No new files were detected on ReleaseNotes directory.',
      'should_skip': True}, {}, None),
    (AddedRNFilesCondition,
     {
         'files': [File(path='Packs/MyPack/Integrations/MyIntegration/MyIntegration.py'),
                   File(path='Packs/MyPack/pack_metadata.json', status='modified'),
                   File(path='Packs/MyPack/ReleaseNotes/1_0_1.md', status='added')]
     },
     {'should_skip': False}, {}, None,),
    (HasConflictOnAllowedFilesCondition,
     {
         'files': CHANGED_FILES,
         'branch_name': 'no-conflicts',
     },
     {
         'should_skip': True,
         'reason': 'No conflicts were detected.'
     }, {}, None,
     ),
    (HasConflictOnAllowedFilesCondition,
     {
         'files': CHANGED_FILES,
         'branch_name': 'allowed-conflicts',
     },
     {
         'should_skip': False,
         'conflicting_packs': {'MyPack'},
     }, {}, None,
     ),
    (HasConflictOnAllowedFilesCondition,
     {
         'files': CHANGED_FILES,
         'branch_name': 'not-allowed-conflicts',
     },
     {
         'should_skip': True,
         'reason': "The PR has conflicts not only at ReleaseNotes and pack_metadata.json. "
                   "The conflicting files are: ['Packs/MyPack/Integrations/MyIntegration/MyIntegration.py', "
                   "'Packs/MyPack/ReleaseNotes/1_0_1.md'].",
     }, {}, None,
     ),
    (PackSupportCondition, {},
     {
         'should_skip': False,
     },
     {
         'branch_metadata': {'support': 'xsoar'}
     }, None,
     ),
    (PackSupportCondition, {},
     {
         'should_skip': True,
         'reason': 'The pack is not xsoar supported. Pack MyPack support type is: partner.'
     },
     {
         'branch_metadata': {'support': 'partner'},
     }, None,
     ),
    (MajorChangeCondition, {},
     {
         'should_skip': True,
         'reason': 'Pack: MyPack major version different in origin 3.0.0 and at the branch 2.1.0.'
     },
     {'branch_metadata': {'currentVersion': '2.1.0'}, 'origin_base_metadata': {'currentVersion': '3.0.0'}},
     None,
     ),
    (MajorChangeCondition, {},
     {
         'should_skip': False,
     },
     {'branch_metadata': {'currentVersion': '2.1.1'}, 'origin_base_metadata': {'currentVersion': '2.1.0'}},
     None,
     ),
    (MaxVersionCondition, {},
     {
         'should_skip': True,
         'reason': 'Pack: MyPack has not allowed version part 99. Versions: origin 2.1.99, branch 2.1.99.'
     },
     {'branch_metadata': {'currentVersion': '2.1.99'}, 'origin_base_metadata': {'currentVersion': '2.1.99'}},
     None,
     ),
    (MaxVersionCondition, {},
     {
         'should_skip': False,
     },
     {'branch_metadata': {'currentVersion': '2.1.1'}, 'origin_base_metadata': {'currentVersion': '2.1.0'}},
     None,
     ),
    (OnlyVersionChangedCondition, {},
     {
         'should_skip': True,
         'reason': "Pack MyPack metadata file has different keys in master and branch: ['marketplaces']."
     },
     {'branch_metadata': {'currentVersion': '2.1.0', 'support': 'xsoar', 'name': 'PackName',
                          'marketplaces': ['xsoar']},
      'origin_base_metadata': {'currentVersion': '2.1.0', 'support': 'xsoar', 'name': 'PackName',
                               'marketplaces': ['xsoar', 'marketplacev2']}},
     None,
     ),
    (OnlyVersionChangedCondition, {},
     {
         'should_skip': True,
         'reason': "Pack MyPack metadata file has different keys in master and branch: ['newField']."
     },
     {'branch_metadata': {'currentVersion': '2.1.0', 'support': 'xsoar', 'name': 'PackName',
                          'marketplaces': ['xsoar'], 'newField': 'new'},
      'origin_base_metadata': {'currentVersion': '2.1.0', 'support': 'xsoar', 'name': 'PackName',
                               'marketplaces': ['xsoar']}},
     None,
     ),
    (OnlyVersionChangedCondition, {},
     {
         'should_skip': False,
     },
     {'branch_metadata': {'currentVersion': '2.1.0', 'support': 'xsoar', 'name': 'PackName',
                          'marketplaces': ['xsoar']},
      'origin_base_metadata': {'currentVersion': '2.1.0', 'support': 'xsoar', 'name': 'PackName',
                               'marketplaces': ['xsoar']}},
     None,
     ),
    (OnlyOneRNPerPackCondition,
     {
         'files': CHANGED_FILES,
     },
     {
         'should_skip': False,
         'pack_new_rn_file': Path('Packs/MyPack/ReleaseNotes/1_0_1.md'),
     },
     {},
     None,
     ),
    (OnlyOneRNPerPackCondition,
     {
         'files': [File(path='Packs/MyPack/Integrations/MyIntegration/MyIntegration.py'),
                   File(path='Packs/MyPack/pack_metadata.json', status='modified'),
                   File(path='Packs/MyPack/ReleaseNotes/1_0_1.md', status='added'),
                   File(path='Packs/MyPack/ReleaseNotes/1_0_2.md', status='added')],
     },
     {
         'should_skip': True,
         'reason': "Pack: MyPack has more than one added rn ['Packs/MyPack/ReleaseNotes/1_0_1.md', "
                   "'Packs/MyPack/ReleaseNotes/1_0_2.md']."
     },
     {},
     None,
     ),
    (SameRNMetadataVersionCondition, {
        'files': [File(path='Packs/MyPack/pack_metadata.json', status='modified'),
                  File(path='Packs/MyPack/ReleaseNotes/1_0_1.md', status='added')],
    },
     {
         'should_skip': True,
         'reason': 'Pack: MyPack has different rn version 1.0.1, and metadata version 2.1.0.'
     },
     {'branch_metadata': {'currentVersion': '2.1.0'}},
     ConditionResult(pack_new_rn_file=Path('Packs/MyPack/ReleaseNotes/1_0_1.md'), should_skip=False),
     ),
    (SameRNMetadataVersionCondition, {
        'files': [File(path='Packs/MyPack/pack_metadata.json', status='modified'),
                  File(path='Packs/MyPack/ReleaseNotes/1_0_1.md', status='added')],
    },
     {
         'should_skip': False,
         'pr_rn_version': Version('1.0.1'),
         'pack_new_rn_file': Path('Packs/MyPack/ReleaseNotes/1_0_1.md'),
     },
     {'branch_metadata': {'currentVersion': '1.0.1'}},
     ConditionResult(pack_new_rn_file=Path('Packs/MyPack/ReleaseNotes/1_0_1.md'), should_skip=False),
     ),
    (AllowedBumpCondition, {},
     {
         'should_skip': True,
         'reason': 'Pack MyPack version was updated from 2.1.0 to 2.1.2 version. Allowed bump only by + 1.'
     },
     {'branch_metadata': {'currentVersion': '2.1.2'}, 'pr_base_metadata': {'currentVersion': '2.1.0'}},
     None
     ),
    (AllowedBumpCondition, {},
     {
         'should_skip': False,
         'pr_rn_version': Version('2.1.1'),
         'update_type': UpdateType.REVISION,
         'pack_new_rn_file': Path('Packs/MyPack/ReleaseNotes/2_1_1.md'),
     },
     {'branch_metadata': {'currentVersion': '2.1.1'}, 'pr_base_metadata': {'currentVersion': '2.1.0'}},
     ConditionResult(pack_new_rn_file=Path('Packs/MyPack/ReleaseNotes/2_1_1.md'),
                     pr_rn_version=Version('2.1.1'),
                     should_skip=False),
     ),
])
def test_metadata_conditions(cond_obj, pr_args, condition_result_attributes, cond_kwargs, prev_res):
    """
    Given:
        Conditions to check, whether the pr should be skipped.
    When:
        Checking if pr's release notes should be auto bumped.
    Then:
        Right ConditionResult returned.
    """
    pr = PullRequest(**pr_args)
    cond = cond_obj(pack='MyPack', pr=pr, git_repo=Repo(files=pr_args.get('files')),
                    **cond_kwargs)
    res = cond.check(previous_result=prev_res)
    for attr, expected_res in condition_result_attributes.items():
        assert res.__getattribute__(attr) == expected_res


@pytest.mark.parametrize('prev_version, new_version, expected_res', [
    (Version('2.1.3'), Version('2.1.4'), UpdateType.REVISION),
    (Version('2.1.3'), Version('2.2.0'), UpdateType.MINOR),
    (Version('2.1.3'), Version('3.0.0'), UpdateType.MAJOR),
    (Version('2.1.3'), Version('2.2.5'), None),
])
def test_check_update_type(prev_version, new_version, expected_res):
    """
    Given:
        - Version bumped by revision + 1.
        - Version bumped by minor + 1.
        - Version bumped by major + 1.
        - Version bumped from 2.1.3 to 2.2.5.
    When:
        - Checking that the bump version is legal and finding the update type.
    Then:
        - Right update type returned.
    """
    res = AllowedBumpCondition.check_update_type(prev_version=prev_version, new_version=new_version)
    assert res == expected_res


def test_pack_auto_bumper(tmp_path, mocker):
    """
    Given:

    When:

    Then:

    """
    pack = tmp_path / 'Packs'
    pack.mkdir()
    pack_path = pack / "MyPack"
    pack_path.mkdir()
    rn_path = pack_path / "ReleaseNotes"
    rn_path.mkdir()
    rn_file = rn_path / "1_0_5.md"
    bc_file = rn_path / "1_0_5.json"
    metadata_file = pack_path / "pack_metadata.json"
    rn_text = '## MyIntegration \n My Changes.'
    rn_file.write_text(rn_text)
    bc_file.write_text(json.dumps({'breakingChanges': True, 'breakingChangesNotes': 'My Notes'}))
    metadata_file.write_text(json.dumps({'name': 'MyPack', 'currentVersion': '1.0.5'}))
    mocker.patch.object(UpdateRN, 'get_master_version', return_value='1.0.5')
    pack_auto_bumper = PackAutoBumper(pack_id='MyPack', rn_file_path=rn_file, update_type=UpdateType.MINOR)
    pack_auto_bumper.set_pr_changed_rn_related_data()
    mocker.patch.object(UpdateRN, 'bump_version_number', return_value=('1.1.0',
                                                                       {'name': 'MyPack', 'currentVersion': '1.1.0'}))
    new_rn = rn_path / '1_1_0.md'
    mocker.patch.object(UpdateRN, 'get_release_notes_path', return_value=str(new_rn))
    new_version = pack_auto_bumper.autobump()
    assert new_version == '1.1.0'
    assert new_rn.read_text() == rn_text

