from demisto_sdk.demisto_sdk.TestSuite.test_tools import ChangeCWD
from release_notes_generator import get_release_notes_dict, generate_release_notes_summary, \
    RELEASE_NOTES_FILE, IGNORE_RN

DUMMY_RELEASE_NOTE_CONTENT = 'This is a release note.'
VERSION = 'VERSION'
ASSET_ID = 'ASSET_ID'

def ignore_release_note_update(file_path):
    with open(file_path, 'w+') as rn_file:
        rn_file.write(IGNORE_RN)


def get_release_note_files(repo):
    release_notes_files = []
    for pack in repo.packs:
        release_notes_files.extend([rn.path for rn in pack.release_notes])
    return release_notes_files


def create_dummy_pack_with_release_notes(repo, pack_name):
    pack = repo.create_pack(pack_name)

    pack.create_integration(pack_name + '_FakeIntegration_1')
    pack.create_integration(pack_name + '_FakeScript_1')

    # add release notes 1.0.1
    pack.update_release_notes('revision')
    pack.release_notes[0].fill()

    pack.create_integration(pack_name + '_FakeIntegration_2')

    # add release notes 2.0.0
    pack.update_release_notes('major')
    pack.release_notes[0].fill(DUMMY_RELEASE_NOTE_CONTENT)

    return pack


def check_assertions_on_release_notes_dict(rn_dict):
    assert '1.0.1' not in rn_dict['FakePack_1'].keys()
    assert DUMMY_RELEASE_NOTE_CONTENT in rn_dict['FakePack_1']['2.0.0']
    assert len(rn_dict['FakePack_2'].items()) == 2


def check_assertions_on_release_notes_summary():
    with open(RELEASE_NOTES_FILE, 'r') as rn_summary_file:
        rn_summary = rn_summary_file.read()
        assert '# Cortex XSOAR Content Release Notes for version {} ({})\n'.format(VERSION, ASSET_ID)

        assert '## FakePack_1 Pack v1.0.1' not in rn_summary
        assert '- __FakePack_1_FakeScript_1__' not in rn_summary
        assert '- __FakePack_1_FakeIntegration_2__' in rn_summary
        assert '## FakePack_1 Pack v2.0.0' in rn_summary
        assert '- __FakePack_1_FakeIntegration_2__' in rn_summary

        assert '## FakePack_2 Pack v1.0.1' in rn_summary
        assert '- __FakePack_1_FakeScript_1__' in rn_summary
        assert '- __FakePack_1_FakeIntegration_2__' in rn_summary
        assert '## FakePack_2 Pack v2.0.0' in rn_summary
        assert '- __FakePack_2_FakeIntegration_2__' in rn_summary

        assert DUMMY_RELEASE_NOTE_CONTENT in rn_summary


def test_release_notes_generator(request: FixtureRequest, tmp_path_factory: TempPathFactory):
    """
    Given
    - A content repository with valid packs.

    When
    - Adding integrations and updating release notes.

    Then
    - Ensure release notes generator creates a valid summary.
    """
    repo = get_repo(request, tmp_path_factory)
    with ChangeCWD(repo.path):
        pack_1 = create_dummy_pack_with_release_notes(repo, 'FakePack_1')
        pack_2 = create_dummy_pack_with_release_notes(repo, 'FakePack_2')
        ignore_release_note_update(pack_1.releasenotes[0].file_path)

        release_notes_files = get_release_note_files(repo)
        rn_dict = get_release_notes_dict(release_notes_files)

        check_assertions_on_release_notes_dict(rn_dict)

        generate_release_notes_summary(rn_dict, VERSION, ASSET_ID)
        check_assertions_on_release_notes_summary()


