from demisto_sdk.TestSuite.repo import Repo


def test_get_release_notes_dict():
    from release_notes_generator import get_release_notes_dict
    repo = Repo()
    pack = repo.create_pack('FakePack')
    pack.add_release_notes()

    mocker.patch.object(demisto_sdk.commands.common.tools, 'get_pack_name', return_value='FakePack')
    release_notes_dict = get_release_notes_dict(release_notes_files)  # todo: fix
    assert release_notes_dict.get('')
