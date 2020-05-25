

def test_get_release_notes_dict():
    from release_notes_generator import get_release_notes_dict
    release_notes_files = [
        'Tests/scripts/infrastructure_tests/tests_data/fake_release_notes/1_0_1.md',
        'Tests/scripts/infrastructure_tests/tests_data/fake_release_notes/1_0_2.md',
        'Tests/scripts/infrastructure_tests/tests_data/fake_release_notes/1_0_3.md'
    ]

    mocker.patch.object(demisto_sdk.commands.common.tools, 'get_pack_name', return_value='FakePack')
    release_notes_dict = get_release_notes_dict(release_notes_files)  # todo: fix
    assert release_notes_dict.get('')
