from Tests.mock_server import AMIConnection, clean_filename, get_mock_file_path, get_log_file_path, get_folder_path
from Tests.test_content import organize_tests


def test_clean_filename():
    assert clean_filename(u'th)))i(s) is a (test8)8   8') == 'th___i_s__is_a__test8_8___8'
    assert clean_filename(u'n&%ew $r#eplac@es', replace='&%$#@') == 'n__ew _r_eplac_es'


def test_silence_output():
    # TODO: How to check output is redirected to /dev/null ?
    pass


def test_get_paths():
    test_playbook_id = u'test_playbook'
    assert get_mock_file_path(test_playbook_id) == 'test_playbook/test_playbook.mock'
    assert get_log_file_path(test_playbook_id) == 'test_playbook/test_playbook_playback.log'
    assert get_log_file_path(test_playbook_id, record=True) == 'test_playbook/test_playbook_record.log'
    assert get_folder_path(test_playbook_id) == 'test_playbook/'


# TODO: Maybe mock subprocess functions??
with patch('Tests.mock_server.AMIConnection._get_docker_ip') as mock:
    mock.return_value = "2.2.2.2"

    ami = AMIConnection('1.1.1.1')


    def test_ami():
        assert ami.public_ip == '1.1.1.1'
        assert ami.docker_ip == '2.2.2.2'


def test_integration_list_split_by_unmockable():
    test1 = {
        'integrations': ['mockable', 'unmockable', 'mockable1', 'unmockable1']
    }
    test2 = {}
    test3 = {
        'integrations': ['mockable']
    }
    tests = [test1, test2, test3]
    unmockable_integrations = {'unmockable': "", 'unmockable1': ""}

    mockable, unmockable = organize_tests(tests, unmockable_integrations, {}, [])

    assert mockable == [test3]
    assert unmockable == [test1, test2]
