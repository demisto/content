import json

""" helper functions """


def get_files_in_dir(mypath, only_with_ext=None):
    from os import listdir
    from os.path import isfile, join
    files_list = [f for f in listdir(mypath) if isfile(join(mypath, f))]
    if only_with_ext:
        return [f for f in files_list if f.endswith(only_with_ext)]
    return files_list


class TestStixDecode:
    FILE_PATH = 'FeedTAXII_test/StixDecodeTest'

    def test_decode(self):
        """Test decode on all files"""
        from FeedTAXII import StixDecode
        xml_files_names = get_files_in_dir(self.FILE_PATH, 'xml')
        for xml_f_name in xml_files_names:
            file_path = f'{self.FILE_PATH}/{xml_f_name}'
            with open(file_path, 'r') as xml_f:
                stix_str = xml_f.read()
                res = StixDecode.decode(stix_str)
                res_path = f'{file_path.rstrip(".xml")}-result.json'
                with open(res_path, 'r') as res_f:
                    expctd_res = json.load(res_f)
                    assert expctd_res == list(res[1])


# def test_fetch_indicators_command(mock):
#     from FeedTAXII import Client, fetch_indicators_command, get_indicators_command
#     mock.patch.object(demisto, 'getLastRun', return_value=None)
#     params = {
#         'discovery_service': 'https://test.taxiistand.com/read-only/services/discovery',
#         'collection': 'single-binding-fast',
#         'credentials': {
#             'identifier': 'guest',
#             'password': 'guest'
#         },
#         'initial_interval': '1000 days',
#         'polling_timeout': 30,
#         # 'poll_service': 'poll_service'
#     }
#     client = Client(**params)
#     get_indicators_command(client, params)
#     # fetch_indicators_command(client)
#
