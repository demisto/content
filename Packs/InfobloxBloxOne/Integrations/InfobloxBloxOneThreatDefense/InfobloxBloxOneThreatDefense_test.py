from InfobloxBloxOneThreatDefense import *


def load_json_file(file_description):
    file_path = Path(__file__).parent / 'test_data' / f'{file_description}.json'
    with open(file_path, 'r') as f:
        return json.load(f)


class E2ETest:
    def test_x(self, requests_mock):
        pass


class TestBloxOneTDClient:
    
    pass


class TestUnitTests:
    pass