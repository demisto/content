import pytest
from CrowdStrikeFalconIntel_v2 import *
from CommonServerPython import DBotScoreType, Common, DemistoException


class TestClientHelperFunctions:
    QUERY_PARAMS = ['offset', 'limit', 'sort', 'q']
    DATE_PARAMS = {
        'created_date': {'operator': '', 'raw_name': 'created_date'},
        'max_last_modified_date': {'operator': '<=', 'api_key': 'last_modified_date'},
        'min_last_activity_date': {'operator': '>=', 'api_key': 'first_activity_date'},
        'max_last_activity_date': {'operator': '<=', 'api_key': 'last_activity_date'}
    }

    @pytest.mark.parametrize('args, output', [
        ({'query': 1}, {'filter': 1}),
        ({'wow': 1}, {'filter': "wow:'1'"})
    ])
    def test_build_request_params(self, args, output, mocker):
        mocker.patch.object(CrowdStrikeClient, "_generate_token")
        client = Client({})
        assert client.build_request_params(args) == output

    @pytest.mark.parametrize('args, output', [
        ({'offset': 1, 'max_last_modified_date': '2020-09-16T22:28:42.143302', 'wow': 2},
         "last_modified_date:<=1600295322+wow:'2'")
    ])
    def test_build_filter_query(self, args, output, mocker):
        mocker.patch.object(CrowdStrikeClient, "_generate_token")
        client = Client({})
        assert client.build_filter_query(args) == output


class TestHelperFunctions:
    INDICATOR_RESOURCE = {
        "_marker": "1600081765f9d74900f63c77b0b570a38c42244b8a",
        "actors": [],
        "deleted": False,
        "domain_types": [],
        "id": "hash_sha1_873ac498179c3d642d816f74dfd42a4e7cdf5bc4",
        "indicator": "873ac498179c3d642d816f74dfd42a4e7cdf5bc4",
        "ip_address_types": [],
        "kill_chains": [],
        "labels": [
            {
                "created_on": 1600081757,
                "last_valid_on": 1600081757,
                "name": "ThreatType/Criminal"
            },
            {
                "created_on": 1600081757,
                "last_valid_on": 1600081757,
                "name": "ThreatType/SpamBot"
            },
            {
                "created_on": 1591207986,
                "last_valid_on": 1591207986,
                "name": "CSD/CSIT-18125"
            },
            {
                "created_on": 1600081754,
                "last_valid_on": 1600081765,
                "name": "MaliciousConfidence/High"
            },
            {
                "created_on": 1600081757,
                "last_valid_on": 1600081757,
                "name": "Malware/SendSafe"
            }
        ],
        "last_updated": 1600081765,
        "malicious_confidence": "high",
        "malware_families": [
            "SendSafe"
        ],
        "published_date": 1600081754,
        "relations": [
            {
                "created_date": 1600081757,
                "id": "hash_md5_afd591503665a5a5073ddf93cdc97c2b",
                "indicator": "afd591503665a5a5073ddf93cdc97c2b",
                "last_valid_date": 1600081757,
                "type": "hash_md5"
            },
            {
                "created_date": 1600081757,
                "id": "ip_address_91.220.131.49",
                "indicator": "91.220.131.49",
                "last_valid_date": 1600081757,
                "type": "ip_address"
            },
            {
                "created_date": 1600081757,
                "id": "hash_sha1_1a3986bf774fa1b841147ef7c1bb2d965f0f0664",
                "indicator": "1a3986bf774fa1b841147ef7c1bb2d965f0f0664",
                "last_valid_date": 1600081757,
                "type": "hash_sha1"
            },
            {
                "created_date": 1600081757,
                "id": "hash_sha256_34bd0ce42c46f8688f9c12747e5ad0d12233f5d26f290ce9f325372466c836e7",
                "indicator": "34bd0ce42c46f8688f9c12747e5ad0d12233f5d26f290ce9f325372466c836e7",
                "last_valid_date": 1600081757,
                "type": "hash_sha256"
            },
            {
                "created_date": 1600081754,
                "id": "hash_sha256_cdde31156a757ce3460ba684be966782697b09b1f882d82bc5fb95b916a07f6a",
                "indicator": "cdde31156a757ce3460ba684be966782697b09b1f882d82bc5fb95b916a07f6a",
                "last_valid_date": 1600081754,
                "type": "hash_sha256"
            },
            {
                "created_date": 1600081754,
                "id": "hash_md5_42ffa45446a1158d09cec9db8e274573",
                "indicator": "42ffa45446a1158d09cec9db8e274573",
                "last_valid_date": 1600081754,
                "type": "hash_md5"
            }
        ],
        "reports": [
            "CSIT-18125"
        ],
        "targets": [],
        "threat_types": [
            "Criminal",
            "SpamBot"
        ],
        "type": "hash_sha1",
        "vulnerabilities": []
    }
    INDICATOR_OUTPUT = {
        "ID": "hash_sha1_873ac498179c3d642d816f74dfd42a4e7cdf5bc4",
        "Type": "hash_sha1",
        "Value": "873ac498179c3d642d816f74dfd42a4e7cdf5bc4",
        "MaliciousConfidence": "high",
        "Reports": [
            "CSIT-18125"
        ],
        "MalwareFamilies": [
            "SendSafe"
        ],
        "Relations": ["hash_md5: afd591503665a5a5073ddf93cdc97c2b",
                      "ip_address: 91.220.131.49",
                      "hash_sha1: 1a3986bf774fa1b841147ef7c1bb2d965f0f0664",
                      "hash_sha256: 34bd0ce42c46f8688f9c12747e5ad0d12233f5d26f290ce9f325372466c836e7",
                      "hash_sha256: cdde31156a757ce3460ba684be966782697b09b1f882d82bc5fb95b916a07f6a",
                      "hash_md5: 42ffa45446a1158d09cec9db8e274573"
                      ],
        "Labels": [
            "ThreatType/Criminal",
            "ThreatType/SpamBot",
            "CSD/CSIT-18125",
            "MaliciousConfidence/High",
            "Malware/SendSafe"
        ]
    }

    def test_get_score_from_resource(self):
        assert get_score_from_resource(TestHelperFunctions.INDICATOR_RESOURCE) == 3

    @pytest.mark.parametrize('hash_value, hash_type, exception', [
        ('88302dbc829636b6ef926f0f055bdebd', 'hash_md5', False),
        ('D2C4535AD4CBCCF3C8E3FF580669958766DDE1CE', 'hash_sha1', False),
        ('9BA81ADE4C162975230BDADCD9D60F00A37907FC10782B76B287B057470F0760', 'hash_sha256', False),
        ('wow', '', True)
    ])
    def test_get_indicator_hash_type(self, hash_value, hash_type, exception):
        if not exception:
            assert get_indicator_hash_type(hash_value) == hash_type
        else:
            with pytest.raises(DemistoException):
                get_indicator_hash_type(hash_value)

    @pytest.mark.parametrize('ind_val, ind_type, dbot_score, output', [
        ('8.8.8.8', 'ip', Common.DBotScore(indicator='8.8.8.8', indicator_type=DBotScoreType.IP,
                                           integration_name='FalconIntel', score=0, malicious_description=''),
         Common.IP(ip='8.8.8.8', dbot_score=Common.DBotScore(indicator='8.8.8.8', indicator_type=DBotScoreType.IP,
                                                             integration_name='FalconIntel', score=0,
                                                             malicious_description=''))),
        ('wow', 'wow', Common.DBotScore(indicator='CVE-1999-0067', indicator_type=DBotScoreType.CVE,
                                        integration_name='FalconIntel', score=0, malicious_description=''), None)
    ])
    def test_get_indicator_object(self, ind_val, ind_type, dbot_score, output):
        if not output:
            assert get_indicator_object(ind_val, ind_type, dbot_score) == output
        else:
            assert get_indicator_object(ind_val, ind_type, dbot_score).to_context() == \
                   output.to_context()

    @pytest.mark.parametrize('items_list, ret_type, keys, output', [
        ([{'value': 1, 'name': 2}], 'str', 'value', '1'),
        ([{'value': 1, 'name': 2}], 'list', 'value', [1]),
        ([{'value': 1, 'name': 2, 'wow': 3}], 'list', ['value', 'name'], [{'Value': 1, 'Name': 2}]),
        ([{'value': 1, 'name': 2, 'wow': 3}], 'str', ['value', 'name'], "{'Value': 1, 'Name': 2}")

    ])
    def test_get_values(self, items_list, ret_type, keys, output):
        assert get_values(items_list, ret_type, keys) == output

    def test_get_indicator_data(self):
        output = get_indicator_outputs(TestHelperFunctions.INDICATOR_RESOURCE)
        assert output == TestHelperFunctions.INDICATOR_OUTPUT

    @pytest.mark.parametrize('_type, output, exception', [
        ('ip', DBotScoreType.IP, False),
        ('domain', DBotScoreType.DOMAIN, False),
        ('file', DBotScoreType.FILE, False),
        ('hash', DBotScoreType.FILE, False),
        ('url', DBotScoreType.URL, False),
        ('wow', None, True)
    ])
    def test_get_dbot_score_type(self, _type, output, exception):
        if exception:
            with pytest.raises(DemistoException, match='Indicator type is not supported.'):
                get_dbot_score_type(_type)
        else:
            assert get_dbot_score_type(_type) == output
