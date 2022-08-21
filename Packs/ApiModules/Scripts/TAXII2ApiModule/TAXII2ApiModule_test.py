from CommonServerPython import *
from TAXII2ApiModule import Taxii2FeedClient, TAXII_VER_2_1, HEADER_USERNAME
from taxii2client import v20, v21
import pytest
import json

with open('test_data/stix_envelope_no_indicators.json', 'r') as f:
    STIX_ENVELOPE_NO_IOCS = json.load(f)

with open('test_data/stix_envelope_17-19.json', 'r') as f:
    STIX_ENVELOPE_17_IOCS_19_OBJS = json.load(f)

with open('test_data/stix_envelope_complex_20-19.json', 'r') as f:
    STIX_ENVELOPE_20_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_17-19.json', 'r') as f:
    CORTEX_17_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_complex_20-19.json', 'r') as f:
    CORTEX_COMPLEX_20_IOCS_19_OBJS = json.load(f)

with open('test_data/cortex_parsed_indicators_complex_skipped_14-19.json', 'r') as f:
    CORTEX_COMPLEX_14_IOCS_19_OBJS = json.load(f)
with open('test_data/id_to_object_test.json', 'r') as f:
    id_to_object = json.load(f)
with open('test_data/parsed_stix_objects.json', 'r') as f:
    parsed_objects = json.load(f)
with open('test_data/objects_envelopes_v21.json', 'r') as f:
    envelopes_v21 = json.load(f)
with open('test_data/objects_envelopes_v20.json', 'r') as f:
    envelopes_v20 = json.load(f)


class MockCollection:
    def __init__(self, id_, title):
        self.id = id_
        self.title = title


class TestInitCollectionsToFetch:
    """
    Scenario: Initialize collections to fetch
    """
    mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False, objects_to_fetch=[])
    default_id = 1
    nondefault_id = 2
    mock_client.collections = [MockCollection(nondefault_id, 'not_default'),
                               MockCollection(default_id, 'default')]

    def test_default_collection(self):
        """
        Scenario: Initialize with collection name provided in class __init__

        Given
        - collection name is provided via __init__ (title: default)
        - collection is available

        When
        - Initializing collection to fetch

        Then
        - Ensure initialized collection to fetch with collection provided in __init__
        """
        self.mock_client.init_collection_to_fetch()
        assert self.mock_client.collection_to_fetch.id == self.default_id

    def test_non_default_collection(self):
        """
        Scenario: Initialize with collection name provided via argument

        Given:
        - collection name is provided via argument (title: non_default)
        - collection is available

        When
        - Initializing collection to fetch

        Then
        - Ensure initialized collection to fetch with collection provided in argument
        """
        self.mock_client.init_collection_to_fetch('not_default')
        assert self.mock_client.collection_to_fetch.id == self.nondefault_id

    def test_collection_not_found(self):
        """
        Scenario: Fail to initialize with a collection that is not available

        Given:
        - collection name is provided via argument (title: not_found)
        - collection is NOT available

        When
        - Initializing collection to fetch

        Then:
        - Ensure exception is raised with proper error message
        """
        with pytest.raises(DemistoException, match="Could not find the provided Collection name"):
            self.mock_client.init_collection_to_fetch('not_found')

    def test_no_collections_available(self):
        """
        Scenario: Fail to initialize when there is no collection available

        Given:
        - collection name is provided via __init__ (title: default)
        - NO collection is available

        When
        - Initializing collection to fetch

        Then:
        - Ensure exception is raised with proper error message
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='default', proxies=[], verify=False,
                                       objects_to_fetch=[])
        with pytest.raises(DemistoException, match="No collection is available for this user"):
            mock_client.init_collection_to_fetch('not_found')


class TestBuildIterator:
    """
    Scenario: Get indicators via build_iterator method
    """

    def test_no_collection_to_fetch(self):
        """
        Scenario: Fail to build iterator when there is no collection to fetch from

        Given:
        - Collection to fetch is empty

        When:
        - Calling build_iterators

        Then:
        - Ensure exception is raised with proper error message
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
        with pytest.raises(DemistoException, match='Could not find a collection to fetch from.'):
            mock_client.build_iterator()

    def test_limit_0_v20(self, mocker):
        """
        Scenario: Call build iterator when limit is 0 and the collection is v20.Collection

        Given:
        - Limit is 0
        - Collection to fetch is of type v20.Collection

        When
        - Initializing collection to fetch

        Then:
        - Ensure 0 iocs are returned
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
        mocker.patch.object(mock_client, "collection_to_fetch", spec=v20.Collection)
        iocs = mock_client.build_iterator(limit=0)
        assert iocs == []

    def test_limit_0_v21(self, mocker):
        """
        Scenario: Call build iterator when limit is 0 and the collection is v21.Collection

        Given:
        - Limit is 0
        - Collection to fetch is of type v21.Collection

        When
        - Initializing collection to fetch

        Then:
        - Ensure 0 iocs are returned
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch=None, proxies=[], verify=False, objects_to_fetch=[])
        mocker.patch.object(mock_client, "collection_to_fetch", spec=v21.Collection)
        iocs = mock_client.build_iterator(limit=0)
        assert iocs == []


class TestInitServer:
    """
    Scenario: Initialize server
    """

    def test_default_v20(self):
        """
        Scenario: Initialize server with the default option

        Given:
        - no version is provided to init_server

        Then:
        - initialize with v20.Server
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
        mock_client.init_server()
        assert isinstance(mock_client.server, v20.Server)

    def test_v21(self):
        """
        Scenario: Initialize server with v21

        Given:
        - v21 version is provided to init_server

        Then:
        - initialize with v21.Server
        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
        mock_client.init_server(TAXII_VER_2_1)
        assert isinstance(mock_client.server, v21.Server)

    def test_auth_key(self):
        """
        Scenario: Initialize server with the default option with an auth key

        Given:
        - no version is provided to init_server
        - client is set with `auth_key` and `auth_header`

        Then:
        - initialize with v20.Server with _conn.headers set with the auth_header
        """
        mock_auth_header_key = 'mock_auth'
        mock_username = f'{HEADER_USERNAME}{mock_auth_header_key}'
        mock_password = 'mock_pass'
        mock_client = Taxii2FeedClient(
            url='',
            username=mock_username,
            password=mock_password,
            collection_to_fetch='',
            proxies=[],
            verify=False,
            objects_to_fetch=[]
        )
        mock_client.init_server()
        assert isinstance(mock_client.server, v20.Server)
        assert mock_auth_header_key in mock_client.server._conn.session.headers[0]
        assert mock_client.server._conn.session.headers[0].get(mock_auth_header_key) == mock_password


class TestInitRoots:
    """
    Scenario: Initialize roots
    """

    api_root_urls = ["https://ais2.cisa.dhs.gov/public/",
                     "https://ais2.cisa.dhs.gov/default/",
                     "https://ais2.cisa.dhs.gov/ingest/",
                     "https://ais2.cisa.dhs.gov/ciscp/",
                     "https://ais2.cisa.dhs.gov/federal/"]
    v20_api_roots = [v20.ApiRoot(url) for url in api_root_urls]
    v21_api_roots = [v21.ApiRoot(url) for url in api_root_urls]

    default_api_root_url = "https://ais2.cisa.dhs.gov/default/"
    v20_default_api_root = v20.ApiRoot(default_api_root_url)
    v21_default_api_root = v21.ApiRoot(default_api_root_url)

    def test_given_default_api_root_v20(self):
        """
        Given:
        - default_api_root is given

        When:
        - Initializing roots in v20

        Then:
        - api_root is initialized with the given default_api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default', proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root='federal')
        mock_client.init_server()
        self._title = ""
        mock_client.server._api_roots = self.v20_api_roots
        mock_client.server._default = self.v20_default_api_root
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == "https://ais2.cisa.dhs.gov/federal/"

    def test_no_default_api_root_v20(self):
        """
        Given:
        - default_api_root is not given, and there is no defined default api_root for the server

        When:
        - Initializing roots in v20

        Then:
        - api_root is initialized with the first api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default', proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root=None)
        mock_client.init_server()
        self._title = ""
        mock_client.server._api_roots = self.v20_api_roots
        mock_client.server._default = False
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == "https://ais2.cisa.dhs.gov/public/"

    def test_no_given_default_api_root_v20(self):
        """
        Given:
        - default_api_root is not given

        When:
        - Initializing roots in v20

        Then:
        - api_root is initialized with the server defined default api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default', proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root=None)
        mock_client.init_server()
        self._title = ""
        mock_client.server._api_roots = self.v20_api_roots
        mock_client.server._default = self.v20_default_api_root
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == self.default_api_root_url

    def test_given_default_api_root_v21(self):
        """
        Given:
        - default_api_root is given

        When:
        - Initializing roots in v21

        Then:
        - api_root is initialized with the given default_api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default', proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root='federal')
        mock_client.init_server(TAXII_VER_2_1)
        self._title = ""
        mock_client.server._api_roots = self.v21_api_roots
        mock_client.server._default = self.v21_default_api_root
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == "https://ais2.cisa.dhs.gov/federal/"

    def test_no_default_api_root_v21(self):
        """
        Given:
        - default_api_root is not given, and there is no defined default api_root for the server

        When:
        - Initializing roots in v21

        Then:
        - api_root is initialized with the first api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default', proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root=None)
        mock_client.init_server(TAXII_VER_2_1)
        self._title = ""
        mock_client.server._api_roots = self.v21_api_roots
        mock_client.server._default = False
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == "https://ais2.cisa.dhs.gov/public/"

    def test_no_given_default_api_root_v21(self):
        """
        Given:
        - default_api_root is not given

        When:
        - Initializing roots in v21

        Then:
        - api_root is initialized with the server defined default api_root
        """
        mock_client = Taxii2FeedClient(url='https://ais2.cisa.dhs.gov/taxii2/', collection_to_fetch='default', proxies=[],
                                       verify=False, objects_to_fetch=[], default_api_root=None)
        mock_client.init_server(TAXII_VER_2_1)
        self._title = ""
        mock_client.server._api_roots = self.v21_api_roots
        mock_client.server._default = self.v21_default_api_root
        mock_client.server._loaded = True

        mock_client.init_roots()
        assert mock_client.api_root.url == self.default_api_root_url


class TestFetchingStixObjects:
    """
    Scenario: Test load_stix_objects_from_envelope and parse_stix_objects
    """

    def test_21_empty(self):
        """
        Scenario: Test 21 envelope extract

        Given:
        - Envelope with 0 STIX2 objects

        When:
        - extract_indicators_from_envelope_and_parse is called

        Then:
        - Extract and parse the indicators from the envelope

        """
        expected = []
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope({"indicator": STIX_ENVELOPE_NO_IOCS}, -1)

        assert len(actual) == 0
        assert expected == actual

    def test_21_simple(self):
        """
        Scenario: Test 21 envelope extract

        Given:
        - Envelope with 19 STIX2 objects - out of them 17 are iocs

        When:
        - extract_indicators_from_envelope_and_parse is called

        Then:
        - Extract and parse the indicators from the envelope

        """
        expected = CORTEX_17_IOCS_19_OBJS
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, tlp_color='GREEN',
                                       objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope({"indicator": STIX_ENVELOPE_17_IOCS_19_OBJS}, -1)

        assert len(actual) == 17
        assert expected == actual

    def test_21_complex_not_skipped(self):
        """
        Scenario: Test 21 envelope complex extract without skip

        Given:
        - Envelope with 19 STIX2 objects - 14 normal iocs, 3 are complex indicators (x2 iocs), and 2 aren't indicators
        - skip is False

        When:
        - extract_indicators_from_envelope_and_parse is called

        Then:
        - Extract and parse the indicators from the envelope with the complex iocs

        """
        expected = CORTEX_COMPLEX_20_IOCS_19_OBJS
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, tlp_color='GREEN',
                                       objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope({"indicator": STIX_ENVELOPE_20_IOCS_19_OBJS}, -1)

        assert len(actual) == 20
        assert actual == expected

    def test_21_complex_skipped(self):
        """
        Scenario: Test 21 envelope complex extract with skip

        Given:
        - Envelope with 19 STIX2 objects - 14 normal iocs, 3 are complex indicators (x2 iocs), and 2 aren't indicators
        - skip is True

        When:
        - extract_indicators_from_envelope_and_parse is called

        Then:
        - Extract and parse the indicators from the envelope with the complex iocs

        """
        expected = CORTEX_COMPLEX_14_IOCS_19_OBJS
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, skip_complex_mode=True,
                                       objects_to_fetch=[])

        actual = mock_client.load_stix_objects_from_envelope({"indicator": STIX_ENVELOPE_20_IOCS_19_OBJS}, -1)

        assert len(actual) == 14
        assert actual == expected

    def test_load_stix_objects_from_envelope_v21(self):
        """
        Scenario: Test loading of STIX objects from envelope for v2.1

        Given:
        - Envelope with indicators, arranged by object type.

        When:
        - load_stix_objects_from_envelope is called

        Then: - Load and parse objects from the envelope according to their object type and ignore
        extension-definition objects.

        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
        objects_envelopes = envelopes_v21
        mock_client.id_to_object = id_to_object

        result = mock_client.load_stix_objects_from_envelope(objects_envelopes, -1)
        assert mock_client.id_to_object == id_to_object
        assert result == parsed_objects

    def test_load_stix_objects_from_envelope_v20(self):
        """
        Scenario: Test loading of STIX objects from envelope for v2.0

        Given:
        - Envelope with indicators, arranged by object type.

        When:
        - parse_generator_type_envelope is called (skipping condition from load_stix_objects_from_envelope).

        Then: - Load and parse objects from the envelope according to their object type and ignore
        extension-definition objects.

        """
        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[])
        objects_envelopes = envelopes_v20
        mock_client.id_to_object = id_to_object

        parse_stix_2_objects = {
            "indicator": mock_client.parse_indicator,
            "attack-pattern": mock_client.parse_attack_pattern,
            "malware": mock_client.parse_malware,
            "report": mock_client.parse_report,
            "course-of-action": mock_client.parse_course_of_action,
            "campaign": mock_client.parse_campaign,
            "intrusion-set": mock_client.parse_intrusion_set,
            "tool": mock_client.parse_tool,
            "threat-actor": mock_client.parse_threat_actor,
            "infrastructure": mock_client.parse_infrastructure
        }
        result = mock_client.parse_generator_type_envelope(objects_envelopes, parse_stix_2_objects)
        assert mock_client.id_to_object == id_to_object
        assert result == parsed_objects

    @pytest.mark.parametrize('last_modifies_client, last_modifies_param, expected_modified_result', [
        (None, None, None), (None, '2021-09-29T15:55:04.815Z', '2021-09-29T15:55:04.815Z'),
        ('2021-09-29T15:55:04.815Z', '2022-09-29T15:55:04.815Z', '2022-09-29T15:55:04.815Z')
    ])
    def test_update_last_modified_indicator_date(self, last_modifies_client, last_modifies_param, expected_modified_result):
        """
               Scenario: Test updating the last_fetched_indicator__modified field of the client.

               Given:
                - A : An empty indicator_modified_str parameter.
                - B : A client with empty last_fetched_indicator__modified field.
                - C : A client with a value in last_fetched_indicator__modified
                 and a valid indicator_modified_str parameter.

               When:
               - Calling the last_modified_indicator_date function with given parameter.

               Then: Make sure the right value is updated in the client's last_fetched_indicator__modified field.
               - A : last_fetched_indicator__modified field remains empty
               - B : last_fetched_indicator__modified field remains empty
               - C : last_fetched_indicator__modified receives new value
        """

        mock_client = Taxii2FeedClient(url='', collection_to_fetch='', proxies=[], verify=False, objects_to_fetch=[], )
        mock_client.last_fetched_indicator__modified = last_modifies_client
        mock_client.update_last_modified_indicator_date(last_modifies_param)

        assert mock_client.last_fetched_indicator__modified == expected_modified_result


class TestParsingSCOIndicators:

    # test examples taken from here - https://docs.oasis-open.org/cti/stix/v2.1/os/stix-v2.1-os.html#_64yvzeku5a5c

    @staticmethod
    @pytest.fixture()
    def taxii_2_client():
        return Taxii2FeedClient(
            url='', collection_to_fetch='', proxies=[], verify=False, tlp_color='GREEN', objects_to_fetch=[]
        )

    def test_parse_autonomous_system_indicator(self, taxii_2_client):
        """
        Given:
         - autonomous-system object

        When:
         - parsing the autonomous-system into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
        """
        autonomous_system_obj = {
            "type": "autonomous-system",
            "spec_version": "2.1",
            "id": "autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74",
            "number": 15139,
            "name": "Slime Industries",
            "rir": "ARIN"
        }

        xsoar_expected_response = [
            {
                'value': 15139,
                'score': Common.DBotScore.NONE,
                'rawJSON': autonomous_system_obj,
                'type': 'ASN',
                'fields': {
                    'stixid': 'autonomous-system--f720c34b-98ae-597f-ade5-27dc241e8c74',
                    'name': 'Slime Industries', 'tags': [], 'trafficlightprotocol': 'GREEN'
                }
            }
        ]

        assert taxii_2_client.parse_sco_autonomous_system_indicator(autonomous_system_obj) == xsoar_expected_response

    @pytest.mark.parametrize(
        '_object, xsoar_expected_response', [
            (
                {
                    "id": "ipv4-addr--e0caaaf7-6207-5d8e-8f2c-7ecf936b3c4e",  # ipv4-addr object.
                    "spec_version": "2.0",
                    "type": "ipv4-addr",
                    "value": "1.1.1.1"
                },
                [
                    {
                        'value': '1.1.1.1',
                        'score': Common.DBotScore.NONE,
                        'type': 'IP',
                        'fields': {
                            'stixid': 'ipv4-addr--e0caaaf7-6207-5d8e-8f2c-7ecf936b3c4e',
                            'tags': [], 'trafficlightprotocol': 'GREEN'
                        }
                    }
                ]
            ),
            (
                {
                    "type": "domain-name",  # domain object.
                    "spec_version": "2.1",
                    "id": "domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5",
                    "value": "example.com"
                },
                [
                    {
                        'fields': {
                            'stixid': 'domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5',
                            'tags': [],
                            'trafficlightprotocol': 'GREEN'
                        },
                        'rawJSON': {
                            'id': 'domain-name--3c10e93f-798e-5a26-a0c1-08156efab7f5',
                            'spec_version': '2.1',
                            'type': 'domain-name',
                            'value': 'example.com'
                        },
                        'score': Common.DBotScore.NONE,
                        'type': 'Domain',
                        'value': 'example.com'
                    }
                ]
            ),

        ]
    )
    def test_parse_general_sco_indicator(self, taxii_2_client, _object: dict, xsoar_expected_response: List[dict]):
        """
        Given:
         - general SCO object.

        When:
         - parsing the SCO indicator into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
        """
        xsoar_expected_response[0]['rawJSON'] = _object
        assert taxii_2_client.parse_general_sco_indicator(_object) == xsoar_expected_response

    def test_parse_file_sco_indicator(self, taxii_2_client):
        """
        Given:
         - file object

        When:
         - parsing the file into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
        """
        file_obj = {
            "type": "file",
            "spec_version": "2.1",
            "id": "file--90bd400b-89a5-51a5-b17d-55bc7719723b",
            "hashes": {
                "SHA-256": "841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649"
            },
            "name": "quêry.dll",
            "name_enc": "windows-1252"
        }

        xsoar_expected_response = [
            {
                'fields': {
                    'associatedfilenames': 'quêry.dll',
                    'md5': None,
                    'path': None,
                    'sha1': None,
                    'sha256': '841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649',
                    'size': None,
                    'stixid': 'file--90bd400b-89a5-51a5-b17d-55bc7719723b',
                    'tags': [],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': file_obj,
                'score': Common.DBotScore.NONE,
                'type': 'File',
                'value': '841a8921140aba50671ebb0770fecc4ee308c4952cfeff8de154ab14eeef4649'
            }
        ]

        assert taxii_2_client.parse_sco_file_indicator(file_obj) == xsoar_expected_response

    def test_parse_mutex_sco_indicator(self, taxii_2_client):
        """
        Given:
         - mutex object

        When:
         - parsing the mutex into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
        """
        mutex_obj = {
            "type": "mutex",
            "spec_version": "2.1",
            "id": "mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300",
            "name": "__CLEANSWEEP__"
        }

        xsoar_expected_response = [
            {
                'fields': {
                    'stixid': 'mutex--eba44954-d4e4-5d3b-814c-2b17dd8de300',
                    'tags': [],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': mutex_obj,
                'score': Common.DBotScore.NONE,
                'type': 'Mutex',
                'value': '__CLEANSWEEP__'
            }
        ]

        assert taxii_2_client.parse_sco_mutex_indicator(mutex_obj) == xsoar_expected_response

    def test_parse_sco_windows_registry_key_indicator(self, taxii_2_client):
        """
        Given:
         - windows registry object

        When:
         - parsing the windows registry into a format XSOAR knows to read.

        Then:
         - make sure all the fields are being parsed correctly.
        """
        registry_object = {
            "type": "windows-registry-key",
            "spec_version": "2.1",
            "id": "windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016",
            "key": "hkey_local_machine\\system\\bar\\foo",
            "values": [
                {
                    "name": "Foo",
                    "data": "qwerty",
                    "data_type": "REG_SZ"
                },
                {
                    "name": "Bar",
                    "data": "42",
                    "data_type": "REG_DWORD"
                }
            ]
        }

        xsoar_expected_response = [
            {
                'fields': {
                    'modified_time': None,
                    'number_of_subkeys': None,
                    'registryvalue': [
                        {
                            'data': 'qwerty',
                            'data_type': 'REG_SZ',
                            'name': 'Foo'
                        },
                        {
                            'data': '42',
                            'data_type': 'REG_DWORD',
                            'name': 'Bar'
                        }
                    ],
                    'stixid': 'windows-registry-key--2ba37ae7-2745-5082-9dfd-9486dad41016',
                    'tags': [],
                    'trafficlightprotocol': 'GREEN'
                },
                'rawJSON': registry_object,
                'score': Common.DBotScore.NONE,
                'type': 'Registry Key',
                'value': "hkey_local_machine\\system\\bar\\foo"
            }
        ]

        assert taxii_2_client.parse_sco_windows_registry_key_indicator(registry_object) == xsoar_expected_response
