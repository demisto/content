
from PacketCapture import Client


def create_mock_client():

    return Client(base_url="https://localhost:41395")


class TestCaptureSearch:
    api_checkstatus = "https://10.255.254.131:41395/v3/fmsearch/"\
        "status?rest_token=c160b695-643e-afb4-6bff-1e980cbe6d48&searchname=continuum_1687041672_1_dctest11"

    api_getpcaps = "https://10.255.254.131:41395/v3/fmsearch/data"\
        "?rest_token=c160b695-643e-afb4-6bff-1e980cbe6d48&searchname=continuum_1687041672_1_dctest11&type=1"

    api_metadata = "https://10.255.254.131:41395/v3/fmsearch/data"\
        "?rest_token=c160b695-643e-afb4-6bff-1e980cbe6d48&searchname=continuum_1687041672_1_dctest11&type=LogData"

    api_objects = "https://10.255.254.131:41395/v3/fmsearch/data"\
        "?rest_token=c160b695-643e-afb4-6bff-1e980cbe6d48&searchname=continuum_1687041672_1_dctest11&type=SearchObjects"

    api_response = {'checkstatus': api_checkstatus,
                    'getpcaps': api_getpcaps,
                    'metadata': api_metadata,
                    'objects': api_objects}

    api_response_status = {"ServerInfo": {
        "NodeName": "test",
        "NodeIP": "127.0.0.1",
        "Upordown": "1",
        "Port": "[0:10 Gbps  1:Down  ]",
        "Status": "Running",
        "Duration": "08:22:11:00",
        "BeginTime": "2024-03-16 13:52:00",
        "EndTime": "2024-03-25 12:03:00",
        "License": "Evaluation",
        "TimeZone": "UTC",
        "PreCaptureFilter": "Off",
        "VirtualStorage": "1.26T",
        "RealStorage": "1.00T",
        "Capturedrops": "0",
        "BeginTimeSeconds": "1710597120",
        "CaptureServerTime": "139858900357280",
        "Throughput": "0.00",
        "CompressionRatio": "1.26",
        "ClusterCount": "0",
        "tcppps": "0",
        "udppps": "0",
        "otherpps": "0",
        "totalpps": "0",
        "LogDataCompressionRatio": "0.00",
        "PercentIOWait": "0.00",
        "LoadAverage": "5.27 5.19 5.08"},
        "FMNodes": {"authenticationmode": "",
                    "throughput": "0.00",
                    "nodename": "test_id",
                    "node_ip": "192.168.1.4",
                    "UserName": "continuum",
                    "Password": "",
                    "Token": "",
                    "groupname": "g1",
                    "port": "[0:10 Gbps  1:Down  ]",
                    "status": "Running",
                    "compressionratio": "1.26",
                    "virtualstorage": "1.26T",
                    "realstorage": "1.00T",
                    "begintime": "2024-03-16 13:52:00",
                    "endtime": "2024-03-25 12:03:00",
                    "license": "Evaluation",
                    "capturemode": "",
                    "precapturefilter": "Off",
                    "duration": "08:22:11:00",
                    "timezone": "UTC",
                    "serverinfo": "0:0:0:0:0:0.00:0.28:4.86 5.09 5.05",
                    "clusternodecount": "",
                    "other": "",
                    "serverip": "192.168.1.4",
                    "percentiowait": "",
                    "loadaverage": "",
                    "selected": "0"},
        "UserName": "",
        "Role": "",
        "Users": "",
        "Groups": {"groupname": "g1",
                    "groupcount": 1,
                    "aggregate_throughput": "0",
                    "userslist": "dcanalystrole,analyst",
                    "selected": "0"},
        "AuthMode": "",
        "Version": "7.3.0.309-408.14r4.52",
        "UserRoles": "",
        "ApiVersion": "1.4"}

    def __init__(self):

        self.client = create_mock_client()

    def test_search(self, mocker):
        """
        Given:
            - Search criteria to find packets of interest 
        Then:
            - Returns hyperlinks to data returned by search 
        """

        postData = {'rest_token': 'c160b695-643e-afb4-6bff-1e980cbe6d48',
                    'search_name': 'test search',
                    'search_filter': 'dest_port:80',
                    'begin_time': '2022-06-10 10:22:00',
                    'end_time': '2022-06- 11 10:22:00',
                    'max_packets': '100'}

        mocker.patch.object(self.client, 'basic_search', self.api_response)

        server_response = self.client.basic_search(postData)

        assert (server_response['checkstatus'] == self.api_checkstatus)

        assert (server_response['getpcaps'] == self.api_getpcaps)

        assert (server_response['metadata'] == self.api_metadata)

        assert (server_response['objects'] == self.api_objects)

    def test_status(self, mocker):
        """
        Given:
            - Url to communicate with server 
        When:
            - Running to check connectivity of remote server 
        Then:
            - Returning metadata describing currently running system
        """

        api_url = "/v3/fmping?rest_token=c160b695-643e-afb4-6bff-1e980cbe6d48"

        mocker.patch.object(self.client, 'get_status', self.api_response_status)

        server_response = self.client.get_status(api_url)

        assert server_response['Version'] == '7.3.0.309-408.14r4.52'

        assert server_response['ServerInfo']['Upordown'] == 1
