from ExpanseParseRawIncident import parse_raw
import json


def test_parse_raw():
    readable_output, parsed, raw = parse_raw(json.dumps(MOCK_RAW_JSON))

    raw_json = MOCK_RAW_JSON
    assert parsed['expanse_raw_json_event']['eventType'] == raw_json['eventType']


MOCK_RAW_JSON = {
    "eventType": "ON_PREM_EXPOSURE_REAPPEARANCE",
    "eventTime": "2020-02-09T00:00:00Z",
    "businessUnit": {
        "id": "a1f0f39b-f358-3c8c-947b-926887871b88",
        "name": "VanDelay Import-Export"
    }, "payload": {
        "_type": "ExposurePayload",
        "id": "6752a761-0cb4-3b23-85f1-61ea48d3e1b5",
        "exposureType": "RDP_SERVER",
        "ip": "61.132.170.14",
        "port": 3389,
        "portProtocol": "TCP",
        "exposureId": "2c23500a-6466-330f-996c-1e4657d72452",
        "domainName": False, "scanned": "2020-02-09T00:00:00Z",
        "geolocation": {
            "latitude": 30.95,
            "longitude": 117.78,
            "city": "TONGLING",
            "regionCode": "AH",
            "countryCode": "CN"
        }, "configuration": {
            "_type": "RdpServerConfiguration",
            "nativeRdpProtocol": True,
            "credSspProtocol": False,
            "sslProtocol": False,
            "nativeRdpAlgorithms": ["56-bit-RC4", "128-bit-RC4", "40-bit-RC4"],
            "certificateId": False
        }, "severity": "CRITICAL",
        "tags": {
            "ipRange": ["untagged"]},
        "providers": ["InternallyHosted"],
        "certificatePem": False,
        "remediationStatuses": []
    }, "id": "98df4bb9-ab17-33f5-87ed-ce851e591d78"
}
