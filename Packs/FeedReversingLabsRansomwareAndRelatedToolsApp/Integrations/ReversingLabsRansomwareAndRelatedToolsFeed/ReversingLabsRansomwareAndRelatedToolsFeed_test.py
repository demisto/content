from ReversingLabsRansomwareAndRelatedToolsFeed import create_indicator_object, confidence_to_score, \
    return_validated_params


RL_INDICATOR = {
    "indicatorValue": "91.243.59.62",
    "indicatorType": "ipv4",
    "daysValid": 30,
    "confidence": 100,
    "rating": 4.0,
    "indicatorTags": {
        "mitre": [
            "T1071 Application Layer Protocol",
            "T1095 Non-Application Layer Protocol",
            "T1105 Ingress Tool Transfer",
            "T1571 Non-Standard Port",
            "T1573 Encrypted Channel"
        ],
        "source": "ReversingLabs",
        "malwareFamilyName": "AgentTesla",
        "lifecycleStage": "Middle",
        "malwareType": "Trojan",
        "port": [
            "TCP-80"
        ],
        "Protocol": [
            "HTTP"
        ]
    },
    "lastUpdate": "2021-11-24T00:09:40Z",
    "deleted": False
}


XSOAR_INDICATOR = {
    "value": "91.243.59.62",
    "type": "IP",
    "rawJSON": RL_INDICATOR,
    "fields": {
        "lastseenbysource": "2021-11-24T00:09:40+00:00",
        "malwaretypes": "Trojan",
        "malwarefamily": "AgentTesla",
        "port": [
            "TCP-80"
        ],
        "tags": [
            "T1071 Application Layer Protocol",
            "T1095 Non-Application Layer Protocol",
            "T1105 Ingress Tool Transfer",
            "T1571 Non-Standard Port",
            "T1573 Encrypted Channel",
            "HTTP",
            "Middle",
            "ReversingLabs",
            "MyCustomTag",
            "AnotherCustomTag"
        ]
    },
    "score": 3
}


PARAMS = {
    "hours": 7,
    "indicatorTypes": ["ipv4", "domain", "Hash", "uri"]
}


def test_confidence_to_score():
    assert confidence_to_score(85) == 3
    assert confidence_to_score(15) == 2
    assert not confidence_to_score(1)


def test_create_indicator_object():
    indicator = create_indicator_object(rl_indicator=RL_INDICATOR, user_tag_list=["MyCustomTag", "AnotherCustomTag"],
                                        tlp_color_param=None)
    assert indicator == XSOAR_INDICATOR


def test_return_validated_params():
    hours_historical, indicator_types_param = return_validated_params(params=PARAMS)

    assert hours_historical <= 4
    assert isinstance(indicator_types_param, str)
    assert indicator_types_param == ",".join(PARAMS.get("indicatorTypes"))
