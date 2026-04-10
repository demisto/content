from ReversingLabsRansomwareAndRelatedToolsFeed import create_indicator_object, confidence_to_score, return_validated_params


RL_INDICATOR = {
    "indicatorValue": "197.232.50.85",
    "indicatorType": "ipv4",
    "daysValid": 30,
    "confidence": 100,
    "rating": 4.0,
    "indicatorTags": {
        "lifecycleStage": "Middle",
        "malwareType": "Trojan",
        "malwareFamilyName": "TrickBot",
        "mitre": [
            "T1071 Application Layer Protocol",
            "T1095 Non-Application Layer Protocol",
            "T1105 Ingress Tool Transfer",
            "T1573 Encrypted Channel",
        ],
        "source": "ReversingLabs",
        "port": ["TCP-443"],
        "asn": "AS36866::KE::JTL",
    },
    "lastUpdate": "2022-01-19T14:48:03Z",
    "deleted": False,
    "uuid": "indicator--4b827068-3ea0-567d-99ba-ec8ed160d1f7",
}


XSOAR_INDICATOR = {
    "value": "197.232.50.85",
    "type": "IP",
    "rawJSON": RL_INDICATOR,
    "fields": {
        "lastseenbysource": "2022-01-19T14:48:03+00:00",
        "malwaretypes": "Trojan",
        "malwarefamily": "TrickBot",
        "port": ["TCP-443"],
        "asn": "AS36866::KE::JTL",
        "tags": [
            "T1071 Application Layer Protocol",
            "T1095 Non-Application Layer Protocol",
            "T1105 Ingress Tool Transfer",
            "T1573 Encrypted Channel",
            "Middle",
            "ReversingLabs",
            "MyCustomTag",
            "AnotherCustomTag",
        ],
    },
    "score": 3,
}


PARAMS = {"hours": 7, "indicatorTypes": ["ipv4", "domain", "hash", "uri"]}


def test_confidence_to_score():
    assert confidence_to_score(85) == 3
    assert confidence_to_score(15) == 2
    assert not confidence_to_score(1)


def test_create_indicator_object():
    indicator = create_indicator_object(
        rl_indicator=RL_INDICATOR, user_tag_list=["MyCustomTag", "AnotherCustomTag"], tlp_color_param=None
    )

    assert indicator == XSOAR_INDICATOR


def test_return_validated_params():
    hours_historical, indicator_types_param = return_validated_params(params=PARAMS)

    assert hours_historical <= 4
    assert isinstance(indicator_types_param, str)
    assert indicator_types_param == ",".join(PARAMS.get("indicatorTypes"))
