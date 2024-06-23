import demistomock as demisto
from unittest.mock import MagicMock

import csv
from io import StringIO

data = {
    "value": "23.82.12.29",
    "description": "IP used by beebone C&C",
    "date_created": "2023-12-18 08:06",
    "info": "http://osint.bambenekconsulting.com/manual/beebone.txt",
}

# Convert the dictionary to a CSV string
csv_string = StringIO()
csv_writer = csv.DictWriter(csv_string, fieldnames=data.keys())
csv_writer.writeheader()
csv_writer.writerow(data)
csv_data = csv_string.getvalue()
csv_string.close()

# Convert the CSV string to a csv.DictReader object
csv_stringio = StringIO(csv_data)
csv_reader = csv.DictReader(csv_stringio)


def test_fetch_indicators_main(mocker):
    """
    Given
    - indicators response from bambenek consulting feed

    When
    - Running main flow for fetching indicators command

    Then
    - Ensure that all indicators values exist and are not 'None'
    """
    from FeedBambenekConsulting import main

    mocker.patch.object(
        demisto,
        "params",
        return_value={
            "feed": True,
            "feedBypassExclusionList": False,
            "feedExpirationInterval": "20160",
            "feedExpirationPolicy": "suddenDeath",
            "feedFetchInterval": 1,
            "feedReliability": "A - Completely reliable",
            "feedReputation": "None",
            "feedTags": None,
            "insecure": True,
            "proxy": False,
            "tlp_color": None,
            "url": "https://faf.bambenekconsulting.com/",
        },
    )
    mocker.patch.object(demisto, "command", return_value="fetch-indicators")
    create_indicators_mocker = mocker.patch.object(demisto, "createIndicators")
    API_CLIENT_MOCK = MagicMock()
    API_CLIENT_MOCK.build_iterator.return_value = [
        {
            "https://faf.bambenekconsulting.com/feeds/dga/c2-ipmasterlist.txt": {
                "result": csv_reader,
                "no_update": False,
            }
        }
    ]
    mocker.patch("CSVFeedApiModule.Client", return_value=API_CLIENT_MOCK)
    main()
    assert (
        create_indicators_mocker.call_args.args[0][0]["rawJSON"]["value"]
        == "23.82.12.29"
    )
    assert (
        create_indicators_mocker.call_args.args[0][0]["rawJSON"]["description"]
        == "IP used by beebone C&C"
    )
    assert (
        create_indicators_mocker.call_args.args[0][0]["rawJSON"]["date_created"]
        == "2023-12-18 08:06"
    )
    assert (
        create_indicators_mocker.call_args.args[0][0]["rawJSON"]["info"]
        == "http://osint.bambenekconsulting.com/manual/beebone.txt"
    )
