import demistomock as demisto
from VerifyIPv4Indicator import main


def test_main(mocker):
    """
    Given:
        - MAC Address as input
    When:
        - Running the script
    Then:
        - Ensure the MAC address is caught as invalid IPv4 and returns empty string
    """
    mocker.patch.object(demisto, "args", return_value={"input": "8.8.8.343"})
    mocker.patch.object(demisto, "results")
    main()
    demisto.results.assert_called_with("")
