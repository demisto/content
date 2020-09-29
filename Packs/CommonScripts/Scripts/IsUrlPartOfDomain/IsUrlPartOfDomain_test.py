import demistomock as demisto


def test_main_localhost_https(mocker):
    """
    Scenario: Make sure localhost https url is recognized as internal url

    Given:
    - URL contains https://localhost

    When:
    - Running the script

    Then:
    - Return localhost url with internal=true
    """
    from IsUrlPartOfDomain import main

    url = "https://localhost:443"
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Contents": "", "Type": "ok"}]
    )
    mocker.patch.object(demisto, "results")
    results = main(urls=url, domains="")
    assert results.outputs[0].get("URL") == url
    assert results.outputs[0].get("IsInternal") is True


def test_main_localhost_http(mocker):
    """
    Scenario: Make sure localhost http url is recognized as internal url

    Given:
    - URL contains http://localhost

    When:
    - Running the script

    Then:
    - Return localhost url with internal=true
    """
    from IsUrlPartOfDomain import main

    url = "http://localhost:8080"
    mocker.patch.object(
        demisto, "executeCommand", return_value=[{"Contents": "", "Type": "ok"}]
    )
    mocker.patch.object(demisto, "results")
    results = main(urls=url, domains="")
    assert results.outputs[0].get("URL") == url
    assert results.outputs[0].get("IsInternal") is True
