import demistomock as demisto


def test_fetch_indicators_main(mocker):
    """
    Given
    - indicators response from google ip feed

    When
    - Running main flow for fetching indicators command

    Then
    - Ensure that all indicators values exist and are not 'None'
    """
    from FeedGoogleIPRanges import main
    from JSONFeedApiModule import Client

    mocker.patch.object(
        demisto, 'params', return_value={
            'feed': True, 'feedBypassExclusionList': False, 'feedExpirationInterval': '20160',
            'feedExpirationPolicy': 'suddenDeath', 'feedFetchInterval': 1,
            'feedReliability': 'A - Completely reliable', 'feedReputation': 'None', 'feedTags': None,
            'insecure': True, 'ip_ranges': 'All available Google IP ranges', 'proxy': False, 'tlp_color': None
        }
    )
    mocker.patch.object(demisto, 'command', return_value='fetch-indicators')
    create_indicators_mocker = mocker.patch.object(demisto, 'createIndicators')

    mocker.patch.object(
        Client, 'build_iterator', side_effect=[
            (
                [{'ipv4Prefix': '1.1.1.1'}, {'ipv4Prefix': '1.2.3.4'}, {'ipv6Prefix': '1111:1111::/28'}],
                True
            ),
            (
                [],
                True
            )
        ]
    )

    main()

    assert create_indicators_mocker.call_args.args[0] == [
        {
            'type': 'CIDR', 'fields': {'tags': []}, 'value': '1.1.1.1', 'rawJSON': {'ipv4Prefix': '1.1.1.1'}
        },
        {
            'type': 'CIDR', 'fields': {'tags': []}, 'value': '1.2.3.4', 'rawJSON': {'ipv4Prefix': '1.2.3.4'}
        }
    ]
