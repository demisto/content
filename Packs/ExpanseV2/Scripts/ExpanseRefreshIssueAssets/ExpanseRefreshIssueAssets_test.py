import demistomock as demisto  # noqa

import ExpanseRefreshIssueAssets


EXAMPLE_INCIDENT = {
    'CustomFields': {
        'expanseasset': [
            {'assettype': 'Certificate', 'assetkey': 'fakeMD5'},
            {'assettype': 'IpRange', 'assetkey': 'fakeIPRange'},
            {'assettype': 'Domain', 'assetkey': 'fakeDomain'},
        ]
    }
}


REFRESH_RESULT = {'expanseasset': [{'assettype': 'Certificate',
                                    'assetkey': 'fakeMD5',
                                    'tags': 'tag-certificate',
                                    'attributionReasons': 'fake-certificate-reason1\nfake-certificate-reason2'},
                                   {'assettype': 'IpRange',
                                    'assetkey': 'fakeIPRange',
                                    'tags': 'tag-iprange1\ntag-iprange2',
                                    'attributionReasons': 'fake-iprange-reason'},
                                   {'assettype': 'Domain',
                                    'assetkey': 'fakeDomain',
                                    'tags': 'tag-domain',
                                    'attributionReasons': 'fake-domain-reason'},
                                   ]}


ASSET_CERTIFICATE = {
    'annotations': {
        'tags': [{'name': 'tag-certificate'}]
    },
    'attributionReasons': [{'reason': 'fake-certificate-reason1'}, {'reason': 'fake-certificate-reason2'}]
}


ASSET_IPRANGE = {
    'annotations': {
        'tags': [{'name': 'tag-iprange1'}, {'name': 'tag-iprange2'}]
    },
    'attributionReasons': [{'reason': 'fake-iprange-reason'}]
}


ASSET_DOMAIN = {
    'annotations': {
        'tags': [{'name': 'tag-domain'}]
    },
    'attributionReasons': [{'reason': 'fake-domain-reason'}]
}


def test_refresh_issue_assets_command(mocker):
    """
    Given:
        - current incident with iprange, domain and certificate assets
    When
        - Refreshing Expanse assets for an incident
    Then
        - commands are invoked to refresh asset data
        - incident is updated with the refreshed asset data
    """
    def executeCommand(name, args):
        if name == "expanse-get-domain" and args['domain'] == 'fakeDomain':
            return [{'Contents': ASSET_DOMAIN}]
        elif name == "expanse-get-iprange" and args['id'] == 'fakeIPRange':
            return [{'Contents': ASSET_IPRANGE}]
        elif name == "expanse-get-certificate" and args['hash'] == 'fakeMD5':
            return [{'Contents': ASSET_CERTIFICATE}]
        elif name == "setIncident":
            return "OK"

        raise ValueError(f"Error: Unknown command or command/argument pair: {name} {args!r}")

    mocker.patch.object(demisto, 'incident', return_value=EXAMPLE_INCIDENT)
    ec_mock = mocker.patch.object(demisto, 'executeCommand', side_effect=executeCommand)

    result = ExpanseRefreshIssueAssets.refresh_issue_assets_command({})

    assert result.readable_output == "OK"
    assert len(ec_mock.call_args_list) == 4
    assert ec_mock.call_args_list[3][0][0] == "setIncident"
    assert ec_mock.call_args_list[3][0][1] == REFRESH_RESULT
