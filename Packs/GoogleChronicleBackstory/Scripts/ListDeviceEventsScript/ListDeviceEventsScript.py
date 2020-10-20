from CommonServerPython import *

asset_identifier = demisto.args().get('asset_identifier')

asset_identifier_type = 'Host Name'
if is_mac_address(asset_identifier):
    asset_identifier_type = 'MAC Address'
if is_ip_valid(asset_identifier, accept_v6_ips=True):
    asset_identifier_type = 'IP Address'

result = demisto.executeCommand('gcb-list-events',
                                {
                                    'asset_identifier': asset_identifier,
                                    'asset_identifier_type': asset_identifier_type
                                }
                                )
demisto.results(result)
