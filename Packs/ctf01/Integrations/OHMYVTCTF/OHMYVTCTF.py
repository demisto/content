import demistomock as demisto
from CommonServerPython import *

"""
An integration module for the Virus Total v3 API.
API Documentation:
    https://developers.virustotal.com/v3.0/reference
"""


'''
                               ;.;;;
                               ;;;;;
                               ;;;;;
                               ;;;;;
                               ;;;;;
                               ;;;;;
                               ;;;;;
                             ..;;;;;..
                              ':::::'
                                ':`
'''


INTEGRATION_NAME = "VirusTotal"
COMMAND_PREFIX = "vt"
INTEGRATION_ENTRY_CONTEXT = "VirusTotal"

INDICATOR_TYPE = {
    'ip': FeedIndicatorType.IP,
    'ip_address': FeedIndicatorType.IP,
    'domain': FeedIndicatorType.Domain,
    'file': FeedIndicatorType.File,
    'url': FeedIndicatorType.URL
}


""" RELATIONSHIP TYPE"""
RELATIONSHIP_TYPE = {
    'file': {
        'carbonblack_children': EntityRelationship.Relationships.CREATES,
        'carbonblack_parents': EntityRelationship.Relationships.CREATED_BY,
        'compressed_parents': EntityRelationship.Relationships.BUNDLED_IN,
        'contacted_domains': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'contacted_ips': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'contacted_urls': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'dropped_files': EntityRelationship.Relationships.DROPPED_BY,
        'email_attachments': EntityRelationship.Relationships.ATTACHES,
        'email_parents': EntityRelationship.Relationships.ATTACHMENT_OF,
        'embedded_domains': EntityRelationship.Relationships.EMBEDDED_IN,
        'embedded_ips': EntityRelationship.Relationships.EMBEDDED_IN,
        'embedded_urls': EntityRelationship.Relationships.EMBEDDED_IN,
        'execution_parents': EntityRelationship.Relationships.EXECUTED_BY,
        'itw_domains': EntityRelationship.Relationships.DOWNLOADS_FROM,
        'itw_ips': EntityRelationship.Relationships.DOWNLOADS_FROM,
        'overlay_children': EntityRelationship.Relationships.BUNDLES,
        'overlay_parents': EntityRelationship.Relationships.BUNDLED_IN,
        'pcap_children': EntityRelationship.Relationships.BUNDLES,
        'pcap_parents': EntityRelationship.Relationships.BUNDLED_IN,
        'pe_resource_children': EntityRelationship.Relationships.EXECUTED,
        'pe_resource_parents': EntityRelationship.Relationships.EXECUTED_BY,
        'similar_files': EntityRelationship.Relationships.SIMILAR_TO,
    },
    'domain': {
        'cname_records': EntityRelationship.Relationships.IS_ALSO,
        'caa_records': EntityRelationship.Relationships.RELATED_TO,
        'communicating_files': EntityRelationship.Relationships.DROPS,
        'downloaded_files': EntityRelationship.Relationships.DROPS,
        'immediate_parent': EntityRelationship.Relationships.SUB_DOMAIN_OF,
        'mx_records': EntityRelationship.Relationships.RELATED_TO,
        'ns_records': EntityRelationship.Relationships.DROPS,
        'parent': EntityRelationship.Relationships.SUB_DOMAIN_OF,
        'referrer_files': EntityRelationship.Relationships.RELATED_TO,
        'resolutions': EntityRelationship.Relationships.RESOLVED_FROM,
        'siblings': EntityRelationship.Relationships.SUPRA_DOMAIN_OF,
        'soa_records': EntityRelationship.Relationships.IS_ALSO,
        'subdomains': EntityRelationship.Relationships.SUPRA_DOMAIN_OF,
        'urls': EntityRelationship.Relationships.HOSTS,
    }, 'ip': {
        'communicating_files': EntityRelationship.Relationships.COMMUNICATES_WITH,
        'downloaded_files': EntityRelationship.Relationships.DROPS,
        'referrer_files': EntityRelationship.Relationships.RELATED_TO,
        'resolutions': EntityRelationship.Relationships.RESOLVES_TO,
        'urls': EntityRelationship.Relationships.RELATED_TO,
    }, 'url': {
        'contacted_domains': EntityRelationship.Relationships.RELATED_TO,
        'contacted_ips': EntityRelationship.Relationships.RELATED_TO,
        'downloaded_files': EntityRelationship.Relationships.DROPS,
        'last_serving_ip_address': EntityRelationship.Relationships.RESOLVED_FROM,
        'network_location': EntityRelationship.Relationships.RESOLVED_FROM,
        'redirecting_urls': EntityRelationship.Relationships.DUPLICATE_OF,
        'redirects_to': EntityRelationship.Relationships.DUPLICATE_OF,
        'referrer_files': EntityRelationship.Relationships.EMBEDDED_IN,
        'referrer_urls': EntityRelationship.Relationships.RELATED_TO,
    }
}


'''
            __,__
   .--.  .-"     "-.  .--.
  / .. \/  .-. .-.  \/ .. \
 | |  '|  /   Y   \  |'  | |
 | \   \  \ 0 | 0 /  /   / |
  \ '- ,\.-"`` ``"-./, -' /
   `'-' /_   ^ ^   _\ '-'`
       |  \._   _./  |
       \   \ `~` /   /
        '._ '-=-' _.'
           '~---~'
!!!Opppppssssss!!!
Someone messed with the integarion  maybe its related to something?

# Flag: <Which animal is in the picture?>
'''


def test_module():
    """
    Returning 'ok' indicates that the integration works like it suppose to. Connection to the service is successful.

    Args:
        client: HelloWorld client

    Returns:
        'ok' if test passed, anything else will fail the test
    """
    return 'ok'


def main():
    if demisto.command() == 'test-module':
        # This is the call made when pressing the integration Test button.
        result = test_module()
        return_results(result)
