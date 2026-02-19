import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' CUSTOMER EDL URL '''
"""
    Note:
        Customers who have their own XSOAR, their edl name starts with 'xsoar_edl_*'.
"""
CUSTOMER_EDL = {
    "Redeban": "redeban_edl",
    "Unisabana": "unisabana_edl",
    "Netdata": "netdata_edl",
    "Brinks": "xsoar_edl",
    "RUNT": "xsoar_edl",
    "Colbun": "colbun_edl",
    "PCO": "pco_edl",
    "Compensar": "compensar_edl",
    "Promigas": "promigas_edl"
}

''' CUSTOMER TAG NAMES '''
"""
    Note:
        It is not necessary to use the "customer_tag" for those customers who have their own XSOAR.
"""
CUSTOMER_TAGS = {
    "Redeban": "Redeban",
    "Unisabana": "Unisabana",
    "Netdata": "Netdata",
    "Colbun": "Colbun",
    "PCO": "PCO",
    "Compensar": "Compensar",
    "Promigas": "Promigas"
}

''' INDICATORS TAG NAMES '''
INDICATOR_TAG = {
    "Domain": "BlockedDomain",
    "URL": "BlockedURL",
    "IP": "BlockedIP",
    "File": "BlockedFile"
}


def build_xsoar_edl_url(customer, indicator_type):
    result = demisto.executeCommand("GetServerURL", {})
    server_url = result[0].get('Contents')
    edl_name = "{}_{}".format(CUSTOMER_EDL.get(customer), indicator_type.lower())
    edl_url = "{}/instance/execute/{}".format(server_url, edl_name)
    return edl_url

# def check_customer_exists(customer):
#     result = demisto.executeCommand("GetInstances", {"brand": "Cortex XDR - IR"})
#     brand_list = [item["name"] for item in result[0].get("Contents")]
#     if any(customer in item for item in brand_list):
#         return True
#     else:
#         return False


def create_indicator(indicator_type, indicator_value):
    indicator_list = indicator_value.split(",")
    for indicator in indicator_list:
        demisto.executeCommand("CreateNewIndicatorsOnly", {"indicator_values": indicator, "type": indicator_type})


def main():
    customer = demisto.args().get('customer')
    indicator_type = demisto.args().get('indicator_type')
    indicator_value = demisto.args().get('indicator_value')

    # customer_exists = check_customer_exists(customer)

    # if customer_exists:

    create_indicator(indicator_type, indicator_value)

    if CUSTOMER_TAGS.get(customer) is None:
        tags_to_add = INDICATOR_TAG.get(indicator_type)
    else:
        tags_to_add = "{},{}".format(INDICATOR_TAG.get(indicator_type), CUSTOMER_TAGS.get(customer))

    demisto.executeCommand("AppendindicatorFieldWrapper", {"indicators_values": indicator_value, "tags": tags_to_add})

    return_results("Indicators added to EDL: {}".format(build_xsoar_edl_url(customer, indicator_type)))

    # else:
    #     return_warning("Could not update the EDL! Customer is in a different XSOAR or the XDR integration is disabled.")


if __name__ in ['__main__', 'builtin', 'builtins']:
    main()
