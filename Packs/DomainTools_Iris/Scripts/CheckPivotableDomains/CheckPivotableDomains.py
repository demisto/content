from CommonServerPython import *
from typing import Any

""" STANDALONE FUNCTION """


def check_pivotable_nameserver_host_or_domain(
    nameservers: list[dict[str, Any]], key: str, max_count: int
) -> list[dict[str, Any]]:
    pivotable = []
    try:
        for ns in nameservers or []:
            prop = ns.get(key)
            count = int(prop.get("count", 0)) if prop is not None else 0

            if max_count >= count > 1:
                value = prop.get("value") if prop is not None else ''
                pivotable.append({"count": count, "value": value})
    except Exception as e:
        demisto.info(
            f"Error in `check_pivotable_nameserver_host_or_domain`: {str(e)}")
        raise

    return pivotable


def check_pivotable_nameserver_ip(
    nameservers: list[dict[str, Any]], max_name_server_ip_count: int
) -> list[dict[str, Any]]:
    pivotable = []
    try:
        for ns in nameservers:
            ips = ns.get("ip") or []
            for ip in ips:
                count = int(ip.get("count") or 0) if ip is not None else 0

                if max_name_server_ip_count >= count > 1:
                    pivotable.append(
                        {"count": count, "value": ip.get("value")})
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_nameserver_ip`: {str(e)}")
        raise

    return pivotable


def check_pivotable_registrant_contact_name(
    registrant_contact: dict[str, Any], max_registrant_contact_name_count: int
) -> Optional[dict[str, Any]]:
    try:
        r_contact_name = registrant_contact.get("Name") or {}
        r_contact_name_count = int(r_contact_name.get("count") or 0)

        if max_registrant_contact_name_count >= r_contact_name_count > 1:
            return r_contact_name
    except Exception as e:
        demisto.info(
            f"Error in `check_pivotable_registrant_contact_name`: {str(e)}")
        raise

    return None


def check_pivotable_registrant_org(
    registrant_contact: dict[str, Any], max_registrant_org_count: int
) -> Optional[dict[str, Any]]:
    try:
        r_contact_org = registrant_contact.get("Org") or {}
        r_contact_org_count = int(r_contact_org.get("count") or 0)

        if max_registrant_org_count >= r_contact_org_count > 1:
            return r_contact_org
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_registrant_org`: {str(e)}")
        raise

    return None


def check_pivotable_registrar(
    registrar: dict[str, Any], max_registrar_count: int
) -> Optional[dict[str, Any]]:
    try:
        registrar = registrar.get("Org") or {}
        registrar_count = int(registrar.get("count") or 0)

        if max_registrar_count >= registrar_count > 1:
            return registrar
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_registrar`: {str(e)}")
        raise

    return None


def check_pivotable_ssl_info(
    ssl_infos: list[dict[str, Any]], key: str, max_property_count: int
) -> list[dict[str, Any]]:
    pivotable = []
    try:
        for ssl_info in ssl_infos:
            prop = ssl_info.get(key)
            count = int(prop.get("count") or 0) if prop is not None else 0
            if max_property_count >= count > 1:
                value = prop.get("value") if prop is not None else ''
                pivotable.append({"count": count, "value": value})
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_ssl_info`: {str(e)}")
        raise

    return pivotable


def check_pivotable_ssl_email(
    ssl_infos: list[dict[str, Any]], max_property_count: int
) -> list[dict[str, Any]]:
    pivotable = []
    try:
        for ssl_info in ssl_infos:
            emails = ssl_info.get("email", []) if ssl_info is not None else []
            for email in emails:
                count = int(email.get("count") or 0)
                if max_property_count >= count >= 1:
                    pivotable.append(
                        {"count": count, "value": email.get("value")})
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_ssl_email`: {str(e)}")
        raise

    return pivotable


def check_pivotable_soa_email(
    soa_emails: list[dict[str, Any]], max_count: int
) -> list[dict[str, Any]]:
    pivotable = []
    try:
        for soa_email in soa_emails:
            count = int(soa_email.get("count") or 0)
            if max_count >= count > 1:
                pivotable.append(
                    {"count": count, "value": soa_email.get("value")})
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_soa_email`: {str(e)}")
        raise

    return pivotable


def check_pivotable_ip_address(
    ips: list[dict[str, Any]], max_count: int
) -> list[dict[str, Any]]:
    pivotable = []
    try:
        for ip in ips:
            address = ip.get("address")
            count = int(address.get("count", 0)) if address is not None else 0
            if max_count >= count >= 1:
                pivotable.append(
                    {"count": count, "value": address.get("value") if address is not None else ''})
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_ip_address`: {str(e)}")
        raise

    return pivotable


def check_pivotable_mx_ip(
    mx: list[dict[str, Any]], max_mx_ip_count: int
) -> list[dict[str, Any]]:
    pivotable = []
    try:
        for prop in mx:
            ips = prop.get("ip") or []
            for ip in ips:
                count = int(ip.get("count") or 0)
                if max_mx_ip_count >= count > 1:
                    pivotable.append(
                        {"count": count, "value": ip.get("value")})
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_mx_ip`: {str(e)}")
        raise

    return pivotable


def check_pivotable_mx_host_or_domain(
    mx: list[dict[str, Any]], key: str, max_count: int
) -> list[dict[str, Any]]:
    pivotable = []
    try:
        for prop in mx:
            prop = prop.get(key, {})
            count = int(prop.get("count") or 0)
            if max_count >= count > 1:
                pivotable.append(
                    {"count": count, "value": prop.get("value")})
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_mx_host_or_domain`: {str(e)}")
        raise

    return pivotable


def check_pivotable_google_props(
    google_prop: dict[str, Any], max_count: int
) -> Optional[dict[str, Any]]:
    try:
        google_prop_count = int(google_prop.get("count") or 0)
        if max_count >= google_prop_count > 1:
            return google_prop
    except Exception as e:
        demisto.info(f"Error in `check_pivotable_google_props`: {str(e)}")
        raise

    return None


""" COMMAND FUNCTION """


def check_pivotable_domains(args: dict[str, Any]) -> CommandResults:
    domaintools_data = args["domaintools_data"]

    # name server
    max_name_server_host_count = arg_to_number(
        args["max_name_server_host_count"]) or 250
    max_name_server_ip_count = arg_to_number(
        args["max_name_server_ip_count"]) or 250
    max_name_server_domain_count = arg_to_number(
        args["max_name_server_domain_count"]) or 250
    # registrant
    max_registrant_contact_name_count = arg_to_number(
        args["max_registrant_contact_name_count"]
    ) or 200
    max_registrant_org_count = arg_to_number(
        args["max_registrant_org_count"]) or 200
    max_registrar_count = arg_to_number(args["max_registrar_count"]) or 200
    # ssl
    max_ssl_info_organization_count = arg_to_number(
        args["max_ssl_info_organization_count"]
    ) or 350
    max_ssl_info_hash_count = arg_to_number(
        args["max_ssl_info_hash_count"]) or 350
    max_ssl_email_count = arg_to_number(args["max_ssl_email_count"]) or 350
    max_ssl_subject_count = arg_to_number(
        args["max_ssl_subject_count"]) or 350
    # soa
    max_soa_email_count = arg_to_number(args["max_soa_email_count"]) or 200
    # ip
    max_ip_address_count = arg_to_number(args["max_ip_address_count"]) or 200
    # mx
    max_mx_ip_count = arg_to_number(args["max_mx_ip_count"]) or 200
    max_mx_host_count = arg_to_number(args["max_mx_host_count"]) or 200
    max_mx_domain_count = arg_to_number(args["max_mx_domain_count"]) or 200
    # google
    max_google_adsense_count = arg_to_number(
        args["max_google_adsense_count"]) or 200
    max_google_analytics_count = arg_to_number(
        args["max_google_analytics_count"]) or 200

    domain_name = domaintools_data.get("Name")
    domain_hosting_data = domaintools_data.get("Hosting", {})
    domain_identity_data = domaintools_data.get("Identity", {})
    domain_analytics_data = domaintools_data.get("Analytics", {})

    human_readable_str = f"Domain: {domain_name} does not have any pivotable attributes"

    results = {
        "Name": domain_name,
        "PivotableRegistrantContactName": {"pivotable": False},
        "PivotableRegistrantOrg": {"pivotable": False},
        "PivotableRegistrar": {"pivotalbe": False},
        "PivotableSslInfoOrganization": {"pivotable": False},
        "PivotableSslInfoHash": {"pivotable": False},
        "PivotableSslSubject": {"pivotable": False},
        "PivotableSslEmail": {"pivotable": False},
        "PivotableNameServerHost": {"pivotable": False},
        "PivotableNameServerIp": {"pivotable": False},
        "PivotableNameServerDomain": {"pivotable": False},
        "PivotableSoaEmail": {"pivotable": False},
        "PivotableIpAddress": {"pivotable": False},
        "PivotableMxIp": {"pivotable": False},
        "PivotableMxHost": {"pivotable": False},
        "PivotableMxDomain": {"pivotable": False},
        "PivotableGoogleAnalytics": {"pivotable": False},
        "PivotableAdsense": {"pivotable": False},
    }

    # Nameservers
    pivotable_ns_hosts = check_pivotable_nameserver_host_or_domain(
        domain_hosting_data.get(
            "NameServers"), "host", max_name_server_host_count
    )
    if len(pivotable_ns_hosts) > 0:
        results["PivotableNameServerHost"]["pivotable"] = True
        results["PivotableNameServerHost"]["items"] = pivotable_ns_hosts

    pivotable_ns_ips = check_pivotable_nameserver_ip(
        domain_hosting_data.get("NameServers"), max_name_server_ip_count
    )
    if len(pivotable_ns_ips) > 0:
        results["PivotableNameServerIp"]["pivotable"] = True
        results["PivotableNameServerIp"]["items"] = pivotable_ns_ips

    pivotable_ns_domains = check_pivotable_nameserver_host_or_domain(
        domain_hosting_data.get(
            "NameServers"), "domain", max_name_server_domain_count
    )
    if len(pivotable_ns_domains) > 0:
        results["PivotableNameServerDomain"]["pivotable"] = True
        results["PivotableNameServerDomain"]["items"] = pivotable_ns_domains

    # Registrant
    pivotable_registrant_contact_name = check_pivotable_registrant_contact_name(
        domain_identity_data.get(
            "RegistrantContact"), max_registrant_contact_name_count
    )
    if pivotable_registrant_contact_name is not None:
        results["PivotableRegistrantContactName"]["pivotable"] = True
        results["PivotableRegistrantContactName"][
            "items"
        ] = pivotable_registrant_contact_name

    pivotable_registrant_org_name = check_pivotable_registrant_org(
        domain_identity_data.get("RegistrantContact"), max_registrant_org_count
    )
    if pivotable_registrant_org_name is not None:
        results["PivotableRegistrantOrg"]["pivotable"] = True
        results["PivotableRegistrantOrg"]["items"] = pivotable_registrant_org_name

    pivotable_registrar = check_pivotable_registrar(
        domain_identity_data.get("Registrar") or {}, max_registrar_count)

    if pivotable_registrar is not None:
        results["PivotableRegistrar"]["pivotable"] = True
        results["PivotableRegistrar"]["items"] = pivotable_registrar

    # SSL
    pivotable_ssl_org = check_pivotable_ssl_info(
        domain_hosting_data.get("SSLCertificate"),
        "organization",
        max_ssl_info_organization_count,
    )
    if len(pivotable_ssl_org) > 0:
        results["PivotableSslInfoOrganization"]["pivotable"] = True
        results["PivotableSslInfoOrganization"]["items"] = pivotable_ssl_org

    pivotable_ssl_hash = check_pivotable_ssl_info(
        domain_hosting_data.get(
            "SSLCertificate"), "hash", max_ssl_info_hash_count
    )
    if len(pivotable_ssl_hash) > 0:
        results["PivotableSslInfoHash"]["pivotable"] = True
        results["PivotableSslInfoHash"]["items"] = pivotable_ssl_hash

    pivotalbe_ssl_subject = check_pivotable_ssl_info(
        domain_hosting_data.get(
            "SSLCertificate"), "subject", max_ssl_subject_count
    )
    if len(pivotalbe_ssl_subject) > 0:
        results["PivotableSslSubject"]["pivotable"] = True
        results["PivotableSslSubject"]["items"] = pivotalbe_ssl_subject

    # PivotableSslEmail
    pivotable_ssl_email = check_pivotable_ssl_email(
        domain_hosting_data.get("SSLCertificate"), max_ssl_email_count
    )
    if len(pivotable_ssl_email) > 0:
        results["PivotableSslEmail"]["pivotable"] = True
        results["PivotableSslEmail"]["items"] = pivotable_ssl_email

    # SOA
    pivotable_soa_email = check_pivotable_soa_email(
        domain_identity_data.get("SOAEmail"), max_soa_email_count
    )
    if len(pivotable_soa_email) > 0:
        results["PivotableSoaEmail"]["pivotable"] = True
        results["PivotableSoaEmail"]["items"] = pivotable_soa_email

    pivotable_ip_address = check_pivotable_ip_address(
        domain_hosting_data.get("IPAddresses"), max_ip_address_count
    )
    if len(pivotable_ip_address) > 0:
        results["PivotableIpAddress"]["pivotable"] = True
        results["PivotableIpAddress"]["items"] = pivotable_ip_address

    pivotable_mx_ip = check_pivotable_mx_ip(
        domain_hosting_data.get("MailServers"), max_mx_ip_count
    )
    if len(pivotable_mx_ip) > 0:
        results["PivotableMxIp"]["pivotable"] = True
        results["PivotableMxIp"]["items"] = pivotable_mx_ip

    pivotable_mx_host = check_pivotable_mx_host_or_domain(
        domain_hosting_data.get("MailServers"), "host", max_mx_host_count
    )
    if len(pivotable_mx_host) > 0:
        results["PivotableMxHost"]["pivotable"] = True
        results["PivotableMxHost"]["items"] = pivotable_mx_host

    pivotable_mx_domain = check_pivotable_mx_host_or_domain(
        domain_hosting_data.get("MailServers"), "domain", max_mx_domain_count
    )
    if len(pivotable_mx_domain) > 0:
        results["PivotableMxDomain"]["pivotable"] = True
        results["PivotableMxDomain"]["items"] = pivotable_mx_domain

    # Google props
    pivotable_google_analytics = check_pivotable_google_props(
        domain_analytics_data.get(
            "GoogleAnalyticTrackingCode"), max_google_analytics_count
    )
    if pivotable_google_analytics is not None:
        results["PivotableGoogleAnalytics"]["pivotable"] = True
        results["PivotableGoogleAnalytics"]["item"] = pivotable_google_analytics

    pivotable_google_adsense = check_pivotable_google_props(
        domain_analytics_data.get(
            "GoogleAdsenseTrackingCode"), max_google_adsense_count
    )
    if pivotable_google_adsense is not None:
        results["PivotableAdsense"]["pivotable"] = True
        results["PivotableAdsense"]["items"] = pivotable_google_adsense

    # Check for any pivotable to update the human readable table output
    if any(
        result.get("pivotable", False)
        for result in results.values()
        if isinstance(result, dict)
    ):
        human_readable_str = tableToMarkdown(
            f"Pivotable Domain: {domain_name}", results
        )

    return CommandResults(
        outputs_prefix="PivotableDomains",
        outputs_key_field="Name",
        outputs=results,
        readable_output=human_readable_str,
        ignore_auto_extract=True,
        raw_response=results,
    )


""" MAIN FUNCTION """


def main():
    try:
        return_results(check_pivotable_domains(demisto.args()))
    except Exception as ex:
        return_error(
            f"Failed to execute check_pivotable_domains. Error: {str(ex)}")


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
