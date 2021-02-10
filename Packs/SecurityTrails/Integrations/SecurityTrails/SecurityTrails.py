import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

requests.packages.urllib3.disable_warnings()

# TODO
# Get the output key field right to use the input domain as the key
# Might be useful to return metadata on paging endpoints so user can pick a page


class Client(BaseClient):
    """
    Client will implement the service API, and should not contain any Demisto logic.
    Should only do requests and return data.
    """

    def __init__(self, base_url, *args, **kwarg):
        super().__init__(base_url, *args, **kwarg)


def test_module(client: Client, **args) -> str:
    uri = "ping"
    client._http_request("GET", uri)

    return "ok"


def get_account_usage(client: Client, **args) -> CommandResults:
    uri = "/account/usage"
    response = client._http_request("GET", uri)

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.account_usage",
        outputs={"account_usage": response},
        readable_output=tableToMarkdown("Account Usage", response),
    )

    return results


# Only available for certain endpoints
def get_scroll_results(client: Client, **args) -> CommandResults:
    scroll_id = args.get("scroll_id")
    uri = f"/scroll/{scroll_id}"
    response = client._http_request("GET", uri)

    return response


def get_company_details(client: Client, **args) -> CommandResults:
    domain = args.get("domain")
    uri = f"/company/{domain}"
    response = client._http_request("GET", uri)
    records = response.get("record")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.company_details",
        outputs={"company_details": records},
        readable_output=tableToMarkdown(f"Company details for {domain}", records),
    )

    return results


def get_company_associated_ips(client: Client, **args) -> CommandResults:
    domain = args.get("domain")
    uri = f"/company/{domain}/associated-ips"
    response = client._http_request("GET", uri)
    records = response.get("records")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.company_associated_ips",
        outputs={"company_associated_ips": records},
        readable_output=tableToMarkdown(f"IPs associated with {domain}", records),
    )

    return results


def get_domain_details(client: Client, **args) -> CommandResults:
    domain = args.get("domain")
    uri = f"/domain/{domain}"
    response = client._http_request("GET", uri)

    md = ""
    current_dns = response["current_dns"]
    del response["current_dns"]
    md = tableToMarkdown(f"Details for {domain}", response)
    for record_type, record_values in current_dns.items():
        # If a record type has multiple values, this will output the last item in MD
        temp_values = {}
        for x in record_values["values"]:
            temp_values.update(**x)
        record_values.update(temp_values)
        del record_values["values"]
        md += tableToMarkdown(f"DNS {record_type} Records for {domain}", record_values)

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.domain_details.{domain}",
        outputs={domain: {"domain_details": response}},
        readable_output=md,
    )

    return results


def get_domain_subdomains(client: Client, **args) -> CommandResults:
    domain = args.get("domain")
    children_only = str(args.get("children_only", "false"))
    uri = f"/domain/{domain}/subdomains?children_only={children_only}"
    response = client._http_request("GET", uri)
    records = response.get("subdomains")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.subdomains.{domain}",
        outputs={domain: {"subdomains": records}},
        readable_output=tableToMarkdown(
            f"Subdomains for {domain}", records, headers="Subdomains"
        ),
    )

    return results


def get_domain_tags(client: Client, **args) -> CommandResults:
    domain = args.get("domain")
    uri = f"/domain/{domain}/tags"
    response = client._http_request("GET", uri)
    records = response.get("tags")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.tags.{domain}",
        outputs={domain: {"tags": records}},
        readable_output=tableToMarkdown(f"Tags for {domain}", records, headers="Tags"),
    )

    return results


def get_domain_whois(client: Client, **args) -> CommandResults:
    domain = args.get("domain")
    uri = f"/domain/{domain}/whois"
    response = client._http_request("GET", uri)

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.whois.{domain}",
        outputs={domain: {"whois": response}},
        readable_output=tableToMarkdown(f"Whois for {domain}", response),
    )

    return results


def get_domain_associated_domains(client: Client, **args) -> CommandResults:
    domain = args.get("domain")

    params = {"page": int(args.get("page"))}

    uri = f"/domain/{domain}/associated"
    response = client._http_request("GET", uri, params=params)
    records = response.get("records")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.associated_domains.{domain}",
        outputs={domain: {"associated_domains": records}},
        readable_output=tableToMarkdown(f"Domains associated with {domain}", records),
    )

    return results


def get_domain_dns_history(client: Client, **args) -> CommandResults:
    domain = args.get("domain")
    type = args.get("type")

    params = {"page": int(args.get("page", 0))}

    uri = f"/history/{domain}/dns/{type}"
    response = client._http_request("GET", uri, params=params)
    records = response.get("records")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.domain_dns_history",
        outputs={"domain_dns_history": records},
        readable_output=tableToMarkdown(f"Domain DNS History for {domain}", records),
    )

    return results


def get_domain_whois_history(client: Client, **args) -> CommandResults:
    domain = args.get("domain")

    params = {"page": int(args.get("page", 0))}

    uri = f"/history/{domain}/whois"
    response = client._http_request("GET", uri, params=params)
    records = response["result"].get("items")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.domain_whois_history",
        outputs={"domain_whois_history": records},
        readable_output=tableToMarkdown(f"Domain Whois History for {domain}", records),
    )

    return results


def get_ip_neighbors(client: Client, **args) -> CommandResults:
    ip = args.get("ip")

    uri = f"/ips/nearby/{ip}"
    response = client._http_request("GET", uri)
    records = response.get("blocks")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.ip_neighbors",
        outputs={"ip_neighbors": records},
        readable_output=tableToMarkdown(f"IP Neighbors for {ip}", records),
    )

    return results


def search_domain_with_dsl(client: Client, **args) -> CommandResults:
    params = {
        "include_ips": args.get("include_ips", "false"),
        "page": int(args.get("page", 0)),
        "scroll": str(args.get("scroll", "false")),
    }

    body = {"query": str(args.get("query"))}

    uri = f"/domains/list"
    response = client._http_request("POST", uri, params=params, json_data=body)
    records = response.get("records")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.domain_dsl_search",
        outputs={"dsl_search_domain": records},
        readable_output=tableToMarkdown(
            f"DSL Search: {str(args.get('query'))}", records
        ),
    )

    return results


def search_domain_with_dsl_statistics(client: Client, **args) -> CommandResults:
    params = {
        "include_ips": args.get("include_ips", "false"),
        "page": int(args.get("page", 0)),
        "scroll": str(args.get("scroll", "false")),
    }

    body = {"query": str(args.get("query"))}

    uri = f"/domains/stats"
    response = client._http_request("POST", uri, params=params, json_data=body)

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.domain_dsl_search",
        outputs={"domain_statistics": response},
        readable_output=tableToMarkdown(
            f"Statistics for Query: {str(args.get('query'))}", response
        ),
    )

    return results


def search_ip_with_dsl(client: Client, **args) -> CommandResults:
    params = {"page": int(args.get("page"))}

    # Docs: https://docs.securitytrails.com/docs/how-to-use-the-dsl
    # Example: ptr_part = 'stackoverflow.com'
    body = {"query": str(args.get("query"))}

    uri = f"/ips/list"
    response = client._http_request("POST", uri, params=params, json_data=body)
    records = response.get("records")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.ip_dsl_search",
        outputs={"dsl_search": records},
        readable_output=tableToMarkdown(
            f'DSL Search: {str(args.get("query"))}', records
        ),
    )

    return results


def search_ip_with_dsl_statistics(client: Client, **args) -> CommandResults:
    # Docs: https://docs.securitytrails.com/docs/how-to-use-the-dsl
    # Example: ptr_part = 'stackoverflow.com'
    body = {"query": str(args.get("query"))}

    uri = f"/ips/stats"
    response = client._http_request("POST", uri, json_data=body)

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.ip_dsl_statistics",
        outputs={"dsl_statistics": response},
        readable_output=tableToMarkdown(
            f"DSL Statistics: {str(args.get('query'))}", response
        ),
    )

    return results


def get_ip_whois(client: Client, **args) -> CommandResults:
    ip = args.get("ip")

    uri = f"/ips/{ip}/whois"
    response = client._http_request("GET", uri)
    records = response.get("record")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.ip_whois",
        outputs={"ip_whois": records},
        readable_output=tableToMarkdown(f"Whois for {ip}", records),
    )

    return results


def get_ip_useragents(client: Client, **args) -> CommandResults:
    ip = args.get("ip")

    params = {"page": int(args.get("page"))}

    uri = f"/ips/{ip}/useragents"
    response = client._http_request("GET", uri, params=params)
    records = response.get("records")

    results = CommandResults(
        outputs_prefix="SecurityTrails",
        outputs_key_field=f"SecurityTrails.ip_useragents",
        outputs={"ip_useragents": records},
        readable_output=tableToMarkdown(f"Useragents for {ip}", records),
    )

    return results


def main():
    args = {**demisto.params(), **demisto.args()}

    base_url = args.get("url")

    verify_certificate = not args.get("insecure", False)

    proxy = args.get("proxy", False)

    headers = {"Content-Type": "application/json", "APIKEY": args.get("api_key")}

    LOG(f"Command being called is {demisto.command()}")
    client = Client(
        base_url=base_url, verify=verify_certificate, headers=headers, proxy=proxy
    )

    command_prefix = "st"

    commands = {
        "test-module": test_module,
        f"{command_prefix}-account-usage": get_account_usage,
        f"{command_prefix}-company-details": get_company_details,
        f"{command_prefix}-company-associated-ips": get_company_associated_ips,
        f"{command_prefix}-domain-details": get_domain_details,
        f"{command_prefix}-domain-subdomains": get_domain_subdomains,
        f"{command_prefix}-domain-tags": get_domain_tags,
        f"{command_prefix}-domain-whois": get_domain_whois,
        f"{command_prefix}-dsl-search-domain": search_domain_with_dsl,
        f"{command_prefix}-dsl-search-statistics-domain": search_domain_with_dsl_statistics,
        f"{command_prefix}-domain-associated-domains": get_domain_associated_domains,
        f"{command_prefix}-domain-dns-history": get_domain_dns_history,
        f"{command_prefix}-domain-whois-history": get_domain_whois_history,
        f"{command_prefix}-ip-neighbors": get_ip_neighbors,
        f"{command_prefix}-ip-whois": get_ip_whois,
        f"{command_prefix}-ip-useragents": get_ip_useragents,
        f"{command_prefix}-dsl-search-ip": search_ip_with_dsl,
        f"{command_prefix}-dsl-search-statistics-ip": search_ip_with_dsl_statistics,
    }

    command = demisto.command()
    if command in commands:
        return_results(commands[command](client, **args))
    else:
        return_error(f"Command {command} is not available in this integration")


if __name__ in ["__main__", "__builtin__", "builtins"]:
    main()
