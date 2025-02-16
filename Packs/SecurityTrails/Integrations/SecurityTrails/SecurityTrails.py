import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

''' CONSTANTS '''

removed_keys = ['endpoint', 'domain', 'hostname']

''' CLIENT CLASS '''


class Client(BaseClient):

    def __init__(self, base_url, verify=True, proxy=False, ok_codes=tuple(), headers=None, auth=None, timeout=10):
        super().__init__(base_url, verify=verify, proxy=proxy, ok_codes=ok_codes, headers=headers, auth=auth)
        self.timeout = timeout

    def domain_tags(self, hostname: str = None):
        res = self._http_request(
            'GET',
            f'domain/{hostname}/tags',
            ok_codes=(200, 403),
            timeout=self.timeout
        )
        return res.get('tags', [])

    def domain_details(self, hostname: str = None):
        return self._http_request(
            'GET',
            f'domain/{hostname}',
            ok_codes=(200, 403),
            timeout=self.timeout
        )

    def domain_subdomains(self, hostname: str = None, children_only: str = 'true'):
        query_string = {"children_only": children_only}
        res = self._http_request(
            'GET',
            f'domain/{hostname}/subdomains',
            params=query_string,
            ok_codes=(200, 403),
            timeout=self.timeout
        )
        return res

    def associated_domains(self, hostname: str = None, page: int = 1):
        params = {
            "page": page
        }
        res = self._http_request(
            'GET',
            f'domain/{hostname}/associated',
            params=params,
            ok_codes=(200, 403),
            timeout=self.timeout
        )
        return res

    def get_ssl_certificates(self, query_type: str = "stream", hostname: str = None, params: dict = None):
        # There's a bug in the API where the result is malformed.
        if query_type == "paged":
            res = self._http_request(
                'GET',
                f'domain/{hostname}/ssl',
                params=params or {},
                ok_codes=(200, 403),
                resp_type='response',
                timeout=self.timeout
            )
        elif query_type == "stream":
            res = self._http_request(
                'GET',
                f'domain/{hostname}/ssl_stream',
                params=params,
                ok_codes=(200, 403),
                resp_type='response',
                timeout=self.timeout
            )
        else:
            res = {}
            demisto.debug(f"The {query_type=} didn't match any value. {res=}")

        return res

    def get_company(self, domain: str = None):
        res = self._http_request(
            'GET',
            f'company/{domain}',
            ok_codes=(200, 403),
            timeout=self.timeout
        )
        return res.get('record', {})

    def get_useragents(self, ip_address: str = None, params: dict = None):
        return self._http_request(
            'GET',
            f'ips/{ip_address}/useragents',
            params=params or {},
            ok_codes=(200, 403),
            timeout=self.timeout
        )

    def get_company_associated_ips(self, domain: str = None):
        res = self._http_request(
            'GET',
            f'company/{domain}/associated-ips',
            ok_codes=(200, 403),
            timeout=self.timeout
        )
        return res.get('record', {})

    def get_whois(self, query_type: str = "domain", hostname: str = None):
        if query_type == "domain":
            return self._http_request(
                'GET',
                f'domain/{hostname}/whois',
                ok_codes=(200, 403),
                timeout=self.timeout
            )
        elif query_type == "ip":
            return self._http_request(
                'GET',
                f'ips/{hostname}/whois',
                ok_codes=(200, 403),
                timeout=self.timeout
            )

    def get_dns_history(self, hostname: str = None, record_type: str = None, page: int = 1):
        params = {
            "page": page
        }
        return self._http_request(
            'GET',
            f'history/{hostname}/dns/{record_type}',
            params=params,
            ok_codes=(200, 403),
            timeout=self.timeout
        )

    def get_whois_history(self, hostname: str = None, page: int = 1):
        params = {
            "page": page
        }
        res = self._http_request(
            'GET',
            f'history/{hostname}/whois',
            params=params,
            ok_codes=(200, 403),
            timeout=self.timeout
        )
        return res.get('result')

    def get_ip_neighbors(self, ipaddress: str = None):
        res = self._http_request(
            'GET',
            f'ips/nearby/{ipaddress}',
            ok_codes=(200, 403),
            timeout=self.timeout
        )
        return res.get('blocks')

    def query(self, query_type: str = "domain_search", body: dict = None, params: dict = None):
        if query_type == "domain_search":
            return self._http_request(
                'POST',
                'domains/list',
                params=params,
                json_data=body,
                ok_codes=(200, 403),
                timeout=self.timeout
            )
        elif query_type == "domain_stats":
            return self._http_request(
                'POST',
                'domains/stats',
                json_data=body,
                ok_codes=(200, 403),
                timeout=self.timeout
            )
        elif query_type == "ip_search":
            return self._http_request(
                'POST',
                'ips/list',
                params=params,
                json_data=body,
                ok_codes=(200, 403),
                timeout=self.timeout
            )
        elif query_type == "ip_stats":
            return self._http_request(
                'POST',
                'ips/stats',
                params=params,
                json_data=body,
                ok_codes=(200, 403),
                timeout=self.timeout
            )

    def sql(self, sql: dict = None, timeout: int = 20):
        return self._http_request(
            'POST',
            'query/scroll',
            json_data=sql,
            timeout=self.timeout
        )

    def sql_next(self, next_id: str = None, timeout: int = 20):
        return self._http_request(
            'GET',
            f'query/scroll/{next_id}',
            timeout=self.timeout
        )


''' HELPER FUNCTIONS '''


#################################
# Standard Context Outputs
#################################


def create_standard_domain_context(domain_data):
    command_results = CommandResults(
        outputs_prefix="Domain",
        outputs_key_field="Name",
        outputs=domain_data,
        readable_output=tableToMarkdown("Domain(s):", domain_data)
    )
    return_results(command_results)


def create_standard_ip_context(ip_data):
    command_results = CommandResults(
        outputs_prefix="IP",
        outputs_key_field="Address",
        outputs=ip_data,
        readable_output=tableToMarkdown("IP Address(es):", ip_data)
    )
    return_results(command_results)


def domain_command(client, args):
    domains = argToList(args.get('domain'))
    command_results: List[CommandResults] = []
    for domain in domains:
        try:
            domain_details = client.domain_details(hostname=domain)
        except Exception:
            demisto.info(f'No information found for domain: {domain}')
            return_results(f'No information found for domain: {domain}')
            continue
        domain_subdomains = client.domain_subdomains(hostname=domain)
        domain_whois = client.get_whois(query_type="domain", hostname=domain)
        domain_tags = client.domain_tags(hostname=domain)
        admin_contact = [{
            "Name": x.get('name'),
            "Email": x.get('email'),
            "Phone": x.get('telephone'),
            "Country": x.get('country')
        } for x in domain_whois.get('contacts', []) if "admin" in x.get('type', '').lower()]
        registrant_contact = [{
            "Name": x.get('name', None),
            "Email": x.get('email', None),
            "Phone": x.get('telephone', None),
            "Country": x.get('country', None)
        } for x in domain_whois.get('contacts', []) if "registrant" in x.get('type', '').lower()]
        registrar_contact = [{
            "Name": x.get('name', None),
            "Email": x.get('email', None),
            "Phone": x.get('telephone', None),
            "Country": x.get('country', None)
        } for x in domain_whois.get('contacts', []) if "registrar" in x.get('type', '').lower()]
        domain_data = {
            "Name": domain,
            "DNS": ",".join(
                [x.get('ip', '') for x in domain_details.get('current_dns', {}).get('a', {}).get('values', [])]),
            "NameServers": ",".join(
                [x.get('nameserver', '') for x in
                 domain_details.get('current_dns', {}).get('ns', {}).get('values', [])]),
            "Organization": domain_details.get('name', None),
            "Subdomains": ",".join(domain_subdomains.get('subdomains', [])),
            "WHOIS": {
                "DomainStatus": domain_whois.get('status'),
                "NameServers": ",".join(domain_whois.get('nameServers')) if domain_whois.get('nameServers') else None,
                "CreationDate": domain_whois.get('createdDate'),
                "UpdatedDate": domain_whois.get('updatedDate'),
                "ExpirationDate": domain_whois.get('expiresData'),
                "Registrant": {
                    "Name": registrant_contact[0].get('Name', None) if registrant_contact else None,
                    "Email": registrant_contact[0].get('Email', None) if registrant_contact else None,
                    "Phone": registrant_contact[0].get('Phone', None) if registrant_contact else None
                },
                "Registrar": {
                    "Name": registrar_contact[0].get('Name', None) if registrar_contact else None,
                    "Email": registrar_contact[0].get('Email', None) if registrar_contact else None,
                    "Phone": registrar_contact[0].get('Phone', None) if registrar_contact else None
                },
                "Admin": {
                    "Name": admin_contact[0].get('Name', None) if admin_contact else None,
                    "Email": admin_contact[0].get('Email', None) if admin_contact else None,
                    "Phone": admin_contact[0].get('Phone', None) if admin_contact else None
                }
            },
            "Tags": ",".join(domain_tags),
            "Admin": {
                "Country": admin_contact[0].get('Country', None) if admin_contact else None,
                "Name": admin_contact[0].get('Name', None) if admin_contact else None,
                "Email": admin_contact[0].get('Email', None) if admin_contact else None,
                "Phone": admin_contact[0].get('Phone', None) if admin_contact else None
            },
            "Registrant": {
                "Country": registrant_contact[0].get('Country', None) if registrant_contact else None,
                "Name": registrant_contact[0].get('Name', None) if registrant_contact else None,
                "Email": registrant_contact[0].get('Email', None) if registrant_contact else None,
                "Phone": registrant_contact[0].get('Phone', None) if registrant_contact else None
            }
        }
        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name='SecurityTrails',
            score=Common.DBotScore.NONE,
            reliability=demisto.params().get('integrationReliability')
        )
        domain_indicator = Common.Domain(
            domain=domain,
            dbot_score=dbot_score
        )
        md = tableToMarkdown(f"Domain {domain}:", domain_data)
        result = CommandResults(
            outputs_prefix="Domain",
            outputs_key_field="Name",
            outputs=domain_data,
            indicator=domain_indicator,
            readable_output=md
        )
        command_results.append(result)

    return_results(command_results)

#################################
# Company endpoints
#################################


def get_company_details_command(client, args):
    domain = args.get('domain')
    res = client.get_company(domain=domain)
    readable_output = f"### Company for {domain}: {res.get('name', None)}"
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs={"name": domain, "company": res.get('name', None)},
        readable_output=readable_output
    )
    return_results(command_results)
    create_standard_domain_context(
        domain_data={
            "Name": domain,
            "Organization": res.get('name', None),
            "Registrant": {
                "Name": res.get('name', None)
            },
            "WHOIS": {
                "Registrant": {
                    "Name": res.get('name', None)
                }
            }
        })


def get_company_associated_ips_command(client, args):
    domain = args.get('domain')
    res = client.get_company_associated_ips(domain=domain)
    readable_output = tableToMarkdown(f"Associated IPs for {domain}", res)
    output_data = {
        "name": domain,
        "associatedips": res,
        "associatedips_count": len(res)
    }

    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs=output_data,
        readable_output=readable_output
    )
    return_results(command_results)


#################################
# Domain endpoints
#################################


def domain_details_command(client, args):
    hostname = args.get('hostname')
    res = client.domain_details(hostname=hostname)
    res = {k: v for k, v in res.items() if k not in removed_keys}
    res['name'] = hostname
    output_data = sorted([{"Type": k, "Record Count": len(v.get('values', []))}
                          for k, v in res.get('current_dns', {}).items()], key=lambda x: x['Type'])
    readable_output = tableToMarkdown(f"Domain details for {hostname}:", output_data, ['Type', 'Record Count'])
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs=res,
        readable_output=readable_output
    )
    return_results(command_results)

    create_standard_domain_context(
        domain_data={
            "Name": hostname,
            "NameServers": ", ".join(
                [x.get('nameserver', None) for x in res.get('current_dns', {}).get('ns', {}).get('values', [])])
        })


def domains_subdomains_command(client, args):
    hostname = args.get('hostname')
    children_only = args.get('children_only', 'true')
    res = client.domain_subdomains(hostname=hostname, children_only=children_only)
    subdomains = res.get('subdomains', [])
    md = tableToMarkdown(f"Subdomains for {hostname}:", [{"Subdomain": x} for x in subdomains])
    output_data = {
        "name": hostname,
        "subdomains": subdomains,
        "subdomains_count": len(subdomains)
    }
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs=output_data,
        readable_output=md
    )
    return_results(command_results)


def get_domain_tags_command(client, args):
    hostname = args.get('hostname')
    res = client.domain_tags(hostname=hostname)
    tags = ', '.join(res)
    readable_output = f"### Tags for {hostname}:\n\n{tags}"
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs={"name": hostname, "tags": res},
        readable_output=readable_output
    )
    return_results(command_results)
    create_standard_domain_context(
        domain_data={
            "Name": hostname,
            "Tags": tags
        })


def get_whois_command(client, args):
    command = demisto.command()
    if command == "securitytrails-get-domain-whois":
        hostname = args.get("hostname")
        res = client.get_whois(query_type="domain", hostname=hostname)
        res = {k: v for k, v in res.items() if k not in removed_keys}
        res["name"] = hostname
        readable_output = tableToMarkdown(f"WHOIS data for {hostname}", res)
        command_results = CommandResults(
            outputs_prefix="SecurityTrails.Domain",
            outputs_key_field="name",
            outputs=res,
            readable_output=readable_output
        )
        return_results(command_results)
        contacts = res.get('contacts', [])
        domain_data = {
            "Name": hostname,
            "UpdatedDate": res.get('updatedDate'),
            "DomainStatus": res.get('status'),
            "WHOIS": {
                "DomainStatus": res.get('status'),
                "CreationDate": res.get('createdDate'),
                "UpdatedDate": res.get('updatedDate'),
                "ExpirationDate": res.get('expiresDate'),
                "Registrar": {
                    "Name": res.get('registrarName')
                }
            }
        }
        if res.get('nameServers', None):
            name_servers = ", ".join(x for x in res.get('nameServers', []))
            domain_data['NameServers'] = name_servers
            domain_data['WHOIS']['NameServers'] = name_servers

        # Find the admin contact
        admin = None
        for contact in contacts:
            if (contact.get('type').lower()).startswith("admin"):
                admin = contact
                break
        if admin:
            domain_data['Admin'] = {
                "Country": admin.get('country', None),
                "Email": admin.get('email', None),
                "Name": admin.get('name', None),
                "Phone": admin.get('telephone', None)
            }
        create_standard_domain_context(domain_data=domain_data)

    elif command == "securitytrails-get-ip-whois":
        ip_address = args.get('ipaddress')
        res = client.get_whois(query_type="ip", hostname=ip_address)
        res = res.get('record', {})
        res = {k: v for k, v in res.items() if k not in removed_keys}
        res["ip"] = ip_address
        readable_output = tableToMarkdown(f"WHOIS data for {ip_address}", res)
        command_results = CommandResults(
            outputs_prefix="SecurityTrails.IP",
            outputs_key_field="ip",
            outputs=res,
            readable_output=readable_output
        )

        return_results(command_results)
        ip_data = {
            "Address": ip_address
        }
        create_standard_ip_context(ip_data=ip_data)


def domain_search_command(client, args):
    include_ips = argToBoolean(args.get('include_ips', 'false'))
    page = int(args.get('page', 1))
    scroll = True if args.get('include_ips', 'false') == "true" else False
    query = args.get('query', None)
    filter = args.get('filter', None)
    if not query and not filter:
        return_error("You must provide at least a query or a filter")
    params = {
        "include_ips": include_ips,
        "page": page,
        "scroll": scroll
    }
    body = dict()
    if query:
        body['query'] = query
    elif filter:
        body['filter'] = filter

    res = client.query(query_type="domain_search", params=params, body=body)
    records = res.get('records')
    record_count = res.get('record_count')
    md = tableToMarkdown(f"Domain DSL Search Results ({record_count} record(s)):", records)
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain.Search",
        outputs_key_field="hostname",
        outputs=records,
        readable_output=md
    )
    return_results(command_results)


def domain_statistics_command(client, args):
    query = args.get('query', None)
    filter = args.get('filter', None)
    if not query and not filter:
        return_error("You must provide at least a query or a filter")
    body = dict()
    if query:
        body['query'] = query
    elif filter:
        body['filter'] = filter

    res = client.query(query_type="domain_stats", body=body)
    res = {k: v for k, v in res.items() if k not in removed_keys}

    top_orgs = res.get('top_organizations', [])
    tld_count = res.get('tld_count', 0)
    hostname_count = res.get('hostname_count', {})
    domain_count = res.get('domain_count', 0)
    table_data = {
        "Top Organizations Count": len(top_orgs),
        "TLD Count": tld_count,
        "Hostname Count": hostname_count,
        "Domain Count": domain_count
    }
    md = tableToMarkdown("Domain Statistics:", table_data)
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain.Search.DomainStats",
        outputs_key_field="hostname",
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def associated_domains_command(client, args):
    hostname = args.get('hostname')
    page = args.get('page', 1)

    res = client.associated_domains(hostname=hostname, page=page)
    records = res.get('records', [])
    record_count = res.get('record_count', 0)
    table_data = {
        "Count": record_count,
        "Domains": ", ".join([x.get('hostname') for x in records]),
        "Current Page": page,
        "Total Pages": res.get('meta', {}).get('total_pages', 1)
    }
    md = tableToMarkdown(f"{hostname} Associated Domains:", table_data,
                         ['Count', 'Current Page', 'Total Pages', 'Domains'])
    output_data = {
        "name": hostname,
        "associated_domains": records,
        "associated_domain_count": record_count
    }
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs=output_data,
        readable_output=md
    )
    return_results(command_results)


def get_ssl_certificates(client, args):
    hostname = args.get('hostname')
    include_subdomains = True if args.get('include_subdomains', 'false') == 'true' else False
    status = args.get('status', 'valid')
    page = None
    params = {
        "include_subdomains": include_subdomains,
        "status": status
    }
    if "page" in args:
        page = int(args.get('page', 1))
        params['page'] = page
    query_type = "paged" if page else "stream"
    res = client.get_ssl_certificates(query_type=query_type, hostname=hostname, params=params)
    records = res.get('records', [])
    # record_count = res.get('record_count', 0)
    table_data = [{
        "Subject Key ID": x.get('subject_key_id'),
        "Subject Common Name": x.get('subject', {}).get('common_name'),
        "Subject Alternative Names": ", ".join([y for y in x.get('subject', {}).get('alt_names', [])]),
        "Serial Number": x.get('serial_number'),
        "Public Key Type": x.get('public_key', {}).get('key_type'),
        "Public Key": x.get('public_key', {}).get('key'),
        "Public Key Bit Length": x.get('public_key', {}).get('bit_length'),
        "Precert": x.get('precert'),
        "Not Before": x.get('not_before'),
        "Not After": x.get('not_after'),
        "Issuer Organization": ",".join(x.get('issuer', {}).get('organization')),
        "Issuer Country": ",".join(x.get('issuer', {}).get('country')),
        "Issuer Common Name": x.get('issuer', {}).get('common_name'),
        "ID": x.get('id'),
        "Fingerprints": x.get('fingerprints'),
        "DNS Names": ",".join(x.get('dns_names'))
    } for x in records]

    md = tableToMarkdown(f"SSL Certificates for {hostname}", table_data, [
        "ID",
        "Subject Key ID",
        "Subject Common Name",
        "Subject Alternative Names",
        "Serial Number",
        "Public Key Type",
        "Public Key",
        "Public Key Bit Length",
        "Precert",
        "Not Before",
        "Not After",
        "Issuer Organization",
        "Issuer Country",
        "Issuer Common Name",
        "Fingerprints",
        "DNS Names"
    ])
    output_data = {
        "name": hostname,
        "ssl_certiticates": records
    }
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs=output_data,
        readable_output=md
    )
    return_results(command_results)


#################################
# History endpoints
#################################


def get_dns_history_command(client, args):
    hostname = args.get('hostname')
    record_type = args.get('type')
    page = int(args.get('page', 1))
    res = client.get_dns_history(hostname=hostname, record_type=record_type, page=page)
    res = {k: v for k, v in res.items() if k not in removed_keys}
    records_list = list()

    if record_type == "a":
        pull_field = "ip"
    elif record_type == "aaaa":
        pull_field = "ipv6"
    elif record_type == "mx":
        pull_field = "host"
    elif record_type == "ns":
        pull_field = "nameserver"
    elif record_type == "soa":
        pull_field = "email"
    elif record_type == "txt":
        pull_field = "value"
    else:
        pull_field = ""
        demisto.debug(f"There is no matching value for {record_type=}. {pull_field=}")
    records = res.get('records', {})
    for record in records:
        for value in record.get('values'):
            if pull_field in value:
                records_list.append(
                    {
                        "Record Type": record_type,
                        "Value(s)": value.get(pull_field)
                    }
                )
    readable_output = tableToMarkdown(f"DNS history for {hostname}:", records_list)

    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs={
            "name": hostname,
            f"{record_type}_history_records": res.get('records'),
            f"{record_type}_history_record_pages": res.get('pages', 1)
        },
        readable_output=readable_output
    )
    return_results(command_results)

    latest_record = res.get('records', [])[0]
    values = latest_record.get('values', [])
    values = [values] if type(values) is dict else values
    # hosts = [x['host'] for x in values if "host" in x]
    ipv4 = [x['ip'] for x in values if "ip" in x]
    ipv6 = [x['ip'] for x in values if "ipv6" in x]
    nameservers = [x['nameserver'] for x in values if "nameserver" in x]

    domain_data = {
        "Name": hostname
    }

    if nameservers:
        domain_data['NameServers'] = ", ".join(nameservers)

    create_standard_domain_context(domain_data=domain_data)

    if ipv4:
        [create_standard_ip_context({"Address": x}) for x in ipv4]
    if ipv6:
        [create_standard_ip_context({"Address": x}) for x in ipv6]


def get_whois_history_command(client, args):
    hostname = args.get('hostname')
    page = int(args.get('page', 1))
    res = client.get_whois_history(hostname=hostname, page=page)
    readable_output = tableToMarkdown(f"WHOIS history for {hostname}:", res.get('items'))
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.Domain",
        outputs_key_field="name",
        outputs={
            "name": hostname,
            "WHOIS_history": res.get('items', []),
            "WHOIS_history_count": res.get('count', 0)
        },
        readable_output=readable_output
    )
    return_results(command_results)

    domain_data = {
        "Name": hostname
    }

    contacts = res.get('items', [])[0].get('contact') if res.get('items', None) else []
    admin_contact = [x for x in contacts if x.get('type', None) == "administrativeContact"]
    admin_contact = admin_contact[0] if admin_contact else None
    registrant_contact = [x for x in contacts if x.get('type', None) == "registrant"]
    registrant_contact = registrant_contact[0] if registrant_contact else None
    registrar_contact = admin_contact if admin_contact else None

    whois_objects = list()

    for x in res.get('items', []):
        whois_object = {
            "DomainStatus": ", ".join(x.get('status', [])),
            "NameServers": ", ".join(x.get('nameServers', [])),
            "CreationDate": datetime.fromtimestamp((x.get('createdDate') / 1000)).strftime(
                "%Y-%m-%dT%H:%M:%SZ") if x.get('createdDate', None) else None,
            "UpdatedDate": datetime.fromtimestamp((x.get('updatedDate') / 1000)).strftime(
                "%Y-%m-%dT%H:%M:%SZ") if x.get('updatedDate', None) else None,
            "ExpirationDate": datetime.fromtimestamp((x.get('expiresDate') / 1000)).strftime(
                "%Y-%m-%dT%H:%M:%SZ") if x.get('expiresDate', None) else None
        }
        if admin_contact:
            whois_object['Admin'] = {   # type: ignore
                "Name": admin_contact.get('name'),
                "Email": admin_contact.get('email'),
                "Phone": admin_contact.get('telephone')
            }
        if registrant_contact:
            whois_object['Registrant'] = {  # type: ignore
                "Name": registrant_contact.get('name'),
                "Email": registrant_contact.get('email'),
                "Phone": registrant_contact.get('telephone')
            }
        if registrar_contact:
            whois_object['Registrar'] = {   # type: ignore
                "Name": registrar_contact.get('name'),
                "Email": registrar_contact.get('email'),
                "Phone": registrar_contact.get('telephone')
            }
        whois_objects.append(whois_object)

    if len(whois_objects) > 0:
        domain_data['WHOIS/History'] = whois_objects
    create_standard_domain_context(domain_data=domain_data)


#################################
# IPs endpoints
#################################


def get_ip_neighbors_command(client, args):
    ipaddress = args.get('ipaddress')
    res = client.get_ip_neighbors(ipaddress=ipaddress)
    readable_output = tableToMarkdown(
        f"IP neighbors for {ipaddress}:",
        [{
            "IP": x.get('ip', ''),
            "Hostnames": x.get('hostnames', None),
            "Sites": x.get('sites', 0),
            "Ports": x.get('ports', None),
            "Active Egress": x.get('active_egress')
        } for x in res],
        ["IP", "Hostnames", "Sites", "Ports", "Active Egress"])
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.IP",
        outputs_key_field="ip",
        outputs={
            "ip": ipaddress,
            "blocks": res
        },
        readable_output=readable_output
    )
    return_results(command_results)
    create_standard_ip_context(
        ip_data=[{
            "Address": x.get('ip').split("/")[0]
        } for x in res])


def ip_search_command(client, args):
    page = arg_to_number(args.get('page', 1))
    query = args.get('query', None)
    params = {
        "page": page
    }
    body = {
        "query": query
    }
    res = client.query(query_type="ip_search", params=params, body=body)
    records = res.get('records')
    record_count = res.get('record_count')
    md = tableToMarkdown(f"IP DSL Search Results ({record_count} record(s)):", records)
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.IP.Search",
        outputs_key_field="ip",
        outputs=records,
        readable_output=md
    )
    return_results(command_results)
    create_standard_ip_context(
        ip_data=[{
            "Address": x.get('ip'),
            "Hostname": x.get('ptr'),
            "Ports": ", ".join([str(y['port']) for y in x.get('ports')])
        } for x in records])


def ip_statistics_command(client, args):
    query = args.get('query')
    body = {
        "query": query
    }

    res = client.query(query_type="ip_stats", body=body)
    res = {k: v for k, v in res.items() if k not in removed_keys}

    top_ptrs = res.get('top_ptr_patterns', [])
    ports = res.get('ports', [])
    total = res.get('total', {}).get('value')
    table_data = {
        "Top PTRs Count": len(top_ptrs),
        "Ports": len(ports),
        "Total": total
    }
    md = tableToMarkdown("IP Statistics:", table_data)
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.IP.Search.IPStats",
        outputs=res,
        readable_output=md
    )
    return_results(command_results)


def get_useragents_command(client, args):
    ip_address = args.get('ipaddress')
    page = arg_to_number(args.get('page', 1))
    params = {
        "page": page
    }
    res = client.get_useragents(ip_address=ip_address, params=params)
    records = res.get('records', [])
    record_count = res.get('record_count', 0)
    table_data = [{
        "User Agent": x.get('user_agent'),
        "OS Name": x.get('os', {}).get('name'),
        "OS Platform": x.get('os', {}).get('platform'),
        "OS Version": x.get('os', {}).get('version'),
        "Browser Family": x.get('browser_family'),
        "Last Seen": x.get('lastseen'),
        "Device Type": x.get('device', {}).get('type'),
        "Device Brand": x.get('device', {}).get('brand'),
        "Device Model": x.get('device', {}).get('model'),
        "Client Type": x.get('client', {}).get('type'),
        "Client Name": x.get('client', {}).get('name'),
        "Client Version": x.get('client', {}).get('version'),
        "Client Engine": x.get('client', {}).get('engine'),
        "Client Engine Verison": x.get('client', {}).get('engine_version'),
    } for x in records]
    md = tableToMarkdown(f"User Agents for {ip_address}:", table_data, [
        'User Agent',
        'OS Name',
        'OS Platform',
        'OS Version',
        'Browser Family',
        'Last Seen',
        'Device Type',
        'Device Brand',
        'Device Model',
        'Client Type',
        'Client Name',
        'Client Version',
        'Client Engine',
        'Client Engine Verison'
    ])
    output_data = {
        "ip": ip_address,
        "useragents": records,
        "useragent_records_count": record_count
    }
    command_results = CommandResults(
        outputs_prefix="SecurityTrails.IP",
        outputs_key_field="ip",
        outputs=output_data,
        readable_output=md
    )
    return_results(command_results)


#################################
# Query endpoints
#################################


def query_sql_command(client, args):
    sql = args.get('sql')
    timeout = int(args.get('timeout', '20'))
    query = {
        "query": sql
    }
    res = client.sql(sql=query, timeout=timeout)
    total = res.get('total', {}).get('value')
    pages = 0
    if total:
        pages = total // 100
    output = {
        "total": res.get('total', {}).get('value'),
        "pages": pages,
        "records": res.get('records'),
        "id": res.get('id'),
        "query": res.get('query')
    }
    readable_output = tableToMarkdown("SQL Query Results:", output)
    command_results = CommandResults(
        outputs_prefix='SecurityTrails.SQL',
        outputs_key_field=['query', 'id'],
        outputs=output,
        readable_output=readable_output
    )
    return_results(command_results)


def query_sql_get_next_command(client, args):
    next_id = str(args.get('id'))
    timeout = int(args.get('timeout', '20'))
    res = client.sql_next(next_id=next_id, timeout=timeout)
    output = {
        "total": res.get('total', {}).get('value'),
        "records": res.get('records'),
        "id": res.get('id'),
        "query": res.get('query')
    }
    readable_output = tableToMarkdown("SQL Query Results:", output)
    command_results = CommandResults(
        outputs_prefix='SecurityTrails.SQL',
        outputs_key_field=['query', 'id'],
        outputs=output,
        readable_output=readable_output
    )
    return_results(command_results)


def test_module(client):
    results = client._http_request('GET', 'ping', ok_codes=(200, 403))
    if "success" in results:
        return "ok"
    else:
        return results.get('message')


''' MAIN FUNCTION '''


def main() -> None:
    params = demisto.params()
    args = demisto.args()

    api_key = params.get('apikey')
    timeout = int(params.get('timeout', '10'))
    verify_certificate = not params.get('insecure', False)
    proxy = params.get('proxy', False)
    base_url = "https://api.securitytrails.com/v1/"

    commands = {
        'securitytrails-sql-query': query_sql_command,
        'securitytrails-sql-get-next': query_sql_get_next_command,
        'securitytrails-get-subdomains': domains_subdomains_command,
        'securitytrails-get-domain-details': domain_details_command,
        'securitytrails-get-tags': get_domain_tags_command,
        'securitytrails-get-company-details': get_company_details_command,
        'securitytrails-get-company-associated-ips': get_company_associated_ips_command,
        'securitytrails-get-domain-whois': get_whois_command,
        'securitytrails-get-dns-history': get_dns_history_command,
        'securitytrails-get-whois-history': get_whois_history_command,
        'securitytrails-get-ip-neighbors': get_ip_neighbors_command,
        'securitytrails-search-domain': domain_search_command,
        'securitytrails-statistics-domain': domain_statistics_command,
        'securitytrails-get-associated-domains': associated_domains_command,
        # These 2 commands have issues with the response object - error when trying to parse to JSON
        # 'securitytrails-get-ssl-certitficates': get_ssl_certificates,
        # 'securitytrails-get-ssl-certitficates-stream': get_ssl_certificates,
        'securitytrails-search-ip': ip_search_command,
        'securitytrails-statistics-ip': ip_statistics_command,
        'securitytrails-get-ip-whois': get_whois_command,
        'securitytrails-get-useragents': get_useragents_command,
        'domain': domain_command
    }

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    try:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            'APIKEY': api_key
        }
        client = Client(
            base_url=base_url,
            verify=verify_certificate,
            headers=headers,
            proxy=proxy,
            timeout=timeout)

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif command in commands:
            commands[command](client, args)

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
