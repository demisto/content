import demistomock as demisto  # noqa # pylint: disable=unused-wildcard-import
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa # pylint: disable=unused-wildcard-import

from typing import (
    Dict, Any, Optional,
    Union, List
)
import traceback

import dns.message
import dns.resolver
import dns.rdatatype
import dns.rdataclass
import dns.rdata


DNS_QUERY_TTL = 10.0
QTYPES = ["CNAME", "NS", "A", "AAAA"]


''' STANDALONE FUNCTION '''


def make_query(resolver: dns.resolver.Resolver, qname: str, qtype: str, use_tcp: bool) -> Dict[str, Any]:
    q_rdtype = dns.rdatatype.from_text(qtype)
    q_rdclass = dns.rdataclass.from_text("IN")

    try:
        ans = resolver.resolve(
            qname,
            q_rdtype, q_rdclass,
            tcp=use_tcp,
            lifetime=DNS_QUERY_TTL,
            raise_on_no_answer=True
        )

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return {}

    if ans.rrset is None:
        return {}

    result: Dict[str, List[str]] = {}

    result[qtype] = [
        rr.to_text()
        for rr in ans.rrset
        if (rr is not None and rr.rdtype == q_rdtype and rr.rdclass == q_rdclass)
    ]

    return result


''' COMMAND FUNCTION '''


def get_domain_dns_details_command(args: Dict[str, Any]) -> CommandResults:
    outputs: Optional[Dict[str, Dict[str, Any]]]
    answer: Union[str, Dict[str, Any]]

    server = args.get('server')
    use_tcp = argToBoolean(args.get('use_tcp', 'Yes'))

    qtypes = QTYPES
    if (arg_qtype := args.get('qtype')) is not None:
        qtypes = argToList(arg_qtype)

    qname = args.get('domain')
    if qname is None:
        raise ValueError("domain is required")

    resolver = dns.resolver.Resolver()
    if server is not None:
        resolver.nameservers = [server]

    answer = {
        'domain': qname,
        'server': server if server is not None else 'system'
    }

    # we ask specifically for CNAMEs
    for qtype in qtypes:
        answer.update(make_query(resolver, qname, qtype, use_tcp=use_tcp))

    outputs = {
        'Expanse.DomainDNSDetails': answer
    }

    markdown = tableToMarkdown(
        f' ExpanseDomainDNSDetails for {qname}',
        answer,
        headers=["domain", "server"] + qtypes
    )

    return CommandResults(
        readable_output=markdown,
        outputs=outputs,
        outputs_key_field=['domain', 'server']
    )


''' MAIN FUNCTION '''


def main():
    try:
        return_results(get_domain_dns_details_command(demisto.args()))
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute ExpanseGetDomainDNSDetails. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
