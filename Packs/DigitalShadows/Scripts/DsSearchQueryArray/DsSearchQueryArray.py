import demistomock as demisto  # noqa: F401
from CommonServerPython import *
from urllib.parse import urlparse

options = ["IP.Address", "Domain.Name", "URL.Data", "File.MD5", "File.SHA256", "File.SHA1", "CVE.ID"]

QUOTED_STRINGS_PATTERN = r'\"[^\"]*\"'
KEYWORDS_PATTERN = " (AND|OR|NOT) "
NON_WORD_PATTERN = "\W+"


def append_arg(terms: Set, arg: Union[str, List[str]], filter_fn=lambda x: True):
    if isinstance(arg, list):
        ts = filter(filter_fn, arg)
        terms.update(ts)
    else:
        # assume str
        if filter_fn(arg):
            terms.add(arg)


def extract_terms(args: Dict[str, Any]):
    terms = set()
    if 'sha1' in args:
        append_arg(terms, args['sha1'])
    if 'md5' in args:
        append_arg(terms, args['md5'])
    if 'sha256' in args:
        append_arg(terms, args['sha256'])
    if 'domain' in args:
        append_arg(terms, args['domain'], filter_fn=check_domain_name)
    if 'ip' in args:
        append_arg(terms, args['ip'], filter_fn=lambda x: "0.0.0.0" != x)
    if 'url' in args:
        append_arg(terms, args['url'], filter_fn=check_url)
    if 'cve' in args:
        append_arg(terms, args['cve'])
    return terms


def convert_to_ds_query_array(args: Dict[str, Any]):
    terms = extract_terms(args)

    res = list()
    query = sorted(terms, key=lambda x: count_terms(x))
    init = list()  # type: List[str]
    term_count = 0

    for q in query:
        if term_count + count_terms(q) > 35:
            res.append(" OR ".join(init))
            init = [q]
            term_count = count_terms(q)
        else:
            init.append(q)
            term_count += count_terms(q)
    if len(init):
        res.append(" OR ".join(init))
    return res


def check_domain_name(domain):
    if not domain.startswith("."):
        domain = "." + domain
    return not domain.endswith(".portal-digitalshadows.com")


def check_url(url):
    domain = urlparse(url).netloc
    return check_domain_name(domain)


def count_terms(query):
    query = re.sub(QUOTED_STRINGS_PATTERN, "x", query)
    query = re.sub(KEYWORDS_PATTERN, " ", query)
    query = re.sub(NON_WORD_PATTERN, " ", query)
    query = query.strip()
    term_count = 0
    if len(query) > 0:
        term_count = query.count(" ") + 1
    return term_count


def main():
    try:
        return_results(convert_to_ds_query_array(demisto.args()))
    except Exception as exception:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(exception)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
