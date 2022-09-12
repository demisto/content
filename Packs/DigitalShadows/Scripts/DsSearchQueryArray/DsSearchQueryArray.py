import demistomock as demisto  # noqa: F401
from CommonServerPython import *
from urllib.parse import urlparse


QUOTED_STRINGS_PATTERN = r'\"[^\"]*\"'
KEYWORDS_PATTERN = " (AND|OR|NOT) "
NON_WORD_PATTERN = "\W+"


def append_arg(terms: Set[str], arg: Union[str, List[str]], filter_fn=lambda _: True):
    """
    Append the given argument to the given set.

    Handles the case where an arg is a list and applies a filter function to remove
    unwanted search terms.

    :param terms: set of terms to append new terms to
    :param filter_fn: a function to be used with the builtin filter function to exclude unwanted terms
    """
    asList = argToList(arg)
    new_terms: List[str] = list(filter(filter_fn, asList))
    if len(new_terms):
        terms.update(new_terms)


def extract_terms(args: Dict[str, Any]) -> Set[str]:
    """
    Extract terms for each type of supported argument.

    Ensure this list remains up to date with the args declared in
    the YML file.

    :param args: dictionary of arguments passed to the command
    :return: set of string terms
    """
    terms: Set[str] = set()
    if 'sha1' in args:
        append_arg(terms, args['sha1'])
    if 'md5' in args:
        append_arg(terms, args['md5'])
    if 'sha256' in args:
        append_arg(terms, args['sha256'])
    if 'domain' in args:
        append_arg(terms, args['domain'], filter_fn=check_domain_name)
    if 'ip' in args:
        append_arg(terms, args['ip'], filter_fn=check_ip)
    if 'url' in args:
        append_arg(terms, args['url'], filter_fn=check_url)
    if 'cve' in args:
        append_arg(terms, args['cve'])
    return terms


def convert_to_ds_query_array(args: Dict[str, Any]):
    """
    Convert the provided args into a list of Shadow Search queries.

    Implements term-counting as Shadow Search has a maximum number of terms permitted
    per query.

    :param args: the arguments supplied to the command
    :return: a list of Shadow Search query strings
    """
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


def check_ip(ip):
    """
    Filter function that excludes the inet any address (0.0.0.0).
    """
    return "0.0.0.0" != ip


def check_domain_name(domain):
    """
    Filter function that removes the Digital Shadows portal hostname and subdomains of it.
    """
    if not domain.startswith("."):
        domain = "." + domain
    return not domain.endswith(".portal-digitalshadows.com")


def check_url(url):
    """
    Filter function that removes URLs associated with Digital Shadows portal hostname and subdomains of it.
    """
    domain = urlparse(url).netloc
    return check_domain_name(domain)


def count_terms(query):
    """Count the query terms in a given string"""
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
