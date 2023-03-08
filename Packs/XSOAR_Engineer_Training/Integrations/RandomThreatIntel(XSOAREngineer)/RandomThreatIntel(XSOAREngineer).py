import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from random import randrange

# this integration really can't be trusted
reliability = demisto.params().get("integrationReliability")

# Utility functions


def random_threat_score():
    """
    Returns a random threat score and dbot score, it's anyones guess!
    """
    threatscore = randrange(1, 100)

    # set dbotscore based on score from threat score between 1 and 100.
    if threatscore >= 20:
        score = Common.DBotScore.BAD
        description = True
    elif threatscore >= 1:
        score = Common.DBotScore.SUSPICIOUS
        description = True
    else:
        score = Common.DBotScore.GOOD
        description = False

    return threatscore, score, description


def create_dbot_score(indicator, indicator_type, score, malicious_description=None):
    """
    Returns the dbot score object
    """
    if malicious_description:
        dbot_score = Common.DBotScore(
            indicator=indicator,
            indicator_type=indicator_type,
            integration_name='RandomThreatIntel',
            malicious_description=f'This URL {indicator} is up to no good!',
            score=score,
            reliability=reliability
        )
    else:
        dbot_score = Common.DBotScore(
            indicator=indicator,
            indicator_type=indicator_type,
            integration_name='RandomThreatIntel',
            score=score,
            reliability=reliability
        )
    return dbot_score


def create_results(readable, prefix, key_field, outputs, indicator):
    """
    Return the results entry
    """

    results = CommandResults(
        readable_output=readable,
        outputs_prefix=f'RandomThreatIntel.{prefix}',
        outputs_key_field=key_field,
        outputs=outputs,
        indicator=indicator
    )

    return results


# Command functions


def url_command(url_arg):
    """
    Return a random result for a given url
    """

    # get some fake data
    threatscore, score, description = random_threat_score()

    # fake raw response and readable output
    url_raw_response = {'url': url_arg, 'threatscore': threatscore}
    readable = tableToMarkdown('Random Threat Intel URL Reputation', url_raw_response, headers=['url', 'threatscore'])

    # create dbotscore
    dbot_score = create_dbot_score(indicator=url_arg, indicator_type=DBotScoreType.URL,
                                   score=score, malicious_description=description)

    # create url context for response
    url = Common.URL(
        url=url_arg,
        dbot_score=dbot_score
    )

    # generate and return results
    results = create_results(readable, 'URL', 'url', url_raw_response, url)

    return results


def ip_command(ip_arg):
    """
    Return a random result for a given ip
    """

    # get some fake data
    threatscore, score, description = random_threat_score()

    # fake raw response and readable output
    ip_raw_response = {'ip': ip_arg, 'threatscore': threatscore}
    readable = tableToMarkdown('Random Threat Intel IP Reputation', ip_raw_response, headers=['ip', 'threatscore'])

    # create dbotscore
    dbot_score = create_dbot_score(indicator=ip_arg, indicator_type=DBotScoreType.IP,
                                   score=score, malicious_description=description)

    # create ip context for response
    ip = Common.IP(
        ip=ip_arg,
        dbot_score=dbot_score
    )

    # generate and return results
    results = create_results(readable, 'IP', 'ip', ip_raw_response, ip)

    return results


def domain_command(domain_arg):
    """
    Return a random result for a given domain
    """

    # get some fake data
    threatscore, score, description = random_threat_score()

    # fake raw response and readable output
    domain_raw_response = {'domain': domain_arg, 'threatscore': threatscore}
    readable = tableToMarkdown('Random Threat Intel Domain Reputation', domain_raw_response, headers=['domain', 'threatscore'])

    # create dbotscore
    dbot_score = create_dbot_score(indicator=domain_arg, indicator_type=DBotScoreType.DOMAIN,
                                   score=score, malicious_description=description)

    # create domain context for response
    domain = Common.Domain(
        domain=domain_arg,
        dbot_score=dbot_score
    )

    # generate and return results
    results = create_results(readable, 'Domain', 'domain', domain_raw_response, domain)

    return results


def file_command(file_arg):
    """
    Return a random result for a given file hash, md5, sha256, sha1
    """

    # get some fake data
    threatscore, score, description = random_threat_score()

    # fake raw response and readable output
    file_raw_response = {'threatscore': threatscore}
    if len(file_arg) == 32:
        file_raw_response['md5'] = file_arg
    if len(file_arg) == 40:
        file_raw_response['sha1'] = file_arg
    if len(file_arg) == 64:
        file_raw_response['sha256'] = file_arg

    readable = tableToMarkdown('Random Threat Intel File Reputation', file_raw_response)

    # create dbotscore
    dbot_score = create_dbot_score(indicator=file_arg, indicator_type=DBotScoreType.FILE,
                                   score=score, malicious_description=description)

    # create domain context for response
    file = Common.File(
        md5=file_raw_response.get('md5', ""),
        sha1=file_raw_response.get('sha1', ""),
        sha256=file_raw_response.get('sha256', ""),
        dbot_score=dbot_score
    )

    # generate and return results
    results = create_results(readable, 'File', 'md5', file_raw_response, file)

    return results


def private_ip_command(ip_arg):
    """
    Same as IP, but for private ip addresses.
    Mocked to handle the Private IP custom indicator. Still returns IP results, but command can be used as the reputation command for a custom indicator.

        Indicator Type: Private IP
        Regex: (10((?:\[\.\]|\.)(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){3}|((172(?:\[\.\]|\.)(1[6-9]|2[0-9]|3[01]))|192(?:\[\.\]|\.)168)((?:\[\.\]|\.)(25[0-5]|2[0-4][0-9]|1[0-9]{1,2}|[0-9]{1,2})){2})
        Reputation Command: private-ip

        Exclusions: For this to work, exclude the following CIDR ranges as type IP so they don't get auto-extracted as such: 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12
    """

    threatscore, score, description = random_threat_score()

    # fake raw response and readable output
    ip_raw_response = {'ip': ip_arg, 'asn': 'privateip', 'threatscore': threatscore, 'description': 'Internal IP'}
    readable = tableToMarkdown('Random Threat Intel IP Reputation', ip_raw_response,
                               headers=['ip', 'asn', 'threatscore', 'description'])

    # create dbotscore
    dbot_score = create_dbot_score(indicator=ip_arg, indicator_type=DBotScoreType.IP,
                                   score=score, malicious_description=description)

    # create ip context for response
    ip = Common.IP(
        ip=ip_arg,
        asn='12345',
        dbot_score=dbot_score
    )

    # generate and return results
    results = create_results(readable, 'IP', 'ip', ip_raw_response, ip)

    return results


def cxhost_command(cxhost_arg):
    """
    This is and example of indicator enrichment on a custom indicator called CXHost, showing how you can set this up automatically run when extracted via regex
    The response is rather picky, you need to return exactly as shown below, with your additions etc in teh raw response.
        Indicator Type: CXHost
        Regex: (crossiscoming\d{3,5}) (autoextract anything with crossiscoming and 3-5 digits)
        Reputation Command: cxhost
    """

    # fake raw response and readable output
    cxhost_raw_response = {'cxhost': cxhost_arg, 'description': 'cxhost custom indicator'}
    readable = tableToMarkdown('Random Threat Intel CXHost Reputation', cxhost_raw_response, headers=['cxhost', 'description'])

    # generate and return results for this indicator
    results = {
        'Type': entryTypes['note'],
        'ContentsFormat': formats['json'],
        'Contents': cxhost_raw_response,
        'HumanReadable': readable,
        'EntryContext': {
            'DBotScore': {
                'Indicator': cxhost_arg,
                'Type': 'CXHost',
                        'Vendor': 'RandomThreatIntel',
                        'Score': 1
            },
            'RandomThreatIntel.CXHost': cxhost_raw_response
        }
    }

    return results


# Command execution

if demisto.command() == 'test-module':
    demisto.results('ok')

elif demisto.command() == 'url':
    url_arg = demisto.args().get('url')
    return_results(url_command(url_arg))

elif demisto.command() == 'ip':
    ip_arg = demisto.args().get('ip')
    return_results(ip_command(ip_arg))

elif demisto.command() == 'domain':
    domain_arg = demisto.args().get('domain')
    return_results(domain_command(domain_arg))

elif demisto.command() == 'file':
    file_arg = demisto.args().get('file')
    return_results(file_command(file_arg))

elif demisto.command() == 'private-ip':
    ip_arg = demisto.args().get('ip')
    return_results(private_ip_command(ip_arg))

elif demisto.command() == 'cxhost':
    cxhost_arg = demisto.args().get('cxhost')
    demisto.results(cxhost_command(cxhost_arg))
