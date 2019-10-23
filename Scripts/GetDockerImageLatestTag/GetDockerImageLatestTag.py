import demistomock as demisto
from CommonServerPython import *
from CommonServerUserPython import *
import requests
import re

requests.packages.urllib3.disable_warnings()

ACCEPT_HEADER = {
    'Accept': "application/json, "
              "application/vnd.docker.distribution.manifest.v2+json, "
              "application/vnd.docker.distribution.manifest.list.v2+json"
}

# use 10 seconds timeout for requests
TIMEOUT = 10
DEFAULT_REGISTRY = "registry-1.docker.io"


def parse_www_auth(www_auth):
    """Parse realm and service from www-authenticate string of the form:
    Bearer realm="https://auth.docker.io/token",service="registry.docker.io"

    :param www_auth: www-authenticate header value
    :type www_auth: string
    """
    match = re.match(r'.*realm="(.+)",service="(.+)".*', www_auth, re.IGNORECASE)
    if not match:
        return None
    return (match.group(1), match.group(2))


def docker_auth(image_name, verify_ssl=True, registry=DEFAULT_REGISTRY):
    """
    Authenticate to the docker service. Return an authentication token if authentication is required.
    """
    res = requests.get(
        'https://{}/v2/'.format(registry),
        headers=ACCEPT_HEADER,
        timeout=TIMEOUT,
        verify=verify_ssl
    )
    if res.status_code == 401:  # need to authenticate
        # defaults in case we fail for some reason
        realm = "https://auth.docker.io/token"
        service = "registry.docker.io"
        # Should contain header: Www-Authenticate
        www_auth = res.headers.get('www-authenticate')
        if www_auth:
            parse_auth = parse_www_auth(www_auth)
            if parse_auth:
                realm, service = parse_auth
            else:
                demisto.info('Failed parsing www-authenticate header: {}'.format(www_auth))
        else:
            demisto.info('Failed extracting www-authenticate header from registry: {}, final url: {}'.format(
                registry, res.url))
        res = requests.get(
            '{}?scope=repository:{}:pull&service={}'.format(realm, image_name, service),
            headers=ACCEPT_HEADER,
            timeout=TIMEOUT,
            verify=verify_ssl
        )
        res.raise_for_status()
        res_json = res.json()
        return res_json.get('token')
    else:
        res.raise_for_status()
        return None


def segment_max_extract(tags, segment_number):
    """Will find the maximal number in a docker image tag segment

    Args:
        tags(list): list of docker image tag names - ordered in lexical order
        segment_number(int): the number of the tag segment to check.
    """
    max_segment = -1
    for tag in tags:
        tag_seg = tag.split('.')
        if len(tag_seg) < segment_number + 1:
            continue

        else:
            tag_seg = tag_seg[segment_number]

        if tag_seg.isdigit():
            if int(tag_seg) > max_segment:
                max_segment = int(tag_seg)

    return max_segment


def clear_older_tags(tags, max_segment, segment_number):
    """Will remove entries from the docker image tags list where their tag segment is lower than the maximal number
    in that segment.

    for example for tag list: [2.0.2000, 2.1.2700 2.1.373, latest] in segment '1' the highest number is '1'
    will return [2.1.2700, 2.1.373]

    Args:
        tags(list): list of docker image tag names - ordered in lexical order
        max_segment(int): the maximal number in a docker image tag in the segment_number
        segment_number(int): the segment_number to clear the list by

    Returns:
        The cleared docker image tags list
    """
    cleared_tag_list = []  # type:List
    for tag in tags:
        tag_seg = tag.split('.')
        if len(tag_seg) < segment_number + 1:
            continue

        else:
            tag_seg = tag_seg[segment_number]

        if tag_seg.isdigit():
            if int(tag_seg) == max_segment:
                cleared_tag_list.append(tag)

    return cleared_tag_list


def lexical_find_latest_tag(tags):
    """Will return the latest numeric docker image tag if possible - otherwise will return the last lexical tag.

    for example for the tag list: [2.0.2000, 2.1.2700 2.1.373, latest], will return 2.1.2700

    Args:
        tags(list): list of docker image tag names - ordered in lexical order
    """
    segment_number = 0
    while True:
        segment_max = segment_max_extract(tags, segment_number)
        # no tags with numbers
        if segment_max == -1:
            return tags[-1]

        tags = clear_older_tags(tags, segment_max, segment_number)
        if len(tags) == 1:
            return tags[0]

        segment_number = segment_number + 1


def find_latest_tag_by_date(tags):
    """Get the latest tags by datetime comparison.

    Args:
        tags(list): List of dictionaries representing the docker image tags

    Returns:
        The last updated docker image tag name
    """
    latest_tag_name = 'latest'
    latest_tag_date = datetime.now() - timedelta(days=400000)
    for tag in tags:
        tag_date = datetime.strptime(tag.get('last_updated'), '%Y-%m-%dT%H:%M:%S.%fZ')
        if tag_date >= latest_tag_date:
            latest_tag_date = tag_date
            latest_tag_name = tag.get('name')

    return latest_tag_name


def main():
    if demisto.args().get('use_system_proxy') == 'no':
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']
    verify_ssl = demisto.args().get('trust_any_certificate') != 'yes'
    docker_full_name = demisto.args()['docker_image']
    registry = DEFAULT_REGISTRY
    image_name = docker_full_name
    if docker_full_name.count('/') > 1:
        registry, image_name = docker_full_name.split('/', 1)
    try:
        auth_token = docker_auth(image_name, verify_ssl, registry)
        headers = ACCEPT_HEADER.copy()
        if auth_token:
            headers['Authorization'] = "Bearer {}".format(auth_token)

        # first try to get the docker image tags using normal http request
        res = requests.get(
            url='https://hub.docker.com/v2/repositories/{}/tags'.format(image_name),
            verify=verify_ssl,
        )
        if res.status_code == 200:
            tags = res.json().get('results', [])
            # if http request successful find the latest tag by date in the response
            if tags:
                tag = find_latest_tag_by_date(tags)

        else:
            # if http request did not successed than get tags using the API.
            # See: https://docs.docker.com/registry/spec/api/#listing-image-tags
            res = requests.get(
                'https://{}/v2/{}/tags/list'.format(registry, image_name),
                headers=headers,
                timeout=TIMEOUT,
                verify=verify_ssl
            )
            res.raise_for_status()
            # the API returns tags in lexical order with no date info - so try an get the numeric highest tag
            tags = res.json().get('tags', [])
            if tags:
                tag = lexical_find_latest_tag(tags)

        demisto.results(tag)
    except Exception as ex:
        return_error("Failed getting tag for: {}. Err: {}".format(docker_full_name, str(ex)))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
