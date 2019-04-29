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

        res = requests.get(
            'https://{}/v2/{}/tags/list'.format(registry, image_name),
            headers=headers,
            timeout=TIMEOUT,
            verify=verify_ssl
        )
        res.raise_for_status()
        # returns tags in lexical order. See: https://docs.docker.com/registry/spec/api/#listing-image-tags
        tags = res.json().get('tags', [])
        if tags:
            if tags[-1] != 'latest':
                tag = tags[-1]
            elif len(tags) > 1:  # skip latest case
                tag = tags[-2]
        else:
            tag = 'latest'
        demisto.results(tag)
    except Exception as ex:
        return_error("Failed getting tag for: {}. Err: {}".format(docker_full_name, str(ex)))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
