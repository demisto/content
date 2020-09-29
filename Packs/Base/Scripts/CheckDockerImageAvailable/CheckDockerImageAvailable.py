import demistomock as demisto
from CommonServerPython import *
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
    res = requests.get("https://{}/v2/".format(registry), headers=ACCEPT_HEADER,
                       timeout=TIMEOUT, verify=verify_ssl)
    if res.status_code == 401:  # need to authenticate
        # defaults in case we fail for some reason
        realm = "https://auth.docker.io/token"
        service = "registry.docker.io"
        # Shold contain header: Www-Authenticate
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
            "{}?scope=repository:{}:pull&service={}".format(realm, image_name, service),
            headers=ACCEPT_HEADER, timeout=TIMEOUT, verify=verify_ssl)
        res.raise_for_status()
        res_json = res.json()
        return res_json.get('token')
    else:
        res.raise_for_status()
        return None


def docker_min_layer(layers):
    def layer_size(layer):
        return layer['size']
    return min(layers, key=layer_size)


def main():
    if demisto.args().get('use_system_proxy') == 'no':
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']
    verify_ssl = demisto.args().get('trust_any_certificate') != 'yes'
    docker_full_name = demisto.args()['input']
    registry = DEFAULT_REGISTRY
    image_name_tag = docker_full_name
    if docker_full_name.count('/') > 1:
        registry, image_name_tag = docker_full_name.split('/', 1)
    try:
        split = image_name_tag.split(':')
        image_name = split[0]
        tag = 'latest'
        if len(split) > 1:
            tag = split[1]
        if tag is None:
            tag = 'latest'
        auth_token = docker_auth(image_name, verify_ssl, registry)
        headers = ACCEPT_HEADER.copy()
        if auth_token:
            headers['Authorization'] = "Bearer {}".format(auth_token)
        res = requests.get("https://{}/v2/{}/manifests/{}".format(registry, image_name, tag),
                           headers=headers, timeout=TIMEOUT, verify=verify_ssl)
        res.raise_for_status()
        layers = res.json().get('layers')
        if not layers:
            raise ValueError("No 'layers' found in json response: {}".format(res.content))
        layer_min = docker_min_layer(layers)
        headers['Range'] = "bytes=0-99"
        res = requests.get("https://{}/v2/{}/blobs/{}".format(registry, image_name, layer_min['digest']),
                           headers=headers, timeout=TIMEOUT, verify=verify_ssl)
        res.raise_for_status()
        expected_len = min([100, layer_min['size']])
        cont_len = len(res.content)
        demisto.info("Docker image check [{}] downloaded layer content of len: {}".format(docker_full_name, cont_len))
        if cont_len < expected_len:
            raise ValueError('Content returned is shorter than expected length: {}. Content: {}'.format(expected_len,
                             res.content))
        demisto.results('ok')
    except Exception as ex:
        return_error("Failed verifying: {}. Err: {}".format(docker_full_name, str(ex)))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
