import demistomock as demisto
from CommonServerPython import *
import requests

ACCEPT_HEADER = {
    'Accept': "application/json, "
    "application/vnd.docker.distribution.manifest.v2+json, "
    "application/vnd.docker.distribution.manifest.list.v2+json"
}

# use 10 seconds timeout for requests
TIMEOUT = 10


def docker_auth(image_name):
    """
    Authenticate to the docker service. Return an authentication token if authentication is required.
    """
    res = requests.get("https://registry-1.docker.io/v2/", headers=ACCEPT_HEADER, timeout=TIMEOUT)
    if res.status_code == 401:  # need to authenticate
        res = requests.get(
            "https://auth.docker.io/token?scope=repository:{}:pull&service=registry.docker.io".format(image_name),
            headers=ACCEPT_HEADER, timeout=TIMEOUT)
        res.raise_for_status()
        res_json = res.json()
        return res_json.get('token')
    else:
        res.raise_for_status()
        return None


def docker_min_layer(layers):
    def layer_size(l):
        return l['size']
    return min(layers, key=layer_size)


def main():
    docker_full_name = demisto.args()['input']
    if demisto.args().get('use_system_proxy') == 'no':
        del os.environ['HTTP_PROXY']
        del os.environ['HTTPS_PROXY']
        del os.environ['http_proxy']
        del os.environ['https_proxy']
    try:
        image_name, tag = docker_full_name.split(':')
        if tag is None:
            tag = 'latest'
        auth_token = docker_auth(image_name)
        headers = ACCEPT_HEADER.copy()
        if auth_token:
            headers['Authorization'] = "Bearer {}".format(auth_token)
        res = requests.get("https://registry-1.docker.io/v2/{}/manifests/{}".format(image_name, tag), 
                           headers=headers, timeout=TIMEOUT)
        res.raise_for_status()
        layers = res.json().get('layers')
        if not layers:
            raise ValueError("No 'layers' found in json response: {}".format(res.content()))
        layer_min = docker_min_layer(layers)
        headers['Range'] = "bytes=0-99"
        res = requests.get("https://registry-1.docker.io/v2/{}/blobs/{}".format(image_name, layer_min['digest']),
                           headers=headers, timeout=TIMEOUT)
        res.raise_for_status()
        expected_len = min([100, layer_min['size']])
        if len(res.content) < expected_len:
            raise ValueError('Content returned is shorter than expected length: {}. Content: {}'.format(expected_len,
                             res.content))
        demisto.results('ok')
    except Exception as ex:
        return_error("Failed verifying: {}. Err: {}".format(docker_full_name, str(ex)))


# python2 uses __builtin__ python3 uses builtins
if __name__ == "__builtin__" or __name__ == "builtins":
    main()
