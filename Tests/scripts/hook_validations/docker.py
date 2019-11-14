from Tests.test_utils import get_yaml, print_error, server_version_compare
from pkg_resources import parse_version
from datetime import datetime, timedelta
import re
import requests


# disable insecure warnings
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
    return [match.group(1), match.group(2)]


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
            if parse_auth and len(parse_auth) == 2:
                realm, service = parse_auth
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


def clear_non_numbered_tags(tags):
    """Clears a given tags list to only keep numbered tags

    Args:
        tags(list): list of docker image tag names - ordered in lexical order

    Returns:
        a tag list with only numbered tags
    """
    only_numbered_tags = []
    for tag in tags:
        number_token = 1
        split_tag = tag.split('.')
        for sub_section in split_tag:
            if not sub_section.isdigit():
                number_token = 0

        if number_token:
            only_numbered_tags.append(tag)

    return only_numbered_tags


def lexical_find_latest_tag(tags):
    """Will return the latest numeric docker image tag if possible - otherwise will return the last lexical tag.

    for example for the tag list: [2.0.2000, 2.1.2700 2.1.373, latest], will return 2.1.2700

    Args:
        tags(list): list of docker image tag names - ordered in lexical order
    """

    only_numbered_tags = clear_non_numbered_tags(tags)

    if len(only_numbered_tags) == 0:
        return tags[-1]

    max_tag = only_numbered_tags[0]

    for num_tag in only_numbered_tags:
        if parse_version(max_tag) < parse_version(num_tag):
            max_tag = num_tag

    return max_tag


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


def get_docker_image_latest_tag(docker_image_name):
    try:
        tag = ''
        auth_token = docker_auth(docker_image_name, False, DEFAULT_REGISTRY)
        headers = ACCEPT_HEADER.copy()
        if auth_token:
            headers['Authorization'] = "Bearer {}".format(auth_token)

        # first try to get the docker image tags using normal http request
        res = requests.get(
            url='https://hub.docker.com/v2/repositories/{}/tags'.format(docker_image_name),
            verify=False,
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
                'https://{}/v2/{}/tags/list'.format(DEFAULT_REGISTRY, docker_image_name),
                headers=headers,
                timeout=TIMEOUT,
                verify=False
            )
            res.raise_for_status()
            # the API returns tags in lexical order with no date info - so try an get the numeric highest tag
            tags = res.json().get('tags', [])
            if tags:
                tag = lexical_find_latest_tag(tags)
        return tag
    except (requests.exceptions.RequestException, Exception):
        print_error("Failed getting tag for: {}. Please check it exists and of demisto format."
                    .format(docker_image_name))
        return ''


def parse_docker_image(docker_image):
    if docker_image:
        try:
            tag = re.findall(r'(demisto\/.+):.+', docker_image, re.IGNORECASE)[0]
            name = re.findall(r'demisto\/.+:(.+)', docker_image, re.IGNORECASE)[0]
            return name, tag
        except IndexError:
            # TODO: Check if need to raise Exception
            print_error("The docker image isn't of format - demisto/image_name:0.0.0")
            return '', ''
    else:
        # If the yml file has no docker image we provide the default one 'demisto/python:1.3-alpine'
        return 'demisto/python', '1.3-alpine'


class DockerImageValidator(object):

    def __init__(self, yml_file_path, is_modified_file):
        self.is_modified_file = is_modified_file
        self.yml_file = get_yaml(yml_file_path)
        self.from_version = self.yml_file.get('fromversion', '0')
        self.docker_image_name, self.docker_image_tag = parse_docker_image(self.yml_file.get('dockerimage', ''))
        self.is_latest_tag = True
        self.docker_image_latest_tag = get_docker_image_latest_tag(self.docker_image_name)

    def is_docker_image_latest_tag(self):
        if not self.docker_image_tag and not self.docker_image_name and not self.docker_image_latest_tag:
            # If the docker image isn't in the format we expect it to be
            self.is_latest_tag = False
        else:
            # Case of a modified file with version >= 5.0.0
            if self.is_modified_file and server_version_compare(self.from_version, '5.0.0') >= 0:
                # If docker image name are different and if the docker image isn't the default one
                if self.docker_image_latest_tag != self.docker_image_tag and not \
                        'demisto/python:1.3-alpine' == '{}:{}'.format(self.docker_image_name, self.docker_image_tag):
                    self.is_latest_tag = False
            # Case of an added file
            elif not self.is_modified_file:
                if self.docker_image_latest_tag != self.docker_image_tag:
                    self.is_latest_tag = False

        if not self.is_latest_tag:
            print_error("The docker image tag isn't the latest, please update it.")
        return self.is_latest_tag
