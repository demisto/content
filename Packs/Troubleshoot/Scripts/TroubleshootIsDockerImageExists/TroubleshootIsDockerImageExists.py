"""Validates that the docker image exists.
"""

from CommonServerPython import *

''' STANDALONE FUNCTION '''


def get_installed_docker_images():
    res = demisto.executeCommand(
        'demisto-api-get',
        {'uri': 'settings/docker-images'}
    )
    if is_error(res):
        raise DemistoException(get_error(res))
    return res[0]['Contents']['response']['images']


def main():
    docker_image: str = demisto.args().get('docker_image')
    if docker_image.count(':') != 1:
        raise DemistoException(f'Got a docker image with more than one \':\'. {docker_image=}')
    repository, tag = docker_image.split(':')
    installed_dockers_images = get_installed_docker_images()
    # Docker exists
    if any(item['repository'] == repository and item['tag'] == tag for item in installed_dockers_images):
        human_readable = f'Docker image {docker_image} exists!'
        exists = True
    else:
        human_readable = f'Could not find docker image {docker_image}'
        exists = False
    context = {
        'TroubleshootIsDockerImageExists(obj.docker_image === val.docker_image)': {
            'docker_image': docker_image,
            'exists': exists
        }
    }
    return_outputs(human_readable, context)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
