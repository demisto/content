import sys
import argparse
import logging
from demisto_sdk.commands.common.hook_validations.docker import DockerImageValidator
from Tests.scripts.utils.log_util import install_logging


def options_handler():
    parser = argparse.ArgumentParser(description='Get full docker image name of latest version.')
    parser.add_argument('-i', '--image', help='The base image without any tags', required=True)
    options = parser.parse_args()
    return options


def get_full_docker_image(base_docker_image: str):
    """Get full docker image name including the tag for the latest version of base_docker_image."""
    # Get the latest tag of the image from Docker Hub
    latest_tag = (DockerImageValidator.get_docker_image_latest_tag_request(base_docker_image))

    if latest_tag:
        return f"{base_docker_image}:{latest_tag}"
    else:  # latest tag not found
        err_msg = f"Error: Failed getting the latest tag of {base_docker_image} from Docker Hub."
        logging.error(err_msg)
        raise RuntimeError(err_msg)


def main():
    install_logging('GetLatestDockerImage.log')
    options = options_handler()
    docker_full_image = get_full_docker_image(options.image)
    print(docker_full_image, file=sys.stdout)


if __name__ == '__main__':
    main()
