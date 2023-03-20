from demisto_sdk.commands.common.git_util import GitUtil
from pathlib import Path
CONTENT_PATH = Path(GitUtil().git_path())
from ruamel.yaml import YAML
yaml = YAML()


def test_verify_same_docker_image_slack_notify_gitlab_ci():
    """
    This test checks if gitlab-ci and slack-notify have the same image.
    IF THIS TEST FAILED, PLEASE UPDATE BOTH DOCKER IMAGES.
    """
    gitlab_ci_path = CONTENT_PATH / '.gitlab' / 'ci' / '.gitlab-ci.yml'
    slack_notify_path = CONTENT_PATH / '.gitlab' / 'ci' / 'slack-notify.yml'

    gitlab_ci_yml = yaml.load(gitlab_ci_path)
    slack_notify_yml = yaml.load(slack_notify_path)

    assert gitlab_ci_yml.get('default', {}).get('image', '') == slack_notify_yml.get('default', {}).get('image', '')
