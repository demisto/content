import json
import argparse
import logging

import demisto_client
from slackclient import SlackClient

from Tests.scripts.utils.log_util import install_simple_logging
from Tests.test_integration import __create_integration_instance, __delete_integrations_instances
from demisto_sdk.commands.common.tools import str2bool
from Tests.configure_and_test_integration_instances import update_content_on_demisto_instance

SERVER_URL = "https://{}"


def options_handler():
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-t', '--instance_tests', type=str2bool, help='is instance test build?', required=True)
    parser.add_argument('-s', '--slack', help='The token for slack', required=True)
    parser.add_argument('-e', '--secret', help='Path to secret conf file', required=True)
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-b', '--buildUrl', help='The url for the build', required=True)
    parser.add_argument('-n', '--buildNumber', help='The build number', required=True)
    options = parser.parse_args()

    return options


def install_new_content(client, server):
    update_content_on_demisto_instance(client, server, 'Demisto Marketplace')


def get_integrations(secret_conf_path):
    with open(secret_conf_path) as data_file:
        secret_conf = json.load(data_file)

    secret_params = secret_conf['integrations'] if secret_conf else []
    return secret_params


def test_instances(secret_conf_path, server, username, password):
    integrations = get_integrations(secret_conf_path)

    instance_ids = []
    failed_integrations = []
    integrations_counter = 0

    content_installation_client = demisto_client.configure(base_url=server, username=username, password=password,
                                                           verify_ssl=False)
    install_new_content(content_installation_client, server)
    for integration in integrations:
        c = demisto_client.configure(base_url=server, username=username, password=password, verify_ssl=False)
        integrations_counter += 1
        integration_name = integration.get('name')
        integration_instance_name = integration.get('instance_name', '')
        integration_params = integration.get('params')
        devops_comments = integration.get('devops_comments')
        product_description = integration.get('product_description', '')
        is_byoi = integration.get('byoi', True)
        has_integration = integration.get('has_integration', True)
        validate_test = integration.get('validate_test', True)

        if has_integration:
            instance_id, failure_message, _ = __create_integration_instance(
                server, username, password, integration_name, integration_instance_name,
                integration_params, is_byoi, validate_test=validate_test)
            if failure_message == 'No configuration':
                logging.warning(
                    f"skipping {integration_name} as it exists in content-test-conf conf.json but not in content repo")
                continue
            if not instance_id:
                logging.error(
                    f'Failed to create instance of {integration_name} with message: {failure_message}')
                failed_integrations.append("{} {} - devops comments: {}".format(
                    integration_name, product_description, devops_comments))
            else:
                instance_ids.append(instance_id)
                logging.success(f'Create integration {integration_name} succeed')
                __delete_integrations_instances(c, instance_ids)

    return failed_integrations, integrations_counter


def create_failed_integrations_file(failed_instances):
    with open("./Tests/failed_instances.txt", "w") as failed_instances_file:
        failed_instances_file.write('\n'.join(failed_instances))


def get_attachments(secret_conf_path, server, user, password, build_url):
    failed_integration, integrations_counter = test_instances(secret_conf_path, server, user, password)
    create_failed_integrations_file(failed_integration)

    fields = []
    if failed_integration:
        field_failed_tests = {
            "title": "Found {0} Problematic Instances. See CircleCI for errors.".format(len(failed_integration)),
            "value": '\n'.join(failed_integration),
            "short": False
        }
        fields.append(field_failed_tests)

    color = 'danger' if failed_integration else 'good'
    title = 'There are no problematic instances' if not failed_integration else 'Encountered problems with instances'

    attachment = [{
        'fallback': title,
        'color': color,
        'title': title,
        'fields': fields,
        'title_link': build_url
    }]

    return attachment, integrations_counter


def slack_notifier(slack_token, secret_conf_path, server, user, password, build_url, build_number):
    logging.info("Starting Slack notifications about instances")
    attachments, integrations_counter = get_attachments(secret_conf_path, server, user, password, build_url)

    sc = SlackClient(slack_token)

    # Failing instances list
    sc.api_call(
        "chat.postMessage",
        channel="dmst-content-lab",
        username="Instances nightly report",
        as_user="False",
        attachments=attachments,
        text="You have {0} instances configurations".format(integrations_counter)
    )

    # Failing instances file
    sc.api_call(
        "chat.postMessage",
        channel="dmst-content-lab",
        username="Instances nightly report",
        as_user="False",
        text="Detailed list of failing instances could be found in the following link:\n"
             "https://{}-60525392-gh.circle-artifacts.com/0/artifacts/failed_instances.txt".format(build_number)
    )


if __name__ == "__main__":
    install_simple_logging()
    options = options_handler()
    if options.instance_tests:
        with open('./env_results.json', 'r') as json_file:
            env_results = json.load(json_file)
            server = SERVER_URL.format(env_results[0]["InstanceDNS"])

        slack_notifier(options.slack, options.secret, server, options.user, options.password, options.buildUrl,
                       options.buildNumber)
        # create this file for destroy_instances script
        with open("./Tests/is_build_passed_{}.txt".format(env_results[0]["Role"].replace(' ', '')), 'a'):
            pass
    else:
        logging.error("Not instance tests build, stopping Slack Notifications about instances")
