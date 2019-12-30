import json
import argparse

import demisto_client
from slackclient import SlackClient
from test_integration import __create_integration_instance, __delete_integrations_instances
from Tests.test_utils import str2bool, print_color, print_error, LOG_COLORS


SERVER_URL = "https://{}"


def options_handler():
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-n', '--instance_tests', type=str2bool, help='is instance test build?', required=True)
    parser.add_argument('-s', '--slack', help='The token for slack', required=True)
    parser.add_argument('-e', '--secret', help='Path to secret conf file', required=True)
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-b', '--buildUrl', help='The url for the build', required=True)
    options = parser.parse_args()

    return options


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

        if has_integration:
            instance_id, failure_message = __create_integration_instance(
                c, integration_name, integration_instance_name, integration_params, is_byoi
            )
            if not instance_id:
                print_error('Failed to create instance of {} with message: {}'.format(integration_name, failure_message))
                failed_integrations.append("{} {} - devops comments: {}".format(
                    integration_name, product_description, devops_comments))
            else:
                instance_ids.append(instance_id)
                print('Create integration %s succeed' % (integration_name,))
                __delete_integrations_instances(c, instance_ids)

    return failed_integrations, integrations_counter


def get_attachments(secret_conf_path, server, user, password, build_url):
    failed_integration, integrations_counter = test_instances(secret_conf_path, server, user, password)

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


def slack_notifier(slack_token, secret_conf_path, server, user, password, build_url):
    print_color("Starting Slack notifications about instances", LOG_COLORS.GREEN)
    attachments, integrations_counter = get_attachments(secret_conf_path, server, user, password, build_url)

    sc = SlackClient(slack_token)
    sc.api_call(
        "chat.postMessage",
        channel="dmst-content-lab",
        username="Instances nightly report",
        as_user="False",
        attachments=attachments,
        text="You have {0} instances configurations".format(integrations_counter)
    )


if __name__ == "__main__":
    options = options_handler()
    if options.instance_tests:
        with open('./env_results.json', 'r') as json_file:
            env_results = json.load(json_file)
            for env in env_results:
                if env["Role"] == "Server Master":
                    server = SERVER_URL.format(env["InstanceDNS"])
                    break

        slack_notifier(options.slack, options.secret, server, options.user, options.password, options.buildUrl)
        # create this file for destroy_instances script
        with open("./Tests/is_build_passed_{}.txt".format(env["Role"].replace(' ', '')), 'a'):
            pass
    else:
        print_error("Not instance tests build, stopping Slack Notifications about instances")
