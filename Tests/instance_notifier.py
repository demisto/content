import re
import sys
import json
import argparse

import demisto
from slackclient import SlackClient

from test_integration import __create_integration_instance, __delete_integrations_instances
from Tests.test_utils import str2bool, run_command, print_color, print_error, LOG_COLORS


SERVER_URL = "https://{}"


def options_handler():
    parser = argparse.ArgumentParser(description='Parser for slack_notifier args')
    parser.add_argument('-n', '--nightly', type=str2bool, help='is nightly build?', required=True)
    parser.add_argument('-s', '--slack', help='The token for slack', required=True)
    parser.add_argument('-e', '--secret', help='Path to secret conf file', required=True)
    parser.add_argument('-u', '--user', help='The username for the login', required=True)
    parser.add_argument('-p', '--password', help='The password for the login', required=True)
    parser.add_argument('-b', '--buildUrl', help='The url for the build', required=True)
    options = parser.parse_args()

    return options


def get_demisto_instance_and_login(server, username, password):
    c = demisto.DemistoClient(None, server, username, password)
    res = c.Login()
    if res.status_code != 200:
        print_error("Login has failed with status code " + str(res.status_code))
        sys.exit(1)

    return c


def get_integrations(secret_conf_path):
    with open(secret_conf_path) as data_file:
        secret_conf = json.load(data_file)

    secret_params = secret_conf['integrations'] if secret_conf else []
    return secret_params


def test_instances(secret_conf_path, server, username, password):
    c = get_demisto_instance_and_login(server, username, password)
    integrations = get_integrations(secret_conf_path)

    instance_ids = []
    failed_integration = []
    integrations_counter = 0
    for integration in integrations:
        integrations_counter += 1
        integration_name = integration.get('name', None)
        integration_params = integration.get('params', None)
        devops_comments = integration.get('devops_comments', None)
        product_description = integration.get('product_description', None)
        is_byoi = integration.get('byoi', True)
        has_integration = integration.get('has_integration', True)

        if has_integration:
            instance_id = __create_integration_instance(c, integration_name, integration_params, is_byoi)
            if not instance_id:
                print_error('Failed to create instance of %s' % (integration_name,))
                failed_integration.append("{0} {1} - {2}".format(integration_name,
                                                                 product_description, devops_comments))
            else:
                instance_ids.append(instance_id)
                print('Create integration %s succeed' % (integration_name,))
                __delete_integrations_instances(c, instance_ids)

    return failed_integration, integrations_counter


def get_attachments(secret_conf_path, server, user, password, build_url):
    failed_integration, integrations_counter = test_instances(secret_conf_path, server, user, password)

    fields = []
    if failed_integration:
        field_failed_tests = {
            "title": "{0} Problematic Instances".format(len(failed_integration)),
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
    branches = run_command("git branch")
    branch_name_reg = re.search("\* (.*)", branches)
    branch_name = branch_name_reg.group(1)

    if branch_name == 'master':
        print_color("Starting Slack notifications about instances", LOG_COLORS.GREEN)
        attachments, integrations_counter = get_attachments(secret_conf_path, server, user, password, build_url)

        sc = SlackClient(slack_token)
        sc.api_call(
            "chat.postMessage",
            channel="devops-events",
            username="Instances nightly report",
            as_user="False",
            attachments=attachments,
            text="You have {0} instances configurations".format(integrations_counter)
        )

        sc.api_call(
            "chat.postMessage",
            channel="content-lab-tests",
            username="Instances nightly report",
            as_user="False",
            attachments=attachments,
            text="You have {0} instances configurations".format(integrations_counter)
        )


if __name__ == "__main__":
    options = options_handler()
    if options.nightly:
        with open('./Tests/instance_ips.txt', 'r') as instance_file:
            instance_ips = instance_file.readlines()
            instance_ips = [line.strip('\n').split(":") for line in instance_ips]

        for ami_instance_name, ami_instance_ip in instance_ips:
            if ami_instance_name == "Demisto GA":
                server = SERVER_URL.format(ami_instance_ip)

        slack_notifier(options.slack, options.secret, server, options.user, options.password, options.buildUrl)
    else:
        print_color("Not nightly build, stopping Slack Notifications about instances", LOG_COLORS.RED)
