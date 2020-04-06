import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS
from typing import Tuple
import httplib2
import urllib.parse
from oauth2client import service_account
from googleapiclient.discovery import build

import json
import requests

# Disable insecure warnings
requests.packages.urllib3.disable_warnings()

# CONSTANTS
SERVICE_NAME = "pubsub"
SERVICE_VERSION = "v1"
SCOPES = ["https://www.googleapis.com/auth/cloud-platform"]

""" HELPER CLASSES """


class GoogleNameParser:
    FULL_PROJECT_PREFIX = "projects/{}"
    FULL_TOPIC_PREFIX = "/topics/{}"
    FULL_SUBSCRIPTION_PREFIX = "/subscriptions/{}"

    @staticmethod
    def get_full_project_name(project_name):
        return GoogleNameParser.FULL_PROJECT_PREFIX.format(project_name)

    @staticmethod
    def get_full_topic_name(project_name, topic_name):
        return GoogleNameParser.get_full_project_name(
            project_name
        ) + GoogleNameParser.FULL_TOPIC_PREFIX.format(topic_name)

    @staticmethod
    def get_full_subscription_project_name(project_name, subscription_name):
        return GoogleNameParser.get_full_project_name(
            project_name
        ) + GoogleNameParser.FULL_SUBSCRIPTION_PREFIX.format(subscription_name)

    @staticmethod
    def get_full_subscription_topic_name(project_name, topic_name, subscription_name):
        return GoogleNameParser.get_full_topic_name(
            project_name, topic_name
        ) + GoogleNameParser.FULL_SUBSCRIPTION_PREFIX.format(subscription_name)


class GoogleClient:
    """
    A Client class to wrap the google cloud api library.
    """

    def __init__(
        self,
        service_name,
        service_version,
        client_secret,
        scopes,
        proxy,
        default_subscription,
        default_project,
        default_max_msgs,
        **kwargs
    ):
        self.default_project = default_project
        self.default_subscription = default_subscription
        self.default_max_msgs = default_max_msgs
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(
            client_secret, scopes
        )
        if proxy:
            http_client = credentials.authorize(self.get_http_client_with_proxy())
            self.service = build(
                service_name, service_version, http=http_client, credentials=credentials
            )
        else:
            self.service = build(service_name, service_version, credentials=credentials)

    def get_topic_list(self, project_name, page_size, page_token):
        return (
            self.service.projects()
            .topics()
            .list(project=project_name, pageSize=page_size, pageToken=page_token)
            .execute()
        )

    def get_topic_subs(self, topic_name, page_size, page_token):
        return (
            self.service.projects()
            .topics()
            .subscriptions()
            .list(topic=topic_name, pageSize=page_size, pageToken=page_token)
            .execute()
        )

    def get_project_subs(self, project_name, page_size, page_token):
        return (
            self.service.projects()
            .subscriptions()
            .list(project=project_name, pageSize=page_size, pageToken=page_token)
            .execute()
        )

    def get_sub(self, sub_name):
        return (
            self.service.projects().subscriptions().get(subscription=sub_name).execute()
        )

    def publish_message(self, project_name, topic_name, req_body):
        return (
            self.service.projects()
            .topics()
            .publish(
                topic=GoogleNameParser.get_full_topic_name(project_name, topic_name),
                body=req_body,
            )
            .execute()
        )

    def pull_messages(self, sub_name, max_messages, ret_immediately=True):
        req_body = {"returnImmediately": ret_immediately, "maxMessages": max_messages}
        return (
            self.service.projects()
            .subscriptions()
            .pull(subscription=sub_name, body=req_body)
            .execute()
        )

    def ack_messages(self, sub_name, acks):
        body = {"ackIds": acks}
        return (
            self.service.projects()
            .subscriptions()
            .acknowledge(subscription=sub_name, body=body)
            .execute()
        )

    # disable-secrets-detection-start
    @staticmethod
    def get_http_client_with_proxy():
        proxies = handle_proxy()
        if not proxies or not proxies["https"]:
            raise Exception(
                "https proxy value is empty. Check Demisto server configuration"
            )
        https_proxy = proxies["https"]
        if not https_proxy.startswith("https") and not https_proxy.startswith("http"):
            https_proxy = "https://" + https_proxy
        parsed_proxy = urllib.parse.urlparse(https_proxy)
        proxy_info = httplib2.ProxyInfo(
            proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
            proxy_host=parsed_proxy.hostname,
            proxy_port=parsed_proxy.port,
            proxy_user=parsed_proxy.username,
            proxy_pass=parsed_proxy.password,
        )
        return httplib2.Http(proxy_info=proxy_info)

    # disable-secrets-detection-end


""" HELPER FUNCTIONS"""


def init_google_client(
    proxy,
    service_account_json,
    default_subscription,
    default_project,
    default_max_msgs,
    **kwargs,
) -> GoogleClient:
    try:
        service_account_json = json.loads(service_account_json)
    except ValueError:
        return_error(
            "Failed to parse Service Account Private Key in json format, please make sure you entered it correctly"
        )
    client = GoogleClient(
        SERVICE_NAME,
        SERVICE_VERSION,
        service_account_json,
        SCOPES,
        proxy,
        default_subscription,
        default_project,
        default_max_msgs,
        **kwargs
    )
    return client


def message_to_incident(message):
    incident = {
        "name": f'Google PubSub Message {message.get("messageId")}',
        "rawJSON": json.dumps(message),
    }
    return incident


""" COMMAND FUNCTIONS """


def test_module(client: GoogleClient):
    """
    Returning 'ok' indicates that the integration works like it is supposed to. Connection to the service is successful.
    :param client: GoogleClient
    :return: 'ok' if test passed, anything else will fail the test.
    """
    return "ok", {}


def topics_list_command(
    client: GoogleClient,
    project_name: str,
    page_size: str = None,
    page_token: str = None,
) -> Tuple[str, dict, dict]:
    """
    Get topics list by project_name
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_name: project name
    :param page_size: page size
    :param page_token: page token, as returned from the api
    :return: list of topics
    """
    full_project_name = GoogleNameParser.get_full_project_name(project_name)
    res = client.get_topic_list(full_project_name, page_size, page_token)

    topics = res.get("topics", [])
    readable_output = tableToMarkdown(f"Topics for project {project_name}", topics)
    outputs = {"GoogleCloudPubSub.Topics": {project_name: topics}}
    return (readable_output, outputs, res)  # raw response - the original response


def publish_message_command(
    client: GoogleClient,
    project_name: str,
    topic_name: str,
    message_data: str = None,
    message_attributes: str = None,
) -> Tuple[str, dict, dict]:
    """
    Publishes message in the topic
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param project_name: project name
    :param topic_name: topic name without project name prefix
    :param message_attributes: message attributes separated by key=val pairs sepearated by ','
    :param message_data: message data str
    :param client: GoogleClient
    :return: list of topics
    """
    body = get_publish_body(message_attributes, message_data)
    published_messages = client.publish_message(project_name, topic_name, body)

    output = []
    for msg_id in published_messages["messageIds"]:
        output.append({"topic": topic_name, "messageId": msg_id})

    ec = {
        "GoogleCloudPubSub.PublishedMessages(val.messageId === obj.messageId)": output
    }
    return (
        tableToMarkdown(
            "Google Cloud PubSub Published Messages",
            published_messages,
            removeNull=True,
        ),
        ec,
        published_messages,
    )


def get_publish_body(message_attributes, message_data):
    """
    Creates publish messages body from given arguments
    :param message_attributes: message attributes
    :param message_data: message data
    :return: publish message body
    """
    message = {}
    if message_data:
        # convert to base64 string
        message["data"] = str(base64.b64encode(message_data.encode("utf8")))[2:-1]
    if message_attributes:
        message["attributes"] = attribute_pairs_to_dict(message_attributes)
    body = {"messages": [message]}
    return body


def attribute_pairs_to_dict(attrs_str: str, delim_char: str = ";"):
    """
    Transforms a string of multiple inputs to a dictionary list

    :param attrs_str: attributes separated by key=val pairs sepearated by ','
    :param delim_char: delimiter character between atrribute pairs
    :return:
    """
    attrs = {}
    regex = re.compile(r"(.*)=(.*)")
    for f in attrs_str.split(delim_char):
        match = regex.match(f)
        if match is None:
            raise ValueError(f"Could not parse field: {f}")

        attrs.update({match.group(1): match.group(2)})

    return attrs


def pull_messages_command(
    client: GoogleClient,
    project_name: str,
    subscription_name: str,
    max_messages: str = None,
    ack: str = None,
) -> Tuple[str, dict, list]:
    """
    Pulls messages from the subscription
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_name: project name
    :param subscription_name: Subscription name to pull messages from
    :param max_messages: The maximum number of messages to return for this request. Must be a positive integer
    :param ack: Acknowledge the messages pulled if set to true.
    :return: list of messages
    """
    full_subscription_name = GoogleNameParser.get_full_subscription_project_name(
        project_name, subscription_name
    )
    raw_msgs = client.pull_messages(full_subscription_name, max_messages)
    if "receivedMessages" in raw_msgs:
        acknowledges, msgs = extract_acks_and_msgs(raw_msgs)
        ec = {
            f"GoogleCloudPubSub.Subscriptions.{project_name}.Messages(val && val.messageId === obj.messageId)": msgs
        }
        if ack == "true":
            client.ack_messages(full_subscription_name, acknowledges)
        hr = tableToMarkdown("Google Cloud PubSub Messages", msgs, removeNull=True)
        return hr, ec, raw_msgs
    else:
        return "No new messages found", {}, raw_msgs


def extract_acks_and_msgs(raw_msgs):
    output = []
    acknowledges = []
    for raw_msg in raw_msgs["receivedMessages"]:
        msg = raw_msg.get("message", {})
        decoded_data = base64.b64decode(str(msg.get("data")))
        try:
            decoded_data = json.loads(decoded_data)
        except Exception:
            # display message with b64 value
            pass

        msg["data"] = decoded_data
        output.append(msg)
        acknowledges.append(raw_msg["ackId"])
    return acknowledges, output


def subscriptions_list_command(
    client: GoogleClient,
    project_name: str,
    page_size: str = None,
    page_token: str = None,
    topic_name: str = None,
) -> Tuple[str, dict, dict]:
    """
    Get subscription list by project_name or by topic_name
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_name: project name
    :param page_size: page size
    :param page_token: page token, as returned from the api
    :param topic_name: topic name
    :return: list of subscriptions
    """
    title = f"Subscriptions"
    if topic_name:
        full_topic_name = GoogleNameParser.get_full_topic_name(project_name, topic_name)
        raw_response = client.get_topic_subs(full_topic_name, page_size, page_token)
        title += f" for topic {topic_name}"
        ec_key = full_topic_name
    else:
        full_project_name = GoogleNameParser.get_full_project_name(project_name)
        raw_response = client.get_project_subs(full_project_name, page_size, page_token)
        ec_key = project_name
    ec_key += "(val && val.name === obj.name)"

    title += f" in project {project_name}"
    subs = raw_response.get("subscriptions", "")
    readable_output = tableToMarkdown(title, subs)
    outputs = {f"GoogleCloudPubSub.Subscriptions.{ec_key}": subs}
    return readable_output, outputs, raw_response


def get_subscription_command(
    client: GoogleClient, project_name: str, subscription_name: str
) -> Tuple[str, dict, dict]:
    """
    Get subscription list by project_name or by topic_name
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param subscription_name:
    :param client: GoogleClient
    :param project_name: project name
    :return: subscription
    """
    full_sub_name = GoogleNameParser.get_full_subscription_project_name(
        project_name, subscription_name
    )
    subs = client.get_sub(full_sub_name)

    title = f"Subscription {subscription_name}"
    readable_output = tableToMarkdown(title, subs)
    outputs = {
        f"GoogleCloudPubSub.Subscriptions.{project_name}(val && val.name === obj.name)": subs
    }
    return readable_output, outputs, subs


def fetch_incidents(client: GoogleClient):
    """
    This function will execute each interval (default is 1 minute).
    :param client: GoogleClient initiallized with default_project, default_subscription and default_max_msgs
    :return: incidents: Incidents that will be created in Demisto
    """
    incidents = []
    sub_name = GoogleNameParser.get_full_subscription_project_name(
        client.default_project, client.default_subscription
    )
    raw_msgs = client.pull_messages(sub_name, client.default_max_msgs)
    if "receivedMessages" in raw_msgs:
        acknowledges, msgs = extract_acks_and_msgs(raw_msgs)

        for msg in msgs:
            incidents.append(message_to_incident(msg))
        client.ack_messages(sub_name, acknowledges)
    return incidents


def main():
    params = demisto.params()
    client = init_google_client(**params)
    command = demisto.command()
    LOG(f"Command being called is {command}")
    try:
        if command == "fetch-incidents":
            demisto.incidents(fetch_incidents(client=client))
        else:
            args = demisto.args()
            commands = {
                "test-module": test_module,
                "google-cloud-pubsub-topics-list": topics_list_command,
                "google-cloud-pubsub-topic-publish-message": publish_message_command,
                "google-cloud-pubsub-topic-messages-pull": pull_messages_command,
                "google-cloud-pubsub-topic-subscriptions-list": subscriptions_list_command,
                "google-cloud-pubsub-topic-subscription-get-by-name": get_subscription_command,
            }
            return_outputs(*commands[command](client, **args))  # type: ignore[operator]

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
