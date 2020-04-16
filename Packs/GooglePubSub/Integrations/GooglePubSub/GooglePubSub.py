import demistomock as demisto
from CommonServerPython import *  # noqa: E402 lgtm [py/polluting-import]
from CommonServerUserPython import *  # noqa: E402 lgtm [py/polluting-import]

# IMPORTS
from typing import Tuple, Optional
import traceback
import dateparser
import httplib2
import urllib.parse
from oauth2client import service_account
from googleapiclient import discovery

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
    """
    Used to easily transform Google Cloud Pub/Sub names
    """
    FULL_PROJECT_PREFIX = "projects/{}"
    FULL_TOPIC_PREFIX = "/topics/{}"
    FULL_SUBSCRIPTION_PREFIX = "/subscriptions/{}"
    FULL_SNAPSHOT_PREFIX = "/snapshots/{}"

    @staticmethod
    def get_project_name(project_id):
        return GoogleNameParser.FULL_PROJECT_PREFIX.format(project_id)

    @staticmethod
    def get_topic_name(project_id, topic_id):
        return GoogleNameParser.get_project_name(
            project_id
        ) + GoogleNameParser.FULL_TOPIC_PREFIX.format(topic_id)

    @staticmethod
    def get_subscription_project_name(project_id, subscription_id):
        return GoogleNameParser.get_project_name(
            project_id
        ) + GoogleNameParser.FULL_SUBSCRIPTION_PREFIX.format(subscription_id)

    @staticmethod
    def get_subscription_topic_name(project_id, topic_id, subscription_id):
        return GoogleNameParser.get_topic_name(
            project_id, topic_id
        ) + GoogleNameParser.FULL_SUBSCRIPTION_PREFIX.format(subscription_id)

    @staticmethod
    def get_snapshot_project_name(project_id, snapshot_id):
        return GoogleNameParser.get_project_name(
            project_id
        ) + GoogleNameParser.FULL_SNAPSHOT_PREFIX.format(snapshot_id)


# disable-secrets-detection-start
class BaseGoogleClient:
    """
    A Client class to wrap the google cloud api library as a service.
    """

    def __init__(self, service_name: str, service_version: str, client_secret: dict, scopes: list, proxy: bool,
                 insecure: bool, **kwargs):
        """
        :param service_name: The name of the service. You can find this and the service  here
         https://github.com/googleapis/google-api-python-client/blob/master/docs/dyn/index.md
        :param service_version:The version of the API.
        :param client_secret: A string of the generated credentials.json
        :param scopes: The scope needed for the project. (i.e. ['https://www.googleapis.com/auth/cloud-platform'])
        :param proxy: Proxy flag
        :param insecure: Insecure flag
        :param kwargs: Potential arguments dict
        """
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(client_secret, scopes=scopes)
        if proxy or insecure:
            http_client = credentials.authorize(self.get_http_client_with_proxy(proxy, insecure))
            self.service = discovery.build(service_name, service_version, http=http_client)
        else:
            self.service = discovery.build(service_name, service_version, credentials=credentials)

    @staticmethod
    def get_http_client_with_proxy(proxy, insecure):
        """
        Create an http client with proxy with whom to use when using a proxy.
        :param proxy: Whether to use a proxy.
        :param insecure: Whether to disable ssl and use an insecure connection.
        :return:
        """
        if proxy:
            proxies = handle_proxy()
            https_proxy = proxies.get('https')
            http_proxy = proxies.get('http')
            proxy_conf = https_proxy if https_proxy else http_proxy
            # if no proxy_conf - ignore proxy
            if proxy_conf:
                if not proxy_conf.startswith('https') and not proxy_conf.startswith('http'):
                    proxy_conf = 'https://' + proxy_conf
                parsed_proxy = urllib.parse.urlparse(proxy_conf)
                proxy_info = httplib2.ProxyInfo(
                    proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
                    proxy_host=parsed_proxy.hostname,
                    proxy_port=parsed_proxy.port,
                    proxy_user=parsed_proxy.username,
                    proxy_pass=parsed_proxy.password)
                return httplib2.Http(proxy_info=proxy_info, disable_ssl_certificate_validation=insecure)
        return httplib2.Http(disable_ssl_certificate_validation=insecure)

# disable-secrets-detection-end


class PubSubClient(BaseGoogleClient):
    def __init__(self, default_project, default_subscription, default_max_msgs, client_secret, **kwargs):
        super().__init__(client_secret=client_secret, **kwargs)
        self.default_project = default_project
        if not default_project:
            self.default_project = self._extract_project_from_client_secret(client_secret)
        self.default_subscription = default_subscription
        self.default_max_msgs = default_max_msgs

    def _extract_project_from_client_secret(self, client_secret):
        """Extracts project name from a client secret json"""
        project_id = client_secret.get('project_id')
        if isinstance(project_id, list):
            project_id = project_id[0]
        return project_id

    def _create_subscription_body(self, ack_deadline_seconds, expiration_ttl, labels, message_retention_duration,
                                  push_attributes, push_endpoint, retain_acked_messages, topic_name):
        """Create a subscription body"""
        if push_endpoint or push_attributes:
            push_config = assign_params(
                pushEndpoint=push_endpoint,
                attributes=push_attributes,
            )
        else:
            push_config = None
        body = assign_params(
            topic=topic_name,
            pushConfig=push_config,
            ackDeadlineSeconds=ack_deadline_seconds,
            retainAckedMessages=retain_acked_messages,
            messageRetentionDuration=message_retention_duration,
            labels=labels,
            expirationPolicy=assign_params(ttl=expiration_ttl)
        )
        return body

    def _create_topic_body(self, allowed_persistence_regions, kms_key_name, labels):
        """Create a topic body"""
        message_storage_policy = assign_params(allowedPersistenceRegions=allowed_persistence_regions)
        body = assign_params(
            labels=labels,
            messageStoragePolicy=message_storage_policy,
            kmsKeyName=kms_key_name
        )
        return body

    def list_topic(self, project_id, page_size, page_token=None):
        """Get topic list from GoogleClient"""
        return (
            self.service.projects()
                .topics()
                .list(project=project_id, pageSize=page_size, pageToken=page_token)
                .execute()
        )

    def list_topic_subs(self, topic_id, page_size, page_token=None):
        """Get topic subscriptions from GoogleClient"""
        return (
            self.service.projects()
                .topics()
                .subscriptions()
                .list(topic=topic_id, pageSize=page_size, pageToken=page_token)
                .execute()
        )

    def list_project_subs(self, project_id, page_size, page_token=None):
        """Get project subscriptions list from GoogleClient"""
        return (
            self.service.projects()
                .subscriptions()
                .list(project=project_id, pageSize=page_size, pageToken=page_token)
                .execute()
        )

    def get_sub(self, sub_name):
        """Get subscription by name from GoogleClient"""
        return (
            self.service.projects()
                .subscriptions()
                .get(subscription=sub_name)
                .execute()
        )

    def publish_message(self, project_id, topic_id, req_body):
        """Publish a topic message via GoogleClient"""
        return (
            self.service.projects()
                .topics()
                .publish(
                topic=GoogleNameParser.get_topic_name(project_id, topic_id),
                body=req_body,
            ).execute()
        )

    def pull_messages(self, sub_name, max_messages, ret_immediately=True):
        """
        Pull messages for the subscription
        :param sub_name: Subscription name
        :param max_messages: The maximum number of messages to return for this request. Must be a positive integer
        :param ret_immediately: when set to true will return immediately, otherwise will be async
        :return: Messages
        """
        req_body = {"returnImmediately": ret_immediately, "maxMessages": max_messages}
        return (
            self.service.projects()
                .subscriptions()
                .pull(subscription=sub_name, body=req_body)
                .execute()
        )

    def ack_messages(self, sub_name, acks):
        """
        Ack a list of messages
        :param sub_name: subscription name
        :param acks: ack ids to ack
        :return:
        """
        body = {"ackIds": acks}
        return (
            self.service.projects()
                .subscriptions()
                .acknowledge(subscription=sub_name, body=body)
                .execute()
        )

    def create_subscription(self, sub_name, topic_name, push_endpoint, push_attributes, ack_deadline_seconds,
                            retain_acked_messages, message_retention_duration, labels, expiration_ttl):
        """
        Creates a subscription
        :param sub_name: full sub name
        :param topic_name: full topic name
        :param push_endpoint: A URL locating the endpoint to which messages should be pushed.
        :param push_attributes: Input format: "key=val" pairs sepearated by ",".
        :param ack_deadline_seconds: The amount of time Pub/Sub waits for the subscriber to ack.
        :param retain_acked_messages: if 'true' then retain acknowledged messages
        :param message_retention_duration: How long to retain unacknowledged messages
        :param labels: Input format: "key=val" pairs sepearated by ",".
        :param expiration_ttl: The "time-to-live" duration for the subscription.

        :return: Subscription
        """
        body = self._create_subscription_body(ack_deadline_seconds, expiration_ttl, labels, message_retention_duration,
                                              push_attributes, push_endpoint, retain_acked_messages, topic_name)
        return (
            self.service.projects()
                .subscriptions()
                .create(name=sub_name, body=body)
                .execute()
        )

    def update_subscription(self, sub_name, topic_name, update_mask, push_endpoint, push_attributes,
                            ack_deadline_seconds, retain_acked_messages, message_retention_duration, labels,
                            expiration_ttl):
        """
        Updates a subscription
        :param sub_name: full sub name
        :param topic_name: full topic name
        :param update_mask: Indicates which fields in the provided subscription to update.
        :param push_endpoint: A URL locating the endpoint to which messages should be pushed.
        :param push_attributes: Input format: "key=val" pairs sepearated by ",".
        :param ack_deadline_seconds: The amount of time Pub/Sub waits for the subscriber to ack.
        :param retain_acked_messages: if 'true' then retain acknowledged messages
        :param message_retention_duration: How long to retain unacknowledged messages
        :param labels: Input format: "key=val" pairs sepearated by ",".
        :param expiration_ttl: The "time-to-live" duration for the subscription.

        :return: Subscription
        """
        sub_body = self._create_subscription_body(ack_deadline_seconds, expiration_ttl, labels,
                                                  message_retention_duration, push_attributes, push_endpoint,
                                                  retain_acked_messages, topic_name)
        body = assign_params(
            subscription=sub_body,
            updateMask=update_mask
        )
        return (
            self.service.projects()
                .subscriptions()
                .patch(name=sub_name, body=body)
                .execute()
        )

    def create_topic(self, topic_name, labels, allowed_persistence_regions, kms_key_name):
        """
        Create a topic in the project
        :param topic_name: name of the topic to be created
        :param labels: "key=val" pairs sepearated by ",".'
        :param allowed_persistence_regions: an str representing a list of IDs of GCP regions
        :param kms_key_name: The full name of the Cloud KMS CryptoKey to be used to restrict access on this topic.
        :return: Topic
        """
        body = self._create_topic_body(allowed_persistence_regions, kms_key_name, labels)
        return (
            self.service.projects()
                .topics()
                .create(name=topic_name, body=body)
                .execute()
        )

    def delete_topic(self, topic_name):
        """
        Deletes a topic in the project
        :param topic_name: name of the topic to be created
        :return: Delete response
        """
        return (
            self.service.projects()
                .topics()
                .delete(topic=topic_name)
                .execute()
        )

    def update_topic(self, topic_name, labels, allowed_persistence_regions, kms_key_name, update_mask):
        """
        Updates a topic in the project
        :param topic_name: name of the topic to be updated
        :param labels: "key=val" pairs sepearated by ",".'
        :param allowed_persistence_regions: an str representing a list of IDs of GCP regions
        :param kms_key_name: The full name of the Cloud KMS CryptoKey to be used to restrict access on this topic.
        :param update_mask: Indicates which fields in the provided topic to update.
        :return: Topic
        """
        topic = self._create_topic_body(allowed_persistence_regions, kms_key_name, labels)
        body = assign_params(
            topic=topic,
            updateMask=update_mask
        )
        return (
            self.service.projects()
                .topics()
                .patch(name=topic_name, body=body)
                .execute()
        )

    def subscription_seek_message(self, subscription_name, time_string, snapshot):
        """
        Seeks messages in subscription
        :param subscription_name: Subscription to seek messages for
        :param time_string: A timestamp in RFC3339 UTC "Zulu" format, accurate to nanoseconds,
        :param snapshot: The snapshot to seek to.
        :return: Empty string if successful
        """
        body = assign_params(
            time=time_string,
            snapshot=snapshot
        )
        return (
            self.service.projects()
                .subscriptions()
                .seek(subscription=subscription_name, body=body)
                .execute()
        )

    def get_topic_snapshots_list(self, topic_name, page_size, page_token=None):
        """
        Get snapshots list
        :param topic_name: The name of the topic from which this snapshot is retaining messages.
        :param page_size: Max number of results
        :param page_token: Next page token as returned from the API.
        :return:
        """
        return (
            self.service.projects()
                .topics()
                .snapshots()
                .list(topic=topic_name, pageSize=page_size, pageToken=page_token)
                .execute()
        )

    def get_project_snapshots_list(self, project_name, page_size, page_token):
        """
        Get snapshots list
        :param project_name: The name of the project from which this snapshot is retaining messages.
        :param page_size: Max number of results
        :param page_token: Next page token as returned from the API.
        :return: Snapshot list
            """
        return (
            self.service.projects()
                .snapshots()
                .list(project=project_name, pageSize=page_size, pageToken=page_token)
                .execute()
        )

    def create_snapshot(self, subscription_name, snapshot_name, labels):
        """
        Create a snapshot
        :param subscription_name: The subscription whose backlog the snapshot retain
        :param snapshot_name: The name of the snapshot
        :param labels: labels dict
        :return: Snapshot
        """
        body = assign_params(
            subscription=subscription_name,
            labels=labels
        )
        return (
            self.service.projects()
                .snapshots()
                .create(name=snapshot_name, body=body)
                .execute()
        )

    def update_snapshot(self, snapshot_name, topic_name, update_mask, expire_time, labels):
        """
        :param snapshot_name: The name of the snapshot
        :param topic_name: The ID of the topic from which this snapshot is retaining messages.
        :param update_mask: Indicates which fields in the provided snapshot to update.
        :param expire_time: A timestamp in RFC3339 UTC "Zulu" format
        :param labels: labels dict
        :return: Snapshot
        """
        snapshot = assign_params(
            name=snapshot_name,
            topic=topic_name,
            expireTime=expire_time,
            labels=labels
        )
        body = assign_params(
            snapshot=snapshot,
            updateMask=update_mask
        )
        return (
            self.service.projects()
                .snapshots()
                .patch(name=snapshot_name, body=body)
                .execute()
        )

    def delete_snapshot(self, snapshot_name):
        """
        Delete a snapshot
        :param snapshot_name: full snapshot name
        :return: Empty response
        """
        return (
            self.service.projects()
                .snapshots()
                .delete(snapshot=snapshot_name)
                .execute()
        )


""" HELPER FUNCTIONS"""


def init_google_client(
        service_account_json,
        default_subscription,
        default_project,
        default_max_msgs,
        insecure,
        **kwargs,
) -> PubSubClient:
    """Initializes google client"""
    try:
        service_account_json = json.loads(service_account_json)
        client = PubSubClient(
            default_project=default_project,
            default_subscription=default_subscription,
            default_max_msgs=default_max_msgs,
            service_name=SERVICE_NAME,
            service_version=SERVICE_VERSION,
            client_secret=service_account_json,
            scopes=SCOPES,
            insecure=insecure,
            **kwargs
        )
        return client
    except ValueError as e:
        return_error(
            "Failed to parse Service Account Private Key in json format, please make sure you entered it correctly"
        )
        raise e


def message_to_incident(message):
    """
    Create incident from a message
    """
    incident = {
        "name": f'Google PubSub Message {message.get("messageId")}',
        "rawJSON": json.dumps(message),
        "occurred": convert_publish_datetime_to_str(dateparser.parse(message.get("publishTime")))
    }
    return incident


def convert_publish_datetime_to_str(publish_time):
    """
    Converts datetime to str in "%Y-%m-%dT%H:%M:%S.%fZ" format
    :param publish_time: Datetime
    :return: date str in "%Y-%m-%dT%H:%M:%S.%fZ" format
    """
    try:
        return publish_time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except ValueError:
        return publish_time.strftime("%Y-%m-%dT%H:%M:%SZ")


def attribute_pairs_to_dict(attrs_str: Optional[str], delim_char: str = ","):
    """
    Transforms a string of multiple inputs to a dictionary list

    :param attrs_str: attributes separated by key=val pairs sepearated by ','
    :param delim_char: delimiter character between atrribute pairs
    :return:
    """
    if not attrs_str:
        return attrs_str
    attrs = {}
    regex = re.compile(r"(.*)=(.*)")
    for f in attrs_str.split(delim_char):
        match = regex.match(f)
        if match is None:
            raise ValueError(f"Could not parse field: {f}")

        attrs.update({match.group(1): match.group(2)})

    return attrs


""" COMMAND FUNCTIONS """


def test_module(client: PubSubClient, is_fetch: bool):
    """
    Returning 'ok' indicates that the integration works like it is supposed to:
        1. Connection to the service is successful.
        2. Fetch incidents is configured properly
    :param client: GoogleClient
    :return: 'ok' if test passed, anything else will fail the test.
    """
    client.list_topic(GoogleNameParser.get_project_name(client.default_project), page_size=1)
    if is_fetch:
        client.pull_messages(
            GoogleNameParser.get_subscription_project_name(client.default_project, client.default_subscription),
            max_messages=1)
    return "ok"


def topics_list_command(
        client: PubSubClient,
        project_id: str,
        page_size: str = None,
        page_token: str = None,
) -> Tuple[str, dict, dict]:
    """
    Get topics list by project_id
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: project name
    :param page_size: page size
    :param page_token: page token, as returned from the api
    :return: list of topics
    """
    full_project_name = GoogleNameParser.get_project_name(project_id)
    res = client.list_topic(full_project_name, page_size, page_token)

    topics = list(res.get("topics", []))
    next_page_token = res.get('nextPageToken')
    readable_output = tableToMarkdown(f"Topics for project {project_id}", topics, ['name'])
    outputs = {"GoogleCloudPubSubTopics(val && val.name === obj.name)": topics}
    if next_page_token:
        outputs["GoogleCloudPubSub.Topics.nextPageToken"] = next_page_token
        readable_output += f'**Next Page Token: {next_page_token}**'
    return readable_output, outputs, res


def publish_message_command(
        client: PubSubClient,
        project_id: str,
        topic_id: str,
        data: str = None,
        attributes: str = None,
) -> Tuple[str, dict, dict]:
    """
    Publishes message in the topic
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param project_id: project name
    :param topic_id: topic name without project name prefix
    :param attributes: message attributes separated by key=val pairs sepearated by ','
    :param data: message data str
    :param client: GoogleClient
    :return: list of topics
    """
    body = get_publish_body(attributes, data)
    published_messages = client.publish_message(project_id, topic_id, body)

    output = []
    for msg_id in published_messages["messageIds"]:
        output.append({"topic": topic_id, "messageId": msg_id, "data": data, "attributes": body.get('attributes')})

    ec = {
        "GoogleCloudPubSubPublishedMessages(val.messageId === obj.messageId)": output
    }
    return (
        tableToMarkdown(
            "Google Cloud PubSub has published the message successfully",
            output,
            removeNull=True,
            headerTransform=pascalToSpace
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


def pull_messages_command(
        client: PubSubClient,
        project_id: str,
        subscription_id: str,
        max_messages: str = None,
        ack: str = None,
) -> Tuple[str, dict, list]:
    """
    Pulls messages from the subscription
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: project name
    :param subscription_id: Subscription name to pull messages from
    :param max_messages: The maximum number of messages to return for this request. Must be a positive integer
    :param ack: Acknowledge the messages pulled if set to true.
    :return: list of messages
    """
    full_subscription_name = GoogleNameParser.get_subscription_project_name(
        project_id, subscription_id
    )
    raw_msgs = client.pull_messages(full_subscription_name, max_messages)
    if "receivedMessages" in raw_msgs:
        acknowledges, msgs = extract_acks_and_msgs(raw_msgs)
        ec = {
            f"GoogleCloudPubSubPulledMessages(val && val.messageId === obj.messageId)": msgs
        }
        if ack == "true":
            client.ack_messages(full_subscription_name, acknowledges)
        hr = tableToMarkdown("Google Cloud PubSub Messages", msgs, removeNull=True)
        return hr, ec, raw_msgs
    else:
        return "No new messages found", {}, raw_msgs


def extract_acks_and_msgs(raw_msgs):
    """
    Extracts acknowledges and message data from raw_msgs
    """
    msg_list = []
    acknowledges = []
    if isinstance(raw_msgs, dict):
        rcvd_msgs = raw_msgs.get("receivedMessages", [])
        for raw_msg in rcvd_msgs:
            msg = raw_msg.get("message", {})
            decoded_data = str(msg.get("data", ''))
            try:
                decoded_data = str(base64.b64decode(decoded_data))[2:-1]
            except Exception:
                # display message with b64 value
                pass

            msg["data"] = decoded_data
            msg_list.append(msg)
            ack_id = raw_msg.get("ackId")
            if ack_id:
                acknowledges.append(ack_id)
    return acknowledges, msg_list


def subscriptions_list_command(
        client: PubSubClient,
        project_id: str,
        page_size: str = None,
        page_token: str = None,
        topic_id: str = None,
) -> Tuple[str, dict, dict]:
    """
    Get subscription list by project_id or by topic_id
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: project name
    :param page_size: page size
    :param page_token: page token, as returned from the api
    :param topic_id: topic name
    :return: list of subscriptions
    """
    title = f"Subscriptions"
    if topic_id:
        full_topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
        raw_response = client.list_topic_subs(full_topic_name, page_size, page_token)
        subs = [{'name': sub} for sub in raw_response.get("subscriptions", [])]
        next_page_token = raw_response.get('nextPageToken')
        title += f" for topic {topic_id} in project {project_id}"
        readable_output = tableToMarkdown(title, subs, headers=["name"], headerTransform=pascalToSpace)
    else:
        full_project_name = GoogleNameParser.get_project_name(project_id)
        raw_response = client.list_project_subs(full_project_name, page_size, page_token)
        subs = raw_response.get("subscriptions", "")
        next_page_token = raw_response.get('nextPageToken')
        title += f" in project {project_id}"
        readable_output = tableToMarkdown(title, subs, headers=["name", "topic", "ackDeadlineSeconds", "labels"],
                                          headerTransform=pascalToSpace)
    outputs = {f"GoogleCloudPubSubSubscriptions(val && val.name === obj.name)": subs}
    if next_page_token:
        outputs["GoogleCloudPubSubSubscriptions.pushConfig.pushEndpoint"] = next_page_token
        readable_output += f'**Next Page Token: {next_page_token}**'

    return readable_output, outputs, raw_response


def get_subscription_command(
        client: PubSubClient, project_id: str, subscription_id: str
) -> Tuple[str, dict, dict]:
    """
    Get subscription list by project_id or by topic_id
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param subscription_id:
    :param client: GoogleClient
    :param project_id: project name
    :return: subscription
    """
    full_sub_name = GoogleNameParser.get_subscription_project_name(
        project_id, subscription_id
    )
    subs = client.get_sub(full_sub_name)

    title = f"Subscription {subscription_id}"
    readable_output = tableToMarkdown(title, subs)
    outputs = {
        f"GoogleCloudPubSubSubscriptions(val && val.name === obj.name)": subs
    }
    return readable_output, outputs, subs


def create_subscription_command(
        client: PubSubClient, project_id: str, subscription_id: str, topic_id: str, push_endpoint: str = '',
        push_attributes: str = '', ack_deadline_seconds: str = '', retain_acked_messages: str = '',
        message_retention_duration: str = '', labels: str = '', expiration_ttl: str = ''
) -> Tuple[str, dict, dict]:
    """
    Creates a subscription
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: Name of the project from which the subscription is receiving messages.
    :param subscription_id: Name of the created subscription.
    :param topic_id: Name of the topic from which the subscription is receiving messages.
    :param push_endpoint: A URL locating the endpoint to which messages should be pushed.
    :param push_attributes: Input format: "key=val" pairs sepearated by ",".
    :param ack_deadline_seconds: The amount of time Pub/Sub waits for the subscriber to ack.
    :param retain_acked_messages: if 'true' then retain acknowledged messages
    :param message_retention_duration: How long to retain unacknowledged messages
    :param labels: Input format: "key=val" pairs sepearated by ",".
    :param expiration_ttl: The "time-to-live" duration for the subscription.
    :return: Created subscription
    """
    full_sub_name = GoogleNameParser.get_subscription_project_name(project_id, subscription_id)
    full_topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
    labels = attribute_pairs_to_dict(labels)
    push_attributes = attribute_pairs_to_dict(push_attributes)
    raw_sub = client.create_subscription(full_sub_name, full_topic_name, push_endpoint, push_attributes,
                                         ack_deadline_seconds, retain_acked_messages, message_retention_duration,
                                         labels, expiration_ttl)
    sub = dict(raw_sub)
    title = f"Subscription {subscription_id} was created successfully"
    readable_output = tableToMarkdown(title, sub)
    sub['projectName'] = project_id
    sub['subscriptionName'] = subscription_id
    outputs = {
        f"GoogleCloudPubSubSubscriptions": sub
    }
    return readable_output, outputs, raw_sub


def update_subscription_command(
        client: PubSubClient, project_id: str, subscription_id: str, topic_id: str, update_mask: str,
        push_endpoint: str = '', push_attributes: str = '', ack_deadline_seconds: str = '',
        retain_acked_messages: str = '', message_retention_duration: str = '', labels: str = '',
        expiration_ttl: str = ''
) -> Tuple[str, dict, dict]:
    """
    Creates a subscription
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: Name of the project from which the subscription is receiving messages.
    :param subscription_id: Name of the created subscription.
    :param topic_id: Name of the topic from which the subscription is receiving messages.
    :param update_mask: Indicates which fields in the provided subscription to update.
    :param push_endpoint: A URL locating the endpoint to which messages should be pushed.
    :param push_attributes: Input format: "key=val" pairs sepearated by ",".
    :param ack_deadline_seconds: The amount of time Pub/Sub waits for the subscriber to ack.
    :param retain_acked_messages: if 'true' then retain acknowledged messages
    :param message_retention_duration: How long to retain unacknowledged messages
    :param labels: Input format: "key=val" pairs sepearated by ",".
    :param expiration_ttl: The "time-to-live" duration for the subscription.
    :return: Created subscription
    """
    full_sub_name = GoogleNameParser.get_subscription_project_name(project_id, subscription_id)
    full_topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
    labels = attribute_pairs_to_dict(labels)
    push_attributes = attribute_pairs_to_dict(push_attributes)
    raw_sub = client.update_subscription(full_sub_name, full_topic_name, update_mask, push_endpoint, push_attributes,
                                         ack_deadline_seconds, retain_acked_messages, message_retention_duration,
                                         labels, expiration_ttl)
    sub = dict(raw_sub)
    title = f"Subscription {subscription_id} was updated successfully"
    readable_output = tableToMarkdown(title, sub)
    sub['projectName'] = project_id
    sub['subscriptionName'] = subscription_id
    outputs = {
        f"GoogleCloudPubSubSubscriptions(val && val.name === obj.name)": sub
    }
    return readable_output, outputs, raw_sub


def create_topic_command(
        client: PubSubClient, project_id: str, topic_id: str,
        allowed_persistence_regions: str = '', kms_key_name: str = None, labels: str = None
) -> Tuple[str, dict, dict]:
    """
    Creates a topic
    :param client: PubSub client instance
    :param project_id: project ID
    :param topic_id: topic ID
    :param labels: "key=val" pairs sepearated by ",".'
    :param allowed_persistence_regions: an str representing a list of IDs of GCP regions
    :param kms_key_name: The full name of the Cloud KMS CryptoKey to be used to restrict access on this topic.
    :return: Created topic
    """
    topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
    allowed_persistence_regions = argToList(allowed_persistence_regions)
    labels = attribute_pairs_to_dict(labels)
    raw_topic = client.create_topic(topic_name, labels, allowed_persistence_regions, kms_key_name)
    title = f"Topic **{topic_id}** was created successfully"
    readable_output = tableToMarkdown(title, raw_topic, headerTransform=pascalToSpace)
    outputs = {
        f"GoogleCloudPubSubTopics": raw_topic
    }
    return readable_output, outputs, raw_topic


def delete_topic_command(
        client: PubSubClient, project_id: str, topic_id: str
) -> Tuple[str, dict, dict]:
    """
    Delete a topic
    :param client: PubSub client instance
    :param project_id: project ID
    :param topic_id: topic ID
    :return: Command success/error message
    """
    topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
    raw_topic = client.delete_topic(topic_name)
    readable_output = f"Topic **{topic_id}** was deleted successfully"
    return readable_output, {}, raw_topic


def update_topic_command(
        client: PubSubClient, project_id: str, topic_id: str, update_mask: str,
        allowed_persistence_regions: str = '', kms_key_name: str = None, labels: str = None
) -> Tuple[str, dict, dict]:
    """
    Creates a topic
    :param client: PubSub client instance
    :param project_id: project ID
    :param topic_id: topic ID
    :param labels: "key=val" pairs sepearated by ",".'
    :param allowed_persistence_regions: an str representing a list of IDs of GCP regions
    :param kms_key_name: The full name of the Cloud KMS CryptoKey to be used to restrict access on this topic.
    :param update_mask: Indicates which fields in the provided topic to update.
    :return: Created topic
    """
    topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
    allowed_persistence_regions = argToList(allowed_persistence_regions)
    labels = attribute_pairs_to_dict(labels)
    raw_topic = client.update_topic(topic_name, labels, allowed_persistence_regions, kms_key_name, update_mask)
    title = f"Topic {topic_id} was updated successfully"
    readable_output = tableToMarkdown(title, raw_topic, headerTransform=pascalToSpace)
    outputs = {
        f"GoogleCloudPubSubTopics(val && val.name === obj.name)": raw_topic
    }
    return readable_output, outputs, raw_topic


def seek_message_command(
        client: PubSubClient,
        project_id: str,
        subscription_id: str,
        time_string: str = None,
        snapshot: str = None,
) -> Tuple[str, dict, dict]:
    """
    Get topics list by project_id
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: ID of the subscription, without project/topic prefix.
    :param subscription_id: ID of the project from which the subscription is receiving messages.
    :param time_string: A timestamp in RFC3339 UTC "Zulu" format, accurate to nanoseconds,
    :param snapshot: The snapshot to seek to.
    :return: list of topics
    """
    if not time_string and not snapshot:
        return_error('Please provide either a time_string or a snapshot')
    sub_name = GoogleNameParser.get_subscription_project_name(project_id, subscription_id)
    raw_res = client.subscription_seek_message(sub_name, time_string, snapshot)
    readable_output = 'Message seek was successful for **' + (
        f'time: {time_string}' if time_string else f'snapshot:{snapshot}') + '**'
    return readable_output, {}, raw_res


def snapshot_list_command(
        client: PubSubClient,
        project_id: str,
        topic_id: str = None,
        page_size: str = None,
        page_token: str = None,
) -> Tuple[str, dict, dict]:
    """
    Get snapshots list by project_id or topic_id
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: project id
    :param topic_id:
    :param page_size: page size
    :param page_token: page token, as returned from the api
    :return: list of snapshots
    """
    if topic_id:
        topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
        res = client.get_topic_snapshots_list(topic_name, page_size, page_token)
        title = f"Snapshots for topic {topic_id}"
    else:
        project_name = GoogleNameParser.get_project_name(project_id)
        res = client.get_project_snapshots_list(project_name, page_size, page_token)
        title = f"Snapshots for project {project_id}"
    snapshots = list(res.get("snapshots", []))
    next_page_token = res.get('nextPageToken')
    readable_output = tableToMarkdown(title, snapshots, ['name'])
    outputs = {"GoogleCloudPubSubSnapshots(val && val.name === obj.name)": snapshots}
    if next_page_token:
        outputs["GoogleCloudPubSub.Snapshots.nextPageToken"] = next_page_token
        readable_output += f'**Next Page Token: {next_page_token}**'
    return readable_output, outputs, res


def snapshot_create_command(
        client: PubSubClient,
        project_id: str,
        subscription_id: str,
        snapshot_id: str,
        labels: str = None,
) -> Tuple[str, dict, dict]:
    """
    Create a snapshot
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: project id
    :param subscription_id: The subscription whose backlog the snapshot retains.
    :param snapshot_id: The id of the snapshot.
    :param labels: Input format: "key=val" pairs sepearated by ",".
    :return: list of topics
    """
    subscription_name = GoogleNameParser.get_subscription_project_name(project_id, subscription_id)
    snapshot_name = GoogleNameParser.get_snapshot_project_name(project_id, snapshot_id)
    labels = attribute_pairs_to_dict(labels)
    raw_snapshot = client.create_snapshot(subscription_name, snapshot_name, labels)
    title = f"Snapshot **{snapshot_id}** was created successfully"
    readable_output = tableToMarkdown(title, raw_snapshot, headerTransform=pascalToSpace)
    outputs = {
        f"GoogleCloudPubSubSnapshots": raw_snapshot
    }
    return readable_output, outputs, raw_snapshot


def snapshot_update_command(
        client: PubSubClient,
        project_id: str,
        topic_id: str,
        snapshot_id: str,
        update_mask: str,
        expire_time: str = None,
        labels: str = None
) -> Tuple[str, dict, dict]:
    """
    Updates a snapshot
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param project_id: ID of the project from which the subscription is receiving messages.
    :param topic_id: The ID of the topic from which this snapshot is retaining messages.
    :param snapshot_id: The id of the snapshot.
    :param update_mask: Indicates which fields in the provided snapshot to update.
    :param expire_time: The snapshot is guaranteed to exist up until this time
    :param labels: An object containing a list of "key": value pairs
    :return:
    """
    snapshot_name = GoogleNameParser.get_snapshot_project_name(project_id, snapshot_id)
    topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
    labels = attribute_pairs_to_dict(labels)
    raw_snapshot = client.update_snapshot(snapshot_name, topic_name, update_mask, expire_time, labels)
    title = f"Snapshot **{snapshot_id}** was updated successfully"
    readable_output = tableToMarkdown(title, raw_snapshot, headerTransform=pascalToSpace)
    outputs = {
        f"GoogleCloudPubSubSnapshots(val && val.name === obj.name)": raw_snapshot
    }
    return readable_output, outputs, raw_snapshot


def snapshot_delete_command(
        client: PubSubClient,
        project_id: str,
        snapshot_id: str
) -> Tuple[str, dict, dict]:
    """
    Delete a topic
    :param client: PubSub client instance
    :param project_id: The ID of the project from which the subscription is receiving messages.
    :param snapshot_id: The id of the snapshot.
    :return: Command success/error message
    """
    snapshot_name = GoogleNameParser.get_snapshot_project_name(project_id, snapshot_id)
    raw_res = client.delete_snapshot(snapshot_name)
    readable_output = f"Snapshot **{snapshot_id}** was deleted successfully"
    return readable_output, {}, raw_res


def fetch_incidents(client: PubSubClient):
    """
    This function will execute each interval (default is 1 minute).
    :param client: GoogleClient initiallized with default_project, default_subscription and default_max_msgs
    :return: incidents: Incidents that will be created in Demisto
    """
    incidents = []
    sub_name = GoogleNameParser.get_subscription_project_name(
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
        commands = {
            "google-cloud-pubsub-topic-publish-message": publish_message_command,
            "google-cloud-pubsub-topic-messages-pull": pull_messages_command,
            "google-cloud-pubsub-topic-subscriptions-list": subscriptions_list_command,
            "google-cloud-pubsub-topic-subscription-get-by-name": get_subscription_command,
            "google-cloud-pubsub-topic-subscription-create": create_subscription_command,
            "google-cloud-pubsub-topic-subscription-update": update_subscription_command,
            "google-cloud-pubsub-topics-list": topics_list_command,
            "google-cloud-pubsub-topic-create": create_topic_command,
            "google-cloud-pubsub-topic-delete": delete_topic_command,
            "google-cloud-pubsub-topic-update": update_topic_command,
            "google-cloud-pubsub-topic-messages-seek": seek_message_command,
            "google-cloud-pubsub-topic-snapshots-list": snapshot_list_command,
            "google-cloud-pubsub-topic-snapshot-create": snapshot_create_command,
            "google-cloud-pubsub-topic-snapshot-update": snapshot_update_command,
            "google-cloud-pubsub-topic-snapshot-delete": snapshot_delete_command
        }
        if command == "test-module":
            demisto.results(test_module(client, params.get('isFetch')))

        elif command == "fetch-incidents":
            demisto.incidents(fetch_incidents(client=client))
        else:
            args = demisto.args()
            return_outputs(*commands[command](client, **args))  # type: ignore[operator]

    # Log exceptions
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command. Error: {str(e)} , traceback: {traceback.format_exc()}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
