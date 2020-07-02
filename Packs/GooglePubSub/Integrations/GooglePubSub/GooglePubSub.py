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
ISO_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
LAST_RUN_TIME_KEY = "fetch_time"
LAST_RUN_FETCHED_KEY = "fetched_ids"

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

    def __init__(
        self,
        service_name: str,
        service_version: str,
        client_secret: dict,
        scopes: list,
        proxy: bool,
        insecure: bool,
        **kwargs,
    ):
        """
        :param service_name: The name of the service. You can find this and the service  here
         https://github.com/googleapis/google-api-python-client/blob/master/docs/dyn/index.md
        :param service_version: The version of the API.
        :param client_secret: A string of the generated credentials.json
        :param scopes: The scope needed for the project. (i.e. ['https://www.googleapis.com/auth/cloud-platform'])
        :param proxy: Proxy flag
        :param insecure: Insecure flag
        :param kwargs: Potential arguments dict
        """
        credentials = service_account.ServiceAccountCredentials.from_json_keyfile_dict(
            client_secret, scopes=scopes
        )
        if proxy or insecure:
            http_client = credentials.authorize(
                self.get_http_client_with_proxy(proxy, insecure)
            )
            self.service = discovery.build(
                service_name, service_version, http=http_client
            )
        else:
            self.service = discovery.build(
                service_name, service_version, credentials=credentials
            )

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
            https_proxy = proxies.get("https")
            http_proxy = proxies.get("http")
            proxy_conf = https_proxy if https_proxy else http_proxy
            # if no proxy_conf - ignore proxy
            if proxy_conf:
                if not proxy_conf.startswith("https") and not proxy_conf.startswith(
                    "http"
                ):
                    proxy_conf = "https://" + proxy_conf
                parsed_proxy = urllib.parse.urlparse(proxy_conf)
                proxy_info = httplib2.ProxyInfo(
                    proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
                    proxy_host=parsed_proxy.hostname,
                    proxy_port=parsed_proxy.port,
                    proxy_user=parsed_proxy.username,
                    proxy_pass=parsed_proxy.password,
                )
                return httplib2.Http(
                    proxy_info=proxy_info, disable_ssl_certificate_validation=insecure
                )
        return httplib2.Http(disable_ssl_certificate_validation=insecure)


# disable-secrets-detection-end


class PubSubClient(BaseGoogleClient):
    def __init__(
        self,
        default_project,
        default_subscription,
        default_max_msgs,
        client_secret,
        **kwargs,
    ):
        super().__init__(client_secret=client_secret, **kwargs)
        self.default_project = default_project
        if not default_project:
            self.default_project = self._extract_project_from_client_secret(
                client_secret
            )
        self.default_subscription = default_subscription
        self.default_max_msgs = default_max_msgs

    def _extract_project_from_client_secret(self, client_secret):
        """Extracts project name from a client secret json"""
        project_id = client_secret.get("project_id")
        if isinstance(project_id, list):
            project_id = project_id[0]
        return project_id

    def _create_subscription_body(
        self,
        ack_deadline_seconds,
        expiration_ttl,
        labels,
        message_retention_duration,
        push_attributes,
        push_endpoint,
        retain_acked_messages,
        topic_name,
    ):
        """Create a subscription body"""
        if push_endpoint or push_attributes:
            push_config = assign_params(
                pushEndpoint=push_endpoint, attributes=push_attributes,
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
            expirationPolicy=assign_params(ttl=expiration_ttl),
        )
        return body

    def _create_topic_body(self, allowed_persistence_regions, kms_key_name, labels):
        """Create a topic body"""
        message_storage_policy = assign_params(
            allowedPersistenceRegions=allowed_persistence_regions
        )
        body = assign_params(
            labels=labels,
            messageStoragePolicy=message_storage_policy,
            kmsKeyName=kms_key_name,
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
            self.service.projects().subscriptions().get(subscription=sub_name).execute()
        )

    def publish_message(self, project_id, topic_id, req_body):
        """Publish a topic message via GoogleClient"""
        return (
            self.service.projects()
            .topics()
            .publish(
                topic=GoogleNameParser.get_topic_name(project_id, topic_id),
                body=req_body,
            )
            .execute()
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

    def create_subscription(
        self,
        sub_name,
        topic_name,
        push_endpoint,
        push_attributes,
        ack_deadline_seconds,
        retain_acked_messages,
        message_retention_duration,
        labels,
        expiration_ttl,
    ):
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
        body = self._create_subscription_body(
            ack_deadline_seconds,
            expiration_ttl,
            labels,
            message_retention_duration,
            push_attributes,
            push_endpoint,
            retain_acked_messages,
            topic_name,
        )
        return (
            self.service.projects()
            .subscriptions()
            .create(name=sub_name, body=body)
            .execute()
        )

    def update_subscription(
        self,
        sub_name,
        topic_name,
        update_mask,
        push_endpoint,
        push_attributes,
        ack_deadline_seconds,
        retain_acked_messages,
        message_retention_duration,
        labels,
        expiration_ttl,
    ):
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
        sub_body = self._create_subscription_body(
            ack_deadline_seconds,
            expiration_ttl,
            labels,
            message_retention_duration,
            push_attributes,
            push_endpoint,
            retain_acked_messages,
            topic_name,
        )
        body = assign_params(subscription=sub_body, updateMask=update_mask)
        return (
            self.service.projects()
            .subscriptions()
            .patch(name=sub_name, body=body)
            .execute()
        )

    def create_topic(
        self, topic_name, labels, allowed_persistence_regions, kms_key_name
    ):
        """
        Create a topic in the project
        :param topic_name: name of the topic to be created
        :param labels: "key=val" pairs sepearated by ",".'
        :param allowed_persistence_regions: an str representing a list of IDs of GCP regions
        :param kms_key_name: The full name of the Cloud KMS CryptoKey to be used to restrict access on this topic.
        :return: Topic
        """
        body = self._create_topic_body(
            allowed_persistence_regions, kms_key_name, labels
        )
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
        return self.service.projects().topics().delete(topic=topic_name).execute()

    def update_topic(
        self, topic_name, labels, allowed_persistence_regions, kms_key_name, update_mask
    ):
        """
        Updates a topic in the project
        :param topic_name: name of the topic to be updated
        :param labels: "key=val" pairs sepearated by ",".'
        :param allowed_persistence_regions: an str representing a list of IDs of GCP regions
        :param kms_key_name: The full name of the Cloud KMS CryptoKey to be used to restrict access on this topic.
        :param update_mask: Indicates which fields in the provided topic to update.
        :return: Topic
        """
        topic = self._create_topic_body(
            allowed_persistence_regions, kms_key_name, labels
        )
        body = assign_params(topic=topic, updateMask=update_mask)
        return (
            self.service.projects().topics().patch(name=topic_name, body=body).execute()
        )

    def subscription_seek_message(self, subscription_name, time_string, snapshot=None):
        """
        Seeks messages in subscription
        :param subscription_name: Subscription to seek messages for
        :param time_string: A timestamp in RFC3339 UTC "Zulu" format, accurate to nanoseconds,
        :param snapshot: The snapshot to seek to.
        :return: Empty string if successful
        """
        body = assign_params(time=time_string, snapshot=snapshot)
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
        body = assign_params(subscription=subscription_name, labels=labels)
        return (
            self.service.projects()
            .snapshots()
            .create(name=snapshot_name, body=body)
            .execute()
        )

    def update_snapshot(
        self, snapshot_name, topic_name, update_mask, expire_time, labels
    ):
        """
        :param snapshot_name: The name of the snapshot
        :param topic_name: The ID of the topic from which this snapshot is retaining messages.
        :param update_mask: Indicates which fields in the provided snapshot to update.
        :param expire_time: A timestamp in RFC3339 UTC "Zulu" format
        :param labels: labels dict
        :return: Snapshot
        """
        snapshot = assign_params(
            name=snapshot_name, topic=topic_name, expireTime=expire_time, labels=labels
        )
        body = assign_params(snapshot=snapshot, updateMask=update_mask)
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
            self.service.projects().snapshots().delete(snapshot=snapshot_name).execute()
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
    """
    Initializes google client
    :param service_account_json: A string of the generated credentials.json
    :param default_subscription: Default subscription to use
    :param default_project: Default project to use
    :param default_max_msgs: Max messages to pull per fetch
    :param insecure: Flag - do not validate https certs
    :param kwargs:
    :return:
    """
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
            **kwargs,
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
    published_time_dt = dateparser.parse(message.get("publishTime"))
    incident = {
        "name": f'Google PubSub Message {message.get("messageId")}',
        "rawJSON": json.dumps(message),
        "occurred": convert_datetime_to_iso_str(published_time_dt),
    }
    return incident


def get_messages_ids_and_max_publish_time(msgs):
    """
    Get message IDs and max publish time from given pulled messages
    """
    msg_ids = set()
    max_publish_time = None
    for msg in msgs:
        msg_ids.add(msg.get("messageId"))
        publish_time = msg.get("publishTime")
        if publish_time:
            publish_time = dateparser.parse(msg.get("publishTime"))
        if not max_publish_time:
            max_publish_time = publish_time
        else:
            max_publish_time = max(max_publish_time, publish_time)
    if max_publish_time:
        max_publish_time = convert_datetime_to_iso_str(max_publish_time)
    return msg_ids, max_publish_time


def convert_datetime_to_iso_str(publish_time):
    """
    Converts datetime to str in "%Y-%m-%dT%H:%M:%S.%fZ" format
    :param publish_time: Datetime
    :return: date str in "%Y-%m-%dT%H:%M:%S.%fZ" format
    """
    try:
        return publish_time.strftime(ISO_DATE_FORMAT)
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
    client.list_topic(
        GoogleNameParser.get_project_name(client.default_project), page_size=1
    )
    if is_fetch:
        client.pull_messages(
            GoogleNameParser.get_subscription_project_name(
                client.default_project, client.default_subscription
            ),
            max_messages=1,
        )
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
    next_page_token = res.get("nextPageToken")
    readable_output = tableToMarkdown(
        f"Topics for project {project_id}", topics, ["name"]
    )
    outputs = {"GoogleCloudPubSubTopics(val && val.name === obj.name)": topics}
    if next_page_token:
        outputs["GoogleCloudPubSub.Topics.nextPageToken"] = next_page_token
        readable_output += f"**Next Page Token: {next_page_token}**"
    return readable_output, outputs, res


def publish_message_command(
    client: PubSubClient,
    topic_id: str,
    project_id: str,
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
    for msg_id in published_messages.get("messageIds"):
        output.append(
            {
                "topic": topic_id,
                "messageId": msg_id,
                "data": data,
                "attributes": body.get("attributes"),
            }
        )

    ec = {"GoogleCloudPubSubPublishedMessages(val.messageId === obj.messageId)": output}
    return (
        tableToMarkdown(
            "Google Cloud PubSub has published the message successfully",
            output,
            removeNull=True,
            headerTransform=pascalToSpace,
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
    subscription_id: str,
    project_id: str,
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
            "GoogleCloudPubSubPulledMessages(val && val.messageId === obj.messageId)": msgs
        }
        if ack == "true":
            client.ack_messages(full_subscription_name, acknowledges)
        hr = tableToMarkdown("Google Cloud PubSub Messages", msgs, removeNull=True)
        return hr, ec, raw_msgs
    else:
        return "No new messages found", {}, raw_msgs


def ack_messages_command(
    client: PubSubClient, ack_ids: str, subscription_id: str, project_id: str,
) -> Tuple[str, dict, list]:
    """
    ACKs previously pulled messages using ack Ids
    Requires one of the following OAuth scopes:

        https://www.googleapis.com/auth/pubsub
        https://www.googleapis.com/auth/cloud-platform

    :param client: GoogleClient
    :param ack_ids: csv str with ack ids
    :param project_id: project name
    :param subscription_id: Subscription name to pull messages from
    :return: Success message
    """
    sub_name = GoogleNameParser.get_subscription_project_name(
        project_id, subscription_id
    )
    ack_ids = argToList(ack_ids)
    raw_res = client.ack_messages(sub_name, ack_ids)
    title = f"Subscription {subscription_id} had the following ids acknowledged"
    readable_output = tableToMarkdown(title, ack_ids, headers=["ACK ID"])
    return readable_output, {}, raw_res


def extract_acks_and_msgs(raw_msgs, add_ack_to_msg=True):
    """
    Extracts acknowledges and message data from raw_msgs
    :param raw_msgs: Raw messages object
    :param add_ack_to_msg: Boolean flag - if true, will add ack to message under "ackId"
    :return:
    """
    msg_list = []
    acknowledges = []
    if isinstance(raw_msgs, dict):
        rcvd_msgs = raw_msgs.get("receivedMessages", [])
        for raw_msg in rcvd_msgs:
            msg = raw_msg.get("message", {})
            decoded_data = str(msg.get("data", ""))
            try:
                decoded_data = str(base64.b64decode(decoded_data))[2:-1]
            except Exception:
                # display message with b64 value
                pass

            msg["data"] = decoded_data
            ack_id = raw_msg.get("ackId")
            if ack_id:
                acknowledges.append(ack_id)
                if add_ack_to_msg:
                    msg["ackId"] = ack_id
            msg_list.append(msg)
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
    title = "Subscriptions"
    if topic_id:
        full_topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
        raw_response = client.list_topic_subs(full_topic_name, page_size, page_token)
        subs = [{"name": sub} for sub in raw_response.get("subscriptions", [])]
        next_page_token = raw_response.get("nextPageToken")
        title += f" for topic {topic_id} in project {project_id}"
        readable_output = tableToMarkdown(
            title, subs, headers=["name"], headerTransform=pascalToSpace
        )
    else:
        full_project_name = GoogleNameParser.get_project_name(project_id)
        raw_response = client.list_project_subs(
            full_project_name, page_size, page_token
        )
        subs = raw_response.get("subscriptions", "")
        next_page_token = raw_response.get("nextPageToken")
        title += f" in project {project_id}"
        for sub in subs:
            sub["deliveryType"] = "Push" if sub.get("pushConfig") else "Pull"
        readable_output = tableToMarkdown(
            title,
            subs,
            headers=["name", "topic", "ackDeadlineSeconds", "labels"],
            headerTransform=pascalToSpace,
        )
    outputs = {"GoogleCloudPubSubSubscriptions(val && val.name === obj.name)": subs}
    if next_page_token:
        outputs["GoogleCloudPubSubSubscriptions.nextPageToken"] = next_page_token
        readable_output += f"**Next Page Token: {next_page_token}**"

    return readable_output, outputs, raw_response


def get_subscription_command(
    client: PubSubClient, subscription_id: str, project_id: str
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
    sub = client.get_sub(full_sub_name)
    sub["deliveryType"] = "Push" if sub.get("pushConfig") else "Pull"
    title = f"Subscription {subscription_id}"
    readable_output = tableToMarkdown(title, sub, headerTransform=pascalToSpace)
    outputs = {"GoogleCloudPubSubSubscriptions(val && val.name === obj.name)": sub}
    return readable_output, outputs, sub


def create_subscription_command(
    client: PubSubClient,
    subscription_id: str,
    topic_id: str,
    project_id: str,
    push_endpoint: str = "",
    push_attributes: str = "",
    ack_deadline_seconds: str = "",
    retain_acked_messages: str = "",
    message_retention_duration: str = "",
    labels: str = "",
    expiration_ttl: str = "",
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
    full_sub_name = GoogleNameParser.get_subscription_project_name(
        project_id, subscription_id
    )
    full_topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
    labels = attribute_pairs_to_dict(labels)
    push_attributes = attribute_pairs_to_dict(push_attributes)
    raw_sub = client.create_subscription(
        full_sub_name,
        full_topic_name,
        push_endpoint,
        push_attributes,
        ack_deadline_seconds,
        retain_acked_messages,
        message_retention_duration,
        labels,
        expiration_ttl,
    )
    sub = dict(raw_sub)
    title = f"Subscription {subscription_id} was created successfully"
    readable_output = tableToMarkdown(title, sub)
    sub["projectName"] = project_id
    sub["subscriptionName"] = subscription_id
    sub["deliveryType"] = "Push" if sub.get("pushConfig") else "Pull"
    outputs = {"GoogleCloudPubSubSubscriptions": sub}
    return readable_output, outputs, raw_sub


def update_subscription_command(
    client: PubSubClient,
    subscription_id: str,
    topic_id: str,
    update_mask: str,
    project_id: str,
    push_endpoint: str = "",
    push_attributes: str = "",
    ack_deadline_seconds: str = "",
    retain_acked_messages: str = "",
    message_retention_duration: str = "",
    labels: str = "",
    expiration_ttl: str = "",
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
    full_sub_name = GoogleNameParser.get_subscription_project_name(
        project_id, subscription_id
    )
    full_topic_name = GoogleNameParser.get_topic_name(project_id, topic_id)
    labels = attribute_pairs_to_dict(labels)
    push_attributes = attribute_pairs_to_dict(push_attributes)
    raw_sub = client.update_subscription(
        full_sub_name,
        full_topic_name,
        update_mask,
        push_endpoint,
        push_attributes,
        ack_deadline_seconds,
        retain_acked_messages,
        message_retention_duration,
        labels,
        expiration_ttl,
    )
    sub = dict(raw_sub)
    title = f"Subscription {subscription_id} was updated successfully"
    readable_output = tableToMarkdown(title, sub)
    sub["projectName"] = project_id
    sub["subscriptionName"] = subscription_id
    sub["deliveryType"] = "Push" if sub.get("pushConfig") else "Pull"
    outputs = {"GoogleCloudPubSubSubscriptions(val && val.name === obj.name)": sub}
    return readable_output, outputs, raw_sub


def create_topic_command(
    client: PubSubClient,
    topic_id: str,
    project_id: str,
    allowed_persistence_regions: str = "",
    kms_key_name: str = None,
    labels: str = None,
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
    raw_topic = client.create_topic(
        topic_name, labels, allowed_persistence_regions, kms_key_name
    )
    title = f"Topic **{topic_id}** was created successfully"
    readable_output = tableToMarkdown(title, raw_topic, headerTransform=pascalToSpace)
    outputs = {"GoogleCloudPubSubTopics": raw_topic}
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
    client: PubSubClient,
    project_id: str,
    topic_id: str,
    update_mask: str,
    allowed_persistence_regions: str = "",
    kms_key_name: str = None,
    labels: str = None,
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
    raw_topic = client.update_topic(
        topic_name, labels, allowed_persistence_regions, kms_key_name, update_mask
    )
    title = f"Topic {topic_id} was updated successfully"
    readable_output = tableToMarkdown(title, raw_topic, headerTransform=pascalToSpace)
    outputs = {"GoogleCloudPubSubTopics(val && val.name === obj.name)": raw_topic}
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
        return_error("Please provide either a time_string or a snapshot")
    sub_name = GoogleNameParser.get_subscription_project_name(
        project_id, subscription_id
    )
    raw_res = client.subscription_seek_message(sub_name, time_string, snapshot)
    readable_output = (
        "Message seek was successful for **"
        + (f"time: {time_string}" if time_string else f"snapshot:{snapshot}")
        + "**"
    )
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
    next_page_token = res.get("nextPageToken")
    readable_output = tableToMarkdown(title, snapshots, ["name"])
    outputs = {"GoogleCloudPubSubSnapshots(val && val.name === obj.name)": snapshots}
    if next_page_token:
        outputs["GoogleCloudPubSub.Snapshots.nextPageToken"] = next_page_token
        readable_output += f"**Next Page Token: {next_page_token}**"
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
    subscription_name = GoogleNameParser.get_subscription_project_name(
        project_id, subscription_id
    )
    snapshot_name = GoogleNameParser.get_snapshot_project_name(project_id, snapshot_id)
    labels = attribute_pairs_to_dict(labels)
    raw_snapshot = client.create_snapshot(subscription_name, snapshot_name, labels)
    title = f"Snapshot **{snapshot_id}** was created successfully"
    readable_output = tableToMarkdown(
        title, raw_snapshot, headerTransform=pascalToSpace
    )
    outputs = {"GoogleCloudPubSubSnapshots": raw_snapshot}
    return readable_output, outputs, raw_snapshot


def snapshot_update_command(
    client: PubSubClient,
    project_id: str,
    topic_id: str,
    snapshot_id: str,
    update_mask: str,
    expire_time: str = None,
    labels: str = None,
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
    raw_snapshot = client.update_snapshot(
        snapshot_name, topic_name, update_mask, expire_time, labels
    )
    title = f"Snapshot **{snapshot_id}** was updated successfully"
    readable_output = tableToMarkdown(
        title, raw_snapshot, headerTransform=pascalToSpace
    )
    outputs = {
        "GoogleCloudPubSubSnapshots(val && val.name === obj.name)": raw_snapshot
    }
    return readable_output, outputs, raw_snapshot


def snapshot_delete_command(
    client: PubSubClient, project_id: str, snapshot_id: str
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


def fetch_incidents(
    client: PubSubClient, last_run: dict, first_fetch_time: str, ack_incidents: bool
):
    """
    This function will execute each interval (default is 1 minute).
    :param client: GoogleClient initialized with default_project, default_subscription and default_max_msgs
    :param last_run: last run dict containing last run data
    :param first_fetch_time: how long ago should the subscription seek in first fetch
    :param ack_incidents: Boolean flag - when set to True will ack back the fetched messages
    :return: incidents: Incidents that will be created in Demisto
    """
    sub_name = GoogleNameParser.get_subscription_project_name(
        client.default_project, client.default_subscription
    )

    # Setup subscription for fetch
    last_run_fetched_ids, last_run_time = setup_subscription_last_run(
        client, first_fetch_time, last_run, sub_name, ack_incidents
    )

    # Pull unique messages if available
    msgs, msg_ids, acknowledges, max_publish_time = try_pull_unique_messages(
        client, sub_name, last_run_fetched_ids, last_run_time, retry_times=1
    )

    # Handle fetch results
    return handle_fetch_results(
        client,
        sub_name,
        last_run,
        acknowledges,
        last_run_time,
        max_publish_time,
        msg_ids,
        msgs,
        ack_incidents,
    )


def setup_subscription_last_run(
    client, first_fetch_time, last_run, sub_name, ack_incidents
):
    """
    Setups the subscription last run data, and seeks the subscription to a previous time if relevant
    :param client: PubSub client
    :param first_fetch_time: First fetch time provided by the user
    :param last_run: Last run dict
    :param sub_name: Name of the subscription
    :param ack_incidents: ACK flag - if true, will not use seek except for first time fetch
    :return:
    """
    last_run_fetched_ids = set()
    # Handle first time fetch
    if not last_run or LAST_RUN_TIME_KEY not in last_run:
        last_run_time, _ = parse_date_range(first_fetch_time, ISO_DATE_FORMAT)
        # Seek previous message state
        client.subscription_seek_message(sub_name, last_run_time)
    else:
        last_run_time = last_run.get(LAST_RUN_TIME_KEY)
        last_run_fetched_val = last_run.get(LAST_RUN_FETCHED_KEY)
        if last_run_fetched_val:
            last_run_fetched_ids = set(last_run_fetched_val)
        if not ack_incidents:
            # Seek previous message state
            client.subscription_seek_message(sub_name, last_run_time)
    return last_run_fetched_ids, last_run_time


def try_pull_unique_messages(
    client, sub_name, previous_msg_ids, last_run_time, retry_times=0
):
    """
    Tries to pull unique messages for the subscription
    :param client: PubSub client
    :param sub_name: Subscription name
    :param previous_msg_ids: Previous message ids set
    :param last_run_time: previous run time
    :param retry_times: How many times to retry pulling
    :return:
        1. Unique list of messages
        2. Unique  set of message ids
        3. Messages acks
        4. max_publish_time
    """
    res_msgs = None
    res_msg_ids = None
    res_acks = None
    res_max_publish_time = None
    raw_msgs = client.pull_messages(sub_name, client.default_max_msgs)
    if "receivedMessages" in raw_msgs:
        res_acks, msgs = extract_acks_and_msgs(raw_msgs)
        # continue only if messages were extracted successfully
        if msgs:
            msg_ids, max_publish_time = get_messages_ids_and_max_publish_time(msgs)
            new_msg_ids = msg_ids.difference(previous_msg_ids)
            # all messages are unique - return as is
            if len(new_msg_ids) == len(msg_ids):
                return msgs, msg_ids, res_acks, max_publish_time
            # no new messages - retry -1
            elif len(new_msg_ids) == 0 and retry_times > 0:
                demisto.debug(
                    f"GCP_PUBSUB_MSG Duplicates with max_publish_time: {max_publish_time}"
                )
                return try_pull_unique_messages(
                    client, sub_name, previous_msg_ids, retry_times - 1
                )
            # clean non-unique ids from raw_msgs
            else:
                filtered_raw_msgs = filter_non_unique_messages(
                    raw_msgs, previous_msg_ids, last_run_time
                )
                res_acks, res_msgs = extract_acks_and_msgs(filtered_raw_msgs)
                (
                    res_msg_ids,
                    res_max_publish_time,
                ) = get_messages_ids_and_max_publish_time(res_msgs)
    return res_msgs, res_msg_ids, res_acks, res_max_publish_time


def is_unique_msg(msg, previous_msg_ids, previous_run_time):
    """
    Determines if message is unique given previous message ids, and that it's greater than previous run time
    :param msg: raw Message object
    :param previous_msg_ids: set of previously fetched message ids
    :param previous_run_time: previous run time string
    :return: True if message is unique
    """
    message_dict = msg.get("message", {})
    if message_dict:
        msg_id = message_dict.get("messageId")
        msg_pub_time = message_dict.get("publishTime", "")
        return msg_id not in previous_msg_ids and msg_pub_time > previous_run_time
    return False


def filter_non_unique_messages(raw_msgs, previous_msg_ids, previous_run_time):
    """
    Filters messages that appear in previous_msg_ids or are older than the previous_run_time
    :param raw_msgs: Raw message object
    :param previous_msg_ids:
    :param previous_run_time:
    :return:
    """
    raw_msgs = raw_msgs.get("receivedMessages", [])
    # filter messages using `previous_msg_ids` and `previous_run_time`
    filtered_raw_msgs = list(
        filter(
            lambda msg: is_unique_msg(msg, previous_msg_ids, previous_run_time),
            raw_msgs,
        )
    )
    return {"receivedMessages": filtered_raw_msgs}


def handle_fetch_results(
    client,
    sub_name,
    last_run,
    acknowledges,
    last_run_time,
    max_publish_time,
    pulled_msg_ids,
    pulled_msgs,
    ack_incidents,
):
    """
    Handle the fetch results
    :param client: PubSub Client
    :param sub_name: Subscription name
    :param last_run: last run dict
    :param acknowledges: acknowledges to make given ack_incidents is True
    :param last_run_time: last run time
    :param max_publish_time: max publish time of pulled messages
    :param pulled_msg_ids: pulled message ids
    :param pulled_msgs: pulled messages
    :param ack_incidents: ack incidents flag
    :return: incidents and last run
    """
    incidents = []
    if pulled_msg_ids and max_publish_time:
        if last_run_time <= max_publish_time:
            # Create incidents
            for msg in pulled_msgs:
                incident = message_to_incident(msg)
                incidents.append(incident)
            # ACK messages if relevant
            if ack_incidents:
                client.ack_messages(sub_name, acknowledges)
            # Recreate last run to return with new values
            last_run = {
                LAST_RUN_TIME_KEY: max_publish_time,
                LAST_RUN_FETCHED_KEY: list(pulled_msg_ids),
            }
    # We didn't manage to pull any unique messages, so we're trying to increment micro seconds - not relevant for ack
    elif not ack_incidents:
        last_run_time_dt = dateparser.parse(
            max_publish_time if max_publish_time else last_run_time
        )
        last_run_time = convert_datetime_to_iso_str(
            last_run_time_dt + timedelta(microseconds=1)
        )
        # Update last run time
        last_run[LAST_RUN_TIME_KEY] = last_run_time
    return incidents, last_run


def main():
    params = demisto.params()
    client = init_google_client(**params)
    command = demisto.command()
    LOG(f"Command being called is {command}")
    try:
        commands = {
            "gcp-pubsub-topic-publish-message": publish_message_command,
            "gcp-pubsub-topic-messages-pull": pull_messages_command,
            "gcp-pubsub-topic-ack-messages": ack_messages_command,
            "gcp-pubsub-topic-subscriptions-list": subscriptions_list_command,
            "gcp-pubsub-topic-subscription-get-by-name": get_subscription_command,
            "gcp-pubsub-topic-subscription-create": create_subscription_command,
            "gcp-pubsub-topic-subscription-update": update_subscription_command,
            "gcp-pubsub-topics-list": topics_list_command,
            "gcp-pubsub-topic-create": create_topic_command,
            "gcp-pubsub-topic-delete": delete_topic_command,
            "gcp-pubsub-topic-update": update_topic_command,
            "gcp-pubsub-topic-messages-seek": seek_message_command,
            "gcp-pubsub-topic-snapshots-list": snapshot_list_command,
            "gcp-pubsub-topic-snapshot-create": snapshot_create_command,
            "gcp-pubsub-topic-snapshot-update": snapshot_update_command,
            "gcp-pubsub-topic-snapshot-delete": snapshot_delete_command,
        }
        if command == "test-module":
            demisto.results(test_module(client, params.get("isFetch")))
        elif command == "fetch-incidents":
            ack_incidents = params.get("ack_incidents")
            first_fetch_time = params.get("first_fetch_time").rstrip()
            last_run = demisto.getLastRun()
            incidents, last_run = fetch_incidents(
                client, last_run, first_fetch_time, ack_incidents
            )
            demisto.incidents(incidents)
            demisto.setLastRun(last_run)
        else:
            args = demisto.args()
            # project_id is expected to be in all commands. If not provided defaults on client.default_project
            if "project_id" not in args:
                args["project_id"] = client.default_project
            return_outputs(*commands[command](client, **args))  # type: ignore[operator]

    # Log exceptions
    except Exception as e:
        return_error(
            f"Failed to execute {demisto.command()} command. Error: {str(e)} , traceback: {traceback.format_exc()}"
        )


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
