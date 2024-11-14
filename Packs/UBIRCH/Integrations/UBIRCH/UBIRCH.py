import demistomock as demisto
from CommonServerPython import *  # noqa # pylint: disable=unused-wildcard-import
from CommonServerUserPython import *  # noqa
import paho.mqtt.client as mqtt
import paho
from collections.abc import Callable
import traceback
import json

''' CONSTANTS '''

QOS_AT_LEAST_ONCE = 1

# SEVERITY
CRITICAL_SEVERITY = 4
HIGH_SEVERITY = 3
MEDIUM_SEVERITY = 2
LOW_SEVERITY = 1
UNKNOWN_SEVERITY = 0

# Types
AUTHENTICATION_TYPE = 'Authentication'
AUTHENTICITY_TYPE = 'UBIRCH Authenticity'
INTEGRITY_TYPE = 'UBIRCH Integrity'
PRIVACY_TYPE = 'UBIRCH Privacy'
SEQUENCE_TYPE = 'UBIRCH Sequence'

# Fields
SEVERITY_FIELD = "severity"
TYPE_FIELD = "type"
MEANING_FIELD = "meaning"

INCIDENT_SEVERITY_MAP = {
    "niomon-auth": {
        "1000": {
            MEANING_FIELD: "Authentication error: request malformed. Possible missing header and parameters.",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: AUTHENTICATION_TYPE
        },
        "2000": {
            MEANING_FIELD: "Authentication error: processing authentication response/Failed Request",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: AUTHENTICATION_TYPE
        },
        "3000": {
            MEANING_FIELD: "Authentication error (3rd party): error processing authentication request",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: AUTHENTICATION_TYPE
        },
        "4000": {
            MEANING_FIELD: "Authentication error: Failed Request",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: AUTHENTICATION_TYPE
        }
    },
    "niomon-decoder": {
        "1100": {
            MEANING_FIELD: "Invalid verification: request malformed. Possible missing headers or parameters.",
            SEVERITY_FIELD: MEDIUM_SEVERITY,
            TYPE_FIELD: AUTHENTICITY_TYPE
        },
        "1200": {
            MEANING_FIELD: "Invalid verification: invalid parts",
            SEVERITY_FIELD: HIGH_SEVERITY,
            TYPE_FIELD: AUTHENTICITY_TYPE
        },
        "1300": {
            MEANING_FIELD: "Invalid verification: signature verification failed. No public key or integrity is "
                           "compromised.",
            SEVERITY_FIELD: HIGH_SEVERITY,
            TYPE_FIELD: AUTHENTICITY_TYPE
        },
        "2100": {
            MEANING_FIELD: "Decoding error: request malformed. Possible missing headers or parameters.",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: INTEGRITY_TYPE
        },
        "2200": {
            MEANING_FIELD: "Decoding Error: Invalid Match",
            SEVERITY_FIELD: MEDIUM_SEVERITY,
            TYPE_FIELD: INTEGRITY_TYPE
        },
        "2300": {
            MEANING_FIELD: "Decoding Error: Decoding Error/Null Payload",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: INTEGRITY_TYPE
        }
    },
    "niomon-enricher": {
        "1000": {
            MEANING_FIELD: "Tenant error: the owner of the device cannot be determined. Possible missing headers or "
                           "parameters or body.",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: AUTHENTICITY_TYPE
        },
        "2000": {
            MEANING_FIELD: "Tenant error: the owner of the device does not exist or cannot be acquired.",
            SEVERITY_FIELD: HIGH_SEVERITY,
            TYPE_FIELD: AUTHENTICITY_TYPE
        },
        "0000": {
            MEANING_FIELD: "Tenant error: the owner of the device does not exist or cannot be acquired (3rd Party).",
            SEVERITY_FIELD: HIGH_SEVERITY,
            TYPE_FIELD: AUTHENTICITY_TYPE
        }
    },
    "filter-service": {
        "0000": {
            MEANING_FIELD: "Integrity violation: duplicate hash detected. Possible injection, reply attack, "
                           "or hash collision. ",
            SEVERITY_FIELD: HIGH_SEVERITY,
            TYPE_FIELD: SEQUENCE_TYPE
        },
        "0010": {
            MEANING_FIELD: "Privacy violation: hash is already disabled or non-existent",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: PRIVACY_TYPE
        },
        "0020": {
            MEANING_FIELD: "Privacy violation: hash is not disabled or non-existent",
            SEVERITY_FIELD: LOW_SEVERITY,
            TYPE_FIELD: PRIVACY_TYPE
        },
        "0030": {
            MEANING_FIELD: "Privacy violation: hash does not exist. Possible DDOS attack",
            SEVERITY_FIELD: HIGH_SEVERITY,
            TYPE_FIELD: PRIVACY_TYPE
        }
    }
}

''' CLIENT CLASS '''


class Client:
    """Client class to subscribe the error from MQTT server

    This Client class is a wrapper class of the paho mqtt Client.

    Args:
        mqtt_host(str): MQTT server's host name
        mqtt_port(int): MQTT server's port number
        username(str): MQTT server's user name
        password(str): MQTT server's password
        stage(str): MQTT server's environment
        tenant_id(str): tenant id related with errors subscribed

    Return:
        None
    """

    def __init__(self, mqtt_host: str, mqtt_port: int, username: str, password: str, stage: str, tenant_id: str):
        self.mqtt_client = mqtt.Client()
        self.mqtt_client.username_pw_set(username, password)
        self.mqtt_host = mqtt_host
        self.mqtt_port = mqtt_port
        self.topic = f"com/ubirch/{stage}/incident/tenant/{tenant_id}"

    def connect(self, on_connect_callback: Callable[[mqtt.Client, dict, dict, int], None] = None) -> None:
        if on_connect_callback is not None:
            self.mqtt_client.on_connect = on_connect_callback
        self.mqtt_client.connect(self.mqtt_host, self.mqtt_port)

    def subscribe(self, on_message_callback: Callable[[mqtt.Client, dict, mqtt.MQTTMessage], None] = None) -> None:
        if on_message_callback is not None:
            self.mqtt_client.on_message = on_message_callback
        self.mqtt_client.subscribe(self.topic, QOS_AT_LEAST_ONCE)

    def loop_forever(self) -> None:
        self.mqtt_client.loop_forever()

    def loop_stop(self) -> None:
        self.mqtt_client.loop_stop()


''' HELPER FUNCTIONS '''


def get_error_definition(incident: Dict) -> Dict:
    """Return the error definition from the incident

    Ex. { "meaning": "xxx", "severity": 1, "type": "AUTHENTICATION" }

    Args:
        incident(Dict): an incident

    Return:
        Dict: error definition
    """
    microservice: str = incident.get("microservice", "")
    error_code: str = incident.get("errorCode", "")
    # ex. { "1000": { ... }, "1100": { ... } }
    error_codes: Dict = INCIDENT_SEVERITY_MAP.get(microservice, {})
    # ex. { "meaning": "xxx", "severity": 1, "type": "AUTHENTICATION" }
    return error_codes.get(error_code, {})


def create_incidents(error_message: str) -> list:
    """Create the incidents

    Args:
        error_message (str): this is the message payload from MQTT server

    Return:
        list: list of incidents
    """
    incident_dict = json.loads(error_message)
    error_definition = get_error_definition(incident_dict)
    return [{
        'name': error_definition.get(MEANING_FIELD, incident_dict.get("error")),
        'type': error_definition.get(TYPE_FIELD, ""),
        'labels': [{'type': "requestId", 'value': incident_dict.get("requestId")},
                   {'type': "hwDeviceId", 'value': incident_dict.get("hwDeviceId")}],
        'rawJSON': json.dumps(incident_dict),
        'details': json.dumps(incident_dict),
        'severity': error_definition.get(SEVERITY_FIELD, UNKNOWN_SEVERITY),
    }]


''' COMMAND FUNCTIONS '''


def long_running_execution(client: Client) -> None:
    """Connects to a MQTT Server and subscribe the error from it in a loop.

    Args:
        client(Client): client class which is a wrapper of the mqtt.Client class.

    Return:
        None: no data returned
    """

    def on_connect(_client: mqtt.Client, _userdata: dict, _flags: dict, rc: int) -> None:
        """
        Callback function when a MQTT client connects to the server

        Check if the connection is succeeded.
        The rc argument is a connection result.
        """
        if rc != mqtt.MQTT_ERR_SUCCESS:
            demisto.info(mqtt.connack_string(rc))
            raise paho.mqtt.MQTTException(mqtt.connack_string(rc))
        else:
            demisto.info(f"connection was succeeded for a long-running container. host: {client.mqtt_host}, port: "
                         f"{client.mqtt_port}")

    def on_message(_client: mqtt.Client, _userdata: dict, message: mqtt.MQTTMessage) -> None:
        """
        Callback function when a MQTT client subscribes to a message from the server

        Create incidents, when the client subscribes to an error from the mqtt server.
        """
        demisto.info(f"on message. {message.topic} {message.qos} {message.payload}")  # type: ignore[str-bytes-safe]
        incidents = create_incidents(message.payload.decode("utf-8", "ignore"))  # the message payload is binary.
        demisto.info(f"catch an incident. {incidents}")
        demisto.createIncidents(incidents)

    try:
        client.connect(on_connect)
        client.subscribe(on_message)
        client.loop_forever()
    except Exception as e:
        demisto.error(f'An error occurred in the long running loop: {e}')
    finally:
        client.loop_stop()


def test_module(client: Client) -> None:
    """Check if the user configuration is correct

    Return:
        None: no data returned
    """

    def on_connect(_client: mqtt.Client, _userdata: dict, _flags: dict, rc: int) -> None:
        """
        Callback function when a MQTT client connects to the server

        Check if the connection is succeeded.
        Stop the loop regardless of whether the connection is succeeded or not.
        The rc argument is a connection result.
        """
        _client.disconnect()
        _client.loop_stop()
        if rc != mqtt.MQTT_ERR_SUCCESS:
            demisto.info(mqtt.connack_string(rc))
            raise paho.mqtt.MQTTException(mqtt.connack_string(rc))
        else:
            demisto.info("connection was succeeded for test")

    try:
        client.connect(on_connect)
        client.subscribe()
        client.loop_forever()
    except Exception as e:
        raise DemistoException(
            f"Test failed. Please check your parameters. \n {e}")
    demisto.results('ok')


def create_sample_incidents() -> None:
    """Extract sample events stored in the integration context and create them as incidents

    Return:
        None: no data returned
    """
    integration_context = get_integration_context()
    sample_events = integration_context.get('sample_events')
    if sample_events:
        try:
            incidents = [{'name': "sample_event", 'rawJSON': json.dumps(event)} for event in json.loads(sample_events)]
            demisto.createIncidents(incidents)
            demisto.info("it was succeeded to create the sample incident.")
        except json.decoder.JSONDecodeError as e:
            raise ValueError(f'Failed deserializing sample events - {e}')
    else:
        incidents = [{
            'name': 'sample incident.',
        }]
        demisto.createIncidents(incidents)
        demisto.info("it was succeeded to create the sample incident.")


demisto.info("connection was succeeded for test")


def main() -> None:
    """ main function, parses params and runs command functions """

    params = demisto.params()
    username = params['credentials'].get('identifier')
    password = params['credentials'].get('password')
    tenant_id = params['tenant_id']
    mqtt_host = params['url']
    mqtt_port = params['port']
    stage = params['stage']

    command = demisto.command()
    demisto.debug(f'Command being called is {command}')

    try:
        try:
            mqtt_port = int(mqtt_port)
        except ValueError as e:
            raise ValueError(f"Invalid the mqtt server's port - {e}")

        client = Client(
            mqtt_host=mqtt_host,
            mqtt_port=mqtt_port,
            username=username,
            password=password,
            stage=stage,
            tenant_id=tenant_id
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            test_module(client)

        elif command == 'long-running-execution':
            long_running_execution(client)

        elif command == 'create-sample-incidents':
            create_sample_incidents()

    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {demisto.command()} command.\nError:\n{str(e)}')


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
