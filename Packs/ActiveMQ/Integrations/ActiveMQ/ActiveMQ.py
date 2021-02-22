import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import stomp
import os
import traceback


''' GLOBAL VARS '''

HOSTNAME = demisto.params()['hostname']
PORT = int(demisto.params()['port'])
USERNAME = demisto.params().get('credentials', {}).get('identifier')
PASSWORD = demisto.params().get('credentials', {}).get('password')
CLIENT_CERT = demisto.params().get('client_cert')
CLIENT_KEY = demisto.params().get('client_key')
ROOT_CA = demisto.params().get('root_ca')


class MsgListener(stomp.ConnectionListener):
    def __init__(self):
        self.result_arr = []
        self.msg_ids = []

    def on_error(self, headers, message):
        demisto.results('received an error "%s"' % message)

    def on_message(self, headers, message):
        self.result_arr.append(message)
        self.msg_ids.append(headers['message-id'])


''' HELPER FUNCTIONS '''


def create_connection(client_cert, client_key, root_ca):
    client_path = None
    client_key_path = None
    if client_cert:
        client_path = 'client.cert'
        with open(client_path, 'wb') as file:
            file.write(client_cert)
            client_path = os.path.abspath(client_path)
    if client_key:
        client_key_path = 'client_key.key'
        with open(client_key_path, 'wb') as file:
            file.write(client_key)
    if root_ca:
        root_ca_path = 'root_ca.key'
        with open(root_ca_path, 'wb') as file:
            file.write(root_ca)

    if client_cert or client_key or root_ca:
        conn = stomp.Connection(host_and_ports=[(HOSTNAME, PORT)], use_ssl=True,
                                ssl_key_file=client_key_path, ssl_cert_file=client_path)
    else:
        conn = stomp.Connection([(HOSTNAME, PORT)])

    return conn


def connect(conn, client_id=None):
    conn.start()
    if USERNAME or PASSWORD:
        if client_id and len(client_id) > 0:
            conn.connect(USERNAME, PASSWORD, wait=True, headers={'client-id': client_id})
        else:
            conn.connect(USERNAME, PASSWORD, wait=True)

    elif CLIENT_KEY or CLIENT_CERT or ROOT_CA:
        if client_id and len(client_id) > 0:
            conn.connect(wait=True)  # , headers = {'client-id': client_id })
        else:
            conn.connect(wait=True)
    else:
        raise ValueError('You must provide username/password or certificates')

    return conn


''' FUNCTIONS '''


def send_message(conn):

    txid = conn.begin()
    dest = demisto.args()['destination']
    body = demisto.args()['body']

    if 'headers' in demisto.args():
        try:
            headers_demisto = json.loads(demisto.args()['headers'])
        except Exception as e:
            demisto.error('Failed to parse "headers". Error: {}'.format(e))
            raise ValueError('Failed to parse "headers" argument to JSON. "headers"={}'
                             .format(demisto.args()['headers']))

        conn.send(dest, body, transaction=txid, headers=headers_demisto)
    else:
        conn.send(dest, body, transaction=txid)

    conn.commit(txid)
    demisto.results('Message sent to ActiveMQ destination: ' + dest + ' with transaction ID: ' + txid)


def subscribe(client, conn, subscription_id, topic_name, queue_name):
    if not queue_name and not topic_name:
        raise ValueError('To subscribe you must provide either queue-name or topic-name')
    elif queue_name and topic_name:
        raise ValueError('Can\'t provide both queue-name and topic-name.')

    listener = MsgListener()
    if client and len(client) > 0:
        conn.set_listener('Demisto', listener)

    # ack='client-individual', headers={'activemq.subscriptionName': client})
    if queue_name:
        conn.subscribe('/queue/' + queue_name, subscription_id, ack='client-individual')
    elif topic_name:
        conn.subscribe(
            '/topic/' + topic_name, subscription_id,
            ack='client-individual',
            headers={'activemq.subscriptionName': client}
        )

    time.sleep(1)

    for msg in listener.result_arr:
        demisto.results(msg)

    for msg_id in listener.msg_ids:
        conn.ack(msg_id, subscription_id)


def fetch_incidents(client, conn, subscription_id, queue_name, topic_name):
    if not queue_name and not topic_name:
        raise ValueError('To fetch incidents you must provide either Queue Name or Topic Name')
    elif queue_name and topic_name:
        raise ValueError('Can\'t provide both Queue Name and Topic name.')

    # conn = stomp.Connection(heartbeats=(4000, 4000))
    listener = MsgListener()
    if client and len(client) > 0:
        conn.set_listener('Demisto', listener)

    if queue_name:
        conn.subscribe('/queue/' + queue_name, subscription_id, ack='client-individual')
    else:
        conn.subscribe(
            '/topic/' + topic_name,
            subscription_id,
            ack='client-individual',
            headers={'activemq.subscriptionName': client}
        )

    incidents = []
    time.sleep(10)
    for i in range(len(listener.result_arr)):
        msg = listener.result_arr[i]
        msg_id = listener.msg_ids[i]
        incidents.append({
            'Name': 'ActiveMQ incident:' + msg_id,
            'rawJSON': msg,
            'details': msg
        })
    demisto.incidents(incidents)

    for msg_id in listener.msg_ids:
        conn.ack(msg_id, subscription_id)


def main():
    client = demisto.params().get('client-id', 'Demisto')

    conn = create_connection(
        client_cert=CLIENT_CERT,
        client_key=CLIENT_KEY,
        root_ca=ROOT_CA
    )

    LOG('command is %s' % (demisto.command(),))

    try:
        if demisto.command() == 'test-module':
            # Test connectivity
            if demisto.params().get('isFetch'):
                queue_name = demisto.params().get('queue_name')
                topic_name = demisto.params().get('topic-name')

                if not queue_name and not topic_name:
                    raise ValueError('To fetch incidents you must provide either Queue Name or Topic Name')
                elif queue_name and topic_name:
                    raise ValueError('Can\'t provide both Queue Name and Topic name.')

            connect(conn)
            demisto.results('ok')

        elif demisto.command() == 'activemq-send':
            connect(conn)
            send_message(conn)

        elif demisto.command() == 'activemq-subscribe':
            subscription_id = demisto.args().get('subscription-id')
            topic_name = demisto.args().get('topic-name')
            queue_name = demisto.args().get('queue-name')

            connect(conn, client)
            subscribe(client, conn, subscription_id, topic_name, queue_name)

        elif demisto.command() == 'fetch-incidents':
            subscription_id = demisto.params().get('subscription-id')
            queue_name = demisto.params().get('queue_name')
            topic_name = demisto.params().get('topic-name')

            connect(conn, client)
            fetch_incidents(client, conn, subscription_id, queue_name, topic_name)

    except Exception as e:
        demisto.error(traceback.format_exc())
        if demisto.command() == 'fetch-incidents':
            raise

        return_error(str(e))

    finally:
        conn.disconnect()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
