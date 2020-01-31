import demistomock as demisto
from CommonServerPython import *

''' IMPORTS '''

import stomp
import os
import traceback

if not demisto.params()['proxy']:
    del os.environ['HTTP_PROXY']
    del os.environ['HTTPS_PROXY']
    del os.environ['http_proxy']
    del os.environ['https_proxy']

''' GLOBAL VARS '''

HOSTNAME = demisto.params()['hostname']
PORT = int(demisto.params()['port'])
USERNAME = ''
PASSWORD = ''
CLIENT_CERT = demisto.params()['client_cert']
CLIENT_KEY = demisto.params()['client_key']


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


def create_connection():
    client_path = None
    client_key_path = None
    if 'client_cert' in demisto.params():
        client_path = 'client.cert'
        with open(client_path, 'wb') as file:
            file.write(demisto.params()['client_cert'])
            client_path = os.path.abspath(client_path)
    if 'client_key' in demisto.params():
        client_key_path = 'client_key.key'
        with open(client_key_path, 'wb') as file:
            file.write(demisto.params()['client_key'])
    if 'root_ca' in demisto.params():
        root_ca_path = 'root_ca.key'
        with open(root_ca_path, 'wb') as file:
            file.write(demisto.params()['root_ca'])
    conn = stomp.Connection(host_and_ports=[(HOSTNAME, PORT)], use_ssl=True,
                            ssl_key_file=client_key_path, ssl_cert_file=client_path)
    return conn


def connect(conn, client_id=None):
    conn.start()
    if client_id and len(client_id) > 0:
        conn.connect(wait=True)  # , headers = {'client-id': client_id })
    else:
        conn.connect(wait=True)
    return conn


''' FUNCTIONS '''


def send_message(conn):

    txid = conn.begin()
    dest = demisto.args()['destination']
    body = demisto.args()['body']
    headers_demisto = json.loads(demisto.args()['headers'])
    demisto.results(headers_demisto)

    if headers_demisto is None:
        demisto.results("Error 'headers' field is required to send correctly the message to activeMQ queue")
        sys.exit(0)

    conn.send(dest, body, transaction=txid, headers=headers_demisto)
    conn.commit(txid)
    demisto.results('Message sent to ActiveMQ destination: ' + dest + ' with transaction ID: ' + txid)


def subscribe(client, conn):

    listener = MsgListener()
    if client and len(client) > 0:
        conn.set_listener('Demisto', listener)
    subscription_id = demisto.args()['subscription-id']
    topic_name = demisto.args()['topic-name']
    # ack='client-individual', headers={'activemq.subscriptionName': client})
    conn.subscribe('/queue/' + topic_name, subscription_id, ack='auto')
    time.sleep(1)
    for msg in listener.result_arr:
        demisto.results(msg)
    for msg_id in listener.msg_ids:
        conn.ack(msg_id, subscription_id)


def fetch_incidents(client, conn):
    # conn = stomp.Connection(heartbeats=(4000, 4000))
    subscription_id = demisto.params()['subscription-id']
    listener = MsgListener()
    if client and len(client) > 0:
        conn.set_listener('Demisto', listener)
    topic_name = demisto.params()['topic-name']
    # , headers = headersDemisto) #ack='client-individual', headers={'activemq.subscriptionName': client})
    conn.subscribe('/queue/' + topic_name, subscription_id, ack='auto')
    incidents = []
    time.sleep(10)
    for i in range(len(listener.result_arr)):
        msg = listener.result_arr[i]
        msg_id = listener.msg_ids[i]
        incidents.append({
            'Name': 'ActiveMQ incident:' + msg_id,
            '_rawJSON': msg,
            'rawJSON': msg,
            'rawPhase': msg,
            'details': msg
        })
    demisto.incidents(incidents)

    for msg_id in listener.msg_ids:
        conn.ack(msg_id, subscription_id)


def main():
    client = 'Demisto'
    if demisto.get(demisto.params(), 'client-id'):
        client = demisto.params()['client-id']

    conn = create_connection()

    LOG('command is %s' % (demisto.command(),))

    try:
        if demisto.command() == 'test-module':
            # Test connectivity
            connect(conn)
            demisto.results('ok')

        elif demisto.command() == 'activemq-send':
            connect(conn)
            send_message(conn)

        elif demisto.command() == 'activemq-subscribe':
            connect(conn, client)
            subscribe(client, conn)

        elif demisto.command() == 'fetch-incidents':
            connect(conn, client)
            fetch_incidents(client, conn)

    except Exception, e:
        demisto.error(traceback.format_exc())
        return_error(str(e))

    finally:
        conn.disconnect()


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
