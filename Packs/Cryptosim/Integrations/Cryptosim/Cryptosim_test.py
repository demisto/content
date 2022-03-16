import base64
import Cryptosim
from Cryptosim import Client, correlation_alerts_command, correlations_command, fecth_incidents


authorization = "admin:admin"
auth_byte= authorization.encode('utf-8')
base64_byte = base64.b64encode(auth_byte)
base64_auth = base64_byte.decode('utf-8')
authValue = "Basic " + base64_auth 

test_client = Client(
    server='https://127.0.0.1',
    verify=False,
    proxy=False,
    headers = {
        "Content-Type": "application/json",
        'Authorization': authValue
    }
)

def test_correlations_command(client):

    results = correlations_command(client)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'Correlations'



def test_correlation_alerts_command(client):

    results = correlation_alerts_command(client)
    assert results.outputs.keys() == ['StatusCode', 'Data', 'OutParameters']
    assert results.outputs_prefix == 'Correlations'

def test_fetch_incidents(client):

    next_run, incidents = fecth_incidents(client)
    assert next_run == {"lastRun": "2018-10-24T14:13:20+00:00"}
    assert isinstance(incidents, list)