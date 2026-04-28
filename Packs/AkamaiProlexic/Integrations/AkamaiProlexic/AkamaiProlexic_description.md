## Akamai Prolexic Event Collector

Collects DDoS detection critical events and general events from the
**Akamai Prolexic Analytics API** and forwards them to Cortex XSIAM as the
``akamai_prolexic_raw`` dataset (vendor=``akamai``, product=``prolexic``).

### How to obtain the configuration parameters

You will need an Akamai API client with **read** access to the *Prolexic
Analytics* API and your Prolexic *Contract ID*.

1. In **Akamai Control Center**, open
   **Identity and Access Management** and click **Create API client**.
2. Click **Quick** and then **Download** under *Credentials*. This places an
   ``.edgerc`` file in your home directory.
3. Open the file in a text editor — it will look like:

   ```ini
   [default]
   client_secret = <client-secret>
   host = akab-xxxxxxxxxxxxxxxx-yyyyyyyyyyyyyyyy.luna.akamaiapis.net
   access_token = <access-token>
   client_token = <client-token>
   ```

4. Use the values from the ``.edgerc`` file in this integration's configuration:

   | ``.edgerc`` field | Integration parameter |
   |---|---|
   | ``host``          | **Server URL** (prefixed with ``https://``) |
   | ``client_token``  | **Client Token** |
   | ``client_secret`` | **Client Secret** |
   | ``access_token``  | **Access Token** |

5. Provide your Prolexic **Contract ID** (the policy domain that the events
   belong to).

### Account Switch Key (multi-account customers)

If you manage more than one Akamai account, supply the **Account Switch Key**
parameter to run the operation against a managed account. The Identity and
Access Management API provides the list of available switch keys.

### Rate limits

The Prolexic Analytics API is limited to **1000 requests per hour**. Configure
the *Maximum events per fetch* and the events fetch interval to stay below
that ceiling.