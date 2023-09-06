## Fortanix Data Security Manager
Fortanix Data Security Manager (DSM) is a unified platform powered by Confidential Computing that delivers a wide-range of data security services, including encryption, multi-cloud key management, tokenization, TDE and multiple other capabilities from one single console.

This pack provides access to Fortanix DSM secrets, keys, and plugins. Configure multiple integration instances if you need to access to different DSM Applications.

Before you can use this Fortanix DSM integration you need to perform several configuration steps in your Fortanix DSM Account. Make sure there is a DSM Group and a DSM App existing in the Group. Obtain the authentication credentials for the DSM App, which may be either an API Key, an username and password, or the client certificate and corresponding private key for mutual TLS authentication.

### Authentication
The integration supports the following auth methods:

#### Username/password or Client Certificate Auth Method
These fields accept  the *Username*  and *Password* parameters for a DSM App. These credentials may also be used for mutual TLS using a client key and certificate. The certificate may be signed by a Trusted Private or Public CA if Fortanix DSM is configured accordingly.

#### API KEY Auth Method
An easy and quick way to test the integration is to specify the *Basic Authentication token* parameter from the Fortanix DSM App's API Key.

For detailed instructions, see the [Fortanix DSM App Authenticate User Guide](https://support.fortanix.com/hc/en-us/articles/360033272171-User-s-Guide-Authentication).
