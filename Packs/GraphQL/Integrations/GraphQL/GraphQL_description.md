### Authentication

The integration supports two optional authentication methods:
1. Basic authentication - using the **Username** and **Password** integration parameters.
2. Token authentication - using the **HTTP Headers** integration parameter.
    For example, if the GraphQL server requires passing a token in the *Authorization* HTTP header, then the parameter should be set as follows:
    `{"Authorization":"TOKEN"}`
