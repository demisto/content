LDAP-Query Integration

The LDAP-Query Integration allows seamless interaction with LDAP servers, enabling users to query and authenticate LDAP entries using various identifiers such as Common Name (CN) and User ID (UID). This integration supports querying functionalities for LDAP servers, including fetching detailed user information.
Features

    LDAP Authentication: Authenticate users against an LDAP server using their credentials.
    Query by CN or UID: Retrieve LDAP entries based on the Common Name (CN) or User ID (UID).
    Attribute Filtering: Optionally retrieve specific attributes of LDAP entries.

Configuration

To configure the LDAP-Query integration:

    Navigate to the Integrations page.
    Click on Add instance to create a new LDAP-Query instance.
    Fill in the following parameters:
        Host: The LDAP server hostname or IP address.
        Port: The LDAP server port (default is 389 for non-SSL/TLS and 636 for SSL/TLS).
        Base DN: The base distinguished name to use for LDAP queries.
        Connection Type: The connection type (None, SSL, or Start TLS).
        SSL Version: The SSL/TLS version to use (optional).
        Insecure: Disable SSL certificate verification if set to true.
        Page Size: The page size for paged search results.
        Credentials: The username and password for LDAP authentication.

Commands

The following commands are available in the LDAP-Query integration:
1. ldap-query

Query LDAP entries based on the Common Name (CN) or User ID (UID) and optionally retrieve a specific attribute.

Arguments:

    cn (optional): The Common Name to query.
    uid (optional): The User ID to query.
    attribute (optional): The specific attribute to retrieve. If not specified, all attributes will be returned.

Usage Examples:
!ldap-query cn="John Doe" attribute="mail"
!ldap-query uid="jdoe" attribute="telephoneNumber"
!ldap-query cn="John Doe"
!ldap-query uid="jdoe"
Testing the Integration

To test the LDAP-Query integration, use the test-module command which verifies the connection and authentication to the LDAP server.

Usage Example:
!test-module

If successful, the command returns "ok".
Conclusion

The LDAP-Query integration provides a robust interface for interacting with LDAP servers, making it easier to manage and query LDAP entries within your environment. Ensure that the correct parameters are configured to enable seamless LDAP queries and authentication.
