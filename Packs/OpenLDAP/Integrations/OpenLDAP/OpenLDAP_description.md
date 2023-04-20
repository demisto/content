## Overview

This integration enables using your OpenLDAP or Active Directory user authentication settings in Cortex XSOAR. Users can log in to Cortex XSOAR with their OpenLDAP or Active Directory username and passwords, and their permissions in Cortex XSOAR will be set according to the groups and mapping set in AD Roles Mapping.  

* For connecting to the LDAP server with TLS connection it is recommended to use this integration instead of the server integration
**Active Directory Authentication**.

## Use Cases

Use OpenLDAP or Active Directory user authentication groups to set user roles in Cortex XSOAR.


## Configure OpenLDAP on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for 'LDAP Authentication' ('OpenLDAP' or 'Active Directory Authentication' should work as well).
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __LDAP Server Vendor (OpenLDAP or Active Directory)__
    * __Server IP or Host Name (e.g., 192.168.0.1)__
    * __Port. If not specified, default port is 389, or 636 for LDAPS.__
    * __User DN (e.g cn=admin,ou=users,dc=domain,dc=com)__
    * __Base DN (e.g. DC=domain,DC=com)__
    * __Auto populate groups__
    * __Groups Object Class__
    * __Groups Unique Identifier Attribute__
    * __Group Membership Identifier Attribute__
    * __User Object Class__
    * __User Unique Identifier Attribute__
    * __Page size__
    * __Connection Type (None, SSL or Start TLS)__
    * __SSL Version (None, TLS, TLSv1, TLSv1_1, TLSv1_2, TLS_CLIENT)__
     (The SSL\TLS version to use in SSL or Start TLS connections types. It is recommended to select the TLS_CLIENT option, which auto-negotiate the highest protocol version that both the client and server support, and configure the context client-side connections. For more information please see: [ssl.PROTOCOLS](https://docs.python.org/3/library/ssl.html#ssl.PROTOCOL_TLS_CLIENT)).
    * __Trust any certificate (not secure)__
    * __Use system proxy settings__
4. Click __Test__ to validate the URLs, token, and connection.