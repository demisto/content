## Configuration without SSL

1. Confirm that your Kafka configuration supports no client authentication: 
   * 'ssl.client.auth' does not equal 'required'
   * Make sure you have the broker port '<port>' which supports non-SSL connection
2. Add '<broker_address>:<port>' to the brokers list.
3. Confirm the 'Use TLS for connection' flag is unchecked.

## Configuration with SSL

1. Make sure you have the broker port '<port>' which supports SSL connection.
2. Add '<broker_address>:<port>' to the brokers list.
3. Check the 'Use TLS for connection' flag.
4. Provide the CA root certificate in the 'CA certificate of Kafka server (.cer)' section.
5. Provide the client certificate in the 'Client certificate (.cer)' section.
6. Provide the client certificate key in the 'Client certificate key (.key)' section.
7. If your client certificate is password protected, provide the password in the 'Client certificate key password (if required)' section.

## Configuration of SASL_SSL PLAIN:
1. Make sure you have the broker port '<port>' which supports SSL connection.
2. Add '<broker_address>:<port>' to the brokers list.
3. Provide the CA root certificate in the 'CA certificate of Kafka server (.cer)' section.
4. If your client certificate is password protected, provide the password in the 'Client certificate key password (if required)' section.
5. Provide SASL PLAIN Username and SASL PLAIN Password

Note: SASL is supported only when used in combination with SSL.

Important:
This integration also supports users with consumer only permissions.