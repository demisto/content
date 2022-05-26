## RemoteAccess v2

This integration enables Cortex XSOAR to access and run commands on a terminal in a remote location (via SSH).

### Ciphers
When ciphers are specified, the SSH connection will be established with the first cipher of the specified ciphers that the given host supports.

### Key Algorithms
When key algorithms are specified, the SSH connection will be established with the first key algorithm of the specified key algorithms that the given host supports.

### SSH Certificate
Currently, OpenSSH keys are not supported. Only RSA keys (.PEM files) are supported.
In order to create an RSA based key with ssh-keygen, use **ssh-keygen -p -m PEM -f <file_name>**.
In case access is required to an instance in the cloud, use the PEM file provided by the cloud provider.