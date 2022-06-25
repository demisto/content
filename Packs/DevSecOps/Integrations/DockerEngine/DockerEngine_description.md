## Docker Engine
Docker Engine is an open source containerization technology for building and containerizing your applications. Docker Engine acts as a client-server application with:

- A server with a long-running daemon process dockerd.
- APIs which specify interfaces that programs can use to talk to and instruct the Docker daemon.
- A command line interface (CLI) client docker.

The CLI uses Docker APIs to control or interact with the Docker daemon through scripting or direct CLI commands. Many other Docker applications use the underlying API and CLI. The daemon creates and manage Docker objects, such as images, containers, networks, and volumes.

## Requirements
By default, Docker runs through a non-networked UNIX socket. It can also optionally communicate using an HTTP socket. This integration manages a Docker Server that has had it's Docker daemon API interface exposed over HTTPS.

Refer to the [Docker documentation](https://docs.docker.com/engine/security/protect-access/#use-tls-https-to-protect-the-docker-daemon-socket) for how to configure Docker server to securely accept HTTPS connections.

To use this integration you need:
1. The Docker server to be running in TLS (HTTPS) mode
2. Have generated a certificate for this integration to act as a Docker Client authorised to manage this server

The integration takes the client certificate, private key, and CA's certificate as paramaters. These three are expected in the PEM format.

If a CA cert is not provided, the Docker server certificate will be validated using the public CA's included in [Python Requests](https://pypi.org/project/requests/)