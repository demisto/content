# CertStream Integration

## Overview

CertStream is a service that provides real-time certificate transparency log updates. This integration allows ingesting CertStream data into our platform to detect new domain certificates in real-time.

## Usage

The integration connects to the CertStream public API server and watch the certificate transparency log.

New TLS certificates are detected from the stream and checked against configured domain names (in the homograph list). Any matches generate an alert containing the certificate details.

## Troubleshooting

Ensure network connectivity that the public CertStream API server is up and running.

<https://certstream.calidog.io/>