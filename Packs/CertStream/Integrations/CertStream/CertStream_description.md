# CertStream Integration

## Overview

CertStream is a service that provides real-time certificate transparency log updates. This integration allows ingesting CertStream data into our platform to detect new domain certificates in real-time.

## Prerequisites

Before using the `Certstream` integration, ensure that you have completed the following steps:

1. **Create Domain's Homographs List**: Run the `Create list for PTH` playbook in the playground to generate a list of domains and their homographs or create the list manually with the expected format: 

```json
{
  "domain1": [
    "domain1_homograph1",
    "domain1_homograph2",
    "domain1_homograph2"
  ],
  "domain2": [
    "domain2_homograph1",
    "domain2_homograph2",
    "domain2_homograph3"
  ]
}
```

After the list is created in the valid format, proceed with configuring integration instance.

## Usage

The integration connects to the CertStream public API server and watch the certificate transparency log.

New TLS certificates are detected from the stream and checked against configured domain names (in the homograph list). Any matches generate an alert containing the certificate details.

## Troubleshooting

Ensure network connectivity that the public CertStream API server is up and running.

<https://certstream.calidog.io/>