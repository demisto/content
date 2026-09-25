# PingFederate (Ping Identity)

<~XSIAM>

## Overview

PingFederate is the Ping Identity federation server that provides single sign-on (SSO), single logout (SLO), federated identity and API security using SAML, WS-Federation and OAuth/OpenID Connect.

## What does this pack contain?

- Modeling Rules for the PingFederate audit log.

## Supported Event Types

The modeling rule maps the PingFederate audit log events that are written in CEF format:

| **Event** | **Description** |
| --- | --- |
| AUTHN_ATTEMPT | Authentication attempt. |
| AUTHN_SESSION_CREATED | Authentication session created. |
| AUTHN_SESSION_USED | Existing authentication session used. |
| AUTHN_SESSIONS_DELETED | Authentication sessions deleted. |
| SSO | Single sign-on. |
| SLO | Single logout. |
| SRI_REVOKED | Session revocation index entry revoked. |
| OAuth | OAuth token request. |

## Collect Events from PingFederate

To collect the PingFederate audit log, configure PingFederate to write the audit log in CEF format and forward it to Cortex using a Broker VM.

### Configure PingFederate to Write the Audit Log in CEF

1. On the PingFederate server, open `<pf_install>/pingfederate/server/default/conf/log4j2.xml`.
2. Enable the `SecurityAudit2CEF` appender (the CEF audit log appender) and make sure it is referenced by the `org.sourceid.websso.profiles.**.**.SecurityAudit` logger.
3. Verify that the audit log pattern includes at least the `rt`, `msg`, `src`, `duid`, `dvchost`, `externalId` and `cs1`-`cs6` fields together with their `cs1Label`-`cs6Label` labels.
4. Restart the PingFederate service.

### Broker VM

To create or configure the Broker VM, see the [Broker VM](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSIAM/Cortex-XSIAM-Documentation/Broker-VM) documentation.

Follow these steps to configure the Broker VM to receive the PingFederate audit log:

1. Navigate to **Settings** > **Configuration** > **Data Broker** > **Broker VMs**.
2. Go to the **APPS** column under the **Brokers** tab and add the **Syslog Collector** app for the relevant broker instance. If the app already exists, hover over it and click **Configure**.
3. Click **Add New** to add a new syslog data source.
4. When configuring the new syslog data source, set the following parameters:

   | Parameter | Value |
   | :--- | :--- |
   | `Vendor` | Enter **Ping Identity**. |
   | `Product` | Enter **PingFederate**. |
   | `Protocol` | Select the protocol used to forward the log (**UDP**, **TCP** or **Secure TCP**). |
   | `Format` | Select **CEF**. |
   | `Port` | Enter the port on which the broker listens for the PingFederate log. |

</~XSIAM>
