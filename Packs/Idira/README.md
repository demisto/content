<~XSIAM>

## What does this pack do?

The **Idira** pack lets you trigger identity (workforce) response actions in the Idira Identity Security Platform as part of a detection-to-containment playbook. From an incident or automation you can:

* Resolve a username to its Idira Identity user unique ID.
* Lock, disable, or unlock a user account.
* Force logout of all of a user's active sessions and cookies.
* Expire a user's password, requiring a reset at next login.
* Remove one or more users from a privileged role.

## This pack includes

* The **Idira Identity Response** integration, which authenticates to the Idira Identity Security Platform Shared Services (ISPSS) using the OAuth 2.0 client-credentials flow and calls the Identity workforce APIs to run containment actions.

## Authentication

The integration requests a Bearer token from `https://<tenant>.id.cyberark.cloud/oauth2/platformtoken` using the OAuth 2.0 **client-credentials** flow and sends it on every Identity API call. Identity workforce actions require a service user with **system-administrator** or **user-management** rights.

Complete the service-user setup in Identity Administration before configuring the integration instance. See the **Idira Identity Response** integration description for the full step-by-step configuration.

***

For more information, see the [Idira Identity Response](Integrations/IdiraIdentityResponse/README.md) integration documentation.

</~XSIAM>
