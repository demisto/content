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
* Playbooks that run a single containment action on the issue's user (`${issue.userid}` by default):
  * **Idira - Lock User** - locks the user.
  * **Idira - Unlock User** - reverses a lock or disable.
  * **Idira - All Logout** - ends all of the user's active sessions and cookies.
* Correlation rules that raise alerts on Idira Identity audit events:
  * **Idira - MFA Failure Detected** - a failed or denied MFA challenge.
  * **Idira - Multiple Failed Logins Detected** - 5 or more failed logins for a user from the same source IP within 10 minutes.
  * **Idira - SSH Sudo Command Detected** - a sudo command executed in an SSH session.

### Correlation rules data source

The correlation rules query the `cyberark_isp_raw` dataset, which is not collected by this pack. To use them, install the **CyberArk PAS** pack and configure its CyberArk Identity Security Platform audit event collector. The MFA and failed-login rules rely on the pack's **CyberArkISP** modeling rule.

## Authentication

The integration requests a Bearer token from `https://<tenant>.id.cyberark.cloud/oauth2/platformtoken` using the OAuth 2.0 **client-credentials** flow and sends it on every Identity API call. Identity workforce actions require a service user with **system-administrator** or **user-management** rights.

Complete the service-user setup in Identity Administration before configuring the integration instance. See the **Idira Identity Response** integration description for the full step-by-step configuration.

***

For more information, see the [Idira Identity Response](Integrations/IdiraIdentityResponse/README.md) integration documentation.

</~XSIAM>
