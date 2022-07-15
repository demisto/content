# Azure AD Identity Protection

Acquire information and perform operations on risks and risky users from Microsoft’s Azure Active Directory Identity Protection using the Microsoft Graph API.

Query Microsoft Graph using Microsoft Graph APIs riskDetection and riskyUsers. These APIs are used to identify suspicious activity and determine the probability that a user has been compromised. 

## Use Cases

Microsoft Graph query examples:
- Get risky users.
- Get a user's risk history.
- Confirm a user as compromised.
- Dismiss a risky user.

## Prerequisites

Make sure to provide the following permissions: 
- `IdentityRiskEvent.Read.All`
- `IdentityRiskyUser.ReadWrite.All` - used to update user status, for example by calling the !azure-ad-identity-protection-risky-user-confirm-compromised command.
- `User.Read`

## Authorization

To connect to the Azure Active Directory Identity Protection using either Cortex XSOAR Azure application or the Self-Deployed Azure application:

1. Fill in the required parameters (application ID and script ID).

2. Run the ***!azure-ad-auth-start*** command. The results are a website URL and one time use code.
3. Copy and paste the URL into a browser and enter the code.
4. Log in to Microsoft.
5. Run the ***!azure-ad-auth-complete command***.
6. At the end of the process, a confirmation message appears.


## Requirements

You need an Azure AD Premium P1 or P2 license to access the riskDetection API (note: P1 licenses receive limited risk information). The riskyUsers API is only available to Azure AD Premium P2 licenses only.

## Other Information

The Microsoft API is beta, which lets you implement and test pre-release software. Since it is beta, it might contain bugs. Updates during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

For more information, see https://docs.microsoft.com/en-us/graph/api/resources/identityprotectionroot?view=graph-rest-1.0.


