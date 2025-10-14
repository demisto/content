Collects DocuSign Customer Events and User Data for Cortex XSIAM.

### Customer Events API

The DocuSign Monitor API provides access to customer events, which are events that occur in your DocuSign account.  

### User Data API

The DocuSign Admin API provides access to user data, which is information about users in your DocuSign account.  

---

## Go-Live - Customer events data type

When you are ready to launch your app in production, you will need to promote your application’s integration key from your developer account to a production Docusign account by passing a Go-Live review, similar to the [Go-Live](https://developers.docusign.com/docs/esign-rest-api/go-live/) process for the eSignature REST API.

Before you can begin the Go-Live process, you must have:

- A paid production Docusign account with a plan that includes Docusign Monitor
- Made at least 20 consecutive successful test eSignature API requests in the developer environment

**The 20 successful requests must be [eSignature REST API](https://developers.docusign.com/docs/esign-rest-api/reference/) requests, not Monitor API requests.**

When you are ready to start Go-Live review for your application, follow the steps described on the [Go-Live](https://developers.docusign.com/docs/esign-rest-api/go-live/) overview page for the Docusign eSignature REST API.

> **Note:** If your application fails Go-Live review, you may be required to bring it into compliance with the [Rules and resource limits](https://developers.docusign.com/docs/esign-rest-api/esign101/rules-and-limits/) before you can Go-Live.

After the form is processed (which takes up to three business days), your integration key will be copied into production, enabling your app to call the production API endpoints.

---

## API Endpoints

The developer and production endpoints for most Docusign APIs use slightly different paths.  
This table lists the endpoint base paths for each Docusign environment so you know how to modify your code when you migrate from the developer environment to production.

| Environment | API base URI | Web Site Login URL |
|-------------|--------------|--------------------|
| Developer   | `https://lens-d.docusign.net/api/v2.0/datasets/monitor/..` | `https://account-d.docusign.com` |
| Production  | `https://lens.docusign.net/api/v2.0/datasets/monitor/...` | `https://{server}.docusign.net/` |

> **Note:** To access production API endpoints, you will need to enable your integration key in the production environment. See [Go-Live](https://developers.docusign.com/platform/go-live/) for more information.

---

## Go-Live - User data type

Before you can begin the Go-Live process for an app that uses the Admin API, you must have:
- Admin API access added to your account  
- Made at least 20 consecutive successful test eSignature API requests in the developer environment

**The 20 successful requests must be API Reference requests, not Admin API requests.**

When you are ready to start a Go-Live review for your application, follow the steps described on the Go-Live overview page for Docusign eSignature.

> **Note:** If your application fails Go-Live review, you may be required to bring it into compliance with the API Rules and resource limits before you can Go-Live.

After the form is processed, your integration key will be copied into your production account, enabling your app to call production Admin API endpoints.  
Note that although your key is copied over, you must configure it with all required values in the production environment separately; configuration settings are not copied automatically.

---

## API Endpoints

The developer and production endpoints for the Admin API use slightly different paths.  
The examples in the how-to section use the developer paths; this table shows the production version of the base path.

| Environment | Admin API base URI | eSignature API base URI |
|-------------|---------------------|--------------------------|
| Developer   | `https://api-d.docusign.net/management/` | `https://demo.docusign.net/` |
| Production  | `https://api.docusign.net/management/`   | `https://{server}.docusign.net/` |
