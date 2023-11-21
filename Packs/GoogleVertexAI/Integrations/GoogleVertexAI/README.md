# Google Vertex AI

## Integration Author: Sameh El-Hakim
***
Fine-tuned to conduct natural conversation. Using Google Vertex Ai (PaLM API for Chat)

The current integration of Google Vertex Ai is focusing only on the Generative AI model (PaLM) using the Chat prediction.

Later, this plugin will be updated to include the following:
PaLM for Text (Once the New API is released to public from Google will be modified to support quick integration)
Access to Model Garden through Playbooks
Model Development

Once the New API for (PaLM for Chat & Text) is released to the public from Google, then this integration will be modified to support quick integration. This integration is using an early version of Generative AI API from Google. So, you are expected to face some challenges.
***
## The setup steps as following:
1. Create a new project on Google Cloud (Recommended instead of using existing project)
2. Enable Vertex AI API
3. Configure Consent Page
4. Create OAuth Client ID
5. Generate Authentication Code (OAuth Code)
6. Setup XSOAR Instance
7. Testing Command

Last Section will be Troubleshooting; the test button is not working with OAuth2 Method
***
If you have a knowledge of Google Cloud Administration, you can configure the project & API and skip directly to step 2.

## Step 1: Create a new project on Google Cloud

In this step, you will need to have permission to create a new project in your GCP console

1.  Login to GCP Console:
	https://console.cloud.google.com/

2.  Click on Create Project

![CreateProject](https://github.com/xsoar-contrib/content/assets/113604678/83320543-66ca-4932-97f6-af78c4a2f504)

3.  Fill project Name: XSOAR\_VertexAI or any name, then click on Create

![projName1](https://github.com/xsoar-contrib/content/assets/113604678/6fea4018-f168-4755-93f4-064986a7ec25)

4.  Select the new created project
5.  Go to marketplace

![marketplacesearch](https://github.com/xsoar-contrib/content/assets/113604678/9e425f44-4d02-47da-a9b5-cc8d6722eb9d)

6.  Search & Select Vertex AI API

![vertexAPIMarketplace](https://github.com/xsoar-contrib/content/assets/113604678/b8004a0a-cda1-48d7-9298-551fe6e36ede)

7.  Click Enable

![enableVertexAIAPI](https://github.com/xsoar-contrib/content/assets/113604678/865c0241-90bf-42a3-bf66-d8a9d3296d0b)

## Step 2: Configure Consent Page

1.  Click on Configure Consent Screen

![consentScreen](https://github.com/xsoar-contrib/content/assets/113604678/3dd03a43-7bbb-4bd6-ab5e-b0b171e4d22c)

2.  Select Internal as User Type and Click on Create; It is recommended to limit the access to your project scope to Internal users in your organization as later as planned you can build your own Model and fine tune in a confidential environment that is shared publicly

![userType](https://github.com/xsoar-contrib/content/assets/113604678/c42bc46d-6a91-49ca-8fec-c32201eff267)

3.  Fill the App information (Fill only the mandatory fields as below, rest are optional) - Click on Save and Continue

![appInfo](https://github.com/xsoar-contrib/content/assets/113604678/76729fa6-d8a9-42c4-bb67-4c651c580c9b)

4.  Click Add or Remove Scopes; We will add Vertex AI API as part of the project scope; NOTE: Don’t add unnecessary scope as this might reveal other data in the project using the created credential

![AppScope](https://github.com/xsoar-contrib/content/assets/113604678/0c48e8d4-c698-48a8-8915-79944f5689f0)

5.  In current version of this integration, it is only require read only permission in the Scope; Then Click Update

![readOnlyScope](https://github.com/xsoar-contrib/content/assets/113604678/d101b6ee-6091-47df-81a6-bde9f901007a)

After added, it will looks like this screenshot

![finalAppLook](https://github.com/xsoar-contrib/content/assets/113604678/876163ab-1fc4-41d3-a0f6-415114347066)

6.  Click Save and Continue; Now Step 3

## Step 3: Create OAuth Client ID

1.  Go to APIs & Services > Credentials

![credential](https://github.com/xsoar-contrib/content/assets/113604678/40b04603-9a39-4120-8d47-8130b520899e)

2.  Click Create Credentials

![createCredential](https://github.com/xsoar-contrib/content/assets/113604678/ef82f519-6764-4152-834d-da63cd17ac10)

3.  Fill your Credential Information as following

Application Type: Web application

Name: XSOAR-VertexAI

In Authorized redirect URIs: https://oproxy.demisto.ninja/authcode

This one will be easy as a user experience to generate the auth code; Please see Step 4

![authCode](https://github.com/xsoar-contrib/content/assets/113604678/c65133ac-c248-498f-9a06-64955b57f98a)

4.  Copy Client ID & Client secret, we will use them during XSOAR’s instance configurations; Then Click OK

![credentialInfo](https://github.com/xsoar-contrib/content/assets/113604678/28b0e933-16b6-40b0-9b84-e6d7abea6eea)

## Step 4: Generate Authentication Code (OAuth Code)

In this step, we will use the created client ID & secret to generate OAuth Code so, the integration can generate access token for authentication & authorization to Google APIs. For more information about Tokens: please check the following URL from Google:

https://developers.google.com/identity/protocols/oauth2

https://cloud.google.com/docs/authentication/token-types

1.  There are two ways to generate the required URL, you can create an instance of the integration and add all information except for auth code as still we don’t have it

First get the project id by clicking on the project name from top left then it will looks as following:

![projectID](https://github.com/xsoar-contrib/content/assets/113604678/1407671a-ef77-4e1e-aee8-84f18a604479)

2.  Fill the instance information on XSOAR as following:

![instanceInfo](https://github.com/xsoar-contrib/content/assets/113604678/652fb47c-c3dd-43f9-868b-595a5ed2993e)

3.  In XSOAR’s CLI, execute the following command:

!google-vertex-ai-generate-auth-url

4.  Copy the generated authorization url to your browser and go to step 6

![authorizationURL](https://github.com/xsoar-contrib/content/assets/113604678/56156166-5c42-4d92-ac17-d615fc03c303)

5.  You can skip previous configuration and use the following URL after filling the required parameters

URL Format:

https://accounts.google.com/o/oauth2/auth/oauthchooseaccount?scope=https://www.googleapis.com/auth/cloud-platform&access_type=offline&prompt=consent&response_type=code&state=state_parameter_passthrough_value&redirect_uri={REDIRECT_URI}&client_id={CLIENT_ID}

{REDIRECT\_URI) replace it with: https://oproxy.demisto.ninja/authcode

{CLIENT\_ID} replace it with: You Client ID that is generated in step 3

So, final URL should like that:

https://accounts.google.com/o/oauth2/auth/oauthchooseaccount?scope=https://www.googleapis.com/auth/cloud-platform&access_type=offline&prompt=consent&response_type=code&state=state_parameter_passthrough_value&redirect_uri=https://oproxy.demisto.ninja/authcode&client_id=223432736531-aqebta31ip0t35vr07gldb4qj9egj2na.apps.googleusercontent.com

6.  Choose your account or Sign in

![image20](https://github.com/xsoar-contrib/content/assets/113604678/29138ccd-9e9d-4241-aa82-7241e1bfb2f9)

7.  Click on Allow

![allow](https://github.com/xsoar-contrib/content/assets/113604678/04fc9a9f-8cf9-4ac5-a069-8d0f4eb47da7)

8.  It will redirect you to the REDIRECT\_URI domain

https://oproxy.demisto.ninja/authcode

The beauty of using the OProxy is to make it easier for users to copy paste the code instead of using manual way from Browser Address bar in case of using localhost as a redirect uri.

For more information about OProxy from Palo Alto Networks; check the following link:

https://xsoar.pan.dev/docs/reference/articles/o-proxy

9.  Copy the auth code to your configured XSOAR instance; the final look for XSOAR Instance should look like Step 5

## Step 5: Setup XSOAR Instance

This is the final look for how your XSOAR instance will looks like

![instancePreview](https://github.com/xsoar-contrib/content/assets/113604678/2557d407-a0b3-4ff2-9b9f-f71888594934)

## Step 7: Testing (Instance Test button doesn’t work with OAuth2 method)

Now it is time to put the integration in test.

1.  Execute the following command:

!google-vertex-PaLM-chat prompt="Any message"

![commandOutput](https://github.com/xsoar-contrib/content/assets/113604678/ca336c1e-97c9-4d78-aa35-df2a12050367)

***
## Troubleshooting

In case of any failure it will be related to authentication code expired or reset somehow. In that case, you will need to repeat steps of generating a new auth code and adding it to XSOAR. BUT before that most important to reset the cache to the integration as following:

1.  In the instance, click reset integration cache
2.  Save & Exit (Important)

![resetIntegrationCache](https://github.com/xsoar-contrib/content/assets/113604678/cedb9fcc-08ca-4a21-abb6-7c2eb73f3339)

3.  Repeat from step 4 to 7 to generate a new authentication code and configure your instance then test
