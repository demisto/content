## Google Chat Integration Help

In order to use this integration, you need to enter your Zoom credentials in the relevant integration instance parameters.

### Redirect user's response to Xsoar

Navigate to [here](https://console.cloud.google.com/apis/credentials) > click on the button +CREATE CREDENTIALS > OAuth client ID > under Authorized redirect URIs insert your Xsoar url

### Space ID param

Go to Google Chat and log in with your Google account [here](https://chat.google.com) > Enter on the required space > display the url (e.g https://mail.google.com/chat/u/0/#chat/space/123456) > the ID after the space is the space ID (e.g 123456)

### Space Key param

Navigate to [here](https://console.cloud.google.com/apis/credentials) > click on the button +CREATE CREDENTIALS > API KEY > copy the created key

### Space Token param

Navigate to [here](https://console.cloud.google.com/apis/credentials) > click on the button +CREATE CREDENTIALS > Service Accounts > create your service account 

### Add permission to access the API

- Navigate to [here](https://console.cloud.google.com/apis/credentials/consent) > choose the user type > go to scope section > ADD OR REMOVE SCOPES > add all endpoints related to Google Chat API
- Navigate to [here](https://console.cloud.google.com/apis/credentials) > under the Service Accounts download the credentials json and follow the following steps:
    - Make sure to pip install requests, pip install PyJWT
    - Use this script to generate an access token (fill the relevant in with the personal credentials):
    ```
        import requests
        import time
        import jwt 

        def create_access_token(service_account_info, scopes):
            # Prepare JWT payload
            now = int(time.time())
            header = {
                "alg": "RS256",
                "typ": "JWT",
                "kid": service_account_info["private_key_id"]
            }
            payload = {
                "iss": service_account_info["client_email"],
                "sub": service_account_info["client_email"],
                "aud": service_account_info["token_uri"],
                "iat": now,
                "exp": now + 3600,  # Token valid for 1 hour
                "scope": " ".join(scopes)
            }

            # Sign JWT with private key
            signed_jwt = jwt.encode(payload, service_account_info["private_key"], algorithm="RS256", headers=header)

            # Request access token
            response = requests.post(
                service_account_info["token_uri"],
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                data={
                    "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                    "assertion": signed_jwt
                }
            )

            response_data = response.json()
            if response.status_code != 200:
                raise Exception(f"Error fetching access token: {response_data}")

            return response_data["access_token"]

        # Replace these variables with your actual values
        service_account_info = {
            "type": "service_account",
            "project_id": "YOUR_PROJECT_ID",
            "private_key_id": "YOUR_PRIVATE_KEY_ID",
            "private_key": "YOUR_PRIVATE_KEY",
            "client_email": "YOUR_CLIENT_EMAIL",
            "client_id": "YOUR_CLIENT_ID",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "YOUR_CERT_URL"
        }
        scopes = ["https://www.googleapis.com/auth/chat.bot"]

        access_token = create_access_token(service_account_info, scopes)
        print(f"Access Token: {access_token}")
    ```
    - Copy the access token under space token