Use this integration to collect events automatically from RunZero.
You can also use the ***runzero-get-events*** command to manually collect events.

## API Key
To get an API key, import the following **CURL** to **POSTMAN**, or run it in **Terminal**.
Please replace <customer_id> and <customer_secret> with valid values from RunZero.
`curl --location --request POST 'https://console.runzero.com/api/v1.0/account/api/token' \
--form 'grant_type="client_credentials"' \
--form 'client_id="<customer_id>"' \
--form 'client_secret="<customer_secret>'`
