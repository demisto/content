## Retrieve Your API ID and Secret

1. Log in to the Censys console as the user for which you want to get the credentials from.
2. Click the username in the upper-right corner.
3. Under *My Account*, click the API tab.
4. Under *API Credentials* copy your **API ID** and the **Secret** and paste it to the integration configuration.
   
## Rate limit

Censys rate limits to 10 queries a day per IP for unauthenticated clients, and variable numbers per day depending on your pricing tier. <https://search.censys.io/subscriptions>

## IP reputation command

Censys API provides reputation data exclusively to paying customers. When set to True, the integration will use labels to determinate reputation on IPs.
