## CrowdStrike Malquery
- Use the MalQuery API to query the contents of over a half-billion binary files, both clean and malicious, that are part of Falcon MalQuery's corpus.

### Creating an API client
You must have the Falcon Administrator role to view, create, or modify API clients or keys. However, you can only see an API client's secret when you create or reset the secret.
1. Sign in to the Falcon console
2. Go to Support > API Clients and Keys
3. Click ***Add new API client***
4. Enter a descriptive ***Client name*** that identifies your API client in Falcon and in API action logs
5. Select one or more API scopes
6. Click Add

***Tip***: Record your API client secret somewhere safe. For security purposes, it's only shown when you create or reset the API client. If you lose your secret, you must reset it, which cuts off access for any integrations that still use the previous secret.