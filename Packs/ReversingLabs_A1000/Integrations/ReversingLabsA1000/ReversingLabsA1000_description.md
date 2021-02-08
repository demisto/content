To generate a token for a given username you can use a simple POST request with the user credentials.
```
curl -X POST --form "username=your-username" --form 'password=your-password' https://a1000-server-name-or-ip/api-token-auth/
```