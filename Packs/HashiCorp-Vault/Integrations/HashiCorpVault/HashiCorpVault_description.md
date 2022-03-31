### Authentication
The integration supports the following auth methods:
#### Userpass Auth Method
It is required to fill in only the *Username / Role ID* parameter with the username and *Password / Secret ID* parameter with the password.
For more details, see the [HashiCorp Vault documentation](https://www.vaultproject.io/docs/auth/userpass).
#### Token Auth Method
It is required to fill in only the *Authentication token* parameter.
For more details, see the [HashiCorp Vault documentation](https://www.vaultproject.io/docs/auth/token).
#### AppRole Auth Method
It is required to fill in only the *Username / Role ID* parameter with the role ID and *Password / Secret ID* parameter with the secret ID, and tick the *Use AppRole Auth Method* checkbox.
For more details, see the [HashiCorp Vault documentation](https://www.vaultproject.io/docs/auth/approle).