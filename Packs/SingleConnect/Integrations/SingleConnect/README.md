Kron PAM is a PAM product that enables enterprises to remove static passwords stored in applications by instead keeping passwords in a secure password vault. Kron PAM provides a token-based authentication for 3rd party applications when accessing the password vault. This authentication process verifies the application identity and gives secure access to the password associated with that identity.

## What does this pack do?

This integration provides the following commands for Password Vault:

* List all Password Vault accounts (kron-pam-vault-account-list-all)
* Show password for a Password Vault account (kron-pam-vault-account-show-password)
* List Password Vault accounts of a specific device (kron-pam-device-list-vault-accounts)
* Search Password Vault accounts by secret name (kron-pam-vault-account-search-with-secret-name)

The `single-connect-*` commands from earlier versions are deprecated and no longer run. Use the `kron-pam-*` commands above instead.
