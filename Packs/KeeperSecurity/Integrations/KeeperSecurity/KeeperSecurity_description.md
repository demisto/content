# Keeper Security Event Collector

## Authentication

Use basic authentication to communicate with the product. Supply your username and password of the account that you want to use.
To create a new user:

1. Log in in as admin in [Keeper Admin Console](https://keepersecurity.com/console/).
2. Go to the **Admin** panel, found in the left side bar.
3. Press on **Add User**, and complete the registration process.
4. Once the user has been created, press on the **Edit** icon, and in the **User Actions** dropdown, click **Disable 2FA** (2FA is currently not supported).

### Authentication Process

In order to authenticate the configured user, the product uses a device registration process. In order to register a new device that will be used to authenticate the user, follow the following procedures:

1. Run the **!keeper-security-register-start** command.
2. If the account does **not** have a configured device, then an authorization code will be sent to the configured email address.
3. Run the **!keeper-security-register-complete** command with the acquired authorization code. If the account already has a registered device, run the command without supplying any arguments.
4. Run the command **!keeper-security-register-test** to test that everything is working fine.

## Server Regions

Use the URLs for the region that hosts your account:
For more information, see the [Server Config File Options](https://docs.keeper.io/en/v/secrets-manager/commander-cli/commander-installation-setup/configuration#config-file-options)

- US Instance: <https://keepersecurity.com>
- EU Instance: <https://keepersecurity.eu>
- AU Instance: <https://keepersecurity.com.au>
- GOV Instance: <https://govcloud.keepersecurity.us>
- CA Instance: <https://keepersecurity.ca>
- JP Instance: <https://keepersecurity.jp>
