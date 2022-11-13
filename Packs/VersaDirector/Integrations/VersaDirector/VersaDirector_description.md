# Versa Director

### Versa Director Authentication flow:
**Versa Director Integration can work in 2 authentication modes: Basic or Auth Token.**

#### Basic Authentication:
Basic authentication method based on Username and Password parameters.

**To use this method:**

Enter required `Username` and `Password` parameters in the Versa Director instance configuration.

#### Auth Token:
`Client ID`, `Client Secret` and `Auth Token` will be required in the integration instance configuration.

**To use this method:**

1. run `vd-auth-start` command.

2. If command was successful, a message will display in War Room with `Client ID` and `Client Secret` values, copy both values.

3. Run `vd-auth-complete` with `Client ID` and `Client Secret` values as arguments.

4. If command was successful, a message will display in War Room with `Auth Token` value, copy this value.

5. In the instance configuration, add `Auth Token`, `Client ID` and `Client Secret` in their corresponding parameters.

6. Make sure that `Use Auth Token` checkbox is checked.
