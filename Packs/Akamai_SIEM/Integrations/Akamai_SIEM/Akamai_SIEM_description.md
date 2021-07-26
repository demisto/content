[Akamai’s security](https://www.akamai.com/us/en/products/security/) solutions provide protection for your websites, applications, APIs, and users.
## API keys generating steps
1. [Open Control panel](https://control.akamai.com/) and login with admin account.
2. Open `identity and access management` menu.
3. Create user with assign roles `Manage SIEM` or make sure the admin has rights for manage SIEM.
4. Log in to new account you created in the last step.
5. Open `identity and access management` menu.
6. Create `new api client for me`
7. Assign API key to the relevant users group, and assign on next page `Read/Write` access for `SIEM`.
8. Save configuration and go to API detail you created.
9. Press `new credentials` and download or copy it.
10. Now use the credentials for configure Akamai WAF in Cortex XSOAR.

