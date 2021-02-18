# Authentication
Top Use-Cases:
- Use credentials from authentication vault in order to configure instances in Demisto (Save credentials in: Settings -> Integrations -> Credentials)
* The integration should include the isFetchCredentials Parameter, and other integrations that will use credentials from the vault, should have the ‘Switch to credentials’ option.
- Lock/Delete Account – Give option to lock account (credentials), and unlock/undelete.
- Reset Account - Perform a reset password command for an account.
- List credential names – Do not post the actual credentials. (For example – Credential name: McAfee ePO, do not show actual username and password.)
- Lock Vault – In case of an emergency (if the vault has been compromised), allow the option to lock + unlock the whole vault.

**Authentication Integration Example** – CyberArk AIM
