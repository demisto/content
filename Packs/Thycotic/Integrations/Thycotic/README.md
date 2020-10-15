Secret Server is the only fully featured Privileged Account Management (PAM) solution available both on premise and in the cloud. It empowers security and IT ops teams to secure and manage all types of privileged accounts and offers the fastest time to value of any PAM solution.
This integration was integrated and tested with version xx of Thycotic
## Configure Thycotic on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Thycotic.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://example.net\) | True |
| credentials | Username | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### thycotic-authenticate-token
***
View access token for session


#### Base Command

`thycotic-authenticate-token`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.authenticate.token | String | Retrived authorization token for access to Thycotic Secret Server | 


#### Command Example
```!thycotic-authenticate-token```

#### Context Example
```json
{
    "Thycotic": {
        "authenticate": "Bearer AgLK0hDZBDCd1U7PCKA6bUTKL72jGLFXlalHtBKfQnh_fnQ9oiILu4Q0CT9AtIFNW5AtgaibGCwhG7JnXntQbDGZz_lp4IZZK-QLOm7pKRotjgvwie-zX0l_Iyth4cmeIqM2iYtzGfaLWB7ivtpThU5XxWl_uvvWGo_eqoUchMxV0AH3pOLUIRh576NesPT7oekAZKxknm6crEMID1rL-fOHGXGRikSCEZo_u9v_ZJjskoqi3NPn8enrs8Ip-bt5svOQdN2LVWmRyD2BPJE3C9jckBwDkuG7Qi8m_LRTjLnMu6ICP_wsT-HmWR980Kb4UNyxlf8_kJpPf5t8jq9vEVggBz2xqzUrxELSXChAjeruKuOZrhlNCMgz9fUavenzinAHsOewoAxvzlrAPnZ-uYrqSAoQmbfz7YJo6CfsLRsor-fGYbyOoAqIanCR353BiNedocpkhH9jBFIzvGtVaP1lcGhxcL8dnKFCXAfuLUVv5Xrv3OrM5kVeadlejX7OH6KfhnTlSUb0q6-xIUZcvTWhRuA0seJuoMi_XzrivMxLY5HJLYH_3W5zWwC2tdUpqRFfG8izyzfG8Q5ngdpz_wq_ZFw3Xtrz-9wNk8npDSBKaaHgKCLCpa92BSJLcHx0pBk"
    }
}
```

#### Human Readable Output

>Access token for current session: Bearer AgLK0hDZBDCd1U7PCKA6bUTKL72jGLFXlalHtBKfQnh_fnQ9oiILu4Q0CT9AtIFNW5AtgaibGCwhG7JnXntQbDGZz_lp4IZZK-QLOm7pKRotjgvwie-zX0l_Iyth4cmeIqM2iYtzGfaLWB7ivtpThU5XxWl_uvvWGo_eqoUchMxV0AH3pOLUIRh576NesPT7oekAZKxknm6crEMID1rL-fOHGXGRikSCEZo_u9v_ZJjskoqi3NPn8enrs8Ip-bt5svOQdN2LVWmRyD2BPJE3C9jckBwDkuG7Qi8m_LRTjLnMu6ICP_wsT-HmWR980Kb4UNyxlf8_kJpPf5t8jq9vEVggBz2xqzUrxELSXChAjeruKuOZrhlNCMgz9fUavenzinAHsOewoAxvzlrAPnZ-uYrqSAoQmbfz7YJo6CfsLRsor-fGYbyOoAqIanCR353BiNedocpkhH9jBFIzvGtVaP1lcGhxcL8dnKFCXAfuLUVv5Xrv3OrM5kVeadlejX7OH6KfhnTlSUb0q6-xIUZcvTWhRuA0seJuoMi_XzrivMxLY5HJLYH_3W5zWwC2tdUpqRFfG8izyzfG8Q5ngdpz_wq_ZFw3Xtrz-9wNk8npDSBKaaHgKCLCpa92BSJLcHx0pBk

### thycotic-secret-password-get
***
Retrieve password from secret


#### Base Command

`thycotic-secret-password-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.secret.secret_password | String | Retrived password from secret  | 


#### Command Example
```!thycotic-secret-password-get secret_id=10366```

#### Context Example
```json
{
    "Thycotic": {
        "secret": "test1234567890"
    }
}
```

#### Human Readable Output

>Retrieved password by ID 10366 test1234567890

### thycotic-secret-username-get
***
Retrieved username from secret


#### Base Command

`thycotic-secret-username-get`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| secret_id | ID secret | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Thycotic.secret.secret_username | String | Retrived username from secret. | 


#### Command Example
```!thycotic-secret-username-get secret_id=10366```

#### Context Example
```json
{
    "Thycotic": {
        "secret": "andy"
    }
}
```

#### Human Readable Output

>Retrieved username by ID 10366 andy
