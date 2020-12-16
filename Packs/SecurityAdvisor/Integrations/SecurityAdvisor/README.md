Contextual coaching and awareness for end users
This integration was integrated and tested with version xx of SecurityAdvisor

## Configure SecurityAdvisor on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for SecurityAdvisor.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description**                      | **Required** |
| ------------- | ------------------------------------ | ------------ |
| proxy         | Use system proxy settings            | False        |
| insecure      | Trust any certificate \(not secure\) | False        |
| url           | API Endpoint URL                     | True         |
| apikey        | API Key                              | False        |

4. Click **Test** to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.

### coach-end-user

---

sends contextual message to single user

#### Base Command

`coach-end-user`

#### Input

| **Argument Name** | **Description**    | **Required** |
| ----------------- | ------------------ | ------------ |
| user              | user email address | Required     |
| context           | coaching context   | Optional     |

#### Context Output

| **Path**                          | **Type** | **Description**                   |
| --------------------------------- | -------- | --------------------------------- |
| SecurityAdvisor.CoachUser.Message | string   | Response for single user coaching |

#### Command Example

!coach-end-user user="user@organization.com" context="malware"

#### Human Readable Output

| **Coaching_date**           | **Coaching_score**          | **Coaching_Status**           | **context**                               | **meassage** | **user**   |
| --------------------------- | --------------------------- | ----------------------------- | ----------------------------------------- | ------------ | ---------- |
| Date when coaching was sent | score if coaching completed | coaching status: pending/done | context of coaching:malware/phishing/spam | string       | user email |
