Use SecurityAdvisor integration to coach your end users on cyber security threats they face.
SecurityAdvisor advisor contextual coaching platform allows you to perform targeted coaching to users therefore making them more likely to change their behavior and reduce the number of incidents.
For example, a user whose system is often targeted for malware can be coached with a malware context, a phishing target educated about phishing.
Our training is quick & relevant not more than 5 minutes and has shown to reduce incidents from targeted user by 90% due to better security awareness and hygine.

## Use Cases
---
1. A user is targeted with a phishing attack. Use coach-end-user end user command with this user's email address and "phishing" context to send them a training on Email Phishing.
2. A malware is found on user's machine due to unsafe browsing habbits. Use coach-end-user end user command with this user's email address and "malware" context to send them a training on staying safe online.
3. A user is targeted with ransomware attack. Use coach-end-user end user command with this user's email address and "ransomware" context to send them a training on staying safe online.
4. You can create conditional coaching conditions like send coaching is the user has scored less than 80 in a particular coaching context.

You can add coach-end-user command (see commands below) to any section of your playbook to trigger these notifications.

## Prerequisites
You need an API key for this integration.

1. Log in to www.securityadvisor.io.
2. Navigate to the __My Profile__ section or contact support@securityadvisor.io.

## Configure SecurityAdvisor on Cortex XSOAR

1. Navigate to __Settings__ > __Integrations__ > __Servers & Services__.
2. Search for SecurityAdvisor.
3. Click __Add instance__ to create and configure a new integration instance.
    * __Name__: a textual name for the integration instance.
    * __use system proxy__
    * __trust any certificate__
    * __API Endpoint URL__ = "https://www.securityadvisor.io/
    * __API Key__ = See Prerequisites above to get your API key
4. Click __Test__ to validate the URLs, token, and connection.

## Commands

You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
1. coach-end-user
### 1. Coach an end user
---
Sends a contextual message to a single user. This command takes a user email address as "user" input. This is where the training email is sent.
The "context" input has four predefined settings:
* _malware_: Coach user on malware
* _phishing_: Coach user on phishing
* _ransomware_: Coach user on ransomware
* _spam_: Coach user to avoid spam

##### Base Command

`coach-end-user`
##### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User email address. | Required | 
| context | Coaching context. | Optional | 


##### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| SecurityAdvisor.CoachUser.coaching_date | string | Time when coaching was sent or completed. | 
| SecurityAdvisor.CoachUser.coaching_status | string | User coaching status for context. "Pending" means that coaching has been sent and is pending. "Done" means the user has completed the coaching. | 
| SecurityAdvisor.CoachUser.coaching_score | string | User's coaching score (out of 100). | 
| SecurityAdvisor.CoachUser.context | string | Coaching context. | 

##### Command Example
```coach-end-user user="track@securityadvisor.io" context="phishing"```

##### Context Example
```
{
    "SecurityAdvisor.CoachUser": {
        "coaching_date": "2019-10-04T21:04:19.480425", 
        "coaching_status": "Pending", 
        "coaching_score": "", 
        "user": "track@securityadvisor.io", 
        "context": "phishing", 
        "message": "Coaching Sent"
    }
}
```
### SecurityAdvisorBot says...
|coaching_date|coaching_status|coaching_score|user|context|message|
|---|---|---|---|---|---|
|2019-10-04T21:04:19.480425|Pending||track@securityadvisor.io|phishing|Coaching Sent|
