## [Unreleased]
Improved error handling.


## [20.4.0] - 2020-04-14
  - Set the listener host to 0.0.0.0 in order to handle IPv6.
  - Fixed an issue where the email address of the message sender was not handled properly.

## [20.3.4] - 2020-03-30
 - Added the ***microsoft-teams-ring-user*** command.
   - To user this functionality add Calls.Initiate.All and Calls.InitiateGroupCall.All premissions to your configured Teams Bot.
   - For more information see the [Microsoft Teams Documentation](https://docs.microsoft.com/en-us/microsoftteams/platform/bots/calls-and-meetings/registering-calling-bot#add-microsoft-graph-permissions) on this subject.
 - Deprecated ***add-user-to-channel*** and ***create-channel*** - Use ***microsoft-teams-add-user-to-channel*** and ***microsoft-teams-create-channel*** instead. 

## [20.1.2] - 2020-01-22
Added the ability to mention users in the ***send-notification*** command.
Added 2 commands.
  - ***add-user-to-channel***
  - ***create-channel***

## [19.10.0] - 2019-10-03
  - Added support for single port mapping.
  - Added the ***microsoft-teams-integration-health*** command.

## [19.9.1] - 2019-09-18
  - Added verification for the authorization header signature.
  - Added support for HTTPS.

## [19.9.0] - 2019-09-04
  - Added the *channel_name* argument to the ***mirror-investigation***, which enables mirroring to a channel with a custom channel name.
  - Added a message that is sent to a channel that is opened as part of the mirror investigation process.
  - Improved messages returned from the bot in direct messages.
  - Improved error handling for HTTP errors returned from Microsoft Bot Framework API.
  
## [19.8.2] - 2019-08-22
#### New Integration
Send messages and notifications to your team members.
