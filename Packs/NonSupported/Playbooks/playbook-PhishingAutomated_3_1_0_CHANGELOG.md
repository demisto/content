## [Unreleased]


## [20.5.0] - 2020-05-12
#### New Playbook
Deprecated: We recommend using Phishing investigation - Generic playbook instead.
This is an automated playbook to investigate suspected Phishing attempts.
It picks up the required information from the incident metadata as created by the mail listener.
Labels:
- Email/from: Email address of the user targeted by the suspected phishing attempt, who reported the email by forwarding it
- Email: the to recipients
- Email/cc: the cc recipients
- Email/format: the format of the email - text / html / etc.
- Email/html: the html body
- Email/text: the text body
- Email/subject: subject of the email
- Email/attachments: list of attachments
- Email/headers: the headers for the email