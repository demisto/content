# Release Notes
 
Release Notes tells the user what has changed in the new version of this integration (or any other content object). If the integration is new, simply write something to describe the integration.

## New ReleaseNotes Format

Under the same path of the changed integrtion yml (or name of json file), add a new file with the same name with the suffix of `_changelog.md`.
For example,
- If the changed file is `Integrations/Alexa/Alexa.py` then create `Integrations/Alexa/CHANGELOG.md` with the release notes inside.
- If the changed file is `Integrations/integration-jira.yml` then create `Integrations/integration-jira_CHANGELOG.md` with the release notes inside.
- If the changed file is `Playbooks/playbook-Phishing.yml` then create `Playbooks/playbook-Phishing_CHANGELOG.md` with the release notes inside.

If the file already exists, add another note as a different bullet at the start of the file.

For example, 
```
## [Unreleased]
  - Added 2 new commands:
    - integ-add-indicator
    - integ-delete-indicator
```

should be updated to:
```
## [Unreleased]
  - Logout errors are now ignored.
  - Added 2 new commands:
    - integ-add-indicator
    - integ-delete-indicator
```

Another example where `19.6.2` is an older release version,
```
## [Unreleased]

## [19.6.2] - 2019-06-20
  - Added 2 new commands:
    - integ-add-indicator
    - integ-delete-indicator
```

should be updated to:
```
## [Unreleased]
  - Logout errors are now ignored.

## [19.6.2] - 2019-06-20
  - Added 2 new commands:
    - integ-add-indicator
    - integ-delete-indicator
```
