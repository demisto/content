# Change Logs
A change log file helps to keep track on the changes made for a specific content entity like an integration or a playbook.

# Naming
Under the same path of the changed content entity add a new file:
 - In case of a package, file name is `CHANGELOG.md`.
 - otherwise, file name has the same base name with the suffix of `_CHANGELOG.md`.

For example,
- If the changed file is `Integrations/Alexa/Alexa.py` then create `Integrations/Alexa/CHANGELOG.md` with the release notes inside.
- If the changed file is `Integrations/integration-jira.yml` then create `Integrations/integration-jira_CHANGELOG.md` with the release notes inside.
- If the changed file is `Playbooks/playbook-Phishing.yml` then create `Playbooks/playbook-Phishing_CHANGELOG.md` with the release notes inside.


# Format
The change log file should be in a descendant order of release sections.

The first section of the file will always be the `Unreleased` changes.
All other sections should start with a header containing the release version and published date:
```## [19.8.0] - 2019-08-06```

each change should be added at the start of the `Unreleased` section as an independed bullet.

For example,
```
## [Unreleased]


## [19.8.0] - 2019-08-06
  - Fixed an issue with the *description* argument in the ***threatstream-create-model*** command.


## [19.6.1] - 2019-06-25
#### New Integration
Use the Anomali ThreatStream V2 integration to query and submit threats.

```
## MD Formatting
For single line RNs, follow this format:
```
## [Unreleased]
Release note here.
```

For single line RNs with a nested list, follow this format:
```
## [Unreleased]
Release note here.
  - List item 1
  - List item 2
```

For multiple line RNs (or appending to existing RN), follow this format:
```
## [Unreleased]
  - Release note 1 here.
  - Release note 2 here.
  - Release note 2 here.
```

For multiple line RNs with nested content, follow this format:
```
## [Unreleased]
  - Release note 1 here.
    - Nested item 1
    - Nested item 2
  - Release note 2 here.
  - Release note 2 here.
```

## What Should Be Logged
One should specify in the corresponding change log file the following changes:
  - everything
  - adding command
  - adding/updating parameters
  - adding/updating arguments
  - updating outputs
  - fixing customer bugs
  
## Note
New content entities (with the exception of classifier and reputation) do not require you to submit a change log file.  This file will be automatically generated in the content release process.

