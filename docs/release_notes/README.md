# Release Notes
 
Release Notes tells the user what has changed in the new version of this integration (or any other content object). If the integration is new, simply write something to describe the integration.

## New ReleaseNotes Format

Under `Releases/LatestRelease` folder, add a new file with the same name of the changed integrtion yml (or name of json file) with the extension of `.md`.
For example,
If the changed file is `Integration/Alexa/Alexa.py` then create `Releases/LatestRelease/Alexa.md` with the release notes inside.

If the file already exists, add another note as a different bullet.
For example, 
```
Added 2 new commands:
  - integ-add-indicator
  - integ-delete-indicator
```

should be updated to:
```
- Added 2 new commands:
  - integ-add-indicator
  - integ-delete-indicator
- Logout errors are now ignored.
```