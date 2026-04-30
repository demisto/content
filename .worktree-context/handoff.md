# Docker Image Update: demisto/python3:3.12.13.8428455

## Task
Update ALL YML files that use `dockerimage: demisto/python3:` to the new tag `demisto/python3:3.12.13.8428455`.

This is a large-scale update affecting hundreds of integrations and scripts.

## Approach
Use `grep -rl "dockerimage: demisto/python3:" Packs/ --include="*.yml"` to find all files, then use `sed` to replace the docker image tag in all of them at once. Exclude files in `venv/` directories.

## Ticket
XSUP-67244