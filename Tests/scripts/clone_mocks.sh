<<<<<<< HEAD
#!/usr/bin/env bash
set -e

if [[ ! -d "content-test-data" ]]; then
    ssh-keyscan github.com >> ~/.ssh/known_hosts
    git clone git@github.com:demisto/content-test-data.git
  else
    cd content-test-data && git reset --hard && git pull -r
fi
=======
#!/usr/bin/env bash
set -e

ssh-keyscan github.com >> ~/.ssh/known_hosts

if [[ ! -d "content-test-data" ]]; then
    git clone git@github.com:demisto/content-test-data.git
fi
>>>>>>> 192e32561a2cc181939547693c9d08c196039d28
