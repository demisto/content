# GUIDE

## Description

This manual explain how to install python development enviorment for Demisto integration development using Ansible, the following action will be done with this role:

1. Installing pyenv.
2. Installing using pyenv - python 2.7.17 & python 3.8.0
3. Setup virtualenv in content repo directory with requirements for running hooks.

## Prequists

1. Install `homebrew` via Terminal:
`/usr/bin/ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"`
2. Install `python2` via Terminal: `brew install python`
3. Install `ansible` via Terminal: `brew install ansible`

## Perform the following to install after prequists full field

change directory - `cd ~/dev/demisto/content/DevEnvSetUp`

### Local setup

1. Run the following command via Terminal - `ansible-playbook playbook.yml`
2. Enjoy (:

### Remote setup

1. Setup remote details in `inventory.txt`:

```txt
ansible_host=other1.example.com  ansible_connection=ssh   ansible_user=myuser ansible_password=password
ansible_host=other1.example.com  ansible_connection=ssh   ansible_ssh_private_key_file=~/.ssh/id_rsa
```

2. Run the following command via terminal - `ansible-playbook -i inventory.txt playbook.yml`