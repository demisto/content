Role Name
=========

Role which install Demisto python development enviorment for developing new integrations, the role actions are:

1. Installing pyenv.
2. Installing using pyenv - python 2.7.17 & python 3.8.0
3. Setup virtualenv in content repo directory with requirements for running hooks.

Requirements
------------

* Platform - MacOS >= 14.1
* python2 installed.
* pip installed.
* ansible installed (brew recommended for installation).

Example Playbook
----------------

Including an example of how to use your role (for instance, with variables passed in as parameters) is always nice for users too:

    - hosts: servers
      roles:
         - { role: dev_env_setup }

License
-------

MIT

Author Information
------------------

Gal Rabin - grabin@paloaltonetworks.com
