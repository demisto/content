## Create an API token.

The following steps generates an API token key to be able to comunicate with your Safewalk server

To create an API token, follow these steps:

- Log in to your Safewalk server using an SSH client.

- Locate your safewalk-server installation directory and execute (replacing --username with the desired username):

/home/safewalk/safewalk-server-venv/bin/django-admin.py create_system_user --username _xsoar --admin-api --settings gaia_server.settings

- Use this API key in your XSOAR server for Safewalk integration configruation.
