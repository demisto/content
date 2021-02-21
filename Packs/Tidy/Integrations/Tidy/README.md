## Tidy:
### Description:
Usually, the main bottleneck in an on-boarding process is the installations that needs to be done on the new recruit's computer.
Whether if it's a developer, customer success or product, it takes about three days to make everything up and running and usually help is required from other colleagues as well.
The **Tidy** pack enables you to reduce the on-boarding process time of a new recruit to matter of minutes.
The **Tidy** pack uses **Ansible** to connect to the new recruit's laptop over ssh and executing predefined commands.

### Main use case:
With the **Tidy** pack you can create a role based playbook that will execute all installations a new recruit needs.
- Install languages with specific versions (currently python, node and go are supported).
- Creating a github ssh key and cloning all the relevant git repositories.
- Installing all relevant programs using **homebrew**.
- Install **zsh** and configure bash_profile / bash_rc.

Currently, the supported actions are the following:
- Installing **pyenv** with specific python versions.
- Installing **goenv** with specific go versions.
- Installing **nodenv** with specific node versions.
- Installing packages on Mac-OS using **homebrew**.
- Generating a **github ssh-key** (a github token is required - see [here](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/creating-a-personal-access-token) for instructions)
- Cloning a **git repository** into a selected path, this command requires a github ssh key on the machine to work.
- Configuring the **git cli** using key-value parameters in a selected scope.
- Installing **zsh** on a machine.
- **Editing a file**, can be used to modify configuration file or bash_profile file on the machine.
- Installing **OSx command line tools** on the machine.
- Executing a command on the machine.
