## Tidy

### Description:

Usually, the main bottlenecks in an on-boarding process are the various software and programs required for the new recruit's computer.
Whether if it's a developer, customer success engineer, or a product specialist, on average it takes about three days to get everything up and running. Also, this process generally requires help from other colleagues.
The **Tidy** pack reduces the on-boarding process for new recruits to a matter of minutes.
The **Tidy** pack uses **Ansible** to connect to the new recruit's laptop over ssh and executing predefined commands.

### Main use cases

With the **Tidy** pack you can create a role-based playbook that will execute all required installations for the new recruit.

- Install languages with specific versions (currently Python, Node and Go are supported).
- Create a GitHub SSH key and clone all relevant git repositories.
- Install all relevant programs using **homebrew**.
- Install **zsh** and configure bash_profile / bash_rc.

#### Supported actions

- Install **pyenv** with specific Python versions.
- Install **goenv** with specific Go versions.
- Install **nodenv** with specific Node versions.
- Install packages on Mac-OS using **homebrew**.
- Generate a **github ssh-key** (a GitHub token is required - see [here](https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/creating-a-personal-access-token) for instructions)
- Clone a **git repository** into a selected path, this command requires a github ssh key on the machine to work.
- Configure the **git cli** using key-value parameters in a selected scope.
- Install **zsh** on the machine.
- **Edit a file**, can be used to modify the configuration file or bash_profile file on the machine.
- Install **OSx command line tools** on the machine.
- Execute a command on the machine.
