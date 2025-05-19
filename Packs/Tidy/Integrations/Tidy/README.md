## Tidy

### Description

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

### tidy-pyenv

***
Install Python versions, Using Pyenv.

#### Base Command

`tidy-pyenv`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| versions | Python versions to be installed. Default is 2.7.18,3.8.5. | Required |
| globals | Python versions to define as globals in enviorment. Default is 3.8.5. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-goenv

***
Install GoLang versions, Using Goenv.

#### Base Command

`tidy-goenv`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| versions | GoLang versions to be installed. Default is 1.16.0. | Required |
| globals | GoLang versions to define as globals in enviorment. Default is 1.16.0. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-nodenv

***
Install Node.js versions, Using nodenv.

#### Base Command

`tidy-nodenv`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| versions | Node.js versions to be installed. Default is 12.20.1. | Required |
| globals | Node.js versions to define as globals in enviorment. Default is 12.20.1. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-homebrew

***
Install and configure homebrew, Install additional homebrew/-cask packages.

#### Base Command

`tidy-homebrew`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| apps | Comma seprated list of homebrew packages (https://formulae.brew.sh/). | Optional |
| cask_apps | Comma seprated list of homebrew cask packages (https://formulae.brew.sh/cask/). | Optional |
| homebrew_taps | Hombrew taps packages to install. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-github-ssh-key

***
Generate private/public key, Configure ssh client, and deploy keys to your GitHub account.

#### Base Command

`tidy-github-ssh-key`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| access_token | GitHub access token with public keys admin permissions.. (https://docs.github.com/en/free-pro-team@latest/github/authenticating-to-github/creating-a-personal-access-token). | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-git-clone

***
Clone git repository to destination.

#### Base Command

`tidy-git-clone`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| repo | Repository to be cloned (SSH/HTTPS). | Required |
| dest | The path of where the repository should be checked out. | Required |
| force | If yes, any modified files in the working repository will be discarded. Possible values are: yes, no. Default is no. | Required |
| update | If no, do not retrieve new revisions from the origin repository. Possible values are: yes, no. Default is yes. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-git-config

***
Configure git cli.

#### Base Command

`tidy-git-config`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| key | The name of the setting. . Possible values are: user.name, user.email, core.editor. | Required |
| value | Git key: value to set. | Required |
| scope | Specify which scope to read/set values from. . Possible values are: local, global, system. Default is global. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-zsh

***
Install zsh, oh-my-zsh.

#### Base Command

`tidy-zsh`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-block-in-file

***
Insert/update/remove a block of multi-line text surrounded by customizable marker lines.

#### Base Command

`tidy-block-in-file`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| path | The file to modify. | Required |
| block | Text block to be added. | Required |
| marker | Marker to manage block if needed to change in the future. Default is " ". | Required |
| create | Create a new file if it does not exist. Possible values are: yes, no. Default is yes. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-exec

***
Run command in host.

#### Base Command

`tidy-exec`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |
| command | Bash command to execute. | Required |
| chdir | Change directory before executing command. Default is $HOME. | Required |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-osx-command-line-tools

***
Install OSx command line tools.

#### Base Command

`tidy-osx-command-line-tools`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-demisto-server

***
Set demisto developement server.

#### Base Command

`tidy-demisto-server`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-demisto-web-client

***
Set demisto developement web-client.

#### Base Command

`tidy-demisto-web-client`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| hostname | Endpoint IP/URL to be installed. | Optional |
| user | Endpoint user to be installed. | Optional |
| password | User login password. | Optional |

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Tidy.Install.Status | String | The status of the installation |
| Tidy.Install.ReturnCode | Number | The return code of the ansible execution |
| Tidy.Install.Canceled | Boolean | Whether the execution was canceled |
| Tidy.Install.Errored | Boolean | Whether the execution has encountered an error |
| Tidy.Install.TimedOut | Boolean | Whether the execution has timed out |
| Tidy.Install.Stats | String | Aditional stats about the ansible execution |
| Tidy.Install.InstalledSoftware | String | The name of the installed software |
| Tidy.Install.AdditionalInfo | String | Additinal information about the installed software |

### tidy-python-env

***
Install python environment.

#### Base Command

`tidy-python-env`

#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |

#### Context Output

There is no context output for this command.
