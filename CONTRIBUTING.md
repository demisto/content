# Content Contribution Guide

![Content logo](demisto_content_logo.png)

Welcome to Demisto content repo! Contributions are welcome and appreciated.

## How to contribute
Please read the following guidelines. Following these guidelines will maximize the chances for a fast, easy and effective review process for everyone involved. If something is not clear, please don't hesitate to reach out to us via GitHub, Slack, or email.

* Setup a development environment by following the [Getting Started Guide](docs/getting_started)
* Use the [Package Directory Structure](docs/package_directory_structure) for all Python code. If working on existing code, beyond trivial changes, we require converting to this structure as it allows running linting, unit tests and provides a clearer review process.
* Make sure to read and follow [code conventions](docs/code_conventions)
* Run and verify that the various linters we support pass, as detailed [here](https://github.com/demisto/content/tree/master/docs/linting)
* Document your changes in the relevant changelog file as detailed [here](https://github.com/demisto/content/tree/master/docs/release_notes)
* Validate files are formatted according correctly, by running from the Content root directory: ```PYTHONPATH="`pwd`:${PYTHONPATH}" python2 Tests/scripts/validate_files.py```
 - Make sure you have test playbook [here](https://github.com/demisto/content/tree/master/docs/tests)
 - Make sure you have documentation [here](https://github.com/demisto/content/tree/master/docs/integration_documentation)
 - Circle CI build must be green [here](https://github.com/demisto/content/tree/master/docs/tests/circleci)

You should now be ready to push your changes to the Content GitHub repository, please do as follows.

## Push changes to GitHub

Demisto content is MIT Licensed and accepts contributions via GitHub pull requests.
If you are a first time GitHub contributor, please look at these links explaining on how to create a Pull Request to a GitHub repo:
* https://guides.github.com/activities/forking/
* https://help.github.com/articles/creating-a-pull-request-from-a-fork/

**Working on your first Pull Request?** You can learn how from this *free* series [How to Contribute to an Open Source Project on GitHub](https://egghead.io/series/how-to-contribute-to-an-open-source-project-on-github)

## Contributor License Agreement
Before merging any PRs, we need all contributors to sign a contributor license agreement. By signing a contributor license agreement, we ensure that the community is free to use your contributions.

When you contribute a new pull request, a bot will evaluate whether you have signed the CLA. If required, the bot will comment on the pull request, including a link to accept the agreement. The CLA document is available for review as a [PDF](docs/cla.pdf).

If the `license/cla` status check remains on *Pending*, even though all contributors have accepted the CLA, you can recheck the CLA status by visiting the following link (replace **[PRID]** with the ID of your PR): https://cla-assistant.io/check/demisto/content?pullRequest=[PRID] .

---
If you have a suggestion or an opportunity for improvement that you've identified, please feel free to open a PR.

Enjoy and feel free to reach out to us on the [DFIR Community Slack channel](http://go.demisto.com/join-our-slack-community), or at [info@demisto.com](mailto:info@demisto.com)

## Pull changes from Demisto

In general, there should be no reason for you to pull changes from the base branch into your forked branch.

In case it is needed, you shouldn't pull from the master branch, but from the Demisto Content branch the Pull Request in based on.

The Demisto Content base branch will have the `contrib/` prefix and your branch name as the suffix.
In order to pull changes from the base branch, run:

`git pull https://github.com/demisto/content.git <DEMISTO-CONTENT-BASE-BRANCH>`

For example, if the base branch name is `contrib/itay_master`, you should run:

`git pull https://github.com/demisto/content.git contrib/itay_master`