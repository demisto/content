# Content Contribution Guide

![Content logo](demisto_content_logo.png)

Welcome to Demisto content repo! Contributions are welcome and appreciated.

## How to contribute

To get you started, refer to our [Getting Started article](https://github.com/demisto/content/blob/master/docs)

After you finish developing, there are a few steps left before you can create a pull request:

 - Follow code conventions [here](https://github.com/demisto/content/tree/master/docs/code_conventions)
 - Run linting and test checks as detailed [here](https://github.com/demisto/content/tree/master/docs/linting)
 - Document your changes in the relevant changelog file as detailed [here](https://github.com/demisto/content/tree/master/docs/release_notes).
 - Validate files are formatted according correctly, by running from the Content root directory: ```PYTHONPATH="`pwd`:${PYTHONPATH}" python2 Tests/scripts/validate_files.py```
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


If you have a suggestion or an opportunity for improvement that you've identified, please feel free to open a PR.

Enjoy and feel free to reach out to us on the [DFIR Community Slack channel](http://go.demisto.com/join-our-slack-community), or at [info@demisto.com](mailto:info@demisto.com)
