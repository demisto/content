# Package directory structure
Content code entities in Demisto are presented by YAML files.

Automation scripts and integrations [YAML files](https://github.com/demisto/content/blob/master/docs/yaml-file-integration/README.MD) include Javascript/Python code.

Python scripts and integrations are stored in directories as packages.

This is required for running [linting](https://github.com/demisto/content/blob/master/docs/linting/README.md) and [unit testing](https://github.com/demisto/content/blob/master/docs/tests/unit-testing/README.md) on the Python code.

The package is converted into a YAML file, which include all the package components, in Demisto's CI build, using the `package_creator.py` script, and then populated in the Content release.

---

A package should be a sub-directory of either Integrations or Scripts directory, and contain the following files:

 - `<INTEGRATION-NAME>.py` - Integration / automation script Python code.
 - `<INTEGRATION-NAME>_test.py` - Python unit test code.
 - `<INTEGRATION-NAME>.yml` - Configuration YAML file.
 - `<INTEGRATION-NAME>_image.png ` - Integration PNG logo (for integrations only).
 - `<INTEGRATION-NAME>_description.md` - Detailed instructions markdown file (for integrations only).
 - [CHANGELOG.md](https://github.com/demisto/content/blob/master/docs/release_notes/README.MD) - a markdown file which include the script/integration release notes.
 - `Pipfile` (can be copied from Tests/scripts/dev_envs/default_python3)
 - `Pipfile.lock` (can be copied from Tests/scripts/dev_envs/default_python3)
    - Note: Since Python 2.7 will not be maintained past 2020, we refer only to Python 3.
 
For example, a package of the integration [Palo Alto Networks Cortex](https://github.com/demisto/content/tree/master/Integrations/PaloAltoNetworksCortex) is stored under Integrations directory in a sub-directory names PaloAltoNetworksCortex and contain the following files:

 - `PaloAltoNetworksCortex.py` - the integration code.
 - `PaloAltoNetworksCortex.yml` - the integration configuration.
 - `PaloAltoNetworksCortex_image.png` - the integration logo.
 - `PaloAltoNetworksCortex_test.py` - the integration unit tests.
 - `PaloAltoNetworksCortex_description.md` - the integration detailed instructions.
 - `Pipfile`
 - `Pipfile.lock`
 
---

You can extract a package from a YAML file by using the following:
 - [Demisto IntelliJ Plugin](https://plugins.jetbrains.com/plugin/12093-demisto-add-on-for-pycharm)
 -  `package_extractor.py` script from the Content repository.



