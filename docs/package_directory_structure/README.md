# Package directory structure
Content code entities in Demisto are presented by YAML files.

Automation scripts and integrations [YAML files](https://github.com/demisto/content/blob/master/docs/yaml-file-integration/README.MD) include Javascript/Python code.

Python scripts and integrations are stored in directories as packages.

This is required for running [linting](https://github.com/demisto/content/blob/master/docs/linting/README.md) and [unit testing](https://github.com/demisto/content/blob/master/docs/tests/unit-testing/README.md) on the Python code.

The package is converted into a YAML file, which include all the package components, in Demisto's CI build, using the `package_creator.py` script, and then populated in the Content release.

---

```
 .
├── <INTEGRATION-NAME>.py              // Integration / automation script Python code.
├── <INTEGRATION-NAME>_test.py         // Python unit test code.
├── <INTEGRATION-NAME>.yml             // Configuration YAML file.
├── <INTEGRATION-NAME>_image.png       // Integration PNG logo (for integrations only).
├── <INTEGRATION-NAME>_description.md  // Detailed instructions markdown file (for integrations only)
├── CHANGELOG.md                       // Markdown file which include the script/integration release notes.
├── README.md                          // Integration / automation script documentation.
├── Pipfile                            // Can be copied from Tests/scripts/dev_envs/default_python3
└── Pipfile.lock                       // Can be copied from Tests/scripts/dev_envs/default_python3    
```
   - Integration logo conventions:
     - Size up to 4KB.
     - Dimensions of 120x50.
     - Transparent background.
     - Dark version of the logo.
   - Note: Since Python 2.7 will not be maintained past 2020, we refer only to Python 3 for the Pipfile.
 
For example, a package of the integration [Palo Alto Networks Cortex](https://github.com/demisto/content/tree/master/Integrations/PaloAltoNetworksCortex) is stored under Integrations directory in a sub-directory named PaloAltoNetworksCortex and contain the following files:

```
.Integrations   
│
└─── .PaloAltoNetworksCortex
│    ├── PaloAltoNetworksCortex.py
│    ├── PaloAltoNetworksCortex_test.py
│    ├── PaloAltoNetworksCortex.yml
│    ├── PaloAltoNetworksCortex_image.png
│    ├── PaloAltoNetworksCortex_description.md
│    ├── README.md
│    ├── Pipfile
|    └── Pipfile.lock
```

---

You can extract a package from a YAML file by using the following:
 - [Demisto IntelliJ Plugin](https://plugins.jetbrains.com/plugin/12093-demisto-add-on-for-pycharm)
 -  `package_extractor.py` script from the Content repository. 
    - Usage example: `python3 package_extractor.py -i /Integrations/integration-WildFire.yml -o Integrations/WildFire -m`

---

#### Integration logo standard

![integration logos-infographic2](https://user-images.githubusercontent.com/33804640/65389274-33119c80-dd5d-11e9-9d15-5ce8dbd03627.png)


