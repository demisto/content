SAMPLE_TESTPLAYBOOK_CONF = [
    {
        "HelloWorldPremium_Scan-Test": {
            "name": "HelloWorld_Scan-Test",
            "file_path": "Packs/HelloWorld/TestPlaybooks/playbook-HelloWorld_Scan-Test.yml",
            "fromversion": "5.0.0",
            "implementing_scripts": [
                "DeleteContext"
            ],
            "implementing_playbooks": [
                "HelloWorld Scan"
            ],
            "pack": "HelloWorld"
        }
    },
    {
        "HighlightWords_Test": {
            "name": "HighlightWords - Test",
            "file_path": "Packs/CommonScripts/TestPlaybooks/playbook-HighlightWords_-_Test.yml",
            "fromversion": "5.0.0",
            "implementing_scripts": [
                "HighlightWords",
                "VerifyHumanReadableContains"
            ],
            "pack": "CommonScripts"
        }
    },
    {
        "HTTPListRedirects - Test SSL": {
            "name": "HTTPListRedirects - Test SSL",
            "file_path": "Packs/CommonScripts/TestPlaybooks/playbook-HTTPListRedirects_-_Test_SSL"
                         ".yml",
            "fromversion": "5.0.0",
            "implementing_scripts": [
                "PrintErrorEntry",
                "DeleteContext",
                "HTTPListRedirects"
            ],
            "pack": "CommonScripts"
        }
    },
]
