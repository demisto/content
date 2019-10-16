# CircleCI capabilities 

Lets start with the basics, CircleCI is the service we use in order to run our tests and to check the integrity of our code.

As you are probably aware, while pushing any code to our repos it will initiate a build within CircleCI, this build will execute several things, or in the Circle language steps.
Lets go over our steps to understand what each of them is doing:
- Prepare Environment:
    - Sets up the testing environment before starting the build. This usually involves provisioning a test server, setting access rules, etc.
- Install dependencies:
    - Here we install our python packages, and give access to the scripts folder. The scripts folder contains all of the scripts we are using for the next steps in Circle.
- Validate Files and Yaml
    - Validates the schema of the yml files you created, and checks to ensure that you haven’t made any changes that may effect backwards compatibility.
    - [You can learn more about the YAML structure here](/docs/yaml-file-integration)
- Configure Test Filter
    - This step gathers all the relevant tests that Circle should run for the changes done in the given branch. When testing a single integration on a branch other than master, it is not necessary to test unrelated integrations or scripts.
    - A full test of every integration takes on average one hour and 15 minutes. Testing a specific integration, however, will take about 20 to 30 minutes.
    - In Nightly builds we will run all the tests we have
- Build Content Descriptor
    - This step populates the content descriptor with correct dates and assetId's.
- Common Server Documentation
    - This step builds all of the documentation for the server and includes, API documentation, getting started, as well as other documentation.
- Create Content Artifacts
    - These artifacts are the zip files that are uploaded to the server and contain all of the content for Demisto. They are composed of two parts:
        - content_new.zip contains all actual content, playbooks/scripts/integrations
        - content_test.zip contains all the test_playbooks
- Download Artifacts
    - This step retrieves the latest "Green" (or stable) build of the Demisto server.
- Download Configuration
    - Downloads data from content-test-conf, where all the private data is stored. This includes API keys, login details, and other configurations needed to create an instance of an integration.
- Create Instance
    - Create AWS instance for the build
- Setup Instance
    - Sets up Demisto on the AWS instance, as well as copies the content from the branch you are working on to the instance itself.
- Run Tests
    - This step iterates over each of the test playbooks. This involves creating an incident, attaching the test playbook to the incident, running the playbook, and finally awaiting the results.
- Slack Notifier
    - Notifies the #content-team of the results of the build test.
        - **Green** - Awesome. Things aren't broken and the build passed all of its tests. You can share your joy in the content team slack channel with the ```:green-build:``` Anar emoji.
        - **Red** - Bad. You've broken something and your current build will probably cause skynet to form. Try looking at the logs and seeing why it failed.
- Instance Test
    - This is for the DevOps teams use and runs on the nightly only.
    - Iterates through all the integrations we have in the content-test-conf repo and tries to create an instance for each of them, after that it will run the test button for each of them. 
- Destroy Instances
    - This step destroys the AWS instance in a case of success in the "Run Tests" step.
    - If the tests have failed, the instance is preserved for debug purposes. You can access the instance using the IP address provided and using the credentials "admin" and "1q2w3e4r".
    - Instances are not persistent and **will be destroyed**.


Some more capabilities we have enabled for CircleCI is to send parameters with the initiation of the build. The following are currently enabled for use:
- Nightly
    - This will make sure we are running all the tests we have in the conf.json file
    - You can initiate a build with this param via utils/trigger_content_nightly_build.sh in content repo
- NON_AMI_RUN
    - This will make sure we are not running the build with the AMI created in the nightly process but with the latest server build passed
    - You can initiate a build with this param via utils/trigger_content_non_ami_build.sh in content repo
