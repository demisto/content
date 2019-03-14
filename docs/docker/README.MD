![](docker-for-beginners.png)

# What is Docker?
Docker is a tool used by developers to package together dependencies into a single container (or image). What this means for *you* is that in order to use your integration, you are not required to "pip install" all of the packages required. They are part of a container that "docks" to the server and contains all of the libraries you need. To learn more about docker, [visit their site here](https://docs.docker.com/)

# Why Use Docker?
Primarily we use docker to run python scripts in a controlled environment. They run isolated from the server to prevent someone from accidentally damaging the server. By packaging libraries and dependencies together, we can prevent unknown issues from occurring since the environment is all the same.

# Docker Images 

There are often times during development where the standard Python libraries will be insufficient to meet our needs. When presented with these challenges, we must begin looking into creating a Docker image which would allow us to utilise other third party libraries.

# Package Requirements
We cannot just choose any package to be used in our integrations and there are many things to consider before we select a package. 
* Does this package have known security issues? 
* Is the package licensed? 
* If so, what type of license is being used?
These are just some of the many things we must take into consideration.

## Licensing
The Demisto Content repository is produced with a (Massachusetts Institute of Technology) MIT license which means that we use only packages whose license is compatible with the MIT license. As a general rule of thumb, we only use `permissive` licenses. For a complete list of OSS licenses and their types see: https://en.wikipedia.org/wiki/Comparison_of_free_and_open-source_software_licenses .

**Please Note:** Other licenses may be permitted with specific approval.

## Security Concerns
It is imperative that we perform due diligence on packages we choose to use. This includes verifying the package name is correct. Just in 2018 alone, a scan of PyPI resulted in the detection of 11 "typo-squatted" packages which were found to be malicious. [[1]](https://medium.com/@bertusk/detecting-cyber-attacks-in-the-python-package-index-pypi-61ab2b585c67)

## Docker Image Creation
So we have decided we now need to create a Docker Image. After having done our due diligence, and checked the licenses, we are now ready to proceed.

### Via Command Line (testing only)
To create a Docker Image you may use the Docker Create command in the war room by executing:
```
/docker_image_create
```

The below example shows the process:
 
 ```python
/docker_image_create name=example_name dependencies=mechanize packages=wget
```

This command is creating the docker image called "example_name" and uses the python dependency, Mechanize. You may also specify OS packeages. This example requires wget as a package.

When the docker image is created, the following dialog box will appear. Once this has occurred, the docker image is ready to use.

<img width="771" alt="screen shot 2019-01-10 at 12 27 34" src="https://user-images.githubusercontent.com/42912128/50962642-5c421380-14d3-11e9-9b3f-5fb22ef5d573.png">

This command accepts the following arguments:

| Argument  | Use  |
|---|---|
| **name**  | New docker image name, should be lower case only  |
| **dependencies**  |  New docker image dependencies, those are python libs like stix or requests, can have multiple as comma separated: lib1,lib2,lib3 |
| **packages**  |  new docker image packages, those are OS packages like libxslt or wget, can have multiple as comma separated: pkg1,pkg2,pkg3 |


You may need to update a Docker Image. Do this by executing the following:
```
/docker_image_update
```

This command accepts the following arguments:

| Argument | Use |
|---|---|
| **image** | Image name |
| **all** | Pull all images|

If you would like to see all available Docker Images, you may execute the following command:
```
/docker_images
```
This command does not accept any arguments and will list all available Docker Images.

### Via Docker Files (required for production)
In most cases, if your integration is for public release, we will need to push Docker Files into the dockerfiles repository [located here](https://github.com/demisto/dockerfiles). See [README,md](https://github.com/demisto/dockerfiles/blob/master/README.md) for instructions on building docker images. 

## Important Notes
When modifying an existing Docker Image, we need to ensure the change will not disrupt other integrations that may use that same package. Thus, all docker images are created with a unique version tag, which we don't allow overriding. 
