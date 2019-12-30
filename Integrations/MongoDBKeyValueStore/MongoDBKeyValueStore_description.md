This Integration needs to be run in a Docker container which has the pymongo dependency added.

From the CLI: 
/docker_image_create name=demisto/mongoclient1 base=demisto/python3 dependencies=pymongo==3.5.1