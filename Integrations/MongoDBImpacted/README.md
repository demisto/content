Manipulates a collection of impacted entities - utilizing
 the MongoDB collection named "impacted". This Integration
  needs to be run in a Docker container which has the 
  pymongo dependency added. Integration uses SCRAM-SHA-1 
  authentication to the backend Mongo database, but 
  functions with noauth as well (MongoDB configuration). 
  This was limited by the supported pymongo, further 
  limited by the Python version supported by Demisto 
  (read: Wanted to use SCRAM-SHA-256).

This Integration needs to be run in a Docker container
 which has the pymongo dependency added.\n\nFrom the 
 CLI: \n/docker_image_create name=demisto/mongoclient1 
 base=demisto/python3 dependencies=pymongo==3.5.1"
