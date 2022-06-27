Note:
-------
This integration will need a custom docker image which includes the pysftp module as a dependency. To create the docker image on your server you can run :

/docker_image_create name=demisto/pysftp base="<demisto/python3>" dependencies=pysftp

Authors:
-----------
Rahul Vijaydev
Vibhu A Bharadwaj
