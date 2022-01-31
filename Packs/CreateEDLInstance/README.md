This pack adds the ability to create EDL instances on XSOAR from a playbook.
Specify a indicator query and instance name to create the EDL.
The allocated ports are tracked in an XSOAR list to ensure duplicate ports aren't used. 

### Setup Notes
You should first create an XSOAR list which can be used to keep track of the
ports which have been allocated by this automation.
If there are existing EDLs these ports should be added to the new list in a 
comma seperated fashion.

A Demi$to REST API integration also needs to be configured for correct operation.
