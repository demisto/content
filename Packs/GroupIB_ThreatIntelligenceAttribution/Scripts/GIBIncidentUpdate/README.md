This Script prevents creation of incidents with the same GIB ID, by checking if there is an existing closed incident 
with the same GIB ID. This script returns False if there is an existing incident with the same GIB ID as the 
incoming incident, and updates the existing incident with the fields of the incoming one. 
If there is no such incident, the script returns True.