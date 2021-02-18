Note: This is a beta Integration, which lets you implement and test pre-release software. Since the integration is beta, it might contain bugs. Updates to the integration during the beta phase might include non-backward compatible features. We appreciate your feedback on the quality and usability of the integration to help us identify issues, fix them, and continually improve.

## Create an instance

To configure a long running integration to be accessed via Cortex XSOAR Server's https endpoint perform the following:

1. Configure the long running integration to listen on a unique port
2. Make sure the long running integration is setup to use HTTP (not HTTPS)
3. Add the following advanced Server parameter:
    - Name: instance.execute.external.<instance_name>
    - Value: true

    For example for an instance named edl set the following:
    Name: instance.execute.external.workday_iam_event_generator_instance_1
    Value: true
    
    **Note**: The instance name is configured via the Name parameter of the integration. 
    
You will then be able to access the long running integration via the Cortex XSOAR Server's HTTPS endpoint. The route to the integration will be available at:
https://<server_hostname>/instance/execute/<instance_name>