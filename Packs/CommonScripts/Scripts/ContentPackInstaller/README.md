### Command Example
!ContentPackInstaller packs_data=`[{"id":"GoogleCloudCompute","itemVersion":"latest"},{"id":"GoogleKubernetesEngine","itemVersion":"latest"},{"id":"GoogleSafeBrowsing","itemVersion":"latest"}]` pack_id_key=id pack_version_key=itemVersion

### Troubleshooting
Multi-tenant environments should be configured with the Cortex Rest API instance when using this 
automation. Make sure the *Use tenant* parameter (in the Cortex Rest API integration) is checked 
to ensure that API calls are made to the current tenant instead of the master tenant.
