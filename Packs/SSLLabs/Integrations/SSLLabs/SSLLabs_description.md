## SSL Labs
A free online services that performs a deep analysis of the configuration of an SSL web server on the public internet.

To create an instance of the SSL Labs integration in Cortex XSOAR, complete the following steps below:

1.  Run the **!ssl-labs-register-email** command from the XSOAR playground and provide your first name, last name, email, and organization to register with Qualys SSL Labs. 
2. Enter your email in the **Registered Email Address** parameter.
3. Test the integration and confirm your connectivity to SSL Labs. 

## Analyze a Host

Before analyzing a host make sure you have permission to run a scan against the target host. 

Below is a detailed description of each parameter that can be set when running the **!ssl-labs-analyze** command.

- **host:** Target hostname or URL
- **publish:** Set to on if assessment results needs to be published on the public results boards. Default: off
- **startNew:** This parameter should only be used once to start a new assessment; any additional use may cause an assessment loop.
- **fromCache:** Delivers cached assessment reports if available. This parameter is intended for API consumers who do not wish to wait for assessment results and cannot be used simultaneously with the startNew parameter. Default: off
- **maxAge:** Maximum report age in hours if retrieving from cache (fromCache parameter). Example: "1"
- **all:** When the parameter is set to on, full information will be returned. When the parameter is set to done, full information will be returned only if the assessment is complete (status is READY or ERROR).
- **ignoreMismatch:** Ignores the mismatch if server certificate doesn't match the assessment hostname and proceeds with assessments if set to on. Default: off Note: This parameter is ignored if a cached report is returned.

---

## SSL Labs Info

Check the availability of the SSL Labs servers, retrieve the engine and criteria version, and initialize the maximum number of concurrent assessments.


[View Integration Documentation](PLACEHOLDER)