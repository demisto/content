# Abnormal Security Demisto Integration

Cortex XSOAR, previously known as Demisto is a product used by the SOC teams of many of our customers. It’s primary purpose is to orchestrate and automate incident reporting. For example, many customers use it together with ServiceNow to automate incident ticket creation as part of their SOC workflow.

A common use-case is to ingest feeds or third party platforms that flag new indicators of compromise or potential incidents. These incidents / IoCs are fetched and created within the Demisto UI which is used by SOC teams to kickoff investigations.

This directory contains the Demisto Integration generated from Abnormal Security's REST API. In the rest of this `README` you will find instructions on how to generate the integration, test the generated integration, as well as provision a download link for the integration for customers.


## Generating the Integration
Requirements:

1. Completed dev environment setup as instructed on [online documentation](https://xsoar.pan.dev/docs/concepts/dev-setup)
2. Download the latest OpenAPI definition of our REST API as JSON Resolved [here](https://app.swaggerhub.com/apis/abnormal-security/abx/1.0.0)

### Steps to generate integration

#### (1) Generate Integration Files

```bash
export OPENAPI_JSON_PATH=<path/to/file/abnormal-security-abx-1.0.0-resolved.json>
export CORTEX_XSOAR_DIR=<path/to/this/readme>
export PACKAGE_NAME=AbxCortexXSOAR

cd $CORTEX_XSOAR_DIR

demisto-sdk openapi-codegen -i $OPENAPI_JSON_PATH -n $PACKAGE_NAME -o $PACKAGE_NAME -u "threatId" -r "Threat"
```

You should see an output in your command line that contains a separate command that looks like this:

```
demisto-sdk openapi-codegen -i "/Users/gengsng/Downloads/abnormal-security-abx-1.0.0-resolved.json" -cf "AbnormalSecurityCortexXSOAR/AbxCortexXSOAR.json" -n "AbxCortexXSOAR" -o "AbxCortexXSOAR" -pr "abxcortexxsoar" -c "AbxCortexXSOAR" -u "threatId" -r "Threat"
```

Save this command somewhere, we'll run it after a few more steps.

To get a better understanding of what the `openapi-codegen` command does, check out the [documentation](https://xsoar.pan.dev/docs/integrations/openapi-codegen).

#### (2) Inspect the generated JSON file

The above command should have generated a `AbxDemisto.json` file which contains metadata about our integration. If you want to update any of this data now is the time to do it. We use the default generated metadata by default.

#### (3) Run the generated command from Step 1

```
demisto-sdk openapi-codegen -i "/Users/gengsng/Downloads/abnormal-security-abx-1.0.0-resolved.json" -cf "AbnormalSecurityCortexXSOAR/AbxCortexXSOAR.json" -n "AbxCortexXSOAR" -o "AbxCortexXSOAR" -pr "abxcortexxsoar" -c "AbxCortexXSOAR" -u "threatId" -r "Threat"
```

#### (4) Update the generated python file

The above command should have generated a `AbxCortexXSOAR.py` file which contains the actual methods our integration provides to the end user. Our REST API uses Bearer Token auth and the codegen does not generate the authentication method in that format by default, so we need to update it:

```py
# look for where the authorization headers are specified and update the code so that it is in Bearer <TOKEN> format
headers['Authorization'] = f'Bearer {params["api_key"]}'
```

#### (5) Package the integration into a YAML file

```
demisto-sdk unify -i AbxCortexXSOAR
```

And that's it! We can repeat this process every time the REST API is updated, or if we want to make direct changes to the integration code itself.
