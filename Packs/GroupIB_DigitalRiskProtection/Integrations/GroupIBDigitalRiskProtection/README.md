# Group-IB Digital Risk Protection Pack for Cortex XSOAR

This pack enables integration between **Group-IB Digital Risk Protection** and **Cortex XSOAR**, allowing you direct retrieval and handling of violations.

## Configuration

| Name                                      | Required | Description |
|-------------------------------------------|----------|-------------|
| **GIB DRP URL**                           | True     | The DRP server URL to connect to. |
| **Fetch incidents**                       | True     | Determines whether the integration should start collecting violations. |
| **Classifier**                            | True     | Maps collections and received data to appropriate incidents. |
| **Incident type**                         | False    | Specifies the incident type to collect the received data into. This field should be ignored as our Classifier and Mapper manage this. |
| **Mapper**                                | True     | Determines how fields are mapped to incidents. |
| **Username**                              | True     | Username is the DRP account email. The API Key and Username required for authentication.  |
| **Password**                              | True     | API Token (not your account password). Generated in the DRP web panel. API token specifically for interaction with the API. The API Key and Username required for authentication.  |
| **Trust any certificate (not secure)**    | False    | Allows skipping SSL verification. Use with caution. |
| **Use system proxy settings**             | False    | Enables XSOAR's proxy settings for the API connection. |
| **Violation Section to filter received violations** | False    | Allows filtering retrieved violations by section. |
| **Brands to filter received violations**  | False    | Allows filtering violations by brand. You must use a **BrandID**, which can be obtained via the `gibdrp-get-brands` command. Currently, filtering is available for only one brand per instance. |
| **Incidents first fetch**                 | True     | Specifies the start date for retrieving violations. |
| **Download images**                       | False    | Download images for each violation and display in the violation layout. |
| **Getting Typosquatting only**            | False    | Retrieve only violations matching the **TypoSquatting** filter. |
| **Number of requests per collection**     | True     | Number of requests per collection the integration sends per fetch iteration. |
| **Log Level**                             | True     | Set the log collection level; we recommend **Debug**. |

---

## Available Commands

These commands can be executed from the CLI, as part of an automation, or within a playbook.

### 1. `gibdrp-get-brands`
Retrieves a list of all available brands.

#### Command Example:
```!gibdrp-get-brands```

#### Context Output:

| Brand Name  | Brand ID |
|------------|---------|
| ExampleBrand | BrandID |

---

### 2. `gibdrp-get-subscriptions`
Retrieves a list of all available subscriptions.

#### Command Example:
```!gibdrp-get-subscriptions```

#### Context Output:

| Subscriptions |
|--------------|
| scam         |

---

### 3. `gibdrp-get-violation-by-id`
Retrieves violation details by ID.

#### Input Parameters:

| Argument Name | Description  | Required |
|--------------|-------------|----------|
| **id**       | GIB DRP ID  | True     |

#### Command Example:
```!gibdrp-get-violation-by-id id=violationID```


#### Context Output:

| approve_state | brand          | company         | dates_approved_date     | dates_created_date     | dates_found_date       | detected               | first_detected         | id           | images        | link  | source         | typosquatting_status | violation_status | violation_type | violation_uri                        |
|--------------|---------------|----------------|------------------------|------------------------|------------------------|------------------------|------------------------|--------------|--------------|------|---------------|---------------------|-----------------|----------------|--------------------------------------|
| approved     | Brand Example | Company Example | 2025-03-24T10:33:57+00:00 | 2025-02-15T00:14:08+00:00 | 2025-02-15T00:14:08+00:00 | 2025-02-15T00:14:08+00:00 | 2025-02-18T16:54:04+00:00 | ViolationID | image_sha256 | [View Violation](https://drp.group-ib.com/p/violation/?id=ViolationID&search={%22id%22:%22ViolationID%22}&dateFrom=15/02/2025&dateTo=15/02/2025) | SOCIAL_NETWORKS | true | detected | trademark | [https://example.com/exampleviolation/](https://example.com/exampleviolation/) |


---

### 4. `gibdrp-change-violation-status`
Changes the status of a violation.

#### Input Parameters:

| Argument Name | Description  | Required | Possible Values |
|--------------|-------------|----------|----------------|
| **id**       | GIB DRP ID  | True     | -              |
| **status**   | Violation Status | True     | approve, reject |

#### Command Example:
```!gibdrp-change-violation-status id=exampleId status=approve```

#### Possible DBOT Messages:
- **"Can not change the status of the selected feed"** – The status of the selected violation cannot be changed.  
- **"Request to change violation status sent"** – The request to change the violation status was sent successfully.  
