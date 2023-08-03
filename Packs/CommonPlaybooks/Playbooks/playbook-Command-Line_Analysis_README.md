This playbook takes a command line from the alert and performs the following actions:
- Checks for base64 string and decodes if exists
- Extracts and enriches indicators from the command line
- Checks specific arguments for malicious usage 

At the end of the playbook, it sets a possible verdict for the command line, based on the finding:
1. Indicators found in the command line
2. Found AMSI techniques
3. Found suspicious parameters
4. Usage of malicious tools
5. Indication of network activity
6. Indication of suspicious LOLBIN execution

Note: In case you are wishing to run this playbook with a list of command lines, set this playbook to be running in a loop. To do so, navigate to the 'Loop'  and check "For Each Input".

## Dependencies

This playbook uses the following sub-playbooks, integrations, and scripts.

### Sub-playbooks

* Compare Process Execution Arguments To LOLBAS Patterns

### Integrations

This playbook does not use any integrations.

### Scripts

* DeleteContext
* Set
* Base64Decode
* MatchRegexV2

### Commands

* extractIndicators

## Playbook Inputs

---

| **Name** | **Description** | **Default Value** | **Required** |
| --- | --- | --- | --- |
| Commandline | The command line. |  | Optional |
| StringSimilarityThreshold | StringSimilarity automation threshold. Used by the Compare "Process Execution Arguments To LOLBAS Patterns" sub-playbook. This input controls the StringSimilarity automation threshold. | 0.5 | Optional |

## Playbook Outputs

---

| **Path** | **Description** | **Type** |
| --- | --- | --- |
| MatchRegex | The regex found in the command line | unknown |
| Indicators | Indicators extracted from the command line | unknown |
| commandline.original | The original command line | unknown |
| commandline.decoded | The decoded command line | unknown |
| CommandlineVerdict | The command line verdict | unknown |
| IP | The IP object. | unknown |
| URL | The URL object. | uknown |
| File | The file object. | unknown |
| Domain | The domain object. | unknown |

## Playbook Image

---

![Command-Line Analysis](../doc_files/Command-Line_Analysis.png)
