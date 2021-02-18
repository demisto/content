Synapse intelligence analysis platform.
This integration was integrated and tested with version `2.7.0` of Synapse
## Configure Synapse on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Synapse.
3. Click **Add instance** to create and configure a new integration instance.

| **Parameter** | **Description** | **Required** |
| --- | --- | --- |
| url | Server URL \(e.g. https://synapse.vertex.link\) | True |
| port | REST API Port \(default is 4443\). | True |
| credentials | Username and password to user to authenticate to Synapse. | True |
| insecure | Trust any certificate \(not secure\) | False |
| proxy | Use system proxy settings | False |
| timezone | Timezone \(optional\) | False |
| bad_tag | Malicious Tag | False |
| good_tag | Benign Tag | False |

4. Click **Test** to validate the URLs, token, and connection.
## Commands
You can execute these commands from the Demisto CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### ip
***
Returns IP information and reputation.


#### Base Command

`ip`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| ip | List of IPs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.IP.ip | String | The IP address of the indicator. | 
| Synapse.IP.tags | String | The tags applied to the IP address. | 
| DBotScore.Indicator | String | The value assigned by DBot for the indicator. | 
| DBotScore.Type | String | The type assigned by DBot for the indicator. | 
| DBotScore.Score | Number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| IP.Address | string | The IP address of the indicator. | 
| IP.Malicious.Vendor | string | For malicious IP addresses, the vendor that made the decision. | 
| IP.Malicious.Description | string | For malicious IP addresses, the full description. | 


#### Command Example
```!ip ip="1.2.3.4"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "1.2.3.4",
        "Score": 3,
        "Type": "ip",
        "Vendor": "Synapse"
    },
    "IP": {
        "Address": "1.2.3.4",
        "Malicious": {
            "Description": "Synapse returned reputation tag: mal",
            "Vendor": "Synapse"
        }
    },
    "Synapse": {
        "IP": {
            "ip": "1.2.3.4",
            "tags": [
                "mal",
                "test"
            ]
        }
    }
}
```

#### Human Readable Output

>### IP List
>|ip|tags|
>|---|---|
>| 1.2.3.4 | mal,<br/>test |


### url
***
Returns URL information and reputation.


#### Base Command

`url`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| url | List of URLs. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.URL.url | String | The data of the URL indicator. | 
| Synapse.URL.tags | String | The tags applied to the url. | 
| DBotScore.Indicator | String | The value assigned by DBot for the indicator. | 
| DBotScore.Type | String | The type assigned by DBot for the indicator. | 
| DBotScore.Score | Number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| URL.Data | string | The data of the URL indicator. | 
| URL.Malicious.Vendor | string | For malicious URLs, the vendor that made the decision. | 
| URL.Malicious.Description | string | For malicious URLs, the full description. | 


#### Command Example
```!url url="https://google.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "https://google.com",
        "Score": 0,
        "Type": "url",
        "Vendor": "Synapse"
    },
    "Synapse": {
        "URL": {
            "tags": [],
            "url": "https://google.com"
        }
    },
    "URL": {
        "Data": "https://google.com"
    }
}
```

#### Human Readable Output

>### URL List
>|tags|url|
>|---|---|
>|  | https://google.com |


### domain
***
Returns Domain information and reputation.


#### Base Command

`domain`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| domain | List of Domains. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Domain.domain | String | The fully qualified domain name. | 
| Synapse.Domain.tags | String | The tags applied to the domain. | 
| DBotScore.Indicator | String | The value assigned by DBot for the indicator. | 
| DBotScore.Type | String | The type assigned by DBot for the indicator. | 
| DBotScore.Score | Number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 
| Domain.Name | string | The name of the domain. | 
| Domain.Malicious.Vendor | string | For malicious domains, the vendor that made the decision. | 
| Domain.Malicious.Description | string | For malicious domains, the full description. | 


#### Command Example
```!domain domain="foobar.com"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "foobar.com",
        "Score": 3,
        "Type": "domain",
        "Vendor": "Synapse"
    },
    "Domain": {
        "Malicious": {
            "Description": "Synapse returned reputation tag: mal",
            "Vendor": "Synapse"
        },
        "Name": "foobar.com"
    },
    "Synapse": {
        "Domain": {
            "domain": "foobar.com",
            "tags": [
                "mal"
            ]
        }
    }
}
```

#### Human Readable Output

>### Domain List
>|domain|tags|
>|---|---|
>| foobar.com | mal |


### file
***
Returns File information and reputation.


#### Base Command

`file`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| file | List of File Hashes (accepts MD5, SHA1, SHA256, SHA512). | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.File.hash | String | The queried file hash. | 
| Synapse.File.MD5 | String | The MD5 hash of the file. | 
| Synapse.File.SHA1 | String | The SHA1 hash of the file. | 
| Synapse.File.SHA256 | String | The SHA256 hash of the file. | 
| Synapse.File.SHA512 | String | The SHA256 hash of the file. | 
| Synapse.File.query | String | The formatted query in storm syntax. | 
| File.MD5 | String | The MD5 hash of the file. | 
| File.SHA1 | String | The SHA1 hash of the file. | 
| File.SHA256 | String | The SHA256 hash of the file. | 
| File.SHA512 | String | The SHA512 hash of the file. | 
| File.Malicious.Vendor | String | For malicious files, the vendor that made the decision. | 
| File.Malicious.Description | String | For malicious files, the full description. | 
| DBotScore.Indicator | String | The value assigned by DBot for the indicator. | 
| DBotScore.Type | String | The type assigned by DBot for the indicator. | 
| DBotScore.Score | Number | The score assigned by DBot for the indicator. | 
| DBotScore.Vendor | String | The vendor used to calculate the score. | 


#### Command Example
```!file file="9e0c442ee3157d3f3aa2be30a1d24d81"```

#### Context Example
```json
{
    "DBotScore": {
        "Indicator": "9e0c442ee3157d3f3aa2be30a1d24d81",
        "Score": 3,
        "Type": "file",
        "Vendor": "Synapse"
    },
    "File": {
        "MD5": "9e0c442ee3157d3f3aa2be30a1d24d81",
        "Malicious": {
            "Description": "Synapse returned reputation tag: mal",
            "Vendor": "Synapse"
        },
        "SHA1": "e7b03ed4dbdfb79477c49942d5796d3dfc78ac7e",
        "SHA256": "290f64a315850c5bccc907f79cbeabd79345719df738ee5d02dc3447d04675b3",
        "SHA512": "53e6baa124f54462786f1122e98e38ff1be3de82fe2a96b1849a8637043fd847eec7e0f53307bddf7a066565292d500c36c941f1f3bb9dcac807b2f4a0bfce1b"
    },
    "Synapse": {
        "File": {
            "MD5": "9e0c442ee3157d3f3aa2be30a1d24d81",
            "SHA1": "e7b03ed4dbdfb79477c49942d5796d3dfc78ac7e",
            "SHA256": "290f64a315850c5bccc907f79cbeabd79345719df738ee5d02dc3447d04675b3",
            "SHA512": "53e6baa124f54462786f1122e98e38ff1be3de82fe2a96b1849a8637043fd847eec7e0f53307bddf7a066565292d500c36c941f1f3bb9dcac807b2f4a0bfce1b",
            "hash": "9e0c442ee3157d3f3aa2be30a1d24d81",
            "query": "file:bytes:md5=9e0c442ee3157d3f3aa2be30a1d24d81",
            "tags": [
                "mal"
            ]
        }
    }
}
```

#### Human Readable Output

>### File List
>|MD5|SHA1|SHA256|SHA512|hash|query|tags|
>|---|---|---|---|---|---|---|
>| 9e0c442ee3157d3f3aa2be30a1d24d81 | e7b03ed4dbdfb79477c49942d5796d3dfc78ac7e | 290f64a315850c5bccc907f79cbeabd79345719df738ee5d02dc3447d04675b3 | 53e6baa124f54462786f1122e98e38ff1be3de82fe2a96b1849a8637043fd847eec7e0f53307bddf7a066565292d500c36c941f1f3bb9dcac807b2f4a0bfce1b | 9e0c442ee3157d3f3aa2be30a1d24d81 | file:bytes:md5=9e0c442ee3157d3f3aa2be30a1d24d81 | mal |


### synapse-storm-query
***
Execute a Synapse Storm query.


#### Base Command

`synapse-storm-query`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Synapse storm query (i.e. "inet:ipv4=1.2.3.4") | Required | 
| limit | Limit the number of results returned. Default is 100. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Nodes.created | String | Timestamp when the node was first created in the Synapse Cortex. | 
| Synapse.Nodes.form | String | The type of node \(i.e. "inet:ipv4" for an IP address\). | 
| Synapse.Nodes.tags | String | The tags associated with the resulting node. | 
| Synapse.Nodes.valu | String | The node primary value \(i.e. "1.2.3.4" for an IP\). | 


#### Command Example
```!synapse-storm-query query="inet:ipv4=1.2.3.5" limit=1```

#### Context Example
```json
{
    "Synapse": {
        "Nodes": {
            "created": "2020/09/12 10:07:17 EDT",
            "form": "inet:ipv4",
            "tags": [
                "test.foo",
                "test.testing"
            ],
            "valu": "1.2.3.5"
        }
    }
}
```

#### Human Readable Output

>### Synapse Query Results: `inet:ipv4=1.2.3.5`
>|form|valu|created|tags|
>|---|---|---|---|
>| inet:ipv4 | 1.2.3.5 | 2020/09/12 10:07:17 EDT | test.foo,<br/>test.testing |
>### Synapse Node Properties
>|.created|type|
>|---|---|
>| 1599919637048 | unicast |


### synapse-list-users
***
Lists current users in Synapse Cortex.


#### Base Command

`synapse-list-users`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Users.Admin | Boolean | True/False whether the Synapse user is an admin. | 
| Synapse.Users.Email | String | The email address of the Synapse user. | 
| Synapse.Users.Iden | String | The unique identifier of the Synapse user. | 
| Synapse.Users.Name | String | The user's Synapse username. | 
| Synapse.Users.Roles | String | The roles applied to the Synapse user. | 
| Synapse.Users.Rules | String | The rules applied to the Synapse user. | 


#### Command Example
```!synapse-list-users```

#### Context Example
```json
{
    "Synapse": {
        "Users": [
            {
                "Admin": true,
                "Email": null,
                "Iden": "9e4fe25a281f3f65aff2fa192d54c705",
                "Name": "root",
                "Roles": [],
                "Rules": []
            },
            {
                "Admin": false,
                "Email": null,
                "Iden": "a2bfead4c16b0354af2a92aa05588fc9",
                "Name": "testuser",
                "Roles": [
                    "xsoar-role",
                    "all"
                ],
                "Rules": []
            },
            {
                "Admin": false,
                "Email": null,
                "Iden": "eec037c730f0976a1b742b9f9773a52e",
                "Name": "xsoartesting",
                "Roles": [
                    "all"
                ],
                "Rules": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Synapse Users
>|Name|Email|Admin|Rules|Roles|
>|---|---|---|---|---|
>| root |  | true |  |  |
>| testuser |  | false |  | xsoar-role,<br/>all |
>| xsoartesting |  | false |  | all |


### synapse-list-roles
***
Lists current roles in Synapse Cortex.


#### Base Command

`synapse-list-roles`
#### Input

There are no input arguments for this command.

#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Roles.Iden | String | The unique identifier of the Synapse Role. | 
| Synapse.Roles.Name | String | The name of the Synapse Role. | 
| Synapse.Roles.Rules | String | The rules applied to the Synapse Role. | 


#### Command Example
```!synapse-list-roles```

#### Context Example
```json
{
    "Synapse": {
        "Roles": [
            {
                "Iden": "bcf176a4cbe240ae1dcf9fbebdffa680",
                "Name": "xsoar-role",
                "Rules": []
            },
            {
                "Iden": "c486fa9eb8d50a8c35a60687f12dc4c9",
                "Name": "all",
                "Rules": []
            },
            {
                "Iden": "e7e6ee238bc5bceeff96d10f100142ae",
                "Name": "xsoartestingrole",
                "Rules": []
            }
        ]
    }
}
```

#### Human Readable Output

>### Synapse Roles
>|Name|Iden|Rules|
>|---|---|---|
>| xsoar-role | bcf176a4cbe240ae1dcf9fbebdffa680 |  |
>| all | c486fa9eb8d50a8c35a60687f12dc4c9 |  |
>| xsoartestingrole | e7e6ee238bc5bceeff96d10f100142ae |  |


### synapse-create-user
***
Create a new Synapse user.


#### Base Command

`synapse-create-user`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| username | New username to be created. | Required | 
| password | Optionally set the new user's password. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Users.Admin | Boolean | True/False whether the Synapse user is an admin. | 
| Synapse.Users.Email | String | The email address of the Synapse user. | 
| Synapse.Users.Iden | String | The unique identifier of the Synapse user. | 
| Synapse.Users.Name | String | The user's Synapse username. | 
| Synapse.Users.Roles | String | The roles applied to the Synapse user. | 
| Synapse.Users.Rules | String | The rules applied to the Synapse user. | 


#### Command Example
```!synapse-create-user username="xsoardemo" password="secret"```

#### Context Example
```json
{
    "Synapse": {
        "Users": {
            "Admin": false,
            "Email": null,
            "Iden": "f1ac5126df0e7407a0804fc6bd41534d",
            "Name": "xsoardemo",
            "Roles": [
                "all"
            ],
            "Rules": []
        }
    }
}
```

#### Human Readable Output

>### Synapse New User
>|Name|Email|Admin|Rules|Roles|
>|---|---|---|---|---|
>| xsoardemo |  | false |  | all |


### synapse-create-role
***
Create a new Synapse role.


#### Base Command

`synapse-create-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| role | New role to create in Synapse. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Roles.Iden | String | The unique identifier of the Synapse Role. | 
| Synapse.Roles.Name | String | The name of the Synapse Role. | 
| Synapse.Roles.Rules | String | The rules applied to the Synapse Role. | 


#### Command Example
```!synapse-create-role role="xsoar-role-demo"```

#### Context Example
```json
{
    "Synapse": {
        "Roles": {
            "Iden": "029019964000fef6ccd2be428f496423",
            "Name": "xsoar-role-demo",
            "Rules": []
        }
    }
}
```

#### Human Readable Output

>### Synapse New Role
>|Name|Iden|Rules|
>|---|---|---|
>| xsoar-role-demo | 029019964000fef6ccd2be428f496423 |  |


### synapse-grant-user-role
***
Grants a user access to role based perrmissions.


#### Base Command

`synapse-grant-user-role`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| user | User's "iden" property - not the username. | Required | 
| role | Role's "iden" property - not the name of the role. | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Users.Admin | Boolean | True/False whether the Synapse user is an admin. | 
| Synapse.Users.Email | String | The email address of the Synapse user. | 
| Synapse.Users.Iden | String | The unique identifier of the Synapse user. | 
| Synapse.Users.Name | String | The user's Synapse username. | 
| Synapse.Users.Roles | String | The roles applied to the Synapse user. | 
| Synapse.Users.Rules | String | The rules applied to the Synapse user. | 


#### Command Example
```!synapse-grant-user-role user="a2bfead4c16b0354af2a92aa05588fc9" role="bcf176a4cbe240ae1dcf9fbebdffa680"```

#### Context Example
```json
{
    "Synapse": {
        "Users": {
            "Admin": false,
            "Email": null,
            "Iden": "a2bfead4c16b0354af2a92aa05588fc9",
            "Name": "testuser",
            "Roles": [
                "xsoar-role",
                "all"
            ],
            "Rules": []
        }
    }
}
```

#### Human Readable Output

>### Synapse New User Role
>|Name|Email|Admin|Rules|Roles|
>|---|---|---|---|---|
>| testuser |  | false |  | xsoar-role,<br/>all |


### synapse-query-model
***
Query the Synapse data model and return details for given type or form (i.e. "inet:ipv4" for an IPv4 IP address).


#### Base Command

`synapse-query-model`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| query | Type/Form query (i.e. "inet:ipv4" or "inet"fqdn") | Required | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Synapse.Model.Doc | String | The docstring associated with the particular Synapse model element. | 
| Synapse.Model.Example | String | An example of the given Synapse element. | 
| Synapse.Model.Form | String | A form is the definition of an object in the Synapse data model \(node\). | 
| Synapse.Model.Properties | String | The unique properties associated with the given Synapse object. | 
| Synapse.Model.Type | String | A Type is the definition of a data element within the data model. | 
| Synapse.Model.Valu | String | The given value of the Synapse object type. | 


#### Command Example
```!synapse-query-model query="file:bytes"```

#### Context Example
```json
{
    "Synapse": {
        "Model": {
            "Doc": "The file bytes type with SHA256 based primary property.",
            "Example": "N/A",
            "Form": "file:bytes",
            "Properties": {
                ".created": "The time the node was created in the cortex.",
                ".seen": "The time interval for first/last observation of the node.",
                "md5": "The md5 hash of the file.",
                "mime": "The \"best\" mime type name for the file.",
                "mime:pe:compiled": "The compile time of the file according to the PE header.",
                "mime:pe:exports:libname": "The export library name according to the PE.",
                "mime:pe:exports:time": "The export time of the file according to the PE.",
                "mime:pe:imphash": "The PE import hash of the file as calculated by pefile; https://github.com/erocarrera/pefile .",
                "mime:pe:pdbpath": "The PDB string according to the PE.",
                "mime:pe:richhdr": "The sha256 hash of the rich header bytes.",
                "mime:pe:size": "The size of the executable file according to the PE file header.",
                "mime:x509:cn": "The Common Name (CN) attribute of the x509 Subject.",
                "name": "The best known base name for the file.",
                "sha1": "The sha1 hash of the file.",
                "sha256": "The sha256 hash of the file.",
                "sha512": "The sha512 hash of the file.",
                "size": "The file size in bytes."
            },
            "Type": "file:bytes",
            "Valu": "file:bytes"
        }
    }
}
```

#### Human Readable Output

>### Synapse Model Type
>|Type|Doc|Example|
>|---|---|---|
>| file:bytes | The file bytes type with SHA256 based primary property. | N/A |
>### Synapse `file:bytes` Form Properties
>|.seen|.created|size|md5|sha1|sha256|sha512|name|mime|mime:x509:cn|mime:pe:size|mime:pe:imphash|mime:pe:compiled|mime:pe:pdbpath|mime:pe:exports:time|mime:pe:exports:libname|mime:pe:richhdr|
>|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
>| The time interval for first/last observation of the node. | The time the node was created in the cortex. | The file size in bytes. | The md5 hash of the file. | The sha1 hash of the file. | The sha256 hash of the file. | The sha512 hash of the file. | The best known base name for the file. | The "best" mime type name for the file. | The Common Name (CN) attribute of the x509 Subject. | The size of the executable file according to the PE file header. | The PE import hash of the file as calculated by pefile; https://github.com/erocarrera/pefile . | The compile time of the file according to the PE header. | The PDB string according to the PE. | The export time of the file according to the PE. | The export library name according to the PE. | The sha256 hash of the rich header bytes. |

