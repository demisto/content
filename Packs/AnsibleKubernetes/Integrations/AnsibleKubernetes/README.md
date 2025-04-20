This integration enables the management of Kubernetes environments using Ansible modules. The Ansible engine is self-contained and pre-configured as part of this pack onto your XSOAR server, all you need to do is provide credentials you are ready to use the feature rich commands.

# Authorize Cortex XSOAR for Ansible Kubernetes

This integration supports API Token, and Username/Password authentication. It is recommended to use API tokens.

To create a service account with API token use the following `kubectl` commands.

1. Create a service account
```
kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: xsoar
  namespace: kube-system
EOF
```

2. Create secret for the above service account.
```
kubectl apply -f - <<EOF
apiVersion: v1
kind: Secret
type: kubernetes.io/service-account-token
metadata:
  name: xsoar-secret
  namespace: kube-system
  annotations:
    kubernetes.io/service-account.name: xsoar
EOF
```

3. Grant the service account an appropriate role. Refer to [Kubernetes RBAC docs](https://kubernetes.io/docs/reference/access-authn-authz/rbac/) if granting more fine grain or scoped access.
```
kubectl apply -f - <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: xsoar-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: xsoar
  namespace: kube-system
EOF
```

4. Generate the service account token.
```
kubectl create token xsoar -n kube-system
```

5. Copy the output token and paste it into the API field.

## Configure Ansible Kubernetes on Cortex XSOAR

1. Navigate to **Settings** > **Integrations** > **Servers & Services**.
2. Search for Ansible Kubernetes.
3. Click **Add instance** to create and configure a new integration instance.

    | **Parameter** | **Description** | **Required** |
    | --- | --- | --- |
    | K8s Host URL | Provide a URL for accessing the API. | True |
    | Username | Provide a username for authenticating with the API. | False |
    | Password | Provide a password for authenticating with the API. | False |
    | API Key | Token used to authenticate with the API. | False |
    | Validate Certs | Allows connection when SSL certificates are not valid. Set to \`false\` when certificates are not trusted. | True |

## Testing

This integration does not support testing from the integration management screen. Instead it is recommended to use the `!k8s-info` command querying a object `kind` allowed by the RBAC assigned. For example `!k8s-info kind="svc"`
# Idempotence
The action commands in this integration are idempotent. This means that the result of performing it once is exactly the same as the result of performing it repeatedly without any intervening actions.

# State Arguement
Some of the commands in this integration take a state argument. These define the desired end state of the object being managed. As a result these commands are able to perform multiple management operations depending on the desired state value. Common state values are:
| **State** | **Result** |
| --- | --- |
| present | Object should exist. If not present, the object will be created with the provided parameters. If present but not with correct parameters, it will be modified to met provided parameters. |
| running | Object should be running not stopped. |
| stopped | Object should be stopped not running. |
| restarted | Object will be restarted. |
| absent | Object should not exist. If it it exists it will be deleted. |

## Complex Command Inputs
Some commands may require structured input arguments such as `lists` or `dictionary`, these can be provided in standard JSON notation wrapped in double curly braces. For example a argument called `dns_servers` that accepts a list of server IPs 8.8.8.8 and 8.8.4.4 would be entered as `dns_servers="{{ ['8.8.8.8', '8.8.4.4'] }}"`.

Other more advanced data manipulation tools such as [Ansible](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html)/[Jinja2 filters](https://jinja.palletsprojects.com/en/3.0.x/templates/#builtin-filters) can also be used in-line. For example to get a [random number](https://docs.ansible.com/ansible/2.9/user_guide/playbooks_filters.html#random-number-filter) between 0 and 60 you can use `{{ 60 | random }}`.
## Commands
You can execute these commands from the Cortex XSOAR CLI, as part of an automation, or in a playbook.
After you successfully execute a command, a DBot message appears in the War Room with the command details.
### k8s-k8s
***
Manage Kubernetes (K8s) objects
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/k8s_module.html


#### Base Command

`k8s-k8s`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| merge_type | Whether to override the default patch merge approach with a specific type. By default, the strategic merge will typically be used.<br/>For example, Custom Resource Definitions typically aren't updatable by the usual strategic merge. You may want to use `merge` if you see "strategic merge patch format is not supported"<br/>See `https://kubernetes.io/docs/tasks/run-application/update-api-object-kubectl-patch/#use-a-json-merge-patch-to-update-a-deployment`<br/>Requires openshift &gt;= 0.6.2<br/>If more than one merge_type is given, the merge_types will be tried in order<br/>If openshift &gt;= 0.6.2, this defaults to `['strategic-merge', 'merge']`, which is ideal for using the same parameters on resource kinds that combine Custom Resources and built-in resources. For openshift &lt; 0.6.2, the default is simply `strategic-merge`.<br/>mutually exclusive with `apply`. Possible values are: json, merge, strategic-merge. | Optional | 
| wait | Whether to wait for certain resource kinds to end up in the desired state. By default the module exits once Kubernetes has received the request<br/>Implemented for `state=present` for `Deployment`, `DaemonSet` and `Pod`, and for `state=absent` for all resource kinds.<br/>For resource kinds without an implementation, `wait` returns immediately unless `wait_condition` is set. Possible values are: Yes, No. Default is No. | Optional | 
| wait_sleep | Number of seconds to sleep between checks. Default is 5. | Optional | 
| wait_timeout | How long in seconds to wait for the resource to end up in the desired state. Ignored if `wait` is not set. Default is 120. | Optional | 
| wait_condition | Specifies a custom condition on the status to wait for. Ignored if `wait` is not set or is set to False. | Optional | 
| validate | how (if at all) to validate the resource definition against the kubernetes schema. Requires the kubernetes-validate python module and openshift &gt;= 0.8.0. | Optional | 
| append_hash | Whether to append a hash to a resource name for immutability purposes<br/>Applies only to ConfigMap and Secret resources<br/>The parameter will be silently ignored for other resource kinds<br/>The full definition of an object is needed to generate the hash - this means that deleting an object created with append_hash will only work if the same object is passed with state=absent (alternatively, just use state=absent with the name including the generated hash and append_hash=no)<br/>Requires openshift &gt;= 0.7.2. | Optional | 
| apply | `apply` compares the desired resource definition with the previously supplied resource definition, ignoring properties that are automatically generated<br/>`apply` works better with Services than 'force=yes'<br/>Requires openshift &gt;= 0.9.2<br/>mutually exclusive with `merge_type`. | Optional | 
| state | Determines if an object should be created, patched, or deleted. When set to `present`, an object will be created, if it does not already exist. If set to `absent`, an existing object will be deleted. If set to `present`, an existing object will be patched, if its attributes differ from those specified using `resource_definition` or `src`. Possible values are: absent, present. Default is present. | Optional | 
| force | If set to `yes`, and `state` is `present`, an existing object will be replaced. Possible values are: Yes, No. Default is No. | Optional | 
| api_version | Use to specify the API version. Use to create, delete, or discover an object without providing a full resource definition. Use in conjunction with `kind`, `name`, and `namespace` to identify a specific object. If `resource definition` is provided, the `apiVersion` from the `resource_definition` will override this option. Default is v1. | Optional | 
| kind | Use to specify an object model. Use to create, delete, or discover an object without providing a full resource definition. Use in conjunction with `api_version`, `name`, and `namespace` to identify a specific object. If `resource definition` is provided, the `kind` from the `resource_definition` will override this option. | Optional | 
| name | Use to specify an object name. Use to create, delete, or discover an object without providing a full resource definition. Use in conjunction with `api_version`, `kind` and `namespace` to identify a specific object. If `resource definition` is provided, the `metadata.name` value from the `resource_definition` will override this option. | Optional | 
| namespace | Use to specify an object namespace. Useful when creating, deleting, or discovering an object without providing a full resource definition. Use in conjunction with `api_version`, `kind`, and `name` to identify a specfic object. If `resource definition` is provided, the `metadata.namespace` value from the `resource_definition` will override this option. | Optional | 
| resource_definition | Provide a valid YAML definition (either as a string, list, or dict) for an object when creating or updating. NOTE: `kind`, `api_version`, `name`, and `namespace` will be overwritten by corresponding values found in the provided `resource_definition`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kubernetes.K8s.result | unknown | The created, patched, or otherwise present object. Will be empty in the case of a deletion. | 


#### Command Example
```!k8s-k8s name="testing" kind="Namespace" state="present" ```

#### Context Example
```json
{
    "Kubernetes": {
        "K8S": [
            {
                "changed": false,
                "method": "patch",
                "result": {
                    "apiVersion": "v1",
                    "kind": "Namespace",
                    "metadata": {
                        "creationTimestamp": "2021-07-04T16:08:41Z",
                        "managedFields": [
                            {
                                "apiVersion": "v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {
                                    "f:status": {
                                        "f:phase": {}
                                    }
                                },
                                "manager": "OpenAPI-Generator",
                                "operation": "Update",
                                "time": "2021-07-04T16:08:41Z"
                            }
                        ],
                        "name": "testing",
                        "resourceVersion": "34538",
                        "uid": "44296a6f-af82-45bf-af3e-e3a7327d7a30"
                    },
                    "spec": {
                        "finalizers": [
                            "Kubernetes"
                        ]
                    },
                    "status": {
                        "phase": "Active"
                    }
                },
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * method: patch
>  * ## Result
>    * apiVersion: v1
>    * kind: Namespace
>    * ### Metadata
>      * creationTimestamp: 2021-07-04T16:08:41Z
>      * name: testing
>      * resourceVersion: 34538
>      * uid: 44296a6f-af82-45bf-af3e-e3a7327d7a30
>      * #### Managedfields
>      * #### List
>        * apiVersion: v1
>        * fieldsType: FieldsV1
>        * manager: OpenAPI-Generator
>        * operation: Update
>        * time: 2021-07-04T16:08:41Z
>        * ##### Fieldsv1
>          * ###### F:Status
>            * ####### F:Phase
>    * ### Spec
>      * #### Finalizers
>        * 0: kubernetes
>    * ### Status
>      * phase: Active


### k8s-info
***
Describe Kubernetes (K8s) objects
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/k8s_info_module.html


#### Base Command

`k8s-info`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_version | Use to specify the API version. in conjunction with `kind`, `name`, and `namespace` to identify a specific object. Default is v1. | Optional | 
| kind | Use to specify an object model. Use in conjunction with `api_version`, `name`, and `namespace` to identify a specific object. | Required | 
| name | Use to specify an object name.  Use in conjunction with `api_version`, `kind` and `namespace` to identify a specific object. | Optional | 
| namespace | Use to specify an object namespace. Use in conjunction with `api_version`, `kind`, and `name` to identify a specific object. | Optional | 
| label_selectors | List of label selectors to use to filter results. | Optional | 
| field_selectors | List of field selectors to use to filter results. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kubernetes.K8sInfo.resources | unknown | The object\(s\) that exists | 


#### Command Example
```!k8s-info kind="namespace" name="testing"```

#### Context Example
```json
{
    "Kubernetes": {
        "K8SInfo": [
            {
                "changed": false,
                "resources": [
                    {
                        "apiVersion": "v1",
                        "kind": "Namespace",
                        "metadata": {
                            "creationTimestamp": "2021-07-04T16:08:41Z",
                            "managedFields": [
                                {
                                    "apiVersion": "v1",
                                    "fieldsType": "FieldsV1",
                                    "fieldsV1": {
                                        "f:status": {
                                            "f:phase": {}
                                        }
                                    },
                                    "manager": "OpenAPI-Generator",
                                    "operation": "Update",
                                    "time": "2021-07-04T16:08:41Z"
                                }
                            ],
                            "name": "testing",
                            "resourceVersion": "34538",
                            "uid": "44296a6f-af82-45bf-af3e-e3a7327d7a30"
                        },
                        "spec": {
                            "finalizers": [
                                "Kubernetes"
                            ]
                        },
                        "status": {
                            "phase": "Active"
                        }
                    }
                ],
                "status": "SUCCESS"
            }
        ]
    }
}
```

#### Human Readable Output

>#  SUCCESS 
>  * changed: False
>  * ## Resources
>  * ## List
>    * apiVersion: v1
>    * kind: Namespace
>    * ### Metadata
>      * creationTimestamp: 2021-07-04T16:08:41Z
>      * name: testing
>      * resourceVersion: 34538
>      * uid: 44296a6f-af82-45bf-af3e-e3a7327d7a30
>      * #### Managedfields
>      * #### List
>        * apiVersion: v1
>        * fieldsType: FieldsV1
>        * manager: OpenAPI-Generator
>        * operation: Update
>        * time: 2021-07-04T16:08:41Z
>        * ##### Fieldsv1
>          * ###### F:Status
>            * ####### F:Phase
>    * ### Spec
>      * #### Finalizers
>        * 0: kubernetes
>    * ### Status
>      * phase: Active


### k8s-scale
***
Set a new size for a Deployment, ReplicaSet, Replication Controller, or Job.
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/k8s_scale_module.html


#### Base Command

`k8s-scale`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| api_version | Use to specify the API version. Use to create, delete, or discover an object without providing a full resource definition. Use in conjunction with `kind`, `name`, and `namespace` to identify a specific object. If `resource definition` is provided, the `apiVersion` from the `resource_definition` will override this option. Default is v1. | Optional | 
| kind | Use to specify an object model. Use to create, delete, or discover an object without providing a full resource definition. Use in conjunction with `api_version`, `name`, and `namespace` to identify a specific object. If `resource definition` is provided, the `kind` from the `resource_definition` will override this option. | Optional | 
| name | Use to specify an object name. Use to create, delete, or discover an object without providing a full resource definition. Use in conjunction with `api_version`, `kind` and `namespace` to identify a specific object. If `resource definition` is provided, the `metadata.name` value from the `resource_definition` will override this option. | Optional | 
| namespace | Use to specify an object namespace. Useful when creating, deleting, or discovering an object without providing a full resource definition. Use in conjunction with `api_version`, `kind`, and `name` to identify a specfic object. If `resource definition` is provided, the `metadata.namespace` value from the `resource_definition` will override this option. | Optional | 
| resource_definition | Provide a valid YAML definition (either as a string, list, or dict) for an object when creating or updating. NOTE: `kind`, `api_version`, `name`, and `namespace` will be overwritten by corresponding values found in the provided `resource_definition`. | Optional | 
| replicas | The desired number of replicas. | Optional | 
| current_replicas | For Deployment, ReplicaSet, Replication Controller, only scale, if the number of existing replicas matches. In the case of a Job, update parallelism only if the current parallelism value matches. | Optional | 
| resource_version | Only attempt to scale, if the current object version matches. | Optional | 
| wait | For Deployment, ReplicaSet, Replication Controller, wait for the status value of `ready_replicas` to change to the number of `replicas`. In the case of a Job, this option is ignored. Possible values are: Yes, No. Default is Yes. | Optional | 
| wait_timeout | When `wait` is `True`, the number of seconds to wait for the `ready_replicas` status to equal  `replicas`. If the status is not reached within the allotted time, an error will result. In the case of a Job, this option is ignored. Default is 20. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kubernetes.K8sScale.result | unknown | If a change was made, will return the patched object, otherwise returns the existing object. | 


#### Command Example
```!k8s-scale kind="Deployment" name="nginx-deployment" namespace="testing" replicas="2" wait_timeout="60"```

#### Context Example
```json
{
    "Kubernetes": {
        "K8SScale": [
            {
                "changed": true,
                "duration": 5,
                "result": {
                    "apiVersion": "apps/v1",
                    "kind": "Deployment",
                    "metadata": {
                        "annotations": {
                            "deployment.kubernetes.io/revision": "1",
                            "kubectl.kubernetes.io/last-applied-configuration": "{\"apiVersion\":\"apps/v1\",\"kind\":\"Deployment\",\"metadata\":{\"annotations\":{},\"labels\":{\"app\":\"nginx\"},\"name\":\"nginx-deployment\",\"namespace\":\"testing\"},\"spec\":{\"replicas\":3,\"selector\":{\"matchLabels\":{\"app\":\"nginx\"}},\"template\":{\"metadata\":{\"labels\":{\"app\":\"nginx\"}},\"spec\":{\"containers\":[{\"image\":\"nginx:1.14.2\",\"name\":\"nginx\",\"ports\":[{\"containerPort\":80}]}]}}}}\n"
                        },
                        "creationTimestamp": "2021-07-04T16:42:43Z",
                        "generation": 2,
                        "labels": {
                            "app": "nginx"
                        },
                        "managedFields": [
                            {
                                "apiVersion": "apps/v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {
                                    "f:metadata": {
                                        "f:annotations": {
                                            ".": {},
                                            "f:kubectl.kubernetes.io/last-applied-configuration": {}
                                        },
                                        "f:labels": {
                                            ".": {},
                                            "f:app": {}
                                        }
                                    },
                                    "f:spec": {
                                        "f:progressDeadlineSeconds": {},
                                        "f:replicas": {},
                                        "f:revisionHistoryLimit": {},
                                        "f:selector": {},
                                        "f:strategy": {
                                            "f:rollingUpdate": {
                                                ".": {},
                                                "f:maxSurge": {},
                                                "f:maxUnavailable": {}
                                            },
                                            "f:type": {}
                                        },
                                        "f:template": {
                                            "f:metadata": {
                                                "f:labels": {
                                                    ".": {},
                                                    "f:app": {}
                                                }
                                            },
                                            "f:spec": {
                                                "f:containers": {
                                                    "k:{\"name\":\"nginx\"}": {
                                                        ".": {},
                                                        "f:image": {},
                                                        "f:imagePullPolicy": {},
                                                        "f:name": {},
                                                        "f:ports": {
                                                            ".": {},
                                                            "k:{\"containerPort\":80,\"protocol\":\"TCP\"}": {
                                                                ".": {},
                                                                "f:containerPort": {},
                                                                "f:protocol": {}
                                                            }
                                                        },
                                                        "f:resources": {},
                                                        "f:terminationMessagePath": {},
                                                        "f:terminationMessagePolicy": {}
                                                    }
                                                },
                                                "f:dnsPolicy": {},
                                                "f:restartPolicy": {},
                                                "f:schedulerName": {},
                                                "f:securityContext": {},
                                                "f:terminationGracePeriodSeconds": {}
                                            }
                                        }
                                    }
                                },
                                "manager": "kubectl-client-side-apply",
                                "operation": "Update",
                                "time": "2021-07-04T16:42:43Z"
                            }
                        ],
                        "name": "nginx-deployment",
                        "namespace": "testing",
                        "resourceVersion": "38764",
                        "uid": "364a24b7-211d-4f9d-8573-9310f5850e50"
                    },
                    "spec": {
                        "progressDeadlineSeconds": 600,
                        "replicas": 2,
                        "revisionHistoryLimit": 10,
                        "selector": {
                            "matchLabels": {
                                "app": "nginx"
                            }
                        },
                        "strategy": {
                            "rollingUpdate": {
                                "maxSurge": "25%",
                                "maxUnavailable": "25%"
                            },
                            "type": "RollingUpdate"
                        },
                        "template": {
                            "metadata": {
                                "creationTimestamp": null,
                                "labels": {
                                    "app": "nginx"
                                }
                            },
                            "spec": {
                                "containers": [
                                    {
                                        "image": "nginx:1.14.2",
                                        "imagePullPolicy": "IfNotPresent",
                                        "name": "nginx",
                                        "ports": [
                                            {
                                                "containerPort": 80,
                                                "protocol": "TCP"
                                            }
                                        ],
                                        "resources": {},
                                        "terminationMessagePath": "/dev/termination-log",
                                        "terminationMessagePolicy": "File"
                                    }
                                ],
                                "dnsPolicy": "ClusterFirst",
                                "restartPolicy": "Always",
                                "schedulerName": "default-scheduler",
                                "securityContext": {},
                                "terminationGracePeriodSeconds": 30
                            }
                        }
                    },
                    "status": {
                        "availableReplicas": 2,
                        "conditions": [
                            {
                                "lastTransitionTime": "2021-07-04T16:42:52Z",
                                "lastUpdateTime": "2021-07-04T16:42:52Z",
                                "message": "Deployment has minimum availability.",
                                "reason": "MinimumReplicasAvailable",
                                "status": "True",
                                "type": "Available"
                            }
                        ],
                        "observedGeneration": 2,
                        "readyReplicas": 2,
                        "replicas": 2,
                        "updatedReplicas": 2
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * duration: 5
>  * ## Result
>    * apiVersion: apps/v1
>    * kind: Deployment
>    * ### Metadata
>      * creationTimestamp: 2021-07-04T16:42:43Z
>      * generation: 2
>      * name: nginx-deployment
>      * namespace: testing
>      * resourceVersion: 38764
>      * uid: 364a24b7-211d-4f9d-8573-9310f5850e50
>      * #### Annotations
>        * deployment.kubernetes.io/revision: 1
>        * kubectl.kubernetes.io/last-applied-configuration: {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"annotations":{},"labels":{"app":"nginx"},"name":"nginx-deployment","namespace":"testing"},"spec":{"replicas":3,"selector":{"matchLabels":{"app":"nginx"}},"template":{"metadata":{"labels":{"app":"nginx"}},"spec":{"containers":[{"image":"nginx:1.14.2","name":"nginx","ports":[{"containerPort":80}]}]}}}}
>
>      * #### Labels
>        * app: nginx
>      * #### Managedfields
>      * #### List
>        * apiVersion: apps/v1
>        * fieldsType: FieldsV1
>        * manager: kubectl-client-side-apply
>        * operation: Update
>        * time: 2021-07-04T16:42:43Z
>        * ##### Fieldsv1
>          * ###### F:Metadata
>            * ####### F:Annotations
>              * ######## .
>              * ######## F:Kubectl.Kubernetes.Io/Last-Applied-Configuration
>            * ####### F:Labels
>              * ######## .
>              * ######## F:App
>          * ###### F:Spec
>            * ####### F:Progressdeadlineseconds
>            * ####### F:Replicas
>            * ####### F:Revisionhistorylimit
>            * ####### F:Selector
>            * ####### F:Strategy
>              * ######## F:Rollingupdate
>                * ######### .
>                * ######### F:Maxsurge
>                * ######### F:Maxunavailable
>              * ######## F:Type
>            * ####### F:Template
>              * ######## F:Metadata
>                * ######### F:Labels
>                  * ########## .
>                  * ########## F:App
>              * ######## F:Spec
>                * ######### F:Containers
>                  * ########## K:{"Name":"Nginx"}
>                    * ########### .
>                    * ########### F:Image
>                    * ########### F:Imagepullpolicy
>                    * ########### F:Name
>                    * ########### F:Ports
>                      * ############ .
>                      * ############ K:{"Containerport":80,"Protocol":"Tcp"}
>                        * ############# .
>                        * ############# F:Containerport
>                        * ############# F:Protocol
>                    * ########### F:Resources
>                    * ########### F:Terminationmessagepath
>                    * ########### F:Terminationmessagepolicy
>                * ######### F:Dnspolicy
>                * ######### F:Restartpolicy
>                * ######### F:Schedulername
>                * ######### F:Securitycontext
>                * ######### F:Terminationgraceperiodseconds
>      * #### List
>        * apiVersion: apps/v1
>        * fieldsType: FieldsV1
>        * manager: kube-controller-manager
>        * operation: Update
>        * time: 2021-07-04T16:42:52Z
>        * ##### Fieldsv1
>          * ###### F:Metadata
>            * ####### F:Annotations
>              * ######## F:Deployment.Kubernetes.Io/Revision
>          * ###### F:Status
>            * ####### F:Availablereplicas
>            * ####### F:Conditions
>              * ######## .
>              * ######## K:{"Type":"Available"}
>                * ######### .
>                * ######### F:Lasttransitiontime
>                * ######### F:Lastupdatetime
>                * ######### F:Message
>                * ######### F:Reason
>                * ######### F:Status
>                * ######### F:Type
>            * ####### F:Observedgeneration
>            * ####### F:Readyreplicas
>            * ####### F:Replicas
>            * ####### F:Updatedreplicas
>    * ### Spec
>      * progressDeadlineSeconds: 600
>      * replicas: 2
>      * revisionHistoryLimit: 10
>      * #### Selector
>        * ##### Matchlabels
>          * app: nginx
>      * #### Strategy
>        * type: RollingUpdate
>        * ##### Rollingupdate
>          * maxSurge: 25%
>          * maxUnavailable: 25%
>      * #### Template
>        * ##### Metadata
>          * creationTimestamp: None
>          * ###### Labels
>            * app: nginx
>        * ##### Spec
>          * dnsPolicy: ClusterFirst
>          * restartPolicy: Always
>          * schedulerName: default-scheduler
>          * terminationGracePeriodSeconds: 30
>          * ###### Containers
>          * ###### Nginx
>            * image: nginx:1.14.2
>            * imagePullPolicy: IfNotPresent
>            * name: nginx
>            * terminationMessagePath: /dev/termination-log
>            * terminationMessagePolicy: File
>            * ####### Ports
>            * ####### List
>              * containerPort: 80
>              * protocol: TCP
>            * ####### Resources
>          * ###### Securitycontext
>    * ### Status
>      * availableReplicas: 2
>      * observedGeneration: 2
>      * readyReplicas: 2
>      * replicas: 2
>      * updatedReplicas: 2
>      * #### Conditions
>      * #### List
>        * lastTransitionTime: 2021-07-04T16:42:52Z
>        * lastUpdateTime: 2021-07-04T16:42:52Z
>        * message: Deployment has minimum availability.
>        * reason: MinimumReplicasAvailable
>        * status: True
>        * type: Available
>      * #### List
>        * lastTransitionTime: 2021-07-04T16:42:43Z
>        * lastUpdateTime: 2021-07-04T16:42:52Z
>        * message: ReplicaSet "nginx-deployment-66b6c48dd5" has successfully progressed.
>        * reason: NewReplicaSetAvailable
>        * status: True
>        * type: Progressing


### k8s-service
***
Manage Services on Kubernetes
Further documentation available at https://docs.ansible.com/ansible/2.9/modules/k8s_service_module.html


#### Base Command

`k8s-service`
#### Input

| **Argument Name** | **Description** | **Required** |
| --- | --- | --- |
| resource_definition | A partial YAML definition of the Service object being created/updated. Here you can define Kubernetes Service Resource parameters not covered by this module's parameters.<br/>NOTE: `resource_definition` has lower priority than module parameters. If you try to define e.g. `metadata.namespace` here, that value will be ignored and `metadata` used instead. | Optional | 
| state | Determines if an object should be created, patched, or deleted. When set to `present`, an object will be created, if it does not already exist. If set to `absent`, an existing object will be deleted. If set to `present`, an existing object will be patched, if its attributes differ from those specified using module options and `resource_definition`. Possible values are: present, absent. Default is present. | Optional | 
| force | If set to `True`, and `state` is `present`, an existing object will be replaced. Possible values are: Yes, No. Default is No. | Optional | 
| merge_type | Whether to override the default patch merge approach with a specific type. By default, the strategic merge will typically be used.<br/>For example, Custom Resource Definitions typically aren't updatable by the usual strategic merge. You may want to use `merge` if you see "strategic merge patch format is not supported"<br/>See `https://kubernetes.io/docs/tasks/run-application/update-api-object-kubectl-patch/#use-a-json-merge-patch-to-update-a-deployment`<br/>Requires openshift &gt;= 0.6.2<br/>If more than one merge_type is given, the merge_types will be tried in order<br/>If openshift &gt;= 0.6.2, this defaults to `['strategic-merge', 'merge']`, which is ideal for using the same parameters on resource kinds that combine Custom Resources and built-in resources. For openshift &lt; 0.6.2, the default is simply `strategic-merge`. Possible values are: json, merge, strategic-merge. | Optional | 
| name | Use to specify a Service object name. | Required | 
| namespace | Use to specify a Service object namespace. | Required | 
| type | Specifies the type of Service to create.<br/>See `https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types`. Possible values are: NodePort, ClusterIP, LoadBalancer, ExternalName. | Optional | 
| ports | A list of ports to expose.<br/>`https://kubernetes.io/docs/concepts/services-networking/service/#multi-port-services`. | Optional | 
| selector | Label selectors identify objects this Service should apply to.<br/>`https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/`. | Optional | 


#### Context Output

| **Path** | **Type** | **Description** |
| --- | --- | --- |
| Kubernetes.K8sService.result | unknown | The created, patched, or otherwise present Service object. Will be empty in the case of a deletion. | 


#### Command Example
```!k8s-service state="present" name="test-https" namespace="testing" ports="{{ [{'port': 443, 'protocol': 'TCP'}] }}" selector="{'app': 'nginx'}" ```

#### Context Example
```json
{
    "Kubernetes": {
        "K8SService": [
            {
                "changed": true,
                "method": "create",
                "result": {
                    "apiVersion": "v1",
                    "kind": "Service",
                    "metadata": {
                        "creationTimestamp": "2021-07-04T16:49:51Z",
                        "managedFields": [
                            {
                                "apiVersion": "v1",
                                "fieldsType": "FieldsV1",
                                "fieldsV1": {
                                    "f:spec": {
                                        "f:ports": {
                                            ".": {},
                                            "k:{\"port\":443,\"protocol\":\"TCP\"}": {
                                                ".": {},
                                                "f:port": {},
                                                "f:protocol": {},
                                                "f:targetPort": {}
                                            }
                                        },
                                        "f:selector": {
                                            ".": {},
                                            "f:app": {}
                                        },
                                        "f:sessionAffinity": {},
                                        "f:type": {}
                                    }
                                },
                                "manager": "OpenAPI-Generator",
                                "operation": "Update",
                                "time": "2021-07-04T16:49:51Z"
                            }
                        ],
                        "name": "test-https",
                        "namespace": "testing",
                        "resourceVersion": "38785",
                        "uid": "71dd0d2d-9c84-497f-b900-6ba4357a325d"
                    },
                    "spec": {
                        "clusterIP": "1.1.1.1",
                        "clusterIPs": [
                            "1.1.1.1"
                        ],
                        "ports": [
                            {
                                "port": 443,
                                "protocol": "TCP",
                                "targetPort": 443
                            }
                        ],
                        "selector": {
                            "app": "nginx"
                        },
                        "sessionAffinity": "None",
                        "type": "ClusterIP"
                    },
                    "status": {
                        "loadBalancer": {}
                    }
                },
                "status": "CHANGED"
            }
        ]
    }
}
```

#### Human Readable Output

>#  CHANGED 
>  * changed: True
>  * method: create
>  * ## Result
>    * apiVersion: v1
>    * kind: Service
>    * ### Metadata
>      * creationTimestamp: 2021-07-04T16:49:51Z
>      * name: test-https
>      * namespace: testing
>      * resourceVersion: 38785
>      * uid: 71dd0d2d-9c84-497f-b900-6ba4357a325d
>      * #### Managedfields
>      * #### List
>        * apiVersion: v1
>        * fieldsType: FieldsV1
>        * manager: OpenAPI-Generator
>        * operation: Update
>        * time: 2021-07-04T16:49:51Z
>        * ##### Fieldsv1
>          * ###### F:Spec
>            * ####### F:Ports
>              * ######## .
>              * ######## K:{"Port":443,"Protocol":"Tcp"}
>                * ######### .
>                * ######### F:Port
>                * ######### F:Protocol
>                * ######### F:Targetport
>            * ####### F:Selector
>              * ######## .
>              * ######## F:App
>            * ####### F:Sessionaffinity
>            * ####### F:Type
>    * ### Spec
>      * clusterIP: 1.1.1.1
>      * sessionAffinity: None
>      * type: ClusterIP
>      * #### Clusterips
>        * 0: 1.1.1.1
>      * #### Ports
>      * #### List
>        * port: 443
>        * protocol: TCP
>        * targetPort: 443
>      * #### Selector
>        * app: nginx
>    * ### Status
>      * #### Loadbalancer


### Troubleshooting
The Ansible-Runner container is not suitable for running as a non-root user.
Therefore, the Ansible integrations will fail if you follow the instructions in [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Docker-Hardening-Guide) or [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide) or [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide). 

The `docker.run.internal.asuser` server configuration causes the software that is run inside of the Docker containers utilized by Cortex XSOAR to run as a non-root user account inside the container.

The Ansible-Runner software is required to run as root as it applies its own isolation via bwrap to the Ansible execution environment. 

This is a limitation of the Ansible-Runner software itself https://github.com/ansible/ansible-runner/issues/611.

A workaround is to use the `docker.run.internal.asuser.ignore` server setting and to configure Cortex XSOAR to ignore the Ansible container image by setting the value of `demisto/ansible-runner` and afterwards running /reset_containers to reload any containers that might be running to ensure they receive the configuration.

See step 2 of this [Docker hardening guide (Cortex XSOAR 6.13)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/6.13/Cortex-XSOAR-Administrator-Guide/Run-Docker-with-Non-Root-Internal-Users). For Cortex XSOAR 8 Cloud see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8 Cloud)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8/Cortex-XSOAR-Cloud-Documentation/Docker-hardening-guide). For Cortex XSOAR 8.7 On-prem see step 3 in *Run Docker with non-root internal users* of this [Docker hardening guide (Cortex XSOAR 8.7 On-prem)](https://docs-cortex.paloaltonetworks.com/r/Cortex-XSOAR/8.7/Cortex-XSOAR-On-prem-Documentation/Docker-hardening-guide) for complete instructions.
