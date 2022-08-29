import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

""" IMPORTS """
# Std imports
import re
from time import sleep
# 3-rd party imports
from typing import Dict, List, Optional, Tuple, Union

import requests
import urllib3
# Local imports
from akamai.edgegrid import EdgeGridAuth

"""

GLOBALS/PARAMS

Attributes:
    INTEGRATION_NAME:
        Name of the integration as shown in the integration UI, for example: Microsoft Graph User.

    INTEGRATION_COMMAND_NAME:
        Command names should be written in all lower-case letters,
        and each word separated with a hyphen, for example: msgraph-user.

    INTEGRATION_CONTEXT_NAME:
        Context output names should be written in camel case, for example: MSGraphUser.
"""


INTEGRATION_NAME = 'Akamai WAF'
INTEGRATION_COMMAND_NAME = 'akamai'
INTEGRATION_CONTEXT_NAME = 'Akamai'
# Disable insecure warnings
urllib3.disable_warnings()


class Client(BaseClient):
    def test_module(self) -> Dict:
        """
            Performs basic GET request to check if the API is reachable and authentication is successful.
        Returns:
            Response dictionary
        """
        return self.get_network_lists(extended=False, include_elements=False)

    # Created by C.L.
    def create_enrollment(self,
                          contractId: str,
                          Country: str,
                          Company: str,
                          OrganizationalUnit: str,
                          City: str,
                          adminContact: dict,
                          techContact: dict,
                          org: dict,
                          csr_cn: str = "",
                          changeManagement: bool = False,
                          certificateType: str = "third-party",
                          enableMultiStackedCertificates: bool = False,  # TBD
                          networkConfiguration_geography: str = "core",
                          networkConfiguration_quicEnabled: bool = True,
                          networkConfiguration_secureNetwork: str = "enhanced-tls",
                          networkConfiguration_sniOnly: bool = True,
                          ra: str = "third-party",
                          validationType: str = "third-party",
                          ) -> dict:
        """
            Create an enrollment
        Args:
            contractId:                 Contract id
            Country:                    Country - Two Letter format
            Company:                    Company Name
            OrganizationalUnit:         Organizational Unit
            City:                       City Name
            adminContact:               Admin Contact - Dictionary
            techContact:                techContact - Dictionary
            org:                        Organization name - Dictionary
            csr_cn:                     CName
            contractId:                 Specify the contract on which to operate or view.
            csr_cn:                     CName to be created
            changeManagement:           changeManagement
            certificateType:            Certificate Type
            enableMultiStackedCertificates:     Enable Multi Stacked Certificates
            networkConfiguration_geography:     Network Configuration geography
            networkConfiguration_quicEnabled:   Network Configuration QuicEnabled
            networkConfiguration_secureNetwork: Network Configuration SecureNetwork
            networkConfiguration_sniOnly:       Network Configuration sniOnly
            ra: str = "third-party",
            validationType: str = "third-party",

        Returns:
            Json response as dictionary
        """
        params = {
            "contractId": contractId,
        }

        body = {"csr": {"cn": csr_cn, "c": Country, "o": Company,
                        "ou": OrganizationalUnit, "l": City,
                        },
                "adminContact": adminContact,
                "techContact": techContact,
                "org": org,
                "networkConfiguration": {"geography": networkConfiguration_geography,
                                         "quicEnabled": networkConfiguration_quicEnabled,
                                         "sniOnly": networkConfiguration_sniOnly,
                                         "secureNetwork": networkConfiguration_secureNetwork,
                                         "dnsNameSettings": {"cloneDnsNames": False},
                                         },
                "certificateType": certificateType,
                "changeManagement": changeManagement,
                "enableMultiStackedCertificates": enableMultiStackedCertificates,  # TBD
                "ra": ra,
                "validationType": validationType,
                "thirdParty": {"excludeSans": False}
                }

        # Add Authorization header to this snippet
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollment-status.v1+json",
            "Content-Type": "application/vnd.akamai.cps.enrollment.v11+json"
        }
        response = self._http_request(method='POST',
                                      url_suffix='/cps/v2/enrollments',
                                      params=params,
                                      json_data=body,
                                      headers=headers)
        return response

    # Created by C.L.

    def list_enrollments(self,
                         contractId: str,
                         ) -> dict:
        """
            List enrollments
        Args:
            contractId: Specify the contract on which to operate or view.

        Returns:
            Json response as dictionary
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollments.v11+json",

        }
        params = {
            "contractId": contractId,
        }
        return self._http_request(method='GET',
                                  url_suffix='/cps/v2/enrollments',
                                  headers=headers,
                                  params=params)

    # Created by C.L.

    def get_change(self,
                   enrollment_path: str,
                   allowedInputTypeParam: str = "third-party-csr"
                   ) -> dict:
        """
            Get change
        Args:
            enrollment_path: The path that includes enrollmentId and changeId : e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
            allowedInputTypeParam: Specify the contract on which to operate or view.

        Returns:
            Json response as dictionary
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.csr.v2+json",
        }
        return self._http_request(method='GET',
                                  url_suffix=f'{enrollment_path}/input/info/{allowedInputTypeParam}',
                                  headers=headers)

    # Created by C.L.
    def update_change(self,
                      change_path: str,
                      Keyfactor_Certificate: str,
                      Keyfactor_TrustChain: str,
                      allowedInputTypeParam: str = "third-party-cert-and-trust-chain"
                      ) -> dict:
        """
            Update a change
        Args:
            change_path: The path that includes enrollmentId and changeId : e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
            changeId: Specify the ChangeID on which to operate or view.
            enrollmentId: Specify the enrollmentID on which to operate or view.
            allowedInputTypeParam: Specify the contract on which to operate or view.

        Returns:
            Json response as dictionary
        """
        payload = {
            'certificatesAndTrustChains': [{
                'certificate': Keyfactor_Certificate,
                'keyAlgorithm': 'RSA',
                'trustChain': Keyfactor_TrustChain,
        }]}
        headers = {
            "Accept": "application/vnd.akamai.cps.change-id.v1+json",
            "Content-Type": "application/vnd.akamai.cps.certificate-and-trust-chain.v2+json",
        }

        return self._http_request(method='POST',
                                  url_suffix=f"{change_path}/input/update/{allowedInputTypeParam}",
                                  headers=headers,
                                  data=payload
                                  )

    # Created by C.L.

    def list_groups(self) -> dict:

        all_groups = self._http_request(method='GET', url_suffix=f'/identity-management/v2/user-admin/groups')

        return all_groups

    def get_group(self,
                  groupID: int = 0
                  ) -> dict:
        """
            Get the information of a group
        Args:
            groupID : Group ID

        Returns:
            Json response as dictionary
        """
        # Add Authorization header to this snippet
        headers = {"Accept": "application/json"}

        return self._http_request(method='GET',
                                  url_suffix=f"/identity-management/v2/user-admin/groups/{groupID}?actions=false",
                                  headers=headers)

    # Created by C.L.

    def create_new_group(self,
                         groupID: int = 0, groupname: str = ""
                         ) -> dict:
        """
            Create a new group
        Args:
            groupID : Group ID

        Returns:
            Json response as dictionary
        """

        body = {"groupName": groupname}
        # Add Authorization header to this snippet
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        return self._http_request(method='POST',
                                  url_suffix=f"/identity-management/v2/user-admin/groups/{groupID}",
                                  json_data=body,
                                  headers=headers)

    # Created by C.L.
    def get_domains(self):
        """
            Get all of the existing domains

        Returns:
            Json response as dictionary
        """
        headers = {"Accept": "application/json"}

        return self._http_request(method='GET',
                                  url_suffix="/config-gtm/v1/domains",
                                  headers=headers)

    # Created by C.L.
    def get_a_domain(self, domainName: str):
        """
            Get information of a specific domain
        Args:
            domainName : Domain Name

        Returns:
            Json response as dictionary
        """
        url_suffix = f"/config-gtm/v1/domains/{domainName}"

        headers = {"Accept": "application/vnd.config-gtm.v1.5+json"}
        response = self._http_request(method='GET',
                                      url_suffix=url_suffix,
                                      headers=headers)
        return response

    # Created by C.L.
    def create_domain(self, groupId: int, domainName: str) -> dict:
        """
           Creating domains
        Args:
            groupId : The group ID
            domainName: Domain Name

        Returns:
            Json response as dictionary
        """

        body = {
            "defaultErrorPenalty": 75,
            "defaultTimeoutPenalty": 25,
            "emailNotificationList": [
                "akamaizers@fisglobal.com"
            ],
            "endUserMappingEnabled": False,
            "mapUpdateInterval": 600,
            "maxProperties": 100,
            "maxResources": 512,
            "maxTestTimeout": 60,
            "maxTTL": 3600,
            "minTestInterval": 0,
            "minTTL": 0,
            "name": domainName,
            "type": "weighted",
            "loadImbalancePercentage": 10,
            "resources": [],
            "properties": [],
            "datacenters": []

        }
        headers = {
            "Accept": "application/vnd.config-gtm.v1.5+json",
            "Content-Type": "application/vnd.config-gtm.v1.5+json"
        }
        params = {
            "gid": groupId}

        return self._http_request(method='POST',
                                  url_suffix='/config-gtm/v1/domains',
                                  params=params,
                                  headers=headers,
                                  json_data=body)

    # Created by C.L.
    def create_datacenter(self, domainName: str, DC_name: str = "", DC_country: str = "",):
        """
        Updating or adding datacenter to existing GTM domain
        Args:

            domainName: Domain Name
            DC_nam2: The name of the Data center
            DC_country: The country of the Data center


        Returns:
            Json response as dictionary
        """

        body = {
            "nickname": DC_name,
            "scorePenalty": 0,
            "country": DC_country,
            "virtual": True,
            "cloudServerTargeting": False,
            "cloudServerHostHeaderOverride": False,
        }

        headers = {
            "Accept": "application/vnd.config-gtm.v1.5+json",
            "Content-Type": "application/datacenter-vnd-config-gtm.v1.5+json"
        }

        return self._http_request(method='POST',
                                  url_suffix=f'/config-gtm/v1/domains/{domainName}/datacenters',
                                  headers=headers,
                                  json_data=body)

    # Created by C.L.

    def update_property(self, property_type: str, domainName: str, property_name: str,
                        static_type: str = "", static_server: str = "", server_1: str = "",
                        server_2: str = "", weight_1: int = 50, weight_2: int = 50):
        """
        Updating or adding properties to existing GTM domain

        Args:
            property_type : Property Type
            domainName: Domain Name
            property_name: Property Name
            static_type: The type of static property
            static_server: The server address of static property
            server_1: The address of server 1
            server_2: The address of server 2
            weight_1: The weight of server 1
            weight_2: The weight of server 2

        Returns:
            Json response as dictionary
        """
        if property_type == "static":
            staticRRSets = [  # empty if type!=static
                {
                    "type": static_type,
                    "ttl": 300,
                    "rdata": [
                        static_server
                    ]
                }
            ]
            trafficTargets = []
        elif property_type == "failover":
            staticRRSets = []
            trafficTargets = []
            if server_1 != "":
                trafficTargets.append(
                    {
                        "datacenterId": 3131,  # static number
                        "enabled": True,
                        "weight": 1,              # 50 if type== round robin, 1 is primary if type==failover
                        "servers": [
                            server_1          # user input
                        ]
                    })
            if server_2 != "":
                trafficTargets.append(
                    {
                        "datacenterId": 3132,  # static number
                        "enabled": True,
                        "weight": 1,              # 50 if type== round robin, 1 is primary if type==failover
                        "servers": [
                            server_2          # user input
                        ]
                    })

        elif property_type == "weighted-round-robin":
            staticRRSets = []
            trafficTargets = []
            if server_1 != "":
                trafficTargets.append(

                    {
                        "datacenterId": 3131,  # static number
                        "enabled": True,
                        "weight": weight_1,              # 50 if type== round robin, 1 is primary if type==failover
                        "servers": [
                            server_1          # user input
                        ]
                    }


                )
            if server_2 != "":
                trafficTargets.append(
                    {
                        "datacenterId": 3132,
                        "enabled": True,
                        "weight": weight_2,                 # 50 if type== round robin, 0 is secondary if type==failover
                        "servers": [
                            server_2            # user input
                        ]
                    }

                )

        body = {
            "balanceByDownloadScore": False,
            "dynamicTTL": 60,
            "failoverDelay": 0,
            "failbackDelay": 0,
            "ghostDemandReporting": False,
            "comments": f"updated- Origin for {domainName}",
            "handoutMode": "normal",
            "handoutLimit": 8,
            "livenessTests": [],
            "mxRecords": [],
            "name": property_name,
            "scoreAggregationType": "mean",
            "stickinessBonusConstant": 0,
            "stickinessBonusPercentage": 0,
            "staticRRSets": staticRRSets,
            "trafficTargets": trafficTargets,
            "type": property_type,
            "useComputedTargets": False,
            "ipv6": False

        }
        headers = {
            "Accept": "application/vnd.config-gtm.v1.5+json",
            "Content-Type": "application/vnd.config-gtm.v1.5+json"
        }

        return self._http_request(method='PUT',
                                  url_suffix=f'/config-gtm/v1/domains/{domainName}/properties/{property_name}',
                                  headers=headers,
                                  json_data=body)

    def get_network_lists(self,
                          search: str = None,
                          list_type: str = None,
                          extended: bool = True,
                          include_elements: bool = True,
                          ) -> dict:
        """
            Get network lists
        Args:
            search: Only list items that match the specified substring in any network list’s name or list of items.
            list_type: Filters the output to lists of only the given type of network lists if provided, either IP or GEO
            extended: Whether to return extended details in the response
            include_elements: Whether to return all list items.

        Returns:
            Json response as dictionary
        """
        params = {
            "search": search,
            "listType": list_type,
            "extended": extended,
            "includeElements": include_elements,
        }
        return self._http_request(method='GET',
                                  url_suffix='/network-list/v2/network-lists',
                                  params=params)

    def get_network_list_by_id(self, network_list_id: str) -> dict:
        """
            Get network list by ID
        Args:
            network_list_id: network list ID

        Returns:
            Json response as dictionary
        """
        params = {
            "extended": True,
            "includeElements": True
        }
        return self._http_request(method='GET',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}',
                                  params=params)

    def create_network_list(self, list_name: str, list_type: str, elements: Optional[Union[list, str]],
                            description: Optional[str] = None) -> dict:
        """
            Create network list
        Args:
            list_name: List name
            list_type: List type, e.g. IP
            description: Description of the list
            elements: list values

        Returns:
            Json response as dictionary
        """
        body = {
            "name": list_name,
            "type": list_type,
            "description": description,
            "list": elements if elements else []
        }
        return self._http_request(method='POST',
                                  url_suffix='/network-list/v2/network-lists',
                                  json_data=body)

    def delete_network_list(self, network_list_id: str) -> dict:
        """
            Delete network list by ID
        Args:
            network_list_id: network list ID

        Returns:
            Json response as dictionary
        """
        return self._http_request(method='DELETE',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}',
                                  resp_type='response')

    def update_network_list_elements(self, network_list_id: str, elements: Union[list, str]) -> dict:
        """
            Update network list by ID
        Args:
            network_list_id: The ID of the network list to update
            elements: A comma-separated list of elements to add to the network list.

        Returns:
            Json response as dictionary

        Notes: The API needs the body in the structure below:
        {
            "name":"SAMPLE 1 Anomali Blocklist 1",
            "syncPoint": 6,
            "type": "IP",
            "list": [
                "13.230.0.0/15",
                "195.7.50.194",
                "50.23.59.233"
            ]
        }

        We have everything except syncPoint. To make sure different API clients don’t overwrite each other’s
        data, their API supports optimistic concurrency control for any modifications to network lists.
        Whenever you run the Get a network list GET operation, you need to retain the value of the response’s
        syncPoint and pass it back in when you subsequently run the Update a network list PUT operation. The update
        operation only succeeds if there haven’t been any interim updates by other API clients. If the update fails,
        you get a 409 error response.

        """

        TempStr = elements[0].strip()
        TempStr = TempStr.upper()

        # demisto.results(TempStr)

        if (TempStr == 'BLANK'):
            elements = []

        raw_response: Dict = self.get_network_list_by_id(network_list_id=network_list_id)
        if raw_response:
            SyncPoint = raw_response.get('syncPoint')
            Name = raw_response.get('name')
            Type = raw_response.get('type')

        else:
            demisto.results("Could not get the Sync Point...")

        body = {
            "name": Name,
            "syncPoint": SyncPoint,
            "type": Type,
            "list": elements
        }

        return self._http_request(method='PUT',
                                  url_suffix=f'/network-list/v2/network-lists/'
                                  f'{network_list_id}?extended=true&includeElements=true',
                                  json_data=body)

    def activate_network_list(self, network_list_id: str, env: str, comment: Optional[str],
                              notify: Optional[list]) -> dict:
        """
            Activating network list in STAGING or PRODUCTION
        Args:
            network_list_id: Network list ID
            env: Staging/Production
            comment: Comment to be logged
            notify: List of email to be notified on activation

        Returns:
            Json response as dictionary
        """
        body = {
            "comments": comment,
            "notificationRecipients": notify
        }
        return self._http_request(method='POST',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}/environments/{env}'
                                             f'/activate',
                                  json_data=body,
                                  resp_type='response')

    def add_elements_to_network_list(self, network_list_id: str, elements: Optional[Union[list, str]]) -> dict:
        """
            Add elements to network list
        Args:
            network_list_id: Network list ID
            elements: List of value to append

        Returns:
            Json response as dictionary
        """
        body = {
            "list": elements
        }

        # demisto.results(elements)

        return self._http_request(method='POST',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}/append',
                                  json_data=body)

    def remove_element_from_network_list(self, network_list_id: str, element: str) -> dict:
        """
            Remove element from network list
        Args:
            network_list_id: Network list ID
            element: Element to remove

        Returns:
            Json response as dictionary
        """
        params = {
            'element': element
        }
        return self._http_request(method='DELETE',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}/elements',
                                  params=params,
                                  resp_type='response')

    def get_activation_status(self, network_list_id: str, env: str) -> dict:
        """
            Get activation status of network list in enviorment - Staging/Production
        Args:
            network_list_id: Network list ID
            env: Staging/Production

        Returns:
            Json response as dictionary
        """
        return self._http_request(method='GET',
                                  url_suffix=f'/network-list/v2/network-lists/{network_list_id}/environments/{env}/status')

    # Created by D.S.
    def new_papi_property(self,
                          productId: str,
                          propertyName: str,
                          contractId: str,
                          groupId: str,
                          ) -> dict:
        """
            Create a new papi property
        Args:
            productId
            propertyName
            contractId
            groupId

        Returns:
            The response provides a URL link to the newly created property.
        """
        body = {
            "productId": productId,
            "propertyName": propertyName,
            "ruleFormat": 'latest'
        }

        headers = {
            "Accept": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contractId,
            "groupId": groupId
        }

        return self._http_request(method='POST',
                                  url_suffix='/papi/v1/properties',
                                  headers=headers,
                                  json_data=body,
                                  params=params,
                                  )

    # created by D.S.
    def list_papi_property_bygroup(self,
                                   contractId: str,
                                   groupId: str) -> dict:
        """
            clone a new property from an existing template property
        Args:
            contractId:
            groupId:

        Returns:
            <Response [200]>
            The response provides a URL link to the newly created property.
        """

        params = {
            "contractId": contractId,
            "groupId": groupId,
        }

        headers = {
            "PAPI-Use-Prefixes": 'true'
        }

        return self._http_request(method='GET',
                                  url_suffix=f'papi/v1/properties',
                                  headers=headers,
                                  params=params)

    # created by D.S.
    def clone_papi_property(self,
                            productId: str,
                            propertyName: str,
                            contractId: str,
                            groupId: str,
                            propertyId: str,
                            version: str
                            ) -> dict:
        """
            Clone a new papi property from an existing template property
        Args:
            productId
            propertyName
            contractId
            groupId

        Returns:
            <Response [201]>
            The response provides a URL link to the newly created property.
        """
        body = {
            "productId": productId,
            "propertyName": propertyName,
            "cloneFrom": {
                "propertyId": propertyId,
                "version": version,
                "copyHostnames": "False"
            }
        }

        headers = {
            "Accept": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contractId,
            "groupId": groupId
        }

        return self._http_request(method='POST',
                                  url_suffix=f'papi/v1/properties',
                                  headers=headers,
                                  json_data=body,
                                  params=params
                                  )

    # created by D.S.
    def add_papi_property_hostname(self,
                                   propertyVersion: str,
                                   propertyId: str,
                                   contractId: str,
                                   groupId: str,
                                   validateHostnames: bool,
                                   includeCertStatus: bool,
                                   cnameFrom: str,
                                   edgeHostnameId: str,
                                   ) -> dict:
        """
            add a hostname into papi property
        Args:
            propertyVersion:
            propertyId:
            contractId:
            groupId:
            validateHostnames:
            includeCertStatus:
            cnameFrom:
            edgeHostnameId: str,

        Returns:
            <Response [200]>
            The response provides TBD
        """
        body = {
            "add": [
                {
                    "certProvisioningType": "CPS_MANAGED",
                    "cnameType": "EDGE_HOSTNAME",
                    "cnameFrom": cnameFrom,
                    "edgeHostnameId": edgeHostnameId,
                }
            ]
        }

        headers = {
            "Accept": 'application/json',
            "Content-Type": 'application/json',
            "PAPI-Use-Prefixes": 'true',
        }

        params = {
            "contractId": contractId,
            "groupId": groupId,
            "validateHostnames": validateHostnames,
            "includeCertStatus": includeCertStatus
        }

        return self._http_request(method='PATCH',
                                  url_suffix=f'papi/v1/properties/{propertyId}/versions/{propertyVersion}/hostnames',
                                  headers=headers,
                                  params=params,
                                  json_data=body)

    # created by D.S.
    def list_papi_edgehostname_bygroup(self,
                                       contractId: str,
                                       groupId: str,
                                       options: str) -> dict:
        """
            clone a new property from an existing template property
        Args:
            contractId:
            groupId:
            options:

        Returns:
            <Response [200]>
            The response provides a URL link to the newly created property.
        """

        params = {
            "contractId": contractId,
            "groupId": groupId,
            "options": options
        }

        headers = {
            "PAPI-Use-Prefixes": 'true'
        }

        return self._http_request(method='GET',
                                  url_suffix=f'papi/v1/edgehostnames',
                                  headers=headers,
                                  params=params)

    # created by D.S.
    def new_papi_edgehostname(self,
                              productId: str,
                              contractId: str,
                              groupId: str,
                              options: str,
                              domainPrefix: str,
                              domainSuffix: str,
                              ipVersionBehavior: str,
                              secure: str,
                              secureNetwork: str,
                              certEnrollmentId: str
                              ) -> dict:
        """
            add a new edge hostname via Papi
        Args:
            productId:
            contractId:
            groupId:
            options:
            domainPrefix:
            domainSuffix:
            ipVersionBehavior:
            secure:
            secureNetwork:
            certEnrollmentId:

        Returns:
            <Response [200]>
            The response provides TBD
        """
        body = {
            "productId": productId,
            "domainPrefix": domainPrefix,
            "domainSuffix": domainSuffix,
            "ipVersionBehavior": ipVersionBehavior,
            "secure": secure,
            "secureNetwork": secureNetwork,
            "certEnrollmentId": certEnrollmentId
        }

        headers = {
            "Accept": 'application/json',
            "Content-Type": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contractId,
            "groupId": groupId,
            "options": options
        }

        return self._http_request(method='POST',
                                  url_suffix=f'papi/v1/edgehostnames',
                                  headers=headers,
                                  json_data=body,
                                  params=params)

    # created by D.S.
    def list_cps_enrollments(self,
                             contractId: str,
                             ) -> dict:
        """
            list all cps enrollments
        Args:
            contractId

        Returns:
            <Response [201]>
            The response provides a URL link to the newly created property.
        """

        headers = {
            "Accept": 'application/vnd.akamai.cps.enrollments.v11+json'
        }

        contractId = contractId.split('_')[1]

        params = {
            "contractId": contractId
        }

        return self._http_request(method='GET',
                                  url_suffix=f'cps/v2/enrollments',
                                  headers=headers,
                                  params=params)

    # created by D.S.
    def list_papi_cpcodeid_bygroup(self,
                                   contractId: str,
                                   groupId: str) -> dict:
        """
            clone a new property from an existing template property
        Args:
            contractId:
            groupId:
            cpcodeName:

        Returns:
            <Response [200]>
            The response provides a URL link to the newly created property.
        """
        headers = {
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contractId,
            "groupId": groupId
        }

        return self._http_request(method='GET',
                                  url_suffix=f'papi/v1/cpcodes',
                                  headers=headers,
                                  params=params)

    # created by D.S.
    def new_papi_cpcode(self,
                        productId: str,
                        contractId: str,
                        groupId: str,
                        cpcodeName: str,
                        ) -> dict:
        """
            clone a new property from an existing template property
        Args:
            productId:
            contractId:
            groupId:
            cpcodeName:

        Returns:
            <Response [201]>
            The response provides a URL link to the newly created property.
        """
        body = {
            "productId": productId,
            "cpcodeName": cpcodeName
        }

        headers = {
            "Accept": 'application/json',
            "Content-Type": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contractId,
            "groupId": groupId
        }

        return self._http_request(method='POST',
                                  url_suffix=f'papi/v1/cpcodes',
                                  headers=headers,
                                  json_data=body,
                                  params=params)

    # created by D.S.
    def patch_papi_property_rule(self,
                                 contractId: str,
                                 groupId: str,
                                 propertyId: str,
                                 propertyVersion: str,
                                 validateRules: str,
                                 body,
                                 ) -> dict:
        """
            clone a new property from an existing template property
        Args:
            contractId: str,
            groupId: str,
            propertyId: str,
            propertyVersion: str,
            validateRules: str,
            body:

        Returns:
            <Response [201]>
            The response provides a URL link to the newly created property.
        """
        body = body

        headers = {
            "Accept": 'application/vnd.akamai.papirules.latest+json',
            "Content-Type": 'application/json-patch+json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contractId,
            "groupId": groupId,
            "validateRules": validateRules
        }

        return self._http_request(method='PATCH',
                                  url_suffix=f'/papi/v1/properties/{propertyId}/versions/{propertyVersion}/rules',
                                  headers=headers,
                                  params=params,
                                  json_data=body)

    # created by D.S.
    def activate_papi_property(self,
                               contractId: str,
                               groupId: str,
                               propertyId: str,
                               network: str,
                               notifyEmails: str,
                               propertyVersion: int,
                               ) -> str:
        """
            activate an property
        Args:
            contractId: str,
            groupId: str,
            propertyId: grp_#######
            network: "STAGING" or "PRODUCTION"
            notifyEmails: akamaizers@fisglobal.com
            propertyVersion:

        Returns:
            <Response [204]>
        """
        body = {
            "acknowledgeAllWarnings": "true",
            "activationType": "ACTIVATE",
            "fastPush": "true",
            "ignoreHttpErrors": "true",
            "network": network,
            "notifyEmails": [notifyEmails],
            "propertyVersion": propertyVersion,
            "useFastFallback": "false"
        }

        headers = {
            "Content-Type": "application/json",
            # "Accept": "application/json",
            # "PAPI-Use-Prefixes": "true"
        }

        params = {
            "contractId": contractId,
            "groupId": groupId
        }

        return self._http_request(method='POST',
                                  url_suffix=f'/papi/v1/properties/{propertyId}/activations',
                                  headers=headers,
                                  json_data=body,
                                  params=params)

    # created by D.S.
    def clone_security_policy(self,
                              configId: int,
                              configVersion: int,
                              createFromSecurityPolicy: str,
                              policyName: str,
                              policyPrefix: str
                              ) -> str:
        """
            Clone a new security policy from template policy
        Args:
            configId:
            createFromSecurityPolicy:
            policyName:
            configVersion:

        Returns:
            <Response [204]>
        """
        body = {
            "createFromSecurityPolicy": createFromSecurityPolicy,
            "policyName": policyName,
            "policyPrefix": policyPrefix
        }

        headers = {
            "Content-Type": "application/json",
        }

        return self._http_request(method='POST',
                                  url_suffix=f'appsec/v1/configs/{configId}/versions/{configVersion}/security-policies',
                                  headers=headers,
                                  json_data=body,
                                  )

    # created by D.S.
    def new_match_target(self,
                         configId: int,
                         configVersion: int,
                         matchType: str,
                         bypassNetworkLists: str,
                         defaultFile: str,
                         filePaths: list,
                         hostnames: list,
                         policyId: dict
                         ) -> str:
        """
            New match target
            TBD: PermitNetwokList
        Args:
            configId
            configVersion
            type
            bypassNetworkLists
            defaultFile
            filePaths
            hostnames
            securityPolicy

        Returns:
            <Response [204]>
            Sample: TBD
        """

        body = {
            'type': matchType,
            'defaultFile': defaultFile,
            'securityPolicy': {'policyId': policyId},
            'bypassNetworkLists': bypassNetworkLists,
            'filePaths': [filePaths],
            'hostnames': hostnames
        }

        headers = {
            "Content-Type": "application/json",
        }

        return self._http_request(method='POST',
                                  url_suffix=f'appsec/v1/configs/{configId}/versions/{configVersion}/match-targets',
                                  headers=headers,
                                  json_data=body
                                  )

    # created by D.S.
    def activate_appsec_config_version(self,
                                       configId: int,
                                       configVersion: int,
                                       acknowledgedInvalidHosts: list,
                                       notificationEmails: list,
                                       action: str,
                                       network: str,
                                       note: str,
                                       ) -> str:
        """
        Activate AppSec Configuration version
        Args:
            configId
            configVersion
            acknowledgedInvalidHosts
            notificationEmails
            action
            network
            note

        Returns:
            <Response [204]>
            Sample: TBD
        """
        body = {
            "acknowledgedInvalidHosts": [acknowledgedInvalidHosts],
            "activationConfigs": [
                {
                    "configId": configId,
                    "configVersion": configVersion,
                }
            ],
            "notificationEmails": [notificationEmails],
            "action": action,
            "network": network,
            "note": note,
        }
        headers = {
            "Content-Type": "application/json",
        }

        return self._http_request(method='POST',
                                  url_suffix='appsec/v1/activations',
                                  headers=headers,
                                  json_data=body,
                                  )

    # created by D.S.
    def get_appsec_config_activation_status(self,
                                            activationId: int,
                                            ) -> str:
        """
            Get AppSec Configuration activation Status
        Args:
            activiationId

        Returns:
            <Response [204]>
            Sample: TBD
        """

        return self._http_request(method='Get',
                                  url_suffix=f'appsec/v1/activations/{activationId}',
                                  )

    # created by D.S.
    def list_appsec_config(self) -> str:
        """
        List security configuration
        Args:

        Returns:
            <Response [204]>
            Sample: TBD
        """

        return self._http_request(method='Get',
                                  url_suffix=f'appsec/v1/configs',
                                  )

    # created by D.S.
    def list_appsec_config_versions(self,
                                    configId: str) -> str:
        """
            List security configuration versions
        Args:
            configId

        Returns:
            <Response [204]>
            Sample: TBD
        """

        return self._http_request(method='Get',
                                  url_suffix=f'appsec/v1/configs/{configId}/versions',
                                  )

    # created by D.S.
    def list_security_policy(self,
                             configId: str,
                             configVersion) -> str:
        """
            List security policy
        Args:
            configId
            versionId

        Returns:
            <Response [204]>
            Sample: TBD
        """

        params = {"detail": "false"}

        return self._http_request(method='Get',
                                  url_suffix=f'appsec/v1/configs/{configId}/versions/{configVersion}/security-policies',
                                  params=params
                                  )

    # created by D.S.
    def clone_appsec_config_version(self,
                                    configId: str,
                                    createFromVersion: str) -> str:
        """
        Create a new version of security configuration from a previous version
        Args:
            configId
            versionId

        Returns:
            <Response [204]>
            Sample: TBD
        """
        body = {
            "createFromVersion": int(createFromVersion),
            "ruleUpdate": True
        }
        return self._http_request(method='Post',
                                  url_suffix=f'appsec/v1/configs/{configId}/versions',
                                  json_data=body,
                                  )


''' HELPER FUNCTIONS '''


def get_network_lists_ec(raw_response: Optional[list]) -> Tuple[list, list]:
    """
        Get raw response list of networks from Akamai and parse to ec
    Args:
        raw_response: network list fro raw response

    Returns:
        List of network lists by entry context, entry context for human readable
    """
    entry_context = []
    human_readable = []
    if raw_response:
        for network in raw_response:
            entry_context.append(assign_params(**{
                "Name": network.get('name'),
                "Type": network.get('type'),
                "UniqueID": network.get('uniqueId'),
                "CreateDate": network.get('CreateDate'),
                "CreatedBy": network.get('createdBy'),
                "ExpeditedProductionActivationStatus": network.get('expeditedProductionActivationStatus'),
                "ExpeditedStagingActivationStatus": network.get('expeditedStagingActivationStatus'),
                "ProductionActivationStatus": network.get('productionActivationStatus'),
                "StagingActivationStatus": network.get('stagingActivationStatus'),
                "UpdateDate": network.get('updateDate'),
                "UpdatedBy": network.get('updatedBy'),
                "ElementCount": network.get('elementCount'),
                "Elements": network.get('list')
            }))
            human_readable.append(assign_params(**{
                "Name": network.get('name'),
                "Type": network.get('type'),
                "Unique ID": network.get('uniqueId'),
                "Updated by": network.get('updatedBy'),
                "Production Activation Status": network.get('productionActivationStatus'),
                "Staging Activation Status": network.get('stagingActivationStatus'),
                "Element count": network.get('elementCount'),
            }))
    return entry_context, human_readable


def get_list_from_file(entry_id: Optional[str]) -> list:
    """
        Get list of IPs and Geo from txt file
    Args:
        entry_id: Entry ID of uploaded file

    Returns:
        list of IP and Geo
    """
    elements: list = []
    try:
        list_path = demisto.getFilePath(entry_id)['path']
        with open(list_path) as list_file:
            elements += list_file.read().split('\n')
    except Exception as ex:
        return_error('Failed to open txt file: {}'.format(ex))
    return elements


# Created by D.S.
def new_papi_property_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        Parse papi propertyLink

    Args:
        raw_response:

    Returns:
        List of propertyId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        propertylink = raw_response.get('propertyLink')
        entry_context.append(assign_params(**{
            "PropertyLink": propertylink,
            "PropertyId": re.search('prp_\d+', propertylink).group(0),
        }))
        human_readable.append(assign_params(**{
            "PropertyLink": propertylink,
            "PropertyId": re.search('prp_\d+', propertylink).group(0),
        }))

    return entry_context, human_readable


# Created by D.S.
def list_papi_property_bygroup_ec(raw_response: dict) -> Tuple[list, list]:
    """
        Parse papi property
    Args:
        raw_response:
    Returns:
        List of propertyId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        propertyName = raw_response.get('propertyName')
        propertyId = raw_response.get('propertyId')
        assetId = raw_response.get('assetId')
        entry_context.append(assign_params(**{
            "PropertyName": propertyName,
            "PropertyId": propertyId,
            "AssetId": assetId
        }))
        human_readable.append(assign_params(**{
            "PropertyName": propertyName,
            "PropertyId": propertyId,
            "AssetId": assetId
        }))
    return entry_context, human_readable

# Created by D.S.


def clone_papi_property_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        Parse papi propertyLink

    Args:
        raw_response:

    Returns:
        List of propertyId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        propertylink = raw_response.get('propertyLink')
        propertyName = raw_response.get('propertyName')
        entry_context.append(assign_params(**{
            "PropertyLink": propertylink,
            "PropertyName": propertyName,
            "PropertyId": re.search('prp_\d+', propertylink).group(0),
        }))
        human_readable.append(assign_params(**{
            "PropertyLink": propertylink,
            "PropertyName": propertyName,
            "PropertyId": re.search('prp_\d+', propertylink).group(0),
        }))

    return entry_context, human_readable

# Created by D.S.


def add_papi_property_hostname_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        Parse papi property

    Args:
        raw_response:

    Returns:
        List of etag
    """
    entry_context = []
    human_readable = []
    if raw_response:
        domainPrefix = raw_response.get('domainPrefix')
        edgeHostnameId = raw_response.get('edgeHostnameId')
        etag = raw_response.get('etag')
        entry_context.append(assign_params(**{
            "DomainPrefix": domainPrefix,
            "EdgeHostnameId": edgeHostnameId,
            "Etag": etag,
        }))
        human_readable.append(assign_params(**{
            "DomainPrefix": domainPrefix,
            "EdgeHostnameId": edgeHostnameId,
            "Etag": etag,
        }))

    return entry_context, human_readable

# Created by D.S.


def list_papi_edgehostname_bygroup_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse edgehostnameId

    Args:
        raw_response:

    Returns:
        List of edgehostnameId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        domainPrefix = raw_response.get('domainPrefix')
        edgeHostnameId = raw_response.get('edgeHostnameId')
        entry_context.append(assign_params(**{
            "DomainPrefix": domainPrefix,
            "EdgeHostnameId": edgeHostnameId,
        }))
        human_readable.append(assign_params(**{
            "DomainPrefix": domainPrefix,
            "EdgeHostnameId": edgeHostnameId,
        }))

    return entry_context, human_readable

# Created by D.S.


def new_papi_edgehostname_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse edgehostnameId

    Args:
        raw_response:

    Returns:
        List of edgehostnameId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        edgeHostnameLink = raw_response.get('edgeHostnameLink')
        domainPrefix = raw_response.get('domainPrefix')
        edgeHostnameId = re.search('ehn_\d+', edgeHostnameLink).group(0)
        entry_context.append(assign_params(**{
            "EdgeHostnameLink": edgeHostnameLink,
            "DomainPrefix": domainPrefix,
            "EdgeHostnameId": edgeHostnameId,
        }))
        human_readable.append(assign_params(**{
            "EdgeHostnameLink": edgeHostnameLink,
            "DomainPrefix": domainPrefix,
            "EdgeHostnameId": edgeHostnameId,
        }))

    return entry_context, human_readable

# Created by D.S.


def get_cps_enrollment_by_cnname(raw_response: dict, cnname: str) -> Dict:
    """
        get cps enrollment info by common name

    Args:
        raw_response: output from list_cps_enrollments
        cnname:

    Returns:
        full enrollment info for given common name
    """

    if raw_response:
        for enrollment in raw_response.get("enrollments"):
            if enrollment.get("csr").get("cn") == cnname:
                return enrollment
        err_msg = f'Error in {INTEGRATION_NAME} Integration - get_cps_enrollment_by_cnname'
        return_error(err_msg, error=err_msg, output=err_msg)

# Created by D.S.


def get_cps_enrollment_by_cnname_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse enrollment and abstract enrollmentId

    Args:
        raw_response: output from get_cps_enrollment_by_cnname, individual enrollment

    Returns:
        List of enrollmentId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        enrollmentId = raw_response.get('id')
        cnname = raw_response.get("csr").get("cn")
        entry_context.append(assign_params(**{
            "EnrollmentId": enrollmentId,
            "CN": cnname
        }))
        human_readable.append(assign_params(**{
            "EnrollmentId": enrollmentId,
            "CN": cnname
        }))

    return entry_context, human_readable

# Created by D.S.


def list_papi_cpcodeid_bygroup_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse cpcode cpcId
    Args:
        raw_response:
    Returns:
        List of cpcodeId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        cpcodeName = raw_response.get('cpcodeName')
        cpcodeId = raw_response.get('cpcodeId')
        entry_context.append(assign_params(**{
            "CpcodeName": cpcodeName,
            "CpcodeId": cpcodeId
        }))
        human_readable.append(assign_params(**{
            "CpcodeName": cpcodeName,
            "CpcodeId": cpcodeId
        }))

    return entry_context, human_readable

# Created by D.S.


def new_papi_cpcode_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse cpcode cpcId

    Args:
        raw_response:

    Returns:
        List of cpcodeId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        cpcodeLink = raw_response.get('cpcodeLink')
        cpcodeName = raw_response.get('cpcodeName')
        cpcodeId = re.search('cpc_\d+', cpcodeLink).group(0)
        entry_context.append(assign_params(**{
            "CpcodeLink": cpcodeLink,
            "CpcodeName": cpcodeName,
            "CpcodeId": cpcodeId
        }))
        human_readable.append(assign_params(**{
            "CpcodeLink": cpcodeLink,
            "CpcodeName": cpcodeName,
            "CpcodeId": cpcodeId
        }))

    return entry_context, human_readable

# Created by D.S.


def patch_papi_property_rule_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse property etag

    Args:
        raw_response:

    Returns:
        List of etag
    """
    entry_context = []
    human_readable = []
    if raw_response:
        etag = raw_response.get('etag')
        entry_context.append(assign_params(**{
            "Etag": etag,
        }))
        human_readable.append(assign_params(**{
            "Etag": etag,
        }))

    return entry_context, human_readable

# Created by D.S.


def activate_papi_property_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse property activationId

    Args:
        raw_response:

    Returns:
        List of activationId
    """
    entry_context = []
    human_readable = []
    if raw_response:

        activationLink = raw_response.get('activationLink')
        entry_context.append(assign_params(**{
            "ActivationLink": activationLink,
            "ActivationId": re.search('atv_\d+', activationLink).group(0),
        }))
        human_readable.append(assign_params(**{
            "ActivationLink": activationLink,
            "ActivationId": re.search('atv_\d+', activationLink).group(0),
        }))

    return entry_context, human_readable

# Created by D.S.


def clone_security_policy_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse security policyId
    Args:
        raw_response:
    Returns:
        List of security policyId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        configId = raw_response.get('configId')
        policyId = raw_response.get('policyId')
        policyName = raw_response.get('policyName')
        entry_context.append(assign_params(**{
            "Id": configId,
            "PolicyId": policyId,
            "PolicyName": policyName
        }))
        human_readable.append(assign_params(**{
            "Id": configId,
            "PolicyId": policyId,
            "PolicyName": policyName
        }))

    return entry_context, human_readable

# Created by D.S.


def new_match_target_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse match target Id

    Args:
        raw_response:

    Returns:
        List of match target Id
    """
    entry_context = []
    human_readable = []

    if raw_response:
        configId = raw_response.get('configId')
        targetId = raw_response.get('targetId')
        policyId = raw_response.get('securityPolicy')['policyId']
        entry_context.append(assign_params(**{
            "Id": configId,
            "TargetId": targetId,
            "PolicyId": policyId
        }))
        human_readable.append(assign_params(**{
            "Id": configId,
            "TargetId": targetId,
            "PolicyId": policyId
        }))

    return entry_context, human_readable

# Created by D.S.


def activate_appsec_config_version_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse appsec config activationId

    Args:
        raw_response:

    Returns:
        List of appsec config activationId
    """
    entry_context = []
    human_readable = []
    if raw_response:
        configId = raw_response.get('configId')
        activationId = raw_response.get('activationId')
        entry_context.append(assign_params(**{
            "Id": configId,
            "ActivationId": activationId,
            "Status": "submitted"
        }))
        human_readable.append(assign_params(**{
            "Id": configId,
            "ActivationId": activationId,
            "Status": "submitted"
        }))
    return entry_context, human_readable


# Created by D.S.
def get_appsec_config_activation_status_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse appsec config activation status

    Args:
        raw_response:

    Returns:
        List of activation status
    """
    entry_context = []
    human_readable = []
    if raw_response:
        network = raw_response.get('network')
        status = raw_response.get('status')
        activationId = raw_response.get('activationId')
        entry_context.append(assign_params(**{
            "ActivationId": activationId,
            "Network": network,
            "Status": status
        }))
        human_readable.append(assign_params(**{
            "ActivationId": activationId,
            "Network": network,
            "Status": status
        }))
    return entry_context, human_readable


# Created by D.S.
def get_appsec_config_latest_version_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        get latest version of appsec configuration

    Args:
        raw_response:

    Returns:
        Dict of latest version
    """
    entry_context = []
    human_readable = []
    if raw_response:
        name = raw_response.get('name')
        id = raw_response.get('id')
        latestVersion = raw_response.get('latestVersion')
        productionVersion = raw_response.get('productionVersion')
        stagingVersion = raw_response.get('stagingVersion')
        entry_context.append(assign_params(**{
            "Name": name,
            "Id": id,
            "LatestVersion": latestVersion,
            "ProductionVersion": productionVersion,
            "StagingVersion": stagingVersion,
        }))
        human_readable.append(assign_params(**{
            "Name": name,
            "Id": id,
            "LatestVersion": latestVersion,
            "ProductionVersion": productionVersion,
            "StagingVersion": stagingVersion,
        }))
    return entry_context, human_readable


# Created by D.S.
def get_security_policy_id_by_name_command_ec(raw_response: dict, isBaselinePolicy) -> Tuple[list, list]:
    """
        parse security policy name and Id

    Args:
        raw_response:

    Returns:
        Dict of latest version
    """
    entry_context = []
    human_readable = []
    if raw_response:
        configId = raw_response.get('Id')
        policyName = raw_response.get('policyName')
        policyId = raw_response.get('policyId')
        if isBaselinePolicy == "yes":
            entry_context.append(assign_params(**{
                "Id": configId,
                "BasePolicyName": policyName,
                "BasePolicyId": policyId,
            }))
            human_readable.append(assign_params(**{
                "Id": configId,
                "BasePolicyName": policyName,
                "BasePolicyId": policyId,
            }))
        else:
            entry_context.append(assign_params(**{
                "PolicyName": policyName,
                "PolicyId": policyId,
            }))
            human_readable.append(assign_params(**{
                "PolicyName": policyName,
                "PolicyId": policyId,
            }))
    return entry_context, human_readable

# Created by D.S.


def clone_appsec_config_version_command_ec(raw_response: dict) -> Tuple[list, list]:
    """
        parse security policy name and Id

    Args:
        raw_response:

    Returns:
        Dict of latest version
    """
    entry_context = []
    human_readable = []
    if raw_response:
        configId = raw_response.get('configId')
        version = raw_response.get('version')
        entry_context.append(assign_params(**{
            "Id": configId,
            "NewVersion": version,
        }))
        human_readable.append(assign_params(**{
            "Id": configId,
            "NewVersion": version,
        }))
    return entry_context, human_readable

# Created by D.S.


def generate_policy_prefix():
    """
        generate policy_prefix string in length of four with fisrt character in letters and
                    rest of the three characters in letters and digits.
    Args:
        raw_response:
    Returns:
        Dict of latest version
    """
    import random
    import string
    firstChar = random.choice(string.ascii_letters)
    lastThreeChars = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(3))
    return firstChar + lastThreeChars


''' COMMANDS '''
# Created by C.L.


@logger
def check_group_command(client: Client, checking_group_name: str = '') -> Tuple[object, dict, Union[List, Dict]]:
    raw_response: Dict = client.list_groups()
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - List Groups'
        if checking_group_name != '':
            path = checking_group_name.split(">")
            group_list = raw_response
            print(group_list)
            for path_groupname in path:
                found = False
                print("check {path_groupname}")
                for group in group_list:
                    if path_groupname == group['groupName']:
                        print(group['groupName'], group.get('parentGroupId', 0), group.get('groupId', 0))
                        group_list = group['subGroups']
                        found = True
                        break
                if found == False:
                    return human_readable, {"Akamai.check_group": {'Found': False, 'checking_group_name': checking_group_name, 'groupName': "No Name", 'parentGroupId': 0, 'groupId': 0}}, raw_response
            return human_readable, {"Akamai.check_group": {'Found': True, 'checking_group_name': checking_group_name, 'groupName': group['groupName'], 'parentGroupId': group.get('parentGroupId', 0), 'groupId': group.get('groupId', 0)}}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L.


@logger
def list_groups_command(client: Client) -> Tuple[object, dict, Union[List, Dict]]:
    """
    List the information of all groups

    Returns:
    Json response as dictionary
    """
    raw_response: Dict = client.list_groups()
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - List Groups'

        return human_readable, {"Akamai.Groups": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L.


@logger
def get_group_command(client: Client, groupID: int = 0) -> Tuple[object, dict, Union[List, Dict]]:
    """
        Get the information of a group
    Args:
        groupID : Group ID

    Returns:
        Json response as dictionary
    """
    raw_response: Dict = client.get_group(groupID)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - get Group: {raw_response}'

        return human_readable, {"Akamai.Get_Group": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def create_enrollment_command(client: Client,
                              Country: str,
                              Company: str,
                              OrganizationalUnit: str,
                              City: str,
                              adminContact_addressLineOne: str,
                              adminContact_firstName: str,
                              adminContact_lastName: str,
                              adminContact_email: str,
                              adminContact_phone: str,
                              techContact_firstName: str,
                              techContact_lastName: str,
                              techContact_email: str,
                              techContact_phone: str,
                              org_name: str,
                              org_country: str,
                              org_city: str,
                              org_region: str,
                              org_postalCode: str,
                              org_phone: str,
                              org_addressLineOne: str,
                              contractId: str,
                              certificateType: str = "third-party",
                              csr_cn: str = "",
                              changeManagement: bool = False,
                              enableMultiStackedCertificates: bool = False,  # TBD
                              networkConfiguration_geography: str = "core",
                              networkConfiguration_quicEnabled: bool = True,
                              networkConfiguration_secureNetwork: str = "enhanced-tls",
                              networkConfiguration_sniOnly: bool = True,
                              ra: str = "third-party",
                              validationType: str = "third-party"
                              ) -> Tuple[object, dict, Union[List, Dict]]:
    """
        Create an enrollment
    Args:
        contractId:                 Contract id
        Country:                    Country - Two Letter format
        Company:                    Company Name
        OrganizationalUnit:         Organizational Unit
        City:                       City Name
        adminContact:               Admin Contact - Dictionary
        techContact:                techContact - Dictionary
        org:                        Organization name - Dictionary
        csr_cn:                     CName
        contractId:                 Specify the contract on which to operate or view.
        csr_cn:                     CName to be created
        changeManagement:           changeManagement
        certificateType:            Certificate Type
        enableMultiStackedCertificates:     Enable Multi Stacked Certificates
        networkConfiguration_geography:     Network Configuration geography
        networkConfiguration_quicEnabled:   Network Configuration QuicEnabled
        networkConfiguration_secureNetwork: Network Configuration SecureNetwork
        networkConfiguration_sniOnly:       Network Configuration sniOnly
        ra: str = "third-party",
        validationType: str = "third-party"

    Returns:
        Json response as dictionary
    """
    adminContact = {"addressLineOne": adminContact_addressLineOne, "firstName": adminContact_firstName,
                    "lastName": adminContact_lastName, "email": adminContact_email, "phone": adminContact_phone}

    techContact = {"firstName": techContact_firstName, "lastName": techContact_lastName, "email": techContact_email,
                   "phone": techContact_phone}

    org = {"name": org_name, "country": org_country, "city": org_city, "region": org_region, "postalCode": org_postalCode,
           "phone": org_phone, "addressLineOne": org_addressLineOne}

    raw_response: Dict = client.create_enrollment(
        Country=Country,
        Company=Company,
        OrganizationalUnit=OrganizationalUnit,
        City=City,
        adminContact=adminContact,
        techContact=techContact,
        org=org,
        contractId=contractId,
        csr_cn=csr_cn,
        changeManagement=changeManagement,
        certificateType=certificateType,
        enableMultiStackedCertificates=enableMultiStackedCertificates,
        networkConfiguration_geography=networkConfiguration_geography,
        networkConfiguration_quicEnabled=networkConfiguration_quicEnabled,
        networkConfiguration_secureNetwork=networkConfiguration_secureNetwork,
        networkConfiguration_sniOnly=networkConfiguration_sniOnly,
        ra=ra,
        validationType=validationType)

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Group {csr_cn} is created successfully'

        return human_readable, {"Akamai.Create.NewGroup": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


def list_enrollments_command(client: Client, contractId: str) -> Tuple[object, dict, Union[List, Dict]]:
    """
        List enrollments
    Args:
        contractId: Specify the contract on which to operate or view.

    Returns:
        Json response as dictionary
    """
    raw_response: Dict = client.list_enrollments(contractId)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - List Enrollments'

        return human_readable, {"Akamai.Enrollments": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def get_enrollment_by_cn_command(client: Client, target_cn: str, contractId: str = "") -> Tuple[object, dict, Union[List, Dict]]:
    """
        List enrollments
    Args:
        contractId: Specify the contract on which to operate or view.

    Returns:
        The enrollment information - Json response as dictionary
    """
    raw_response: Dict = client.list_enrollments(contractId)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - List Enrollments'
        context = {}
        print(len(raw_response.keys()))
        for enrollment in raw_response["enrollments"]:
            if 'csr' in enrollment.keys():
                if 'cn' in enrollment["csr"].keys():
                    if enrollment["csr"]["cn"] == target_cn:
                        context = enrollment['csr']
                        context['existing'] = True
                        context['target_cn'] = target_cn
                        return human_readable, {"Akamai.Get_Enrollment": context}, raw_response
        context = raw_response
        context['existing'] = False
        context['target_cn'] = target_cn
        return human_readable, {"Akamai.Get_Enrollment": context}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L.


@logger
def get_change_command(client: Client, enrollment_path: str, allowedInputTypeParam: str = "third-party-csr") -> Tuple[object, dict, Union[List, Dict]]:
    """
        Get change
    Args:
        enrollment_path: The path that includes enrollmentId and changeId : e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
        allowedInputTypeParam: Specify the contract on which to operate or view.

    Returns:
        Json response as dictionary
    """
    raw_response: Dict = client.get_change(enrollment_path, allowedInputTypeParam)
    print("test.getcommand")
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Get_change'

        return human_readable, {"Akamai.get_change": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def update_change_command(client: Client, change_path: str,
                          Certificate: str, TrustChain: str, allowedInputTypeParam: str = "third-party-cert-and-trust-chain") -> Tuple[object, dict, Union[List, Dict]]:
    """
        Update a change
    Args:
        change_path: The path that includes enrollmentId and changeId : e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
        Certificate :Certificate,
        TrustChain: TrustChain,
        allowedInputTypeParam: Specify the contract on which to operate or view.

    Returns:
        Json response as dictionary
    """
    raw_response: Dict = client.update_change(change_path,
                                              Certificate, TrustChain, allowedInputTypeParam)

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Update_change'

        return human_readable, {"Akamai.update_change": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def create_new_group_command(client: Client, group_path: str = '') -> Tuple[object, dict, Union[List, Dict]]:
    """
        Create a new group
    Args:
        groupID : Group ID

    Returns:
        Json response as dictionary
    """

    raw_response_list: Dict = client.list_groups()
    if raw_response_list:
        if group_path != '':
            path = group_path.split(">")
            group_list = raw_response_list
            found_groupId: int = 0
            for path_groupname in path:
                found = False
                for group in group_list:
                    if path_groupname == group['groupName']:
                        group_list = group['subGroups']
                        print("true", group_list)
                        found = True
                        found_groupId = group.get('groupId', 0)
                        break
                if found == False:
                    create_folder = client.create_new_group(found_groupId, path_groupname)
                    found_groupId = create_folder.get('groupId')
                    group_list = [client.get_group(found_groupId)]
                    print("false", group_list)
        human_readable = f'{INTEGRATION_NAME} - Group {group_path} is created successfully'

        return human_readable, {"Akamai.Created_New_group": group_path}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L.


def get_domains_command(client: Client) -> Tuple[object, dict, Union[List, Dict]]:
    """
        Get all of the existing domains

    Returns:
        Json response as dictionary
    """
    raw_response: Dict = client.get_domains()
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Domains are listed successfully'

        return human_readable, {"Akamai.Get_Domains": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


def get_a_domain_command(client: Client, domainName: str) -> Tuple[object, dict, Union[List, Dict]]:
    """
        Get information of a specific domain
    Args:
        domainName : Domain Name

    Returns:
        Json response as dictionary
    """
    raw_response: Dict = client.get_a_domain(domainName)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - The domain is listed successfully'

        return human_readable, {"Akamai.Get_A_Domain": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def create_domain_command(client: Client, groupId: int, domainName: str) -> Tuple[object, dict, Union[List, Dict]]:
    """
       Creating domains
    Args:
        groupId : The group ID
        domainName: Domain Name

    Returns:
        Json response as dictionary
    """

    raw_response: Dict = client.create_domain(groupId, domainName=domainName)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Domain is created successfully'

        return human_readable, {"Akamai.Create_Domain": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def create_datacenter_command(client: Client, domainName: str, DC_name: str = "", DC_country: str = "US") -> Tuple[object, dict, Union[List, Dict]]:
    """
    Updating or adding datacenter to existing GTM domain
    Args:

        domainName: Domain Name
        DC_nam2: The name of the Data center
        DC_country: The country of the Data center


    Returns:
        Json response as dictionary
    """

    raw_response: Dict = client.create_datacenter(domainName, DC_name, DC_country)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Property is created successfully'

        return human_readable, {"Akamai.Create_datacenter": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def update_property_command(client: Client, property_type: str, domainName: str, property_name: str,
                            static_type: str = "", static_server: str = "", server_1: str = "",
                            server_2: str = "", weight_1: int = 50, weight_2: int = 50) -> Tuple[object, dict, Union[List, Dict]]:
    """
    Updating or adding properties to existing GTM domain

    Args:
        property_type : Property Type
        domainName: Domain Name
        property_name: Property Name
        static_type: The type of static property
        static_server: The server address of static property
        server_1: The address of server 1
        server_2: The address of server 2
        weight_1: The weight of server 1
        weight_2: The weight of server 2

    Returns:
        Json response as dictionary
    """
    raw_response: Dict = client.update_property(property_type, domainName=domainName,
                                                property_name=property_name, static_type=static_type,
                                                static_server=static_server, server_1=server_1,
                                                server_2=server_2, weight_1=weight_1, weight_2=weight_2)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Property is created successfully'

        return human_readable, {"Akamai.Property": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def test_module_command(client: Client, *_) -> Tuple[None, None, str]:
    """Performs a basic GET request to check if the API is reachable and authentication is successful.

    Args:
        client: Client object with request
        *_: Usually demisto.args()

    Returns:
        'ok' if test successful.

    Raises:
        DemistoException: If test failed.
    """
    results = client.test_module()
    if 'links' in results:
        return None, None, 'ok'
    raise DemistoException(f'Test module failed, {results}')


@logger
def get_network_lists_command(
        client: Client,
        search: str = None,
        list_type: str = None,
        extended: str = 'true',
        include_elements: str = 'true',
) -> Tuple[object, dict, Union[List, Dict]]:
    """Get network lists

    Args:
        client: Client object with request
        search: Only list items that match the specified substring in any network list’s name or list of items.
        list_type: Filters the output to lists of only the given type of network lists if provided, either IP or GEO.
        extended: Whether to return extended details in the response
        include_elements: Whether to return all list items.

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: Dict = client.get_network_lists(
        search=search, list_type=list_type, extended=(extended == 'true'), include_elements=(include_elements == 'true')
    )
    if raw_response:
        title = f'{INTEGRATION_NAME} - network lists'
        entry_context, human_readable_ec = get_network_lists_ec(raw_response.get('networkLists'))
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.Lists(val.UniqueID && val.UniqueID == obj.UniqueID && val.UpdateDate &&"
            f" val.UpdateDate == obj.UpdateDate)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def get_network_list_by_id_command(client: Client, network_list_id: str) -> Tuple[object, dict, Union[List, Dict]]:
    """Get network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: Dict = client.get_network_list_by_id(network_list_id=network_list_id)
    if raw_response:
        title = f'{INTEGRATION_NAME} - network list {network_list_id}'
        entry_context, human_readable_ec = get_network_lists_ec([raw_response])
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.Lists(val.UniqueID && val.UniqueID == obj.UniqueID &&"
            f" val.UpdateDate && val.UpdateDate == obj.UpdateDate)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def create_network_list_command(client: Client, list_name: str, list_type: str, description: Optional[str] = None,
                                entry_id: Optional[str] = None, elements: Optional[Union[str, list]] = None) \
        -> Tuple[object, dict, Union[List, Dict]]:
    """
        Create network list

    Args:
        client: Client object with request
        list_name: Network list name
        list_type: Network list type IP/GEO
        description: Network list description
        entry_id: Entry ID of list file (Each line should have one IP or GEO)
        elements: Elements separated by commas

    Returns:
        human readable (markdown format), entry context and raw response
    """
    if entry_id:
        elements = get_list_from_file(entry_id)
    else:
        elements = argToList(elements)
    raw_response: dict = client.create_network_list(list_name=list_name,
                                                    list_type=list_type,
                                                    elements=elements,
                                                    description=description)
    entry_context, human_readable_ec = get_network_lists_ec([raw_response])
    if raw_response:
        title = f'{INTEGRATION_NAME} - network list {list_name} created successfully'
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.Lists(val.UniqueID && val.UniqueID == obj.UniqueID && val.UpdateDate &&"
            f" val.UpdateDate == obj.UpdateDate)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def delete_network_list_command(client: Client, network_list_id: str) -> Tuple[object, dict, Union[List, Dict]]:
    """Delete network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response = client.delete_network_list(network_list_id=network_list_id)
    if raw_response:
        human_readable = f'**{INTEGRATION_NAME} - network list {network_list_id} deleted**'
        return human_readable, {}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def update_network_list_elements_command(client: Client, network_list_id: str, elements: Optional[Union[str, list]] = None) \
        -> Tuple[object, dict, Union[List, Dict]]:
    """Update network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list

    Returns:
        human readable (markdown format), entry context and raw response
    """

    elements = argToList(elements)
    # demisto.results(elements)

    raw_response = client.update_network_list_elements(network_list_id=network_list_id, elements=elements)

    if raw_response:
        human_readable = f'**{INTEGRATION_NAME} - network list {network_list_id} updated**'
        return human_readable, {}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def activate_network_list_command(client: Client, network_list_ids: str, env: str, comment: Optional[str] = None,
                                  notify: Optional[str] = None) -> Tuple[object, dict, Union[List, Dict]]:
    """Activate network list by ID

    Args:
        client: Client object with request
        network_list_ids: Unique ID of network list
        env: STAGING or PRODUCTION
        comment: Comment to be logged
        notify: Email to notify on activation

    Returns:
        human readable (markdown format), entry context and raw response
    """
    network_list_ids = argToList(network_list_ids)
    human_readable = ""
    for network_list_id in network_list_ids:
        try:
            raw_response = client.activate_network_list(network_list_id=network_list_id,
                                                        env=env,
                                                        comment=comment,
                                                        notify=argToList(notify))
            if raw_response:
                human_readable += f'{INTEGRATION_NAME} - network list **{network_list_id}** activated on {env} **successfully**\n'
        except DemistoException as e:
            if "This list version is already active" in e.args[0]:
                human_readable += f'**{INTEGRATION_NAME} - network list {network_list_id} already active on {env}**\n'
        except requests.exceptions.RequestException:
            human_readable += f'{INTEGRATION_NAME} - Could not find any results for given query\n'

    return human_readable, {}, {}


@logger
def add_elements_to_network_list_command(client: Client, network_list_id: str, entry_id: Optional[str] = None,
                                         elements: Optional[Union[str, list]] = None) \
        -> Tuple[object, dict, Union[List, Dict]]:
    """Add elements to network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list
        entry_id: Entry ID of list file (Each line should have one IP or GEO)
        elements: Elements separated by commas

    Returns:
        human readable (markdown format), entry context and raw response
    """
    if entry_id:
        elements = get_list_from_file(entry_id)
    else:
        elements = argToList(elements)
    raw_response: dict = client.add_elements_to_network_list(network_list_id=network_list_id,
                                                             elements=elements)
    if raw_response:
        title = f'**{INTEGRATION_NAME} - elements added to network list {network_list_id} successfully**'
        human_readable = tableToMarkdown(name=title,
                                         t={'elements': elements},
                                         removeNull=True)
        return human_readable, {}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def remove_element_from_network_list_command(client: Client, network_list_id: str, element: str) -> \
        Tuple[object, dict, Union[List, Dict]]:
    """Remove element from network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list
        element: Element to be removed

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: dict = client.remove_element_from_network_list(network_list_id=network_list_id,
                                                                 element=element)
    if raw_response:
        human_readable = f'**{INTEGRATION_NAME} - element {element} removed from network list {network_list_id} successfully**'
        return human_readable, {}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def get_activation_status_command(client: Client, network_list_ids: Union[str, list], env: str) \
        -> Tuple[object, dict, Union[List, Dict]]:
    """Get activation status

    Args:
        client: Client object with request
        network_list_ids: Unique ID of network list (can be list as a string)
        env: STAGING or PRODUCTION

    Returns:
        human readable (markdown format), entry context and raw response
    """
    network_list_ids = argToList(network_list_ids)
    raws = []
    ecs = []
    context_entry: Dict = {}
    human_readable = ""
    for network_list_id in network_list_ids:
        try:
            raw_response: dict = client.get_activation_status(network_list_id=network_list_id,
                                                              env=env)
            if raw_response:
                raws.append(raw_response)
                if env == "PRODUCTION":
                    ecs.append({
                        "UniqueID": network_list_id,
                        "ProductionStatus": raw_response.get('activationStatus')

                    })
                elif env == "STAGING":
                    ecs.append({
                        "UniqueID": network_list_id,
                        "StagingStatus": raw_response.get('activationStatus')

                    })
                human_readable += f"{INTEGRATION_NAME} - network list **{network_list_id}** is " \
                                  f"**{raw_response.get('activationStatus')}** in **{env}**\n"
        except DemistoException as e:
            if "The Network List ID should be of the format" in e.args[0]:
                human_readable += f"{INTEGRATION_NAME} - network list **{network_list_id}** canot be found\n"
        except requests.exceptions.RequestException:
            human_readable += f'{INTEGRATION_NAME} - Could not find any results for given query\n'

    if env == "PRODUCTION":
        context_entry = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.ActivationStatus(val.UniqueID == obj.UniqueID)": ecs
        }
    elif env == "STAGING":
        context_entry = {
            f"{INTEGRATION_CONTEXT_NAME}.NetworkLists.ActivationStatus(val.UniqueID == obj.UniqueID)": ecs
        }

    return human_readable, context_entry, raws


# Created by D.S.
def clone_papi_property_command(client: Client,
                                productId: str,
                                propertyName: str,
                                contractId: str,
                                groupId: str,
                                propertyId: str,
                                version: str,
                                continueIfExist="yes") -> dict:
    """
        Post clone property command
    Args:
        client: Client object with request
        productId
        propertyName
        contractId
        groupId
        propertyId: source propertyId to be cloned from
        version
        continueIfExist: Do not create a new one if one with the same name already exists. Default is "yes".
    Returns:
        human readable (markdown format), entry context and raw response
    """
    isExistingOneFound = False
    if continueIfExist.lower() == "yes":
        raw_response: Dict = client.list_papi_property_bygroup(contractId=contractId, groupId=groupId)
        lookupKey = 'propertyName'
        lookupValue = propertyName
        returnDict: Dict = next((item for item in raw_response["properties"]["items"]
                                if item[lookupKey] == lookupValue), None)
        if returnDict != None:
            isExistingOneFound = True
            title = f'{INTEGRATION_NAME} - new papi property command - found existing property'
            entry_context, human_readable_ec = list_papi_property_bygroup_ec(returnDict)
    if not isExistingOneFound:
        raw_response: Dict = client.clone_papi_property(productId=productId,
                                                        propertyName=propertyName,
                                                        contractId=contractId,
                                                        groupId=groupId,
                                                        propertyId=propertyId,
                                                        version=version
                                                        )
        if raw_response:
            title = f'{INTEGRATION_NAME} - Clone papi property {propertyName} in group {groupId} from {propertyId}'
            raw_response["propertyName"] = propertyName
            entry_context, human_readable_ec = clone_papi_property_command_ec(raw_response)
    context_entry: Dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Papi.Property(val.PropertyName && val.PropertyName == obj.PropertyName)": entry_context
    }
    human_readable = tableToMarkdown(name=title,
                                     t=human_readable_ec,
                                     removeNull=True)
    return human_readable, context_entry, raw_response


# Created by D.S.
def add_papi_property_hostname_command(client: Client,
                                       propertyVersion: str,
                                       propertyId: str,
                                       contractId: str,
                                       groupId: str,
                                       validateHostnames: bool,
                                       includeCertStatus: bool,
                                       cnameFrom: str,
                                       edgeHostnameId: str,
                                       sleepTime: str
                                       ) -> dict:
    """
        add hostname papi property

    Args:
        client: Client object with request
        propertyVersion:
        propertyId:
        contractId:
        groupId:
        validateHostnames:
        includeCertStatus:
        cnameFrom:
        edgeHostnameId:

    Returns:
        human readable (markdown format), entry context and raw response
    """
    import time
    raw_response: Dict = client.add_papi_property_hostname(
        propertyVersion=propertyVersion,
        propertyId=propertyId,
        contractId=contractId,
        groupId=groupId,
        validateHostnames=validateHostnames,
        includeCertStatus=includeCertStatus,
        cnameFrom=cnameFrom,
        edgeHostnameId=edgeHostnameId,
    )
    demisto.info(f'{INTEGRATION_NAME} - Add hostnames into papi property'
                 f' - Pause {sleepTime} seconds before adding next hostname')
    sleep(int(sleepTime))
    if raw_response:
        title = f'{INTEGRATION_NAME} - Add hostname papi property'
        raw_response["domainPrefix"] = cnameFrom
        raw_response["edgeHostnameId"] = edgeHostnameId
        entry_context, human_readable_ec = add_papi_property_hostname_command_ec(raw_response)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.Papi.Property.EdgeHostnames(val.DomainPrefix && val.DomainPrefix == obj.DomainPrefix)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)
        return human_readable, context_entry, raw_response


# Created by D.S.
def list_papi_edgehostname_bygroup_command(client: Client,
                                           contractId: str,
                                           groupId: str,
                                           domainPrefix: str) -> dict:
    """
        add papi edge hostname command
    Args:
        client: Client object with request
        contractId:
        groupId:
        options:
        domainPrefix:
    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: Dict = client.list_papi_edgehostname_bygroup(contractId=contractId,
                                                               groupId=groupId,
                                                               options="mapDetails"
                                                               )
    lookupKey = 'domainPrefix'
    lookupValue = domainPrefix
    returnDict: Dict = next((item for item in raw_response["edgeHostnames"]["items"]
                             if item[lookupKey] == lookupValue), None)
    if raw_response:
        title = f'{INTEGRATION_NAME} - new papi edgeHostname command'
        # raw_response["domainPrefix"] = domainPrefix
        entry_context, human_readable_ec = list_papi_edgehostname_bygroup_ec(returnDict)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.Papi.Property.EdgeHostnames"
            f"(val.DomainPrefix && val.DomainPrefix == obj.DomainPrefix)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)
        return human_readable, context_entry, raw_response


# Created by D.S.
def new_papi_edgehostname_command(client: Client,
                                  productId: str,
                                  contractId: str,
                                  groupId: str,
                                  options: str,
                                  domainPrefix: str,
                                  domainSuffix: str,
                                  ipVersionBehavior: str,
                                  secure: str,
                                  secureNetwork: str,
                                  certEnrollmentId: str,
                                  continueIfExist="yes") -> dict:
    """
        add papi edge hostname command

    Args:
        client: Client object with request
        productId:
        contractId:
        groupId:
        options:
        domainPrefix:
        domainSuffix:
        ipVersionBehavior:
        secure:
        secureNetwork:
        certEnrollmentId:
        continueIfExist: Do not create a new one if one with the same name already exists. Default is "yes".

    Returns:
        human readable (markdown format), entry context and raw response
    """
    isExistingOneFound = False
    if continueIfExist.lower() == "yes":
        raw_response: Dict = client.list_papi_edgehostname_bygroup(contractId=contractId,
                                                                   groupId=groupId,
                                                                   options="mapDetails"
                                                                   )
        lookupKey = 'domainPrefix'
        lookupValue = domainPrefix
        returnDict: Dict = next((item for item in raw_response["edgeHostnames"]["items"]
                                 if item[lookupKey] == lookupValue), None)
        if returnDict != None:
            isExistingOneFound = True
            title = f'{INTEGRATION_NAME} - new papi edgeHostname command - found existing edgeHostname'
            entry_context, human_readable_ec = list_papi_edgehostname_bygroup_ec(returnDict)
    if not isExistingOneFound:
        raw_response: Dict = client.new_papi_edgehostname(productId=productId,
                                                          contractId=contractId,
                                                          groupId=groupId,
                                                          options=options,
                                                          domainPrefix=domainPrefix,
                                                          domainSuffix=domainSuffix,
                                                          ipVersionBehavior=ipVersionBehavior,
                                                          secure=secure,
                                                          secureNetwork=secureNetwork,
                                                          certEnrollmentId=certEnrollmentId,
                                                          )
        if raw_response:
            title = f'{INTEGRATION_NAME} - new papi edgeHostname command'
            raw_response["domainPrefix"] = domainPrefix
            entry_context, human_readable_ec = new_papi_edgehostname_command_ec(raw_response)
    context_entry: Dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Papi.Property.EdgeHostnames(val.DomainPrefix && val.DomainPrefix == obj.DomainPrefix)": entry_context
    }
    human_readable = tableToMarkdown(name=title,
                                     t=human_readable_ec,
                                     removeNull=True)
    return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def get_cps_enrollmentid_by_cnname_command(client: Client,
                                           contractId: str,
                                           cnname: str,
                                           ) -> dict:
    """
        get CPS EnrollmentID by Common Name

    Args:
        client: Client object with request
        contractId:
        cnname:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: Dict = client.list_cps_enrollments(contractId=contractId)

    if raw_response:
        enrollment: Dict = get_cps_enrollment_by_cnname(raw_response=raw_response, cnname=cnname)
        title = f'{INTEGRATION_NAME} - Get cps enrollmentid by cnname command'
        entry_context, human_readable_ec = get_cps_enrollment_by_cnname_ec(enrollment)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.Cps.Enrollment": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def new_papi_cpcode_command(client: Client,
                            productId: str,
                            contractId: str,
                            groupId: str,
                            cpcodeName: str,
                            continueIfExist="yes"
                            ) -> dict:
    """
        get papi property All Versions by groupId and propertyId command
    Args:
        productId:
        contractId:
        groupId:
        cpcodeName:
        continueIfExist: Do not create a new Cpcode if one with the same name already exists. Default is "yes".

    Returns:
        human readable (markdown format), entry context and raw response
    """
    isExistingOneFound = False
    if continueIfExist.lower() == "yes":
        raw_response: Dict = client.list_papi_cpcodeid_bygroup(contractId=contractId, groupId=groupId)
        lookupKey = 'cpcodeName'
        lookupValue = cpcodeName
        returnDict: Dict = next((item for item in raw_response["cpcodes"]["items"]
                                 if item[lookupKey] == lookupValue), None)

        if returnDict != None:
            isExistingOneFound = True
            title = f'{INTEGRATION_NAME} - get papi cpcode command - found existing Cpcode'
            entry_context, human_readable_ec = list_papi_cpcodeid_bygroup_ec(returnDict)
    if not isExistingOneFound:
        raw_response: Dict = client.new_papi_cpcode(contractId=contractId,
                                                    groupId=groupId,
                                                    productId=productId,
                                                    cpcodeName=cpcodeName,
                                                    )
        if raw_response:
            title = f'{INTEGRATION_NAME} - new papi cpcode command'
            raw_response["cpcodeName"] = cpcodeName
            entry_context, human_readable_ec = new_papi_cpcode_ec(raw_response)

    context_entry: Dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Papi.Cpcode": entry_context
    }
    human_readable = tableToMarkdown(name=title,
                                     t=human_readable_ec,
                                     removeNull=True)
    return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def patch_papi_property_rule_cpcode_command(client: Client,
                                            contractId: str,
                                            groupId: str,
                                            propertyId: str,
                                            propertyVersion: str,
                                            validateRules: str,
                                            operation: str,
                                            path: str,
                                            cpcodeId: str,
                                            name: str,
                                            ) -> dict:
    """
        get papi property All Versions by groupId and propertyId command
    Args:
        contractId:
        groupId:
        propertyId:
        propertyVersion:
        validateRules:
        operation:
        path:
        value:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    body = [
        {
            "op": operation,
            "path": path,
            "value":
                {
                    "id": int(cpcodeId.split('_')[1]),
                    "name": name
                }
        }
    ]

    raw_response: Dict = client.patch_papi_property_rule(contractId=contractId,
                                                         groupId=groupId,
                                                         propertyId=propertyId,
                                                         propertyVersion=propertyVersion,
                                                         validateRules=validateRules,
                                                         body=body,
                                                         )

    if raw_response:
        title = f'{INTEGRATION_NAME} - Patch papi property cpcode command'
        entry_context, human_readable_ec = patch_papi_property_rule_ec(raw_response)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.Papi.Property": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def patch_papi_property_rule_origin_command(client: Client,
                                            contractId: str,
                                            groupId: str,
                                            propertyId: str,
                                            propertyVersion: str,
                                            validateRules: str,
                                            operation: str,
                                            path: str,
                                            hostname: str,
                                            ) -> dict:
    """
        get papi property All Versions by groupId and propertyId command
    Args:
        contractId:
        groupId:
        propertyId:
        propertyVersion:
        validateRules:
        operation:
        path:
        value:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    body = [
        {
            "op": operation,
            "path": path,
            "value":
            [
                {
                    "name": "origin",
                            "options": {
                                "cacheKeyHostname": "REQUEST_HOST_HEADER",
                                "compress": True,
                                "enableTrueClientIp": True,
                                "forwardHostHeader": "REQUEST_HOST_HEADER",
                                "httpPort": 80,
                                "httpsPort": 443,
                                "originCertificate": "",
                                "originSni": True,
                                "originType": "CUSTOMER",
                                "ports": "",
                                "trueClientIpClientSetting": False,
                                "trueClientIpHeader": "True-Client-IP",
                                "verificationMode": "PLATFORM_SETTINGS",
                                "hostname": hostname
                            }
                }
            ]
        }
    ]

    raw_response: Dict = client.patch_papi_property_rule(contractId=contractId,
                                                         groupId=groupId,
                                                         propertyId=propertyId,
                                                         propertyVersion=propertyVersion,
                                                         validateRules=validateRules,
                                                         body=body,
                                                         )

    if raw_response:
        title = f'{INTEGRATION_NAME} - Patch papi property origin command'
        entry_context, human_readable_ec = patch_papi_property_rule_ec(raw_response)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.Papi.Property": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def activate_papi_property_command(client: Client,
                                   contractId: str,
                                   groupId: str,
                                   propertyId: str,
                                   network: str,
                                   notifyEmails: str,
                                   propertyVersion: int,
                                   ) -> str:
    """
        activate an property command
    Args:
        client: Client object with request
        contractId: crt_xxxxxxx
        groupId: grp_#######
        propertyId: prp_#######
        network: "STAGING" or "PRODUCTION"
        notifyEmails: akamaizers@fisglobal.com
        propertyVersion:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: Dict = client.activate_papi_property(contractId=contractId,
                                                       groupId=groupId,
                                                       propertyId=propertyId,
                                                       network=network,
                                                       notifyEmails=notifyEmails,
                                                       propertyVersion=propertyVersion,
                                                       )
    if raw_response:
        title = f'{INTEGRATION_NAME} - activate an property'
        entry_context, human_readable_ec = activate_papi_property_command_ec(raw_response)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.Papi.Property.{network.capitalize()}": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)

        return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def clone_security_policy_command(client: Client,
                                  configId: int,
                                  configVersion: int,
                                  createFromSecurityPolicy: str,
                                  policyName: str,
                                  policyPrefix: str = None,
                                  continueIfExist="yes") -> str:
    """
        Clone security policy property command
    Args:
        client: Client object with request
        configId:
        configVersion:
        createFromSecurityPolicy:
        policyName:
        continueIfExist: Continue execution if a Existing Record found without creating an new record

    Returns:
        human readable (markdown format), entry context and raw response
    """

    if continueIfExist.lower() == "yes":
        raw_response: Dict = client.list_security_policy(configId=configId,
                                                         configVersion=configVersion)
        lookupKey = 'policyName'
        lookupValue = policyName
        returnDict: Dict = next((item for item in raw_response['policies'] if item[lookupKey] == lookupValue), None)
        if returnDict != None:
            title = f'{INTEGRATION_NAME} - clone security policy command - found existing Security Policy'
            entry_context, human_readable_ec = clone_security_policy_command_ec(returnDict)
            context_entry: Dict = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config.Policy(val.PolicyName && val.PolicyName == obj.PolicyName)": entry_context
            }
            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
            return human_readable, context_entry, raw_response

    if policyPrefix is None:
        isDuplicated = True
        while isDuplicated:
            policyPrefix = generate_policy_prefix()
            isErrored = False
            try:
                raw_response: Dict = client.clone_security_policy(configId=configId,
                                                                  configVersion=configVersion,
                                                                  createFromSecurityPolicy=createFromSecurityPolicy,
                                                                  policyName=policyName,
                                                                  policyPrefix=policyPrefix
                                                                  )
            except Exception as e:
                isErrored = True
                if "You entered a Policy ID that already exists." not in e.message:
                    err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
                    return_error(err_msg, error=e)
            if not isErrored:
                isDuplicated = False
        if raw_response:
            title = f'{INTEGRATION_NAME} - clone security policy'
            entry_context, human_readable_ec = clone_security_policy_command_ec(raw_response)
            context_entry: Dict = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config.Policy(val.PolicyName && val.PolicyName == obj.PolicyName)": entry_context
            }
            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
        return human_readable, context_entry, raw_response
    else:
        raw_response: Dict = client.clone_security_policy(configId=configId,
                                                          configVersion=configVersion,
                                                          createFromSecurityPolicy=createFromSecurityPolicy,
                                                          policyName=policyName,
                                                          policyPrefix=policyPrefix
                                                          )
        if raw_response:
            title = f'{INTEGRATION_NAME} - clone security policy'
            entry_context, human_readable_ec = clone_security_policy_command_ec(raw_response)
            context_entry: Dict = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config.Policy(val.PolicyName && val.PolicyName == obj.PolicyName)": entry_context
            }
            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
            return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def new_match_target_command(client: Client,
                             configId: int,
                             configVersion: int,
                             matchType: str,
                             bypassNetworkLists: str,
                             defaultFile: str,
                             filePaths: list,
                             hostnames: list,
                             policyId: dict
                             ) -> str:
    """
        New match target command
    Args:
        client:
        configId
        configVersion
        type
        bypassNetworkLists
        defaultFile
        filePaths
        hostnames
        policyId

    Returns:
        human readable (markdown format), entry context and raw response
    """
    networkList = []
    for network in bypassNetworkLists.split(','):
        networkList.append({'id': network})
    hostnameList = []
    for hostname in hostnames.split(','):
        hostnameList.append(hostname)

    raw_response: Dict = client.new_match_target(configId=configId,
                                                 configVersion=configVersion,
                                                 matchType=matchType,
                                                 bypassNetworkLists=networkList,
                                                 defaultFile=defaultFile,
                                                 filePaths=filePaths,
                                                 hostnames=hostnameList,
                                                 policyId=policyId,
                                                 )
    if raw_response:
        title = f'{INTEGRATION_NAME} - create match target'
        entry_context, human_readable_ec = new_match_target_command_ec(raw_response)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config.Policy(val.PolicyId && val.PolicyId == obj.PolicyId)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)
        return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def activate_appsec_config_version_command(client: Client,
                                           configId: int,
                                           configVersion: int,
                                           acknowledgedInvalidHosts: list,
                                           notificationEmails: list,
                                           action: str,
                                           network: str,
                                           note: str,) -> str:
    """
        Activate appsec config version command
    Args:
        configId
        configVersion
        acknowledgedInvalidHosts:
        notificationEmails:
        action:
        network:
        note:
    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: Dict = client.activate_appsec_config_version(configId=configId,
                                                               configVersion=configVersion,
                                                               acknowledgedInvalidHosts=acknowledgedInvalidHosts,
                                                               notificationEmails=notificationEmails,
                                                               action=action,
                                                               network=network,
                                                               note=note,
                                                               )
    if raw_response:
        title = f'{INTEGRATION_NAME} - activate appsec config version'
        entry_context, human_readable_ec = activate_appsec_config_version_command_ec(raw_response)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config.{network.capitalize()}": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)
        return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def get_appsec_config_activation_status_command(client: Client,
                                                activationId: int,
                                                sleepTime: str,
                                                retries: str) -> str:
    """
        Get appsec config version activation status command
    Args:
        client:
        activationsId
        sleepTime
        retries

    Returns:
        human readable (markdown format), entry context and raw response
    """
    activated = False
    retry = 0
    while not activated and retry < int(retries):
        sleep(int(sleepTime))
        activated = True
        raw_response: Dict = client.get_appsec_config_activation_status(activationId=activationId)
        if raw_response:
            if raw_response['status'] == 'ACTIVATED':
                network = raw_response.get('network')
                title = f'{INTEGRATION_NAME} - get appsec config version activation status'
                entry_context, human_readable_ec = get_appsec_config_activation_status_command_ec(raw_response)
                context_entry: Dict = {
                    f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config.{network.capitalize()}"
                    f"(val.ActivationId && val.ActivationId == obj.ActivationId)": entry_context
                }
                human_readable = tableToMarkdown(name=title,
                                                 t=human_readable_ec,
                                                 removeNull=True)
                return human_readable, context_entry, raw_response
        retry += 1

# Created by D.S.


@logger
def get_appsec_config_latest_version_command(client: Client,
                                             secConfigName: str,
                                             sleepTime: str,
                                             retries: str,
                                             skipConsistencyCheck: str) -> str:
    """
        1) Get appsec config Id and latestVersion.
        2) Check latestVersion and stagingVersion, productionVersion consistency
        if latestVersion, stagingVersion, productionVersion are not the same value,
        wait sleepTime X seconds and retries Y times.
    Args:
        client: http api client
        secConfigName: Name of the Security Configuration
        skipConsistencyCheck: Do not conduction LatestVersion, Staging Version, Production Version consistency check
        sleepTime: Number of seconds to wait before the next consistency check
        retries: Number of retries for the consistency check to be conducted

    Returns:
        human readable (markdown format), entry context and raw response
    """
    for i in range(0, int(retries)):
        raw_response: Dict = client.list_appsec_config()
        lookupKey = 'name'
        lookupValue = secConfigName
        appsec_config_latest: Dict = next(
            (item for item in raw_response['configurations'] if item[lookupKey] == lookupValue), None)
        latestVersion = appsec_config_latest.get("latestVersion")
        stagingVersion = appsec_config_latest.get("stagingVersion")
        productionVersion = appsec_config_latest.get("productionVersion")
        if skipConsistencyCheck == 'yes' or (latestVersion == stagingVersion == productionVersion or int(latestVersion) == 1):
            title = f'{INTEGRATION_NAME} - get secuirty configuration Latest Version'
            entry_context, human_readable_ec = get_appsec_config_latest_version_command_ec(appsec_config_latest)
            appsec_config_latest = demisto.get(demisto.context(), f"{INTEGRATION_CONTEXT_NAME}.AppSec")
            context_entry: Dict = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config(val.Name && val.Name == obj.Name)": entry_context
            }

            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
            return human_readable, context_entry, appsec_config_latest
        sleep(int(sleepTime))
    errorMsg = f'inconsistent latestVersion vs stagingVersion vs productionVersion for Security Configuration: {secConfigName}'
    return_error(errorMsg)


# Created by D.S.
@logger
def get_security_policy_id_by_name_command(client: Client,
                                           configId: dict,
                                           configVersion: str,
                                           policyName: str,
                                           isBaselinePolicy: str) -> str:
    """
        get a security policy ID by Policy name
                    It is also used to get the policy ID of "Baseline Security Policy"
    Args:
        client:
        configId
        versonId
        policyName
        isBaselinePolicy
    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: Dict = client.list_security_policy(configId=configId,
                                                     configVersion=configVersion)

    lookupKey = "policyName"
    lookupValue = policyName
    returnDict: Dict = next((item for item in raw_response['policies'] if item[lookupKey] == lookupValue), None)
    if returnDict is None:
        err_msg = f'Error in {INTEGRATION_NAME} - get a security policy ID by Policy name: Policy [{policyName}] not found'
        return_error(err_msg)
    else:
        title = f'{INTEGRATION_NAME} - get a security policy ID by Policy name'
        entry_context, human_readable_ec = get_security_policy_id_by_name_command_ec(returnDict, isBaselinePolicy)
        entry_context[0]['Id'] = configId
        if isBaselinePolicy == "yes":
            context_entry: Dict = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config(val.Id && val.Id == obj.Id)": entry_context
            }
        else:
            context_entry: Dict = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config.Policy(val.PolicyId && val.PolicyId == obj.PolicyId)": entry_context
            }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)
        return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def clone_appsec_config_version_command(client: Client,
                                        configId: int,
                                        createFromVersion: int,
                                        doNotClone: str,
                                        ) -> str:
    """
        Appsec Configurtion - create a new version by clone the latest version
    Args:
        configId
        createFromVersion
        doNotClone: Do not clone to create a new version, use in the test

    Returns:
        human readable (markdown format), entry context and raw response
    """
    if doNotClone == 'yes':
        raw_response: Dict = {"version": createFromVersion,
                              "configId": configId
                              }
    else:
        raw_response: Dict = client.clone_appsec_config_version(configId=configId,
                                                                createFromVersion=createFromVersion,
                                                                )
    if raw_response:
        title = f'{INTEGRATION_NAME} - Appsec Configurtion - create a new version by clone the latest version'
        entry_context, human_readable_ec = clone_appsec_config_version_command_ec(raw_response)
        context_entry: Dict = {
            f"{INTEGRATION_CONTEXT_NAME}.AppSec.Config(val.Id && val.Id == obj.Id)": entry_context
        }
        human_readable = tableToMarkdown(name=title,
                                         t=human_readable_ec,
                                         removeNull=True)
        return human_readable, context_entry, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client = Client(
        base_url=params.get('host'),
        verify=verify_ssl,
        proxy=proxy,
        auth=EdgeGridAuth(
            client_token=params.get('clientToken'),
            access_token=params.get('accessToken'),
            client_secret=params.get('clientSecret')
        )
    )
    command = demisto.command()
    demisto.debug(f'Command being called is {command}')
    commands = {
        'test-module': test_module_command,
        f'{INTEGRATION_COMMAND_NAME}-get-network-lists': get_network_lists_command,
        f'{INTEGRATION_COMMAND_NAME}-get-network-list-by-id': get_network_list_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-create-network-list': create_network_list_command,
        f'{INTEGRATION_COMMAND_NAME}-delete-network-list': delete_network_list_command,
        f'{INTEGRATION_COMMAND_NAME}-update-network-list-elements': update_network_list_elements_command,
        f'{INTEGRATION_COMMAND_NAME}-activate-network-list': activate_network_list_command,
        f'{INTEGRATION_COMMAND_NAME}-add-elements-to-network-list': add_elements_to_network_list_command,
        f'{INTEGRATION_COMMAND_NAME}-remove-element-from-network-list': remove_element_from_network_list_command,
        f'{INTEGRATION_COMMAND_NAME}-get-network-list-activation-status': get_activation_status_command,
        f'{INTEGRATION_COMMAND_NAME}-list-groups': list_groups_command,
        f'{INTEGRATION_COMMAND_NAME}-create-enrollment': create_enrollment_command,
        f'{INTEGRATION_COMMAND_NAME}-list-enrollments': list_enrollments_command,
        f'{INTEGRATION_COMMAND_NAME}-get-enrollment-by-cn': get_enrollment_by_cn_command,
        f'{INTEGRATION_COMMAND_NAME}-get-domains': get_domains_command,
        f'{INTEGRATION_COMMAND_NAME}-get-a-domain': get_a_domain_command,
        f'{INTEGRATION_COMMAND_NAME}-create-domain': create_domain_command,
        f'{INTEGRATION_COMMAND_NAME}-create-datacenter': create_datacenter_command,
        f'{INTEGRATION_COMMAND_NAME}-update-property': update_property_command,
        f'{INTEGRATION_COMMAND_NAME}-get-change': get_change_command,
        f'{INTEGRATION_COMMAND_NAME}-update-change': update_change_command,
        f'{INTEGRATION_COMMAND_NAME}-check-group': check_group_command,
        f'{INTEGRATION_COMMAND_NAME}-create-new-group': create_new_group_command,
        f'{INTEGRATION_COMMAND_NAME}-get-group': get_group_command,
        f'{INTEGRATION_COMMAND_NAME}-clone-papi-property': clone_papi_property_command,
        f'{INTEGRATION_COMMAND_NAME}-add-papi-property-hostname': add_papi_property_hostname_command,
        f'{INTEGRATION_COMMAND_NAME}-list-papi-edgehostname-bygroup': list_papi_edgehostname_bygroup_command,
        f'{INTEGRATION_COMMAND_NAME}-new-papi-edgehostname': new_papi_edgehostname_command,
        f'{INTEGRATION_COMMAND_NAME}-get-cps-enrollmentid-by-cnname': get_cps_enrollmentid_by_cnname_command,
        f'{INTEGRATION_COMMAND_NAME}-new-papi-cpcode': new_papi_cpcode_command,
        f'{INTEGRATION_COMMAND_NAME}-patch-papi-property-rule-cpcode': patch_papi_property_rule_cpcode_command,
        f'{INTEGRATION_COMMAND_NAME}-patch-papi-property-rule-origin': patch_papi_property_rule_origin_command,
        f'{INTEGRATION_COMMAND_NAME}-activate-papi-property': activate_papi_property_command,
        f'{INTEGRATION_COMMAND_NAME}-clone-security-policy': clone_security_policy_command,
        f'{INTEGRATION_COMMAND_NAME}-new-match-target': new_match_target_command,
        f'{INTEGRATION_COMMAND_NAME}-activate-appsec-config-version': activate_appsec_config_version_command,
        f'{INTEGRATION_COMMAND_NAME}-get-appsec-config-activation-status': get_appsec_config_activation_status_command,
        f'{INTEGRATION_COMMAND_NAME}-get-appsec-config-latest-version': get_appsec_config_latest_version_command,
        f'{INTEGRATION_COMMAND_NAME}-get-security-policy-id-by-name': get_security_policy_id_by_name_command,
        f'{INTEGRATION_COMMAND_NAME}-clone-appsec-config-version': clone_appsec_config_version_command,
    }
    try:
        readable_output, outputs, raw_response = commands[command](client=client, **demisto.args())
        return_outputs(readable_output, outputs, raw_response)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
