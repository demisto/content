import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401


""" IMPORTS """
# Std imports
import re
from datetime import datetime
import time
# 3-rd party imports
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
    def test_module(self) -> dict:
        """
            Performs basic GET request to check if the API is reachable and authentication is successful.
        Returns:
            Response dictionary
        """
        return self.get_network_lists(extended=False, include_elements=False)

    # Created by C.L.
    def create_enrollment(self,
                          contract_id: str,
                          country: str,
                          company: str,
                          organizational_unit: str,
                          city: str,
                          admin_contact: dict,
                          tech_contact: dict,
                          org: dict,
                          csr_cn: str = "",
                          change_management: bool = False,
                          certificate_type: str = "third-party",
                          enable_multi_stacked_certificates: bool = False,
                          network_configuration_geography: str = "core",
                          network_configuration_quic_enabled: bool = True,
                          network_configuration_secure_network: str = "enhanced-tls",
                          network_configuration_sni_only: bool = True,
                          clone_dns_names: bool = True,
                          exclude_sans: bool = False,
                          ra: str = "third-party",
                          validation_type: str = "third-party",
                          sans: list = []
                          ) -> dict:
        """
            Create an enrollment
        Args:
            contract_id:                 Contract id
            country:                    country - Two Letter format
            company:                    company Name
            organizational_unit:         Organizational Unit
            city:                       city Name
            admin_contact:               Admin Contact - Dictionary
            tech_contact:                tech_contact - Dictionary
            org:                        Organization name - Dictionary
            csr_cn:                     CName
            contract_id:                 Specify the contract on which to operate or view.
            csr_cn:                     CName to be created
            change_management:           change_management
            certificate_type:            Certificate Type
            enable_multi_stacked_certificates:     Enable Multi Stacked Certificates
            network_configuration_geography:     Network Configuration geography
            network_configuration_quic_enabled:   Network Configuration QuicEnabled
            network_configuration_secure_network: Network Configuration SecureNetwork
            network_configuration_sni_only:       Network Configuration sniOnly
            clone_dns_names:                    Network Configuration - Dns Name Settings - Clone DNS Names
            exclude_sans:                       Third Party - Exclude Sans
            ra: str = "third-party",
            validation_type: str = "third-party",

        Returns:
            Json response as dictionary
        """
        params = {
            "contractId": contract_id,
        }

        body = {"csr": {"sans": sans, "cn": csr_cn, "c": country, "o": company,
                        "ou": organizational_unit, "l": city,
                        },
                "adminContact": admin_contact,
                "techContact": tech_contact,
                "org": org,
                "networkConfiguration": {"geography": network_configuration_geography,
                                         "quicEnabled": network_configuration_quic_enabled,
                                         "sniOnly": network_configuration_sni_only,
                                         "secureNetwork": network_configuration_secure_network,
                                         "dnsNameSettings": {
                                             "cloneDnsNames": clone_dns_names,
                                             "dnsNames": [csr_cn]
                                         },
                                         },
                "certificateType": certificate_type,
                "changeManagement": change_management,
                "enableMultiStackedCertificates": enable_multi_stacked_certificates,
                "ra": ra,
                "validationType": validation_type,
                "thirdParty": {"excludeSans": exclude_sans}
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
                                      headers=headers,
                                      )
        return response

    # Created by C.L.

    def list_enrollments(self,
                         contract_id: str,
                         ) -> dict:
        """
            List enrollments
            Please refer to https://techdocs.akamai.com/cps/reference/get-enrollments

        Args:
            contract_id: Specify the contract on which to operate or view.

        Returns:
            Json response as dictionary
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.enrollments.v11+json",

        }
        params = {
            "contractId": contract_id,
        }
        return self._http_request(method='GET',
                                  url_suffix='/cps/v2/enrollments',
                                  headers=headers,
                                  timeout=(60, 180),
                                  params=params
                                  )

    # Created by C.L.

    def get_change(self,
                   enrollment_path: str,
                   allowed_input_type_param: str = "third-party-csr"
                   ) -> dict:
        """
            Get change
            Please refer to https://techdocs.akamai.com/cps/reference/get-change-allowed-input-param

        Args:
            enrollment_path: The path that includes enrollmentId and changeId:
                e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
            allowed_input_type_param: Specify the contract on which to operate or view.

        Returns:
            Json response as dictionary
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.csr.v2+json",
        }
        return self._http_request(method='GET',
                                  url_suffix=f'{enrollment_path}/input/info/{allowed_input_type_param}',
                                  headers=headers)

    # Created by C.L.
    def update_change(self,
                      change_path: str,
                      certificate: str,
                      trust_chain: str,
                      allowed_input_type_param: str = "third-party-cert-and-trust-chain",
                      key_algorithm: str = "RSA"
                      ) -> dict:
        """
            Update a change
            Please refer to https://techdocs.akamai.com/cps/reference/post-change-allowed-input-param

        Args:
            change_path: The path that includes enrollmentId and changeId: e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
            changeId: Specify the ChangeID on which to operate or view.
            enrollmentId: Specify the enrollmentID on which to operate or view.
            allowed_input_type_param: Specify the contract on which to operate or view.
            key_algorithm: RSA and ECDSA

        Returns:
            Json response as dictionary
        """
        payload = ""
        if key_algorithm == "RSA":
            payload = '{\"certificatesAndTrustChains\":[{\"certificate\":\"' + certificate + '\",' \
                ' \"keyAlgorithm\":\"RSA\",' \
                '\"trustChain\":\"' + trust_chain + '\"}]}'

        if key_algorithm == "ECDSA":
            payload = '{\"certificatesAndTrustChains\":[{\"certificate\":\"' + certificate + '\",' \
                ' \"keyAlgorithm\":\"ECDSA\",' \
                '\"trustChain\":\"' + trust_chain + '\"}]}'

        headers = {
            "Accept": "application/vnd.akamai.cps.change-id.v1+json",
            "Content-Type": "application/vnd.akamai.cps.certificate-and-trust-chain.v2+json",
        }

        return self._http_request(method='POST',
                                  url_suffix=f"{change_path}/input/update/{allowed_input_type_param}",
                                  headers=headers,
                                  data=payload
                                  )

    # Created by C.L.

    def acknowledge_warning(self, change_path: str, allowed_input_type_param: str = 'post-verification-warnings-ack') -> dict:
        """
            Acknowledge the warning message after updating a enrollment change

        Args:
            change_path: The path that includes enrollmentId and changeId: e.g. /cps/v2/enrollments/enrollmentId/changes/changeId

        Returns:
            Json response as dictionary
        """
        headers = {
            "Accept": "application/vnd.akamai.cps.change-id.v1+json",
            "Content-Type": "application/vnd.akamai.cps.acknowledgement.v1+json",
        }
        payload = '{"acknowledgement": "acknowledge"}'
        return self._http_request(
            method='POST',
            url_suffix=f"{change_path}/input/update/{allowed_input_type_param}",
            headers=headers,
            data=payload
        )

    # Created by C.L.

    def acknowledge_pre_verification_warning(self, change_path: str) -> dict:
        """
            Acknowledge the pre verification warning message after initiate an enrollment change

        Args:
            change_path: The path that includes enrollmentId and changeId: e.g. /cps/v2/enrollments/enrollmentId/changes/changeId

        Returns:
            Json response as dictionary
        """
        headers = {
            "Content-Type": "application/vnd.akamai.cps.acknowledgement.v1+json",
            "Accept": "application/vnd.akamai.cps.change-id.v1+json"
        }

        payload = '{"acknowledgement": "acknowledge"}'
        return self._http_request(
            method='POST',
            url_suffix=f"{change_path}/input/update/pre-verification-warnings-ack",
            headers=headers,
            data=payload
        )

    # Created by C.L. Oct-06-22

    def get_production_deployment(self,
                                  enrollment_id: str
                                  ) -> dict:
        """
            get production deployment by enrollment id.

        Returns:
            Json response as dictionary
        """

        headers = {"accept": "application/vnd.akamai.cps.deployment.v7+json"}

        return self._http_request(method='GET',
                                  url_suffix=f"/cps/v2/enrollments/{enrollment_id}/deployments/production",
                                  headers=headers,
                                  )

    # Created by C.L. Oct-06-22
    def get_change_history(self,
                           enrollment_id: str
                           ) -> dict:
        """
            get change history by enrollment id.

        Returns:
            Json response as dictionary
        """

        headers = {"accept": "application/vnd.akamai.cps.change-history.v5+json"}

        return self._http_request(method='GET',
                                  url_suffix=f"/cps/v2/enrollments/{enrollment_id}/history/changes",
                                  headers=headers,
                                  )

    # Created by C.L.

    def list_groups(self):

        all_groups = self._http_request(method='GET', url_suffix='/identity-management/v2/user-admin/groups')

        return all_groups

    def get_group(self,
                  group_id: int = 0
                  ) -> dict:
        """
            Get the information of a group
        Args:
            group_id : Group ID

        Returns:
            Json response as dictionary
        """
        # Add Authorization header to this snippet
        headers = {"Accept": "application/json"}

        return self._http_request(method='GET',
                                  url_suffix=f"/identity-management/v2/user-admin/groups/{group_id}?actions=false",
                                  headers=headers)

    # Created by C.L.

    def create_group(self,
                     group_id: int = 0, groupname: str = ""
                     ) -> dict:
        """
            Create a new group
        Args:
            group_id : Group ID

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
                                  url_suffix=f"/identity-management/v2/user-admin/groups/{group_id}",
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
    def get_domain(self, domain_name: str):
        """
            Get information of a specific domain
        Args:
            domain_name : Domain Name

        Returns:
            Json response as dictionary
        """
        url_suffix = f"/config-gtm/v1/domains/{domain_name}"

        headers = {"Accept": "application/vnd.config-gtm.v1.5+json"}
        response = self._http_request(method='GET',
                                      url_suffix=url_suffix,
                                      headers=headers)
        return response

    # Created by C.L.
    def create_domain(self, group_id: int, domain_name: str) -> dict:
        """
           Creating domains
        Args:
            group_id : The group ID
            domain_name: Domain Name

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
            "name": domain_name,
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
            "gid": group_id}

        return self._http_request(method='POST',
                                  url_suffix='/config-gtm/v1/domains',
                                  params=params,
                                  headers=headers,
                                  json_data=body)

    # Created by C.L.
    def create_datacenter(self, domain_name: str, dc_name: str = "", dc_country: str = "",):
        """
        Updating or adding datacenter to existing GTM domain
        Args:

            domain_name: Domain Name
            DC_nam2: The name of the Data center
            dc_country: The country of the Data center


        Returns:
            Json response as dictionary
        """

        body = {
            "nickname": dc_name,
            "scorePenalty": 0,
            "country": dc_country,
            "virtual": True,
            "cloudServerTargeting": False,
            "cloudServerHostHeaderOverride": False,
        }

        headers = {
            "Accept": "application/vnd.config-gtm.v1.5+json",
            "Content-Type": "application/datacenter-vnd-config-gtm.v1.5+json"
        }

        return self._http_request(method='POST',
                                  url_suffix=f'/config-gtm/v1/domains/{domain_name}/datacenters',
                                  headers=headers,
                                  json_data=body)

    # Created by C.L.

    def update_property(self, property_type: str, domain_name: str, property_name: str,
                        static_type: str = "", property_comments: str = "", static_server: str = "", server_1: str = "",
                        server_2: str = "", weight_1: int = 50, weight_2: int = 50, dc1_id: int = 3131, dc2_id: int = 3132):
        """
        Updating or adding properties to existing GTM domain

        Args:
            property_type : Property Type
            domain_name: Domain Name
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
            trafficTargets: List[dict] = []
        elif property_type == "failover":
            staticRRSets = []
            trafficTargets = []
            if server_1 != "":
                trafficTargets.append(
                    {
                        "datacenterId": dc1_id,  # static number
                        "enabled": True,
                        "weight": 1,              # 50 if type== round robin, 1 is primary if type==failover
                        "servers": [
                            server_1          # user input
                        ]
                    })
            if server_2 != "":
                trafficTargets.append(
                    {
                        "datacenterId": dc2_id,  # static number
                        "enabled": True,
                        "weight": 0,              # 50 if type== round robin, 1 is primary if type==failover
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
                        "datacenterId": dc1_id,  # static number
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
                        "datacenterId": dc2_id,
                        "enabled": True,
                        "weight": weight_2,                 # 50 if type== round robin, 0 is secondary if type==failover
                        "servers": [
                            server_2            # user input
                        ]
                    }

                )
        else:
            staticRRSets = []
            trafficTargets = []
            demisto.debug(f"{property_type} -> initialized {staticRRSets=} {trafficTargets=}")

        body = {
            "balanceByDownloadScore": False,
            "dynamicTTL": 60,
            "failoverDelay": 0,
            "failbackDelay": 0,
            "ghostDemandReporting": False,
            "comments": property_comments,
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
                                  url_suffix=f'/config-gtm/v1/domains/{domain_name}/properties/{property_name}',
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

    def create_network_list(self, list_name: str, list_type: str, elements: Union[list, str] = None,
                            description: str = None) -> dict:
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
                "1.2.3.4/15",
                "1.2.3.5"
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

        raw_response: dict = self.get_network_list_by_id(network_list_id=network_list_id)
        if raw_response:
            SyncPoint = raw_response.get('syncPoint')
            Name = raw_response.get('name')
            Type = raw_response.get('type')

        else:
            SyncPoint = None
            Name = None
            Type = None
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

    def activate_network_list(self, network_list_id: str, env: str, comment: str = None,
                              notify: list = None) -> dict:
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
                                             '/activate',
                                  json_data=body,
                                  resp_type='response')

    def add_elements_to_network_list(self, network_list_id: str, elements: Union[list, str] = None) -> dict:
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
                          product_id: str,
                          property_name: str,
                          contract_id: str,
                          group_id: str,
                          ) -> dict:
        """
            Create a new papi property
        Args:
            product_id
            property_name
            contract_id
            group_id

        Returns:
            The response provides a URL link to the newly created property.
        """
        body = {
            "productId": product_id,
            "propertyName": property_name,
            "ruleFormat": 'latest'
        }

        headers = {
            "Accept": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id
        }

        return self._http_request(method='POST',
                                  url_suffix='/papi/v1/properties',
                                  headers=headers,
                                  json_data=body,
                                  params=params,
                                  )

    # created by D.S.
    def list_papi_property_bygroup(self,
                                   contract_id: str,
                                   group_id: str) -> dict:
        """
            List properties available for the current contract and group.
        Args:
            contract_id:
            group_id:

        Returns:
            <Response [200]>
            The response lists all properties available for the requested contract and group.
        """

        params = {
            "contractId": contract_id,
            "groupId": group_id,
        }

        headers = {
            "PAPI-Use-Prefixes": 'true'
        }

        return self._http_request(method='GET',
                                  url_suffix='papi/v1/properties',
                                  headers=headers,
                                  params=params)

    # created by D.S.
    def clone_papi_property(self,
                            product_id: str,
                            property_name: str,
                            contract_id: str,
                            group_id: str,
                            property_id: str,
                            version: str
                            ) -> dict:
        """
            Clone a new papi property from an existing template property
        Args:
            product_id
            property_name
            contract_id
            group_id

        Returns:
            <Response [201]>
            The response provides a URL link to the newly created property.
        """
        body = {
            "productId": product_id,
            "propertyName": property_name,
            "cloneFrom": {
                "propertyId": property_id,
                "version": version,
                "copyHostnames": "False"
            }
        }

        headers = {
            "Accept": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id
        }

        return self._http_request(method='POST',
                                  url_suffix='papi/v1/properties',
                                  headers=headers,
                                  json_data=body,
                                  params=params
                                  )

    # created by D.S.
    def add_papi_property_hostname(self,
                                   property_version: str,
                                   property_id: str,
                                   contract_id: str,
                                   group_id: str,
                                   validate_hostnames: bool,
                                   include_cert_status: bool,
                                   cname_from: str,
                                   edge_hostname_id: str,
                                   ) -> dict:
        """
            add a hostname into papi property
        Args:
            property_version:
            property_id:
            contract_id:
            group_id:
            validate_hostnames:
            include_cert_status:
            cname_from:
            edge_hostname_id: str,

        Returns:
            <Response [200]>
        """
        body = {
            "add": [
                {
                    "certProvisioningType": "CPS_MANAGED",
                    "cnameType": "EDGE_HOSTNAME",
                    "cnameFrom": cname_from,
                    "edgeHostnameId": edge_hostname_id,
                }
            ]
        }

        headers = {
            "Accept": 'application/json',
            "Content-Type": 'application/json',
            "PAPI-Use-Prefixes": 'true',
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id,
            "validateHostnames": validate_hostnames,
            "includeCertStatus": include_cert_status
        }

        return self._http_request(method='PATCH',
                                  url_suffix=f'papi/v1/properties/{property_id}/versions/{property_version}/hostnames',
                                  headers=headers,
                                  params=params,
                                  json_data=body)

    # created by D.S.
    def list_papi_edgehostname_bygroup(self,
                                       contract_id: str,
                                       group_id: str,
                                       options: str) -> dict:
        """
            clone a new property from an existing template property
        Args:
            contract_id:
            group_id:
            options:

        Returns:
            <Response [200]>
            The response provides a URL link to the newly created property.
        """

        params = {
            "contractId": contract_id,
            "groupId": group_id,
            "options": options
        }

        headers = {
            "PAPI-Use-Prefixes": 'true'
        }

        return self._http_request(method='GET',
                                  url_suffix='papi/v1/edgehostnames',
                                  headers=headers,
                                  params=params)

    # created by D.S.
    def new_papi_edgehostname(self,
                              product_id: str,
                              contract_id: str,
                              group_id: str,
                              options: str,
                              domain_prefix: str,
                              domain_suffix: str,
                              ip_version_behavior: str,
                              secure: str,
                              secure_network: str,
                              cert_enrollment_id: str
                              ) -> dict:
        """
            add a new edge hostname via Papi
        Args:
            product_id:
            contract_id:
            group_id:
            options:
            domain_prefix:
            domain_suffix:
            ip_version_behavior:
            secure:
            secure_network:
            cert_enrollment_id:

        Returns:
            <Response [200]>

        """
        body = {
            "productId": product_id,
            "domainPrefix": domain_prefix,
            "domainSuffix": domain_suffix,
            "ipVersionBehavior": ip_version_behavior,
            "secure": secure,
            "secureNetwork": secure_network,
            "certEnrollmentId": cert_enrollment_id
        }

        headers = {
            "Accept": 'application/json',
            "Content-Type": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id,
            "options": options
        }

        return self._http_request(method='POST',
                                  url_suffix='papi/v1/edgehostnames',
                                  headers=headers,
                                  json_data=body,
                                  params=params)

    # created by D.S.
    def list_cps_enrollments(self,
                             contract_id: str,
                             ) -> dict:
        """
            list all cps enrollments
        Args:
            contract_id

        Returns:
            <Response [201]>
            The response provides a URL link to the newly created property.
        """

        headers = {
            "Accept": 'application/vnd.akamai.cps.enrollments.v11+json'
        }

        contract_id = contract_id.split('_')[1]

        params = {
            "contractId": contract_id
        }

        return self._http_request(method='GET',
                                  url_suffix='cps/v2/enrollments',
                                  headers=headers,
                                  params=params)

    # created by D.S.
    def list_papi_cpcodeid_bygroup(self,
                                   contract_id: str,
                                   group_id: str) -> dict:
        """
            clone a new property from an existing template property
        Args:
            contract_id:
            group_id:

        Returns:
            <Response [200]>
            The response provides a URL link to the newly created property.
        """
        headers = {
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id
        }

        return self._http_request(method='GET',
                                  url_suffix='papi/v1/cpcodes',
                                  headers=headers,
                                  params=params)

    # created by D.S.
    def new_papi_cpcode(self,
                        product_id: str,
                        contract_id: str,
                        group_id: str,
                        cpcode_name: str,
                        ) -> dict:
        """
            clone a new property from an existing template property
        Args:
            product_id:
            contract_id:
            group_id:
            cpcode_name:

        Returns:
            <Response [201]>
            The response provides a URL link to the newly created property.
        """
        body = {
            "productId": product_id,
            "cpcodeName": cpcode_name
        }

        headers = {
            "Accept": 'application/json',
            "Content-Type": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id
        }

        return self._http_request(method='POST',
                                  url_suffix='papi/v1/cpcodes',
                                  headers=headers,
                                  json_data=body,
                                  params=params)

    # created by D.S.
    def patch_papi_property_rule(self,
                                 contract_id: str,
                                 group_id: str,
                                 property_id: str,
                                 property_version: str,
                                 validate_rules: str,
                                 body,
                                 ) -> dict:
        """
            clone a new property from an existing template property
        Args:
            contract_id: str,
            group_id: str,
            property_id: str,
            property_version: str,
            validate_rules: str,
            body:

        Returns:
            <Response [201]>
            The response provides a URL link to the newly created property.
        """

        headers = {
            "Accept": 'application/vnd.akamai.papirules.latest+json',
            "Content-Type": 'application/json-patch+json',
            "PAPI-Use-Prefixes": 'true'
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id,
            "validateRules": validate_rules
        }

        return self._http_request(method='PATCH',
                                  url_suffix=f'/papi/v1/properties/{property_id}/versions/{property_version}/rules',
                                  headers=headers,
                                  params=params,
                                  json_data=body)

    # created by D.S.
    def activate_papi_property(self,
                               contract_id: str,
                               group_id: str,
                               property_id: str,
                               network: str,
                               notify_emails: str,
                               property_version: int,
                               note: str
                               ):
        """
            activate an property
        Args:
            contract_id: str,
            group_id: str,
            property_id: grp_#######
            network: "STAGING" or "PRODUCTION"
            notify_emails: akamaizers@fisglobal.com
            property_version:

        Returns:
            <Response [204]>
        """
        body = {
            "acknowledgeAllWarnings": "true",
            "activationType": "ACTIVATE",
            "fastPush": "true",
            "ignoreHttpErrors": "true",
            "network": network,
            "notifyEmails": [notify_emails],
            "propertyVersion": property_version,
            "useFastFallback": "false",
            "note": note
        }

        headers = {
            "PAPI-Use-Prefixes": "true"
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id
        }

        return self._http_request(method='POST',
                                  url_suffix=f'/papi/v1/properties/{property_id}/activations',
                                  headers=headers,
                                  json_data=body,
                                  params=params)

    # created by D.S.
    def clone_security_policy(self,
                              config_id: int,
                              config_version: int,
                              create_from_security_policy: str,
                              policy_name: str,
                              policy_prefix: str
                              ):
        """
            Clone a new security policy from template policy
        Args:
            config_id:
            create_from_security_policy:
            policy_name:
            config_version:

        Returns:
            <Response [204]>
        """
        body = {
            "createFromSecurityPolicy": create_from_security_policy,
            "policyName": policy_name,
            "policyPrefix": policy_prefix
        }

        headers = {
            "Content-Type": "application/json",
        }

        return self._http_request(method='POST',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions/{config_version}/security-policies',
                                  headers=headers,
                                  json_data=body,
                                  )

    # created by D.S.
    def new_match_target(self,
                         config_id: int,
                         config_version: int,
                         match_type: str,
                         bypass_network_lists: list,
                         default_file: str,
                         file_paths: list,
                         hostnames: list,
                         policy_id: str
                         ):
        """
            New match target
        Args:
            config_id
            config_version
            type
            bypass_network_lists
            default_file
            file_paths
            hostnames
            securityPolicy

        Returns:
            <Response [204]>

        """

        body = {
            'type': match_type,
            'defaultFile': default_file,
            'securityPolicy': {'policyId': policy_id},
            'bypassNetworkLists': bypass_network_lists,
            'filePaths': file_paths,
            'hostnames': hostnames
        }

        headers = {
            "Content-Type": "application/json",
        }

        return self._http_request(method='POST',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions/{config_version}/match-targets',
                                  headers=headers,
                                  json_data=body
                                  )

    # created by D.S.
    def activate_appsec_config_version(self,
                                       config_id: int,
                                       config_version: int,
                                       acknowledged_invalid_hosts: list,
                                       notification_emails: list,
                                       action: str,
                                       network: str,
                                       note: str,
                                       ):
        """
        Activate AppSec Configuration version
        Args:
            config_id
            config_version
            acknowledged_invalid_hosts
            notification_emails
            action
            network
            note

        Returns:
            <Response [204]>

        """
        body = {
            "acknowledgedInvalidHosts": acknowledged_invalid_hosts,
            "activationConfigs": [
                {
                    "configId": config_id,
                    "configVersion": config_version,
                }
            ],
            "notificationEmails": notification_emails,
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
                                            activation_id: str,
                                            ):
        """
            Get AppSec Configuration activation Status
        Args:
            activiationId

        Returns:
            <Response [204]>
        """

        return self._http_request(method='Get',
                                  url_suffix=f'appsec/v1/activations/{activation_id}',
                                  )

    # created by D.S.
    def list_appsec_config(self):
        """
        List security configuration
        Args:

        Returns:
            <Response [204]>
            Sample: TBD
        """

        return self._http_request(method='Get',
                                  url_suffix='appsec/v1/configs',
                                  )

    # created by D.S.
    def list_appsec_config_versions(self,
                                    config_id: str):
        """
            List security configuration versions
        Args:
            config_id

        Returns:
            <Response [204]>
            Sample: TBD
        """

        return self._http_request(method='Get',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions',
                                  )

    # created by D.S.
    def list_security_policy(self,
                             config_id: str,
                             config_version):
        """
            List security policy
        Args:
            config_id
            versionId

        Returns:
            <Response [204]>
            Sample: TBD
        """

        params = {"detail": "false"}

        return self._http_request(method='Get',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions/{config_version}/security-policies',
                                  params=params
                                  )

    # created by D.S.
    def clone_appsec_config_version(self,
                                    config_id: str,
                                    create_from_version: str,
                                    rule_update: bool = True) -> dict:
        """
        Create a new version of security configuration from a previous version
        Args:
            config_id: AppSec configuration ID
            create_from_version: AppSec configuration version number to create from
            rule_update: Specifies whether the application rules should be migrated to the latest version.

        Returns:
            <Response [204]>
        """
        body = {
            "createFromVersion": int(create_from_version),
            "ruleUpdate": rule_update
        }
        return self._http_request(method='Post',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions',
                                  json_data=body,
                                  timeout=(60, 180),
                                  retries=0,
                                  )

    # created by D.S.
    def get_papi_property_activation_status(self,
                                            activation_id: int,
                                            property_id
                                            ):
        """
            Get papi property activation Status
        Args:
            activiationId
            property_id
        Returns:
            <Response [204]>
        """

        headers = {
            "PAPI-Use-Prefixes": 'true'
        }

        return self._http_request(method='Get',
                                  url_suffix=f'papi/v1/properties/{property_id}/activations/{activation_id}',
                                  headers=headers
                                  )

    # created by D.S.

    def get_papi_edgehostname_creation_status(self,
                                              contract_id: str,
                                              group_id: str,
                                              edgehostname_id: str,
                                              options: str
                                              ):
        """
            Get papi edgehostname creation Status
        Args:
            contract_id
            group_id
            edgehostname_id
            options
        Returns:
            <Response [204]>
        """

        headers = {
            "Accept": 'application/json',
            "PAPI-Use-Prefixes": 'true'
        }

        return self._http_request(
            method='Get',
            url_suffix=f'papi/v1/edgehostnames/{edgehostname_id}?contractId={contract_id}&groupId={group_id}&options={options}',
            headers=headers
        )

    # Created by D.S. 2022-10-25

    def modify_appsec_config_selected_hosts(self, config_id: int,
                                            config_version: int,
                                            hostname_list: List[dict],
                                            mode: str
                                            ) -> dict:
        """
            Update the list of selected hostnames for a configuration version.

        Args:
            config_id: A unique identifier for each configuration.
            config_version: A unique identifier for each version of a configuration.
            hostname_list:  A list hostnames is used to modifying the configuration.
            mode: The type of update you want to make to the evaluation hostname list.
                - Use "append" to add additional hostnames.
                - Use "remove" to delete the hostnames from the list.
                - Use "replace" to replace the existing list with the hostnames you pass in your request.

        Returns:
            Json response as dictionary

        Notes:
           hostname_list = [{"hostname": "*.abc.com"}, {"hostname": "*.bdc.com"}]
        """

        headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }

        body = {
            "hostnameList": hostname_list,
            "mode": mode
        }

        return self._http_request(method='PUT',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions/{config_version}/selected-hostnames',
                                  headers=headers,
                                  json_data=body)

    # Created by D.S.

    def update_appsec_config_version_notes(self, config_id: int, config_version: int, notes: str) -> dict:
        """
            Update application secuirty configuration version notes
        Args:
            config_id: The ID of the application seucirty configuration
            config_version: The version number of the application seucirty configuration
            notes:  The notes need to be written into the application seucirty configuration version

        Returns:
            Json response as dictionary

        """

        headers = {
            "accept": "application/json",
            "content-type": "application/json"
        }

        body = {"notes": notes}

        return self._http_request(method='PUT',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions/{config_version}/version-notes',
                                  headers=headers,
                                  json_data=body)

    # created by D.S.

    def list_match_target(self,
                          config_id: int,
                          config_version: int,
                          policy_id: str,
                          includeChildObjectName: str
                          ):
        """
            list match targets within a Security Policy of the security configuration
        Args:
            config_id: A unique identifier for each configuration.
            config_version: A unique identifier for each version of a configuration.
            policy_id: Specifies the security policy to filter match targets.
            includeChildObjectName: Specify whether to return the object name in the payload.

        Returns:
            <Response [200]>

        """

        headers = {
            "accept": "application/json",
        }

        return self._http_request(method='GET',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions/{config_version}/match-targets?policyId='
                                  f'{policy_id}&includeChildObjectName={includeChildObjectName}',
                                  headers=headers,
                                  )

    # created by D.S.

    def modify_match_target(self,
                            config_id: int,
                            config_version: int,
                            policy_id: str,
                            match_target_id: int,
                            match_type: str,
                            bypass_network_lists: list,
                            default_file: str,
                            file_paths: list,
                            hostnames: list,
                            ):
        """
            modify match target
        Args:
            config_id: A unique identifier for each configuration.
            config_version: A unique identifier for each version of a configuration.
            policy_id: Specifies the security policy to filter match targets.
            match_target_id: A unique identifier for each match target
            bypass_network_lists: Bypass network lists
            default_file: Describes the rule to match on paths.
            file_paths: Contains a list of file paths
            hostnames: A list of hostnames that need to be added into match target

        Returns:
            <Response [204]>

        """

        body = {
            'type': match_type,
            'defaultFile': default_file,
            'securityPolicy': {'policyId': policy_id},
            'bypassNetworkLists': bypass_network_lists,
            'filePaths': file_paths,
            'hostnames': hostnames
        }
        headers = {
            "accept": "application/json",
            "Content-Type": "application/json",
        }

        return self._http_request(method='PUT',
                                  url_suffix=f'appsec/v1/configs/{config_id}/versions/{config_version}/'
                                             f'match-targets/{match_target_id}',
                                  headers=headers,
                                  json_data=body
                                  )

    # created by D.S.
    def get_papi_property_rule(self,
                               contract_id: str,
                               property_id: str,
                               property_version: int,
                               group_id: str,
                               validate_rules: str
                               ):
        """
            get papi property rule dictionary
        Args:
            contract_id: str,
            property_id: str,
            property_version: int,
            group_id: str
            validateRules: str
        Returns:
            <Response [200]>

        """

        headers = {
            "accept": "application/json ",
            'PAPI-Use-Prefixes': 'true'
        }

        return self._http_request(method='GET',
                                  url_suffix=f'papi/v1/properties/{property_id}/versions/{property_version}'
                                             f'/rules?contractId={contract_id}'
                                  f'&groupId={group_id}&validateRules={validate_rules}',
                                  headers=headers,
                                  )

    # Created by D.S. 2022-11-25
    def get_papi_property_bygroup(self,
                                  contract_id: str,
                                  group_id: str,
                                  property_id: str,) -> dict:
        """
            get property by propertyId with a group
        Args:
            contract_id: Unique identifier for the contract
            group_id: Unique identifier for the group
            property_id: Unique identifier for the property

        Returns:
            <Response [200]>
        """

        params = {
            "contractId": contract_id,
            "groupId": group_id,
        }

        headers = {
            "accept": "application/json",
            "PAPI-Use-Prefixes": 'true'
        }

        return self._http_request(method='GET',
                                  url_suffix=f'papi/v1/properties/{property_id}',
                                  headers=headers,
                                  params=params)

    # Created by D.S. 2023-02-27
    def new_papi_property_version(self,
                                  contract_id: str,
                                  property_id: str,
                                  group_id: str,
                                  create_from_version: str,
                                  ) -> dict:
        """
            Create a new property version based on any previous version.
            All data from the createFromVersion populates the new version, including its rules and hostnames.
        Args:
            contract_id: Unique identifier for the contract.
            property_id: Unique identifier for the property.
            group_id: Unique identifier for the group.
            create_from_version: The property version on which to base the new version.

        Returns:
            The response provides a URL link to the newly created property in dictionary
            {
                "versionLink": "/papi/v1/properties/prp_123456/versions/4?contractId=ctr_X-nYYYYY&groupId=grp_654321"
            }
        """
        body = {
            "createFromVersion": create_from_version
        }
        headers = {
            "Accept": 'application/json',
            "content-type": "application/json",
        }

        params = {
            "contractId": contract_id,
            "groupId": group_id
        }

        return self._http_request(method='POST',
                                  url_suffix=f'/papi/v1/properties/{property_id}/versions',
                                  headers=headers,
                                  json_data=body,
                                  params=params,
                                  )

    def list_papi_property_activations(self,
                                       contract_id: str,
                                       property_id: str,
                                       group_id: str,) -> dict:
        """
            This lists all activations for all versions of a property, on both production and staging networks.
        Args:
            contract_id: Unique identifier for the contract.
            property_id: Unique identifier for the property.
            group_id: Unique identifier for the group.

        Returns:
            The response provides a dictionary that include a list of activations

        """

        params = {
            "contractId": contract_id,
            "groupId": group_id
        }

        return self._http_request(method='GET',
                                  url_suffix=f'/papi/v1/properties/{property_id}/activations',
                                  params=params,
                                  )

    def list_appsec_configuration_activation_history(self,
                                                     config_id: int,) -> dict:
        """
            Lists the activation history for a configuration.
            The history is an array in descending order of submitDate.
            The most recent submitted activation lists first. Products: All.
        Args:
            config_id: Unique identifier for the contract.

        Returns:
            The response provides a dictionary that include a list of activations

        """
        headers = {"accept": "application/json"}

        return self._http_request(method='GET',
                                  url_suffix=f'/appsec/v1/configs/{config_id}/activations',
                                  headers=headers,
                                  )

    def list_papi_property_by_hostname(self,
                                       hostname: str,
                                       network: str = None,
                                       contract_id: str = None,
                                       group_id: str = None,) -> dict:
        """
            This operation lists active property hostnames for all properties available in an account.
        Args:
            hostname: Filter the results by cnameFrom. Supports wildcard matches with *.
            network: Network of activated hostnames, either STAGING or PRODUCTION.
            contract_id: Unique identifier for the contract.
            group_id: Unique identifier for the group.

        Returns:
            The response provides a dictionary that include a list of properties

        """
        headers = {"accept": "application/json"}
        method = "GET"
        params = {"sort": "hostname:a",
                  "hostname": hostname,
                  "network": network,
                  "contractId": contract_id,
                  "groupId": group_id
                  }
        return self._http_request(method=method,
                                  url_suffix='papi/v1/hostnames',
                                  params=params,
                                  headers=headers,
                                  )

    def list_siteshield_maps(self) -> dict:
        """
            Returns a list of all Site Shield maps that belong to your account.
        Args:
            N/A

        Returns:
            The response provides a list of siteshield maps

        """
        return self._http_request(method="GET",
                                  url_suffix='siteshield/v1/maps',
                                  headers={"accept": "application/json"},
                                  )

    def list_cidr_blocks(self, effective_date_gt: str = '', last_action: str = '') -> dict:
        """
            List all CIDR blocks for all services you are subscribed to.
            To see additional CIDR blocks, subscribe yourself to more services and run this operation again
        Args:
            last_action:
                Whether a CIDR block was added, updated, or removed from service.
                You can use this parameter as a sorting mechanism and return only CIDR blocks with a change status of add,
                update, or delete.
                Note that a status of delete means the CIDR block is no longer in service, and you can remove it from your
                firewall rules.
            effective_date_gt:
                The ISO 8601 date the CIDR block starts serving traffic to your origin.
                Expected format MM-DD-YYYY or YYYY-MM-DD
                Ensure your firewall rules are updated to allow this traffic to pass through before the effective date.

        Returns:
            The response provides a list of siteshield maps

        """
        headers = {"accept": "application/json"}
        params = {
            "lastAction": last_action,
            "effectiveDateGt": effective_date_gt,
        }
        method = "GET"
        return self._http_request(method=method,
                                  url_suffix='firewall-rules-manager/v1/cidr-blocks',
                                  headers=headers,
                                  params=params,
                                  )

    def get_cps_enrollment_deployment(self,
                                      enrollment_id: int,
                                      environment: str,) -> dict:
        """
            Returns the certification/Enarollment deployment status for specific a environtment: production or staging.
        Args:
            enrollment_id: Unique Identifier of the Enrollment on which to perform the desired operation.
            environment: Environment where the certificate is deployed: production or staging

        Returns:
            The response provides a deployment associcated to the enrollment id

        """
        headers = {"accept": "application/vnd.akamai.cps.deployment.v7+json"}
        method = "GET"
        return self._http_request(method=method,
                                  url_suffix=f'cps/v2/enrollments/{enrollment_id}/deployments/{environment}',
                                  headers=headers,
                                  )

    def update_cps_enrollment(self,
                              enrollment_id: str,
                              updates: dict,
                              deploy_not_after: str = '',
                              deploy_not_before: str = '',
                              allow_cancel_pending_changes: str = 'true',
                              allow_staging_bypass: str = 'true',
                              force_renewal: str = 'true',
                              renewal_date_check_override: str = 'true',
                              allow_missing_certificate_addition: str = 'true') -> dict:
        """
            Returns the enrollment change path.
        Args:
            enrollment_id: Unique Identifier of the Enrollment on which to perform the desired operation.
            updates: updates in dict format

        Returns:
            The response provides the enrollment change path

        """
        method = "PUT"
        headers = {
            'Accept': 'application/vnd.akamai.cps.enrollment-status.v1+json',
            'content-type': 'application/vnd.akamai.cps.enrollment.v11+json',
        }
        params = {
            "allow-cancel-pending-changes": allow_cancel_pending_changes,
            "allow-staging-bypass": allow_staging_bypass,
            "deploy-not-after": deploy_not_after,
            "deploy-not-before": deploy_not_before,
            "force-renewal": force_renewal,
            "renewal-date-check-override": renewal_date_check_override,
            "allow-missing-certificate-addition": allow_missing_certificate_addition
        }

        return self._http_request(method=method,
                                  url_suffix=f'cps/v2/enrollments/{enrollment_id}',
                                  headers=headers,
                                  params=params,
                                  json_data=updates
                                  )

    def get_enrollment_byid(self,
                            enrollment_id: str,
                            json_version: str = '11') -> dict:
        """
            Returns the enrollment with the ID specified.
        Args:
            enrollment_id: Unique Identifier of the Enrollment on which to perform the desired operation.
            json_version: the version of the data structure in Json format

        Reference:
            https://techdocs.akamai.com/cps/reference/get-enrollment

        Returns:
            The response provides the enrollment

        """
        method = "GET"
        headers = {
            'Accept': f'application/vnd.akamai.cps.enrollment.v{json_version}+json',
        }

        return self._http_request(method=method,
                                  url_suffix=f'cps/v2/enrollments/{enrollment_id}',
                                  headers=headers
                                  )

    def update_cps_enrollment_schedule(self,
                                       deploy_not_before: str,
                                       enrollment_path: str = '',
                                       enrollment_id: str = '',
                                       change_id: str = '',
                                       deploy_not_after: Optional[str] = '',
                                       ) -> dict:
        """
            Returns the enrollment change path.
        Args:
            enrollment_path:
                Enrollment path found in the pending change location field.
            enrollment_id:
                Unique Identifier of the Enrollment on which to perform the desired operation.
            change_id:
                Chnage ID on which to perform the desired operation.
            deploy_not_after:
                The time after when the change will no longer be in effect.
                This value is an ISO-8601 timestamp. (UTC)
                Sample: 2021-01-31T00:00:00.000Z
            deploy_not_before:
                The time that you want change to take effect. If you do not set this, the change occurs immediately,
                although most changes take some time to take effect even when they are immediately effective.
                This value is an ISO-8601 timestamp. (UTC)
                Sample: 2021-01-31T00:00:00.000Z

        Returns:
            The response provides the enrollment change path

        """
        if enrollment_path == '' and not all(s != '' for s in [enrollment_id, change_id]):
            raise DemistoException(
                'If "enrollment_path" is blank than "enrollment_id" and "change_id" should both contain a value')
        method = "PUT"
        headers = {
            'Accept': 'application/vnd.akamai.cps.change-id.v1+json',
            'content-type': 'application/vnd.akamai.cps.deployment-schedule.v1+json',
        }
        body = {
            "notBefore": deploy_not_before,
            "notAfter": deploy_not_after
        }
        if enrollment_path == '':
            url_suffix = f'cps/v2/enrollments/{enrollment_id}/changes/{change_id}/deployment-schedule'
        else:
            url_suffix = f'{enrollment_path}/deployment-schedule'
        return self._http_request(method=method,
                                  url_suffix=url_suffix,
                                  headers=headers,
                                  json_data=body
                                  )

    def get_cps_change_status(self,
                              enrollment_path: str = "",
                              enrollment_id: str = "",
                              change_id: str = "",) -> dict:
        """
            Gets the status of a pending change.
        Args:
            enrollment_path: Enrollment path found in the pending change location field.
            enrollment_id: Unique Identifier of the Enrollment on which to perform the desired operation.
            change_id: The change for this enrollment on which to perform the desired operation.

        Returns:
            The response to provide the change status

        """
        if enrollment_path == '' and not all(s != '' for s in [enrollment_id, change_id]):
            raise DemistoException(
                'If "enrollment_path" is blank than "enrollment_id" and "change_id" should both contain a value')
        headers = {"accept": "application/vnd.akamai.cps.change.v2+json"}
        method = "GET"
        if enrollment_path == "":
            url_suffix = f'cps/v2/enrollments/{enrollment_id}/changes/{change_id}'
        else:
            url_suffix = enrollment_path
        return self._http_request(method=method,
                                  url_suffix=url_suffix,
                                  headers=headers,
                                  )

    def list_cps_active_certificates(self, contract_id: str,) -> dict:
        """
            Lists enrollments with active certificates.
            Note that the rate limit for this operation is 10 requests per minute per account.
        Args:
            contract_id: Specify the contract on which to operate or view.

        Returns:
            The response provides a list of active certificates

        """
        return self._http_request(method="GET",
                                  url_suffix=f'cps/v2/active-certificates?contractId={contract_id}',
                                  headers={"accept": "application/vnd.akamai.cps.active-certificates.v1+json"},
                                  )

    def cancel_cps_change(self, change_path: str, account_switch_key: str = "") -> dict:
        """
            Cancels a pending change.

        Args:
            change_path: Change path on which to perform the desired operation.
            account_switch_key: For customers who manage more than one account,
                this runs the operation from another account. The Identity and
                Access Management API provides a list of available account switch keys.

        Returns:
            The response provides a dict of change_path.

        """
        method = 'delete'
        headers = {"accept": "application/vnd.akamai.cps.change-id.v1+json"}
        params = {"accountSwitchKey": account_switch_key}
        return self._http_request(method=method,
                                  url_suffix=change_path,
                                  headers=headers,
                                  params=params,
                                  )

    def get_cps_enrollment_by_id(self,
                                 enrollment_id: int) -> dict:
        """
            Returns the Enarollment by enrollment id
        Args:
            enrollment_id: Unique Identifier of the Enrollment on which to perform the desired operation.

        Returns:
            The response provides a deployment associcated to the enrollment id

        """
        headers = {"accept": "application/vnd.akamai.cps.enrollment.v12+json"}
        method = "GET"
        return self._http_request(method=method,
                                  url_suffix=f'cps/v2/enrollments/{enrollment_id}',
                                  headers=headers,
                                  )

    # created by D.S.
    def list_dns_zones(self):
        """
        List Edge DNS Zones
        Args:

        Returns:
            <Response [200]>
        """

        return self._http_request(method='Get',
                                  url_suffix='config-dns/v2/zones?showAll=true',
                                  )

    # created by D.S.

    def list_dns_zone_recordsets(self, zone: str):
        """
        List Edge DNS zone recordsets
        Args:
            zone: string. The name of the zone.

        Returns:
            <Response [200]>
        """

        return self._http_request(method='Get',
                                  url_suffix=f'config-dns/v2/zones/{zone}/recordsets?showAll=true',
                                  )


''' HELPER FUNCTIONS '''


def get_network_lists_ec(raw_response: list = None) -> tuple[list, list]:
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


def get_list_from_file(entry_id: str = None) -> list:
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
        return_error(f'Failed to open txt file: {ex}')
    return elements


# Created by D.S.
def new_papi_property_command_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse papi propertyLink

    Args:
        raw_response:

    Returns:
        List of property_id
    """
    entry_context = []
    human_readable = []
    if raw_response:
        propertylink = raw_response.get('propertyLink', '')
        regex_match = re.search('prp_\d+', propertylink)
        entry_context.append(assign_params(**{
            "PropertyLink": propertylink,
            "PropertyId": regex_match.group(0) if regex_match else '',
        }))
        human_readable.append(assign_params(**{
            "PropertyLink": propertylink,
            "PropertyId": regex_match.group(0) if regex_match else '',
        }))

    return entry_context, human_readable


# Created by D.S. [Modified on 2023/02/27, add a few new fields]
def list_papi_property_bygroup_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse papi property
    Args:
        raw_response:
    Returns:
        dictionary of Property
    """
    entry_context = []
    human_readable = []
    if raw_response:
        entry_context.append(assign_params(**{
            "AccountId": raw_response.get("accountId", ''),
            "ContractId": raw_response.get("contractId", ''),
            "GroupId": raw_response.get("groupId", ''),
            "PropertyId": raw_response.get("propertyId", ''),
            "PropertyName": raw_response.get("propertyName", ''),
            "LatestVersion": raw_response.get("latestVersion", ''),
            "StagingVersion": raw_response.get("stagingVersion", ''),
            "ProductionVersion": raw_response.get("productionVersion", ''),
            "AssetId": raw_response.get("assetId", '')
        }))
        human_readable = entry_context
    return entry_context, human_readable


# Created by D.S.
def clone_papi_property_command_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse papi propertyLink

    Args:
        raw_response:

    Returns:
        List of property_id
    """
    entry_context = []
    human_readable = []
    if raw_response:
        propertylink = raw_response.get('propertyLink', '')
        property_name = raw_response.get('propertyName')
        regex_match = re.search('prp_\d+', propertylink)
        entry_context.append(assign_params(**{
            "PropertyLink": propertylink,
            "PropertyName": property_name,
            "PropertyId": regex_match.group(0) if regex_match else '',
        }))
        human_readable.append(assign_params(**{
            "PropertyLink": propertylink,
            "PropertyName": property_name,
            "PropertyId": regex_match.group(0) if regex_match else '',
        }))

    return entry_context, human_readable


# Created by D.S.
def add_papi_property_hostname_command_ec(raw_response: dict) -> tuple[list, list]:
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
        domain_prefix = raw_response.get('domainPrefix')
        edge_hostname_id = raw_response.get('edgeHostnameId')
        etag = raw_response.get('etag')
        entry_context.append(assign_params(**{
            "DomainPrefix": domain_prefix,
            "EdgeHostnameId": edge_hostname_id,
            "Etag": etag,
        }))
        human_readable.append(assign_params(**{
            "DomainPrefix": domain_prefix,
            "EdgeHostnameId": edge_hostname_id,
            "Etag": etag,
        }))

    return entry_context, human_readable


# Created by D.S.
def list_papi_edgehostname_bygroup_ec(raw_response: dict) -> tuple[list, list]:
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
        domain_prefix = raw_response.get('domainPrefix')
        edge_hostname_id = raw_response.get('edgeHostnameId')
        entry_context.append(assign_params(**{
            "DomainPrefix": domain_prefix,
            "EdgeHostnameId": edge_hostname_id,
        }))
        human_readable.append(assign_params(**{
            "DomainPrefix": domain_prefix,
            "EdgeHostnameId": edge_hostname_id,
        }))

    return entry_context, human_readable


# Created by D.S.
def new_papi_edgehostname_command_ec(raw_response: dict) -> tuple[list, list]:
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
        edgeHostnameLink = raw_response.get('edgeHostnameLink', '')
        domain_prefix = raw_response.get('domainPrefix')
        regex_match = re.search('ehn_\d+', edgeHostnameLink)
        edge_hostname_id = regex_match.group(0) if regex_match else ''
        entry_context.append(assign_params(**{
            "EdgeHostnameLink": edgeHostnameLink,
            "DomainPrefix": domain_prefix,
            "EdgeHostnameId": edge_hostname_id,
        }))
        human_readable.append(assign_params(**{
            "EdgeHostnameLink": edgeHostnameLink,
            "DomainPrefix": domain_prefix,
            "EdgeHostnameId": edge_hostname_id,
        }))

    return entry_context, human_readable


# Created by D.S.
def get_cps_enrollment_by_cnname(raw_response: dict, cnname: str) -> dict:
    """
        get cps enrollment info by common name

    Args:
        raw_response: output from list_cps_enrollments
        cnname:

    Returns:
        full enrollment info for given common name
    """
    for enrollment in raw_response.get("enrollments", []):
        if enrollment.get("csr").get("cn") == cnname:
            return enrollment

    err_msg = f'Error in {INTEGRATION_NAME} Integration - get_cps_enrollment_by_cnname'
    raise DemistoException(err_msg)


# Created by D.S.
def get_cps_enrollment_by_cnname_ec(raw_response: dict) -> tuple[list, list]:
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
        cnname = raw_response.get("csr", {}).get("cn")
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
def list_papi_cpcodeid_bygroup_ec(raw_response: dict) -> tuple[list, list]:
    """
        parse cpcode cpcId
    Args:
        raw_response:
    Returns:
        List of cpcode_id
    """
    entry_context = []
    human_readable = []
    if raw_response:
        cpcode_name = raw_response.get('cpcodeName')
        cpcode_id = raw_response.get('cpcodeId')
        entry_context.append(assign_params(**{
            "CpcodeName": cpcode_name,
            "CpcodeId": cpcode_id
        }))
        human_readable.append(assign_params(**{
            "CpcodeName": cpcode_name,
            "CpcodeId": cpcode_id
        }))

    return entry_context, human_readable


# Created by D.S.
def new_papi_cpcode_ec(raw_response: dict) -> tuple[list, list]:
    """
        parse cpcode cpcId

    Args:
        raw_response:

    Returns:
        List of cpcode_id
    """
    entry_context = []
    human_readable = []
    if raw_response:
        cpcodeLink = raw_response.get('cpcodeLink', '')
        cpcode_name = raw_response.get('cpcodeName')
        regex_match = re.search('cpc_\d+', cpcodeLink)
        cpcode_id = regex_match.group(0) if regex_match else ''
        entry_context.append(assign_params(**{
            "CpcodeLink": cpcodeLink,
            "CpcodeName": cpcode_name,
            "CpcodeId": cpcode_id
        }))
        human_readable.append(assign_params(**{
            "CpcodeLink": cpcodeLink,
            "CpcodeName": cpcode_name,
            "CpcodeId": cpcode_id
        }))

    return entry_context, human_readable


# Created by D.S.
def patch_papi_property_rule_ec(raw_response: dict) -> tuple[list, list]:
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
def activate_papi_property_command_ec(raw_response: dict) -> tuple[list, list]:
    """
        parse property activation_id

    Args:
        raw_response:

    Returns:
        List of activation_id
    """
    entry_context = []
    human_readable = []
    if raw_response:
        activationLink = raw_response.get('activationLink', '')
        regex_match = re.search('atv_\d+', activationLink)
        entry_context.append(assign_params(**{
            "ActivationLink": activationLink,
            "ActivationId": regex_match.group(0) if regex_match else '',
        }))
        human_readable.append(assign_params(**{
            "ActivationLink": activationLink,
            "ActivationId": regex_match.group(0) if regex_match else '',
        }))

    return entry_context, human_readable


# Created by D.S.
def clone_security_policy_command_ec(raw_response: dict) -> tuple[list, list]:
    """
        parse security policy_id
    Args:
        raw_response:
    Returns:
        List of security policy_id
    """
    entry_context = []
    human_readable = []
    if raw_response:
        config_id = raw_response.get('configId')
        policy_id = raw_response.get('policyId')
        policy_name = raw_response.get('policyName')
        entry_context.append(assign_params(**{
            "Id": config_id,
            "PolicyId": policy_id,
            "PolicyName": policy_name
        }))
        human_readable.append(assign_params(**{
            "Id": config_id,
            "PolicyId": policy_id,
            "PolicyName": policy_name
        }))

    return entry_context, human_readable


# Created by D.S.
def new_match_target_command_ec(raw_response: dict) -> tuple[list, list]:
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
        config_id = raw_response.get('configId')
        targetId = raw_response.get('targetId')
        policy_id = raw_response.get('securityPolicy', {}).get('policyId')
        entry_context.append(assign_params(**{
            "Id": config_id,
            "TargetId": targetId,
            "PolicyId": policy_id
        }))
        human_readable.append(assign_params(**{
            "Id": config_id,
            "TargetId": targetId,
            "PolicyId": policy_id
        }))

    return entry_context, human_readable


# Created by D.S.
def activate_appsec_config_version_command_ec(raw_response: dict) -> tuple[list, list]:
    """
        parse appsec config activation_id

    Args:
        raw_response:

    Returns:
        List of appsec config activation_id
    """
    entry_context = []
    human_readable = []
    if raw_response:
        config_id = raw_response.get('configId')
        activation_id = raw_response.get('activationId')
        entry_context.append(assign_params(**{
            "Id": config_id,
            "ActivationId": activation_id,
            "Status": "submitted"
        }))
        human_readable.append(assign_params(**{
            "Id": config_id,
            "ActivationId": activation_id,
            "Status": "submitted"
        }))
    return entry_context, human_readable


# Created by D.S.
def get_appsec_config_activation_status_command_ec(raw_response: dict) -> tuple[list, list]:
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
        activation_id = raw_response.get('activationId')
        entry_context.append(assign_params(**{
            "ActivationId": activation_id,
            "Network": network,
            "Status": status
        }))
        human_readable.append(assign_params(**{
            "ActivationId": activation_id,
            "Network": network,
            "Status": status
        }))
    return entry_context, human_readable


# Created by D.S.
def get_appsec_config_latest_version_command_ec(raw_response: dict) -> tuple[list, list]:
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
def get_security_policy_id_by_name_command_ec(raw_response: dict, is_baseline_policy) -> tuple[list, list]:
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
        config_id = raw_response.get('Id')
        policy_name = raw_response.get('policyName')
        policy_id = raw_response.get('policyId')
        if is_baseline_policy == "yes":
            entry_context.append(assign_params(**{
                "Id": config_id,
                "BasePolicyName": policy_name,
                "BasePolicyId": policy_id,
            }))
            human_readable.append(assign_params(**{
                "Id": config_id,
                "BasePolicyName": policy_name,
                "BasePolicyId": policy_id,
            }))
        else:
            entry_context.append(assign_params(**{
                "PolicyName": policy_name,
                "PolicyId": policy_id,
            }))
            human_readable.append(assign_params(**{
                "PolicyName": policy_name,
                "PolicyId": policy_id,
            }))
    return entry_context, human_readable

# Created by D.S.


def clone_appsec_config_version_command_ec(raw_response: dict) -> tuple[list, list]:
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
        config_id = raw_response.get('configId')
        version = raw_response.get('version')
        entry_context.append(assign_params(**{
            "Id": config_id,
            "NewVersion": version,
        }))
        human_readable.append(assign_params(**{
            "Id": config_id,
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


# Created by D.S.
def get_papi_property_activation_status_command_ec(raw_response: dict) -> tuple[list, list]:
    """
        parse papi property activation status

    Args:
        raw_response:

    Returns:
        List of activation status
    """
    entry_context = []
    human_readable = []
    if raw_response:
        network = raw_response["activations"]["items"][0].get('network')
        status = raw_response["activations"]["items"][0].get('status')
        activation_id = raw_response["activations"]["items"][0].get('activationId')
        entry_context.append(assign_params(**{
            "ActivationId": activation_id,
            "Network": network,
            "Status": status
        }))
        human_readable.append(assign_params(**{
            "ActivationId": activation_id,
            "Network": network,
            "Status": status
        }))
    return entry_context, human_readable


# Created by D.S.
def get_papi_edgehostname_creation_status_command_ec(raw_response: dict) -> tuple[list, list]:
    """
        parse papi edgehostname creation status

    Args:
        raw_response:

    Returns:
        List of activation status
    """
    entry_context = []
    human_readable = []
    if raw_response:
        edgehostname_id = raw_response["edgeHostnames"]["items"][0].get('edgeHostnameId')
        status = raw_response["edgeHostnames"]["items"][0].get('status')
        entry_context.append(assign_params(**{
            "EdgeHostnameId": edgehostname_id,
            "Status": status
        }))
        human_readable.append(assign_params(**{
            "EdgeHostnameId": edgehostname_id,
            "Status": status
        }))

    return entry_context, human_readable


# Created by D.S. 2022-11-25
def get_papi_property_bygroup_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse papi property
    Args:
        raw_response:
    Returns:
        dictionary of Property
    """
    entry_context = []
    human_readable = []
    if raw_response:
        entry_context.append(assign_params(**{
            "AccountId": raw_response["accountId"],
            "ContractId": raw_response["contractId"],
            "GroupId": raw_response["groupId"],
            "PropertyId": raw_response["propertyId"],
            "PropertyName": raw_response["propertyName"],
            "LatestVersion": raw_response["latestVersion"],
            "StagingVersion": raw_response["stagingVersion"],
            "ProductionVersion": raw_response["productionVersion"],
            "AssetId": raw_response["assetId"]
        }))
        human_readable = entry_context
    return entry_context, human_readable


# Created by D.S. 2023-02-27
def new_papi_property_version_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse papi propertyLink

    Args:
        raw_response:

    Returns:
        List of property_id
    """
    entry_context = []
    human_readable = []
    if raw_response:
        version_link = raw_response.get('versionLink', '')
        entry_context.append(assign_params(**{
            "VersionLink": version_link,
        }))
        human_readable.append(assign_params(**{
            "VersionLink": version_link,
        }))

    return entry_context, human_readable


def list_papi_property_activations_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse papi activations

    Args:
        raw_response:

    Returns:
        List of property activations
    """
    entry_context = []
    human_readable = []
    if raw_response:
        activations = raw_response.get('activations', {}).get('items', [])
        entry_context.append(assign_params(**{
            "Activations": activations,
        }))
        human_readable.append(assign_params(**{
            "Activations": activations,
        }))

    return entry_context, human_readable


def list_appsec_configuration_activation_history_ec(raw_response: dict,
                                                    config_id: int) -> tuple[list, list]:
    """
        Parse Secuirty configuration activation history

    Args:
        raw_response:

    Returns:
        List of property activations
    """
    entry_context = []
    human_readable = []
    if raw_response:
        entry_context.append(assign_params(**{
            "id": config_id,
            "ActivationHistory": raw_response.get('activationHistory'),
        }))
        human_readable.append(assign_params(**{
            "id": config_id,
            "Activations": raw_response.get('activationHistory'),
        }))

    return entry_context, human_readable


def list_papi_property_by_hostname_ec(raw_response: dict,
                                      cname_from: str) -> tuple[list, list]:
    """
        Parse papi properties list

    Args:
        raw_response:
        cname_from:

    Returns:
        List of papi properties
    """
    entry_context = []
    human_readable = []
    if raw_response:
        properties = raw_response.get('hostnames', {}).get('items', [])
        entry_context.append(assign_params(**{
            "CNameFrom": cname_from,
            "Properties": properties,
        }))
        human_readable.append(assign_params(**{
            "CNameFrom": cname_from,
            "Properties": properties,
        }))

    return entry_context, human_readable


def list_siteshield_maps_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse siteshield map

    Args:
        raw_response:

    Returns:
        List of site shield maps
    """
    entry_context = []
    human_readable = []
    if raw_response:
        entry_context = raw_response.get('siteShieldMaps', [])
        human_readable = raw_response.get('siteShieldMaps', [])
    return entry_context, human_readable


def update_cps_enrollment_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse enrollment change path

    Args:
        raw_response:

    Returns:
        List of enrollment change path
    """
    entry_context = []
    human_readable = []
    if raw_response:
        enrollment = raw_response.get('enrollment', {})
        changes = raw_response.get('changes', [])
        if enrollment != {}:
            enrollmentId = enrollment.split('/')[4]
        else:
            enrollmentId = ""
        if changes != []:
            changeId = changes[0].split('/')[6]
        else:
            changeId = ""
        entry_context.append(assign_params(**{
            "id": enrollmentId,
            "enrollment": enrollment,
            "changeId": changeId,
            "changes": changes
        }))
        human_readable = entry_context
    return entry_context, human_readable


def update_cps_enrollment_schedule_ec(raw_response: dict) -> tuple[list, list]:
    """
        Parse enrollment change path

    Args:
        raw_response:

    Returns:
        List of enrollment change path
    """
    entry_context = []
    human_readable = []
    if raw_response:
        change = raw_response.get('change', '')
        if change != '':
            enrollmentId = change.split('/')[4]
            changeId = change.split('/')[6]
        else:
            changeId = ""
            enrollmentId = ""
        entry_context.append(assign_params(**{
            "id": enrollmentId,
            "changeId": changeId,
            "change": change
        }))
        human_readable = entry_context
    return entry_context, human_readable


def try_parsing_date(date: str, arr_fmt: list):
    """
    Check if the date that the user provided as an argument to a command is valid.
    Args:
        date: str - The string representation of the date that the user provided
        arr_fmt: list - A list of possible date formats.
    Returns:
        If the string date from the user is ok - returns the datetime value.
        Else raises a ValueError.
    """
    for fmt in arr_fmt:
        try:
            return datetime.strptime(date, fmt)
        except ValueError:
            pass
    raise ValueError(f'The date you provided does not match the wanted format {arr_fmt}')


''' COMMANDS '''
# Created by C.L.


@logger
def check_group_command(client: Client, checking_group_name: str) -> tuple[object, dict, Union[list, dict]]:
    raw_response: dict = client.list_groups()
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - List Groups'
        path = argToList(checking_group_name, separator='>')
        group_list = raw_response
        for path_groupname in path:
            found = False
            for group in group_list:
                if path_groupname == group['groupName']:
                    group_list = group['subGroups']
                    found = True
                    break

            if not found:
                context = {"Akamai.CheckGroup": {
                    'Found': False,
                    'checking_group_name': checking_group_name,
                    'groupName': "No Name",
                    'parentGroupId': 0,
                    'groupId': 0,
                }}
                return human_readable, context, raw_response

        context = {"Akamai.CheckGroup": {
            'Found': True,
            'checking_group_name': checking_group_name,
            'groupName': group['groupName'],
            'parentGroupId': group.get('parentGroupId', 0),
            'groupId': group.get('groupId', 0),
        }}
        return human_readable, context, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L.


@logger
def list_groups_command(client: Client) -> tuple[object, dict, Union[list, dict]]:
    """
    List the information of all groups

    Returns:
    Json response as dictionary
    """
    raw_response: dict = client.list_groups()
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - List Groups'

        return human_readable, {"Akamai.Group": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L.


@logger
def get_group_command(client: Client, group_id: int = 0) -> tuple[object, dict, Union[list, dict]]:
    """
        Get the information of a group
    Args:
        group_id : Group ID

    Returns:
        Json response as dictionary
    """
    raw_response: dict = client.get_group(group_id)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - get Group: {raw_response}'

        return human_readable, {"Akamai.Group": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def create_enrollment_command(client: Client,
                              country: str,
                              company: str,
                              organizational_unit: str,
                              city: str,
                              admin_contact_address_line_one: str,
                              admin_contact_first_name: str,
                              admin_contact_last_name: str,
                              admin_contact_email: str,
                              admin_contact_phone: str,
                              tech_contact_first_name: str,
                              tech_contact_last_name: str,
                              tech_contact_email: str,
                              tech_contact_phone: str,
                              org_name: str,
                              org_country: str,
                              org_city: str,
                              org_region: str,
                              org_postal_code: str,
                              org_phone: str,
                              org_address_line_one: str,
                              contract_id: str,
                              certificate_type: str = "third-party",
                              csr_cn: str = "",
                              change_management: bool = False,
                              enable_multi_stacked_certificates: bool = False,
                              network_configuration_geography: str = "core",
                              network_configuration_quic_enabled: bool = True,
                              network_configuration_secure_network: str = "enhanced-tls",
                              network_configuration_sni_only: bool = True,
                              clone_dns_names: bool = True,
                              exclude_sans: bool = False,
                              ra: str = "third-party",
                              validation_type: str = "third-party",
                              sans: list = []
                              ) -> tuple[object, dict, Union[list, dict]]:
    """
        Create an enrollment
    Args:
        contract_id:                 Contract id
        country:                    country - Two Letter format
        company:                    company Name
        organizational_unit:         Organizational Unit
        city:                       city Name
        admin_contact:               Admin Contact - Dictionary
        tech_contact:                tech_contact - Dictionary
        org:                        Organization name - Dictionary
        csr_cn:                     CName
        contract_id:                 Specify the contract on which to operate or view.
        csr_cn:                     CName to be created
        change_management:           change_management
        certificate_type:            Certificate Type
        enable_multi_stacked_certificates:     Enable Multi Stacked Certificates
        network_configuration_geography:     Network Configuration geography
        network_configuration_quic_enabled:   Network Configuration QuicEnabled
        network_configuration_secure_network: Network Configuration SecureNetwork
        network_configuration_sni_only:       Network Configuration sniOnly
        clone_dns_names:                    Clone DNS Names
        exclude_sans:                       Exclude Sans
        ra: str = "third-party",
        validation_type: str = "third-party"

    Returns:
        Json response as dictionary
    """
    admin_contact = {"addressLineOne": admin_contact_address_line_one, "firstName": admin_contact_first_name,
                     "lastName": admin_contact_last_name, "email": admin_contact_email, "phone": admin_contact_phone}

    tech_contact = {"firstName": tech_contact_first_name, "lastName": tech_contact_last_name, "email": tech_contact_email,
                    "phone": tech_contact_phone}

    org = {"name": org_name, "country": org_country, "city": org_city, "region": org_region, "postalCode": org_postal_code,
           "phone": org_phone, "addressLineOne": org_address_line_one}

    raw_response: dict = client.create_enrollment(
        country=country,
        company=company,
        organizational_unit=organizational_unit,
        city=city,
        admin_contact=admin_contact,
        tech_contact=tech_contact,
        org=org,
        contract_id=contract_id,
        csr_cn=csr_cn,
        change_management=change_management,
        certificate_type=certificate_type,
        enable_multi_stacked_certificates=enable_multi_stacked_certificates,
        network_configuration_geography=network_configuration_geography,
        network_configuration_quic_enabled=network_configuration_quic_enabled,
        network_configuration_secure_network=network_configuration_secure_network,
        network_configuration_sni_only=network_configuration_sni_only,
        clone_dns_names=clone_dns_names,
        exclude_sans=exclude_sans,
        ra=ra,
        validation_type=validation_type,
        sans=sans
    )

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Enrollment {csr_cn} is created successfully'

        return human_readable, {"Akamai.Enrollment": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


def list_enrollments_command(client: Client, contract_id: str) -> tuple[object, dict, Union[list, dict]]:
    """
        List enrollments
    Args:
        contract_id: Specify the contract on which to operate or view.

    Returns:
        Json response as dictionary
    """
    raw_response: dict = client.list_enrollments(contract_id)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - List Enrollments'

        return human_readable, {"Akamai.Enrollments": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def get_enrollment_by_cn_command(client: Client, target_cn: str, contract_id: str = ""
                                 ) -> tuple[object, dict, Union[list, dict]]:
    """
        List enrollments
    Args:
        contract_id: Specify the contract on which to operate or view.

    Returns:
        The enrollment information - Json response as dictionary
    """
    raw_response: dict = client.list_enrollments(contract_id)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - List Enrollments'
        context = {}
        for enrollment in raw_response["enrollments"]:
            if 'csr' in enrollment and 'cn' in enrollment["csr"] and enrollment["csr"]["cn"] == target_cn:
                context = enrollment['csr']
                context['existing'] = True
                context['target_cn'] = target_cn
                context['changes'] = enrollment['pendingChanges']
                return human_readable, {"Akamai.Enrollment": context}, raw_response
        context = raw_response
        context['existing'] = False
        context['target_cn'] = target_cn
        return human_readable, {"Akamai.Enrollment": context}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L.


@logger
def get_change_command(client: Client, enrollment_path: str, allowed_input_type_param: str = "third-party-csr"
                       ) -> tuple[object, dict, Union[list, dict]]:
    """
        Get change
    Args:
        enrollment_path: The path that includes enrollmentId and changeId: e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
        allowed_input_type_param: Specify the contract on which to operate or view.

    Returns:
        Json response as dictionary
    """
    raw_response: dict = client.get_change(enrollment_path, allowed_input_type_param)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Get_change'

        return human_readable, {"Akamai.Change": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def update_change_command(client: Client, change_path: str,
                          certificate: str, trust_chain: str,
                          allowed_input_type_param: str = "third-party-cert-and-trust-chain",
                          key_algorithm: str = "RSA"
                          ) -> tuple[object, dict, Union[list, dict]]:
    """
        Update a change
    Args:
        change_path: The path that includes enrollmentId and changeId : e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
        certificate :certificate,
        trust_chain: trust_chain,
        allowed_input_type_param: Specify the contract on which to operate or view.
        key_algorithm: RSA or ECDSA

    Returns:
        Json response as dictionary
    """
    raw_response: dict = client.update_change(change_path,
                                              certificate, trust_chain, allowed_input_type_param, key_algorithm)

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Update_change'

        return human_readable, {"Akamai.Change": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def acknowledge_warning_command(client: Client,
                                change_path: str,
                                allowed_input_type_param: str = 'post-verification-warnings-ack'
                                ) -> tuple[object, dict, Union[list, dict]]:
    """
    Acknowledge the warning message after updating a enrollment change

    Args:
        change_path: The path that includes enrollmentId and changeId: e.g. /cps/v2/enrollments/enrollmentId/changes/changeId
        allowed_input_type_param:    Enum Found as the last part of Change.allowedInput[].update hypermedia URL.
            supported values include:
                     change-management-ack,
                     lets-encrypt-challenges-completed,
                     post-verification-warnings-ack,
                     pre-verification-warnings-ack.
    Returns:
        Json response as dictionary
    """
    raw_response: dict = client.acknowledge_warning(change_path, allowed_input_type_param)

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Acknowledge_warning'

        return human_readable, {"Akamai.Acknowledge": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def acknowledge_pre_verification_warning_command(client: Client, change_path: str) -> tuple[object, dict, Union[list, dict]]:

    raw_response: dict = client.acknowledge_pre_verification_warning(change_path)

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Acknowledge_warning'

        return human_readable, {"Akamai.Acknowledge": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L. Oct-06-22


def get_production_deployment_command(client: Client, enrollment_id: str) -> tuple[object, dict, Union[list, dict]]:

    raw_response: dict = client.get_production_deployment(enrollment_id)

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Get_production_deployment'

        return human_readable, {"Akamai.ProductionDeployment": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L. Oct-06-22


def get_change_history_command(client: Client, enrollment_id: str) -> tuple[object, dict, Union[list, dict]]:

    raw_response: dict = client.get_change_history(enrollment_id)

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Get_change_history'

        return human_readable, {"Akamai.ChangeHistory": raw_response}, raw_response
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def create_group_command(client: Client, group_path: str = '') -> tuple[object, dict, Union[list, dict]]:
    """
        Create a new group
    Args:
        groupID : Group ID

    Returns:
        Json response as dictionary
    """

    raw_response_list: list = client.list_groups()
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
                        found = True
                        found_groupId = group.get('groupId', 0)
                        break
                if not found:
                    create_folder = client.create_group(found_groupId, path_groupname)
                    found_groupId = create_folder.get('groupId', 0)
                    group_list = [client.get_group(found_groupId)]
        human_readable = f'{INTEGRATION_NAME} - Group {group_path} is created successfully'

        return human_readable, {"Akamai.CreateGroup": found_groupId}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}

# Created by C.L.


def get_domains_command(client: Client) -> tuple[object, dict, Union[list, dict]]:
    """
        Get all of the existing domains

    Returns:
        Json response as dictionary
    """
    raw_response: dict = client.get_domains()
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Domains are listed successfully'

        return human_readable, {'Akamai.Domain': raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


def get_domain_command(client: Client, domain_name: str) -> tuple[object, dict, Union[list, dict]]:
    """
        Get information of a specific domain
    Args:
        domain_name : Domain Name

    Returns:
        Json response as dictionary
    """
    raw_response: dict = client.get_domain(domain_name)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - The domain is listed successfully'

        return human_readable, {'Akamai.Domain': raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def create_domain_command(client: Client, group_id: int, domain_name: str) -> tuple[object, dict, Union[list, dict]]:
    """
       Creating domains
    Args:
        group_id : The group ID
        domain_name: Domain Name

    Returns:
        Json response as dictionary
    """

    raw_response: dict = client.create_domain(group_id, domain_name=domain_name)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Domain is created successfully'

        return human_readable, {"Akamai.Domain": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def create_datacenter_command(client: Client, domain_name: str, dc_name: str = "", dc_country: str = "US"
                              ) -> tuple[object, dict, Union[list, dict]]:
    """
    Updating or adding datacenter to existing GTM domain
    Args:

        domain_name: Domain Name
        DC_nam2: The name of the Data center
        dc_country: The country of the Data center


    Returns:
        Json response as dictionary
    """

    raw_response: dict = client.create_datacenter(domain_name, dc_name, dc_country)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Datacenter is created successfully'

        return human_readable, {"Akamai.Datacenter": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


# Created by C.L.
@logger
def update_property_command(client: Client, property_type: str, domain_name: str, property_name: str,
                            static_type: str = "", property_comments: str = "", static_server: str = "", server_1: str = "",
                            server_2: str = "", weight_1: int = 50, weight_2: int = 50, dc1_id: int = 3131, dc2_id: int = 3132
                            ) -> tuple[object, dict, Union[list, dict]]:
    """
    Updating or adding properties to existing GTM domain

    Args:
        property_type : Property Type
        domain_name: Domain Name
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
    raw_response: dict = client.update_property(property_type, domain_name=domain_name,
                                                property_name=property_name, static_type=static_type,
                                                static_server=static_server, property_comments=property_comments,
                                                server_1=server_1, server_2=server_2, weight_1=weight_1, weight_2=weight_2,
                                                dc1_id=dc1_id, dc2_id=dc2_id)
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Property is created successfully'

        return human_readable, {"Akamai.Property": raw_response}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def test_module_command(client: Client, *_) -> tuple[None, None, str]:
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
) -> tuple[object, dict, Union[list, dict]]:
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
    raw_response: dict = client.get_network_lists(
        search=search, list_type=list_type, extended=(extended == 'true'), include_elements=(include_elements == 'true')
    )
    if raw_response:
        title = f'{INTEGRATION_NAME} - network lists'
        entry_context, human_readable_ec = get_network_lists_ec(raw_response.get('networkLists'))
        context_entry: dict = {
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
def get_network_list_by_id_command(client: Client, network_list_id: str) -> tuple[object, dict, Union[list, dict]]:
    """Get network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list

    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: dict = client.get_network_list_by_id(network_list_id=network_list_id)
    if raw_response:
        title = f'{INTEGRATION_NAME} - network list {network_list_id}'
        entry_context, human_readable_ec = get_network_lists_ec([raw_response])
        context_entry: dict = {
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
def create_network_list_command(client: Client, list_name: str, list_type: str, description: str = None,
                                entry_id: str = None, elements: Union[str, list] = None) \
        -> tuple[object, dict, Union[list, dict]]:
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
        context_entry: dict = {
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
def delete_network_list_command(client: Client, network_list_id: str) -> tuple[object, dict, Union[list, dict]]:
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
def update_network_list_elements_command(client: Client, network_list_id: str, elements: Union[str, list] = None) \
        -> tuple[object, dict, Union[list, dict]]:
    """Update network list by ID

    Args:
        client: Client object with request
        network_list_id: Unique ID of network list

    Returns:
        human readable (markdown format), entry context and raw response
    """

    elements = argToList(elements)
    # demisto.results(elements)

    raw_response = client.update_network_list_elements(network_list_id=network_list_id, elements=elements)  # type: ignore # noqa

    if raw_response:
        human_readable = f'**{INTEGRATION_NAME} - network list {network_list_id} updated**'
        return human_readable, {}, {}
    else:
        return f'{INTEGRATION_NAME} - Could not find any results for given query', {}, {}


@logger
def activate_network_list_command(client: Client, network_list_ids: str, env: str, comment: str = None,
                                  notify: str = None) -> tuple[object, dict, Union[list, dict]]:
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
                human_readable += (
                    f'{INTEGRATION_NAME} - network list **{network_list_id}** activated on {env} **successfully**\n'
                )
        except DemistoException as e:
            if "This list version is already active" in e.args[0]:
                human_readable += f'**{INTEGRATION_NAME} - network list {network_list_id} already active on {env}**\n'
        except requests.exceptions.RequestException:
            human_readable += f'{INTEGRATION_NAME} - Could not find any results for given query\n'

    return human_readable, {}, {}


@logger
def add_elements_to_network_list_command(client: Client, network_list_id: str, entry_id: str = None,
                                         elements: Union[str, list] = None) \
        -> tuple[object, dict, Union[list, dict]]:
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
        tuple[object, dict, Union[list, dict]]:
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
        -> tuple[str, dict, Union[list, dict]]:
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
    context_entry: dict = {}
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
                                product_id: str,
                                property_name: str,
                                contract_id: str,
                                group_id: str,
                                property_id: str,
                                version: str,
                                check_existence_before_create="yes") -> tuple[str, dict, Union[list, dict]]:
    """
        Post clone property command
    Args:
        client: Client object with request
        product_id
        property_name
        contract_id
        group_id
        property_id: source property_id to be cloned from
        version
        check_existence_before_create: Do not create a new one if one with the same name already exists. Default is "yes".
    Returns:
        human readable (markdown format), entry context and raw response
    """
    title = ""
    human_readable_ec: list = []
    isExistingOneFound = False
    if check_existence_before_create.lower() == "yes":
        raw_response: dict = client.list_papi_property_bygroup(contract_id=contract_id, group_id=group_id)
        lookupKey = 'propertyName'
        lookupValue = property_name
        returnDict = next((item for item in raw_response["properties"]["items"]
                           if item[lookupKey] == lookupValue), None)
        if returnDict is not None:
            isExistingOneFound = True
            title = f'{INTEGRATION_NAME} - new papi property command - found existing property'
            entry_context, human_readable_ec = list_papi_property_bygroup_ec(returnDict)

    if not isExistingOneFound:
        raw_response = client.clone_papi_property(product_id=product_id,
                                                  property_name=property_name,
                                                  contract_id=contract_id,
                                                  group_id=group_id,
                                                  property_id=property_id,
                                                  version=version,
                                                  )
        if raw_response:
            title = f'{INTEGRATION_NAME} - Clone papi property {property_name} in group {group_id} from {property_id}'
            raw_response["propertyName"] = property_name
            entry_context, human_readable_ec = clone_papi_property_command_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty(val.PropertyName && val.PropertyName == obj.PropertyName)": entry_context
    }
    human_readable = tableToMarkdown(name=title,
                                     t=human_readable_ec,
                                     removeNull=True)

    return human_readable, context_entry, raw_response


# Created by D.S.
def add_papi_property_hostname_command(client: Client,
                                       property_version: str,
                                       property_id: str,
                                       contract_id: str,
                                       group_id: str,
                                       validate_hostnames: str,
                                       include_cert_status: str,
                                       cname_from: str,
                                       edge_hostname_id: str,
                                       sleep_time: str = '30'
                                       ) -> tuple[str, dict, Union[list, dict]]:
    """
        add hostname papi property

    Args:
        client: Client object with request
        property_version:
        property_id:
        contract_id:
        group_id:
        validate_hostnames:
        include_cert_status:
        cname_from:
        edge_hostname_id:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.add_papi_property_hostname(
        property_version=property_version,
        property_id=property_id,
        contract_id=contract_id,
        group_id=group_id,
        validate_hostnames=argToBoolean(validate_hostnames),
        include_cert_status=argToBoolean(include_cert_status),
        cname_from=cname_from,
        edge_hostname_id=edge_hostname_id,
    )
    time.sleep(int(sleep_time))

    title = f'{INTEGRATION_NAME} - Add hostname papi property'
    raw_response["domainPrefix"] = cname_from
    raw_response["edgeHostnameId"] = edge_hostname_id
    entry_context, human_readable_ec = add_papi_property_hostname_command_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.EdgeHostnames(val.DomainPrefix && val.DomainPrefix == obj.DomainPrefix)":
            entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
def list_papi_edgehostname_bygroup_command(client: Client,
                                           contract_id: str,
                                           group_id: str,
                                           domain_prefix: str) -> tuple[str, dict, Union[list, dict]]:
    """
        add papi edge hostname command
    Args:
        client: Client object with request
        contract_id:
        group_id:
        options:
        domain_prefix:
    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: dict = client.list_papi_edgehostname_bygroup(contract_id=contract_id,
                                                               group_id=group_id,
                                                               options="mapDetails"
                                                               )
    lookupKey = 'domainPrefix'
    lookupValue = domain_prefix
    returnDict = next((item for item in raw_response["edgeHostnames"]["items"]
                       if item[lookupKey] == lookupValue), None)

    title = f'{INTEGRATION_NAME} - new papi edgeHostname command'
    # raw_response["domainPrefix"] = domain_prefix
    entry_context, human_readable_ec = list_papi_edgehostname_bygroup_ec(returnDict)  # type: ignore
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.EdgeHostnames"
        f"(val.DomainPrefix && val.DomainPrefix == obj.DomainPrefix)": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
def new_papi_edgehostname_command(client: Client,
                                  product_id: str,
                                  contract_id: str,
                                  group_id: str,
                                  options: str,
                                  domain_prefix: str,
                                  domain_suffix: str,
                                  ip_version_behavior: str,
                                  secure: str,
                                  secure_network: str,
                                  cert_enrollment_id: str,
                                  check_existence_before_create="yes") -> tuple[str, dict, Union[list, dict]]:
    """
        add papi edge hostname command

    Args:
        client: Client object with request
        product_id:
        contract_id:
        group_id:
        options:
        domain_prefix:
        domain_suffix:
        ip_version_behavior:
        secure:
        secure_network:
        cert_enrollment_id:
        check_existence_before_create: Do not create a new one if one with the same name already exists. Default is "yes".

    Returns:
        human readable (markdown format), entry context and raw response
    """
    title = ""
    human_readable_ec: list = []
    isExistingOneFound = False
    if check_existence_before_create.lower() == "yes":
        raw_response: dict = client.list_papi_edgehostname_bygroup(contract_id=contract_id,
                                                                   group_id=group_id,
                                                                   options="mapDetails"
                                                                   )
        lookupKey = 'domainPrefix'
        lookupValue = domain_prefix
        returnDict = next((item for item in raw_response["edgeHostnames"]["items"]
                           if item[lookupKey] == lookupValue), None)
        if returnDict is not None:
            isExistingOneFound = True
            title = f'{INTEGRATION_NAME} - new papi edgeHostname command - found existing edgeHostname'
            entry_context, human_readable_ec = list_papi_edgehostname_bygroup_ec(returnDict)

    if not isExistingOneFound:
        raw_response = client.new_papi_edgehostname(product_id=product_id,
                                                    contract_id=contract_id,
                                                    group_id=group_id,
                                                    options=options,
                                                    domain_prefix=domain_prefix,
                                                    domain_suffix=domain_suffix,
                                                    ip_version_behavior=ip_version_behavior,
                                                    secure=secure,
                                                    secure_network=secure_network,
                                                    cert_enrollment_id=cert_enrollment_id,
                                                    )
        if raw_response:
            title = f'{INTEGRATION_NAME} - new papi edgeHostname command'
            raw_response["domainPrefix"] = domain_prefix
            entry_context, human_readable_ec = new_papi_edgehostname_command_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.EdgeHostnames(val.DomainPrefix && val.DomainPrefix == obj.DomainPrefix)":
            entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def get_cps_enrollmentid_by_cnname_command(client: Client,
                                           contract_id: str,
                                           cnname: str,
                                           ) -> tuple[str, dict, Union[list, dict]]:
    """
        get CPS EnrollmentID by Common Name

    Args:
        client: Client object with request
        contract_id:
        cnname:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_cps_enrollments(contract_id=contract_id)
    enrollment: dict = get_cps_enrollment_by_cnname(raw_response=raw_response, cnname=cnname)
    title = f'{INTEGRATION_NAME} - Get cps enrollmentid by cnname command'
    entry_context, human_readable_ec = get_cps_enrollment_by_cnname_ec(enrollment)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Cps.Enrollment": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def new_papi_cpcode_command(client: Client,
                            product_id: str,
                            contract_id: str,
                            group_id: str,
                            cpcode_name: str,
                            check_existence_before_create="yes"
                            ) -> tuple[str, dict, Union[list, dict]]:
    """
        get papi property All Versions by group_id and property_id command
    Args:
        product_id:
        contract_id:
        group_id:
        cpcode_name:
        check_existence_before_create: Do not create a new Cpcode if one with the same name already exists. Default is "yes".

    Returns:
        human readable (markdown format), entry context and raw response
    """
    title = ""
    human_readable_ec: list = []
    isExistingOneFound = False
    if check_existence_before_create.lower() == "yes":
        raw_response: dict = client.list_papi_cpcodeid_bygroup(contract_id=contract_id, group_id=group_id)
        lookupKey = 'cpcodeName'
        lookupValue = cpcode_name
        returnDict = next((item for item in raw_response["cpcodes"]["items"]
                           if item[lookupKey] == lookupValue), None)

        if returnDict is not None:
            isExistingOneFound = True
            title = f'{INTEGRATION_NAME} - get papi cpcode command - found existing Cpcode'
            entry_context, human_readable_ec = list_papi_cpcodeid_bygroup_ec(returnDict)
    if not isExistingOneFound:
        raw_response = client.new_papi_cpcode(
            contract_id=contract_id,
            group_id=group_id,
            product_id=product_id,
            cpcode_name=cpcode_name,
        )
        if raw_response:
            title = f'{INTEGRATION_NAME} - new papi cpcode command'
            raw_response["cpcodeName"] = cpcode_name
            entry_context, human_readable_ec = new_papi_cpcode_ec(raw_response)

    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiCpcode": entry_context
    }
    human_readable = tableToMarkdown(name=title,
                                     t=human_readable_ec,
                                     removeNull=True)

    return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def patch_papi_property_rule_cpcode_command(client: Client,
                                            contract_id: str,
                                            group_id: str,
                                            property_id: str,
                                            property_version: str,
                                            validate_rules: str,
                                            operation: str,
                                            path: str,
                                            cpcode_id: str,
                                            name: str,
                                            ) -> tuple[str, dict, Union[list, dict]]:
    """
        get papi property All Versions by group_id and property_id command
    Args:
        contract_id:
        group_id:
        property_id:
        property_version:
        validate_rules:
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
                    "id": int(cpcode_id.split('_')[1]),
                    "name": name
                }
        }
    ]

    raw_response: dict = client.patch_papi_property_rule(contract_id=contract_id,
                                                         group_id=group_id,
                                                         property_id=property_id,
                                                         property_version=property_version,
                                                         validate_rules=validate_rules,
                                                         body=body,
                                                         )

    title = f'{INTEGRATION_NAME} - Patch papi property cpcode command'
    entry_context, human_readable_ec = patch_papi_property_rule_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def patch_papi_property_rule_origin_command(client: Client,
                                            contract_id: str,
                                            group_id: str,
                                            property_id: str,
                                            property_version: str,
                                            validate_rules: str,
                                            operation: str,
                                            path: str,
                                            origin: str,
                                            external_url: str,
                                            gzip_compression: str,
                                            sleep_time: str = '30',
                                            ) -> tuple[str, dict, Union[list, dict]]:
    """
        get papi property All Versions by group_id and property_id command
    Args:
        contract_id:
        group_id:
        property_id:
        property_version:
        validate_rules:
        operation:
        path:
        value:

    Returns:
        human readable (markdown format), entry context and raw response
    """
    body = []
    time.sleep(int(sleep_time))
    if path == "/rules/behaviors":
        body = [
            {
                "op": operation,
                "path": path,
                "value": [
                    {
                        "name": "origin",
                        "options": {
                            "cacheKeyHostname": "REQUEST_HOST_HEADER",
                            "compress": gzip_compression.lower() == 'yes',
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
                            "verificationMode": "CUSTOM",
                            "hostname": origin,
                            "customValidCnValues": [
                                "{{Origin Hostname}}",
                                "{{Forward Host Header}}"
                            ],
                            "originCertsToHonor": "STANDARD_CERTIFICATE_AUTHORITIES",
                            "standardCertificateAuthorities": [
                                "akamai-permissive",
                                "THIRD_PARTY_AMAZON"
                            ]
                        }
                    }
                ]
            }
        ]
    if path == "/rules/children/-":
        body = [
            {
                "op": operation,
                "path": path,
                "value": {  # type: ignore
                    "name": "Origin for " + external_url,
                    "children": [],
                    "behaviors": [
                        {
                            "name": "origin",
                            "options": {
                                "cacheKeyHostname": "REQUEST_HOST_HEADER",
                                "compress": gzip_compression.lower() == 'yes',
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
                                "verificationMode": "CUSTOM",
                                "hostname": origin,
                                "customValidCnValues": [
                                    "{{Origin Hostname}}",
                                    "{{Forward Host Header}}"
                                ],
                                "originCertsToHonor": "STANDARD_CERTIFICATE_AUTHORITIES",
                                "standardCertificateAuthorities": [
                                    "akamai-permissive",
                                    "THIRD_PARTY_AMAZON"
                                ]
                            }
                        }
                    ],
                    "criteria": [
                        {
                            "name": "hostname",
                            "options": {
                                "matchOperator": "IS_ONE_OF",
                                "values": [
                                    external_url
                                ]
                            }
                        }
                    ],
                    "criteriaMustSatisfy": "all"
                }
            }
        ]

    raw_response: dict = client.patch_papi_property_rule(contract_id=contract_id,
                                                         group_id=group_id,
                                                         property_id=property_id,
                                                         property_version=property_version,
                                                         validate_rules=validate_rules,
                                                         body=body,
                                                         )

    title = f'{INTEGRATION_NAME} - Patch papi property origin command'
    entry_context, human_readable_ec = {"Origins added": origin}, {"Origins added": origin}
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def activate_papi_property_command(client: Client,
                                   contract_id: str,
                                   group_id: str,
                                   property_id: str,
                                   network: str,
                                   notify_emails: str,
                                   property_version: str,
                                   note: str,
                                   ) -> tuple[str, dict, Union[list, dict]]:
    """
        activate an property command
    Args:
        client: Client object with request
        contract_id: crt_xxxxxxx
        group_id: grp_#######
        property_id: prp_#######
        network: "STAGING" or "PRODUCTION"
        notify_emails:
        property_version:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.activate_papi_property(contract_id=contract_id,
                                                       group_id=group_id,
                                                       property_id=property_id,
                                                       network=network,
                                                       notify_emails=notify_emails,
                                                       property_version=arg_to_number(property_version),  # type: ignore[arg-type]
                                                       note=note,
                                                       )

    title = f'{INTEGRATION_NAME} - activate an property'
    entry_context, human_readable_ec = activate_papi_property_command_ec(raw_response)
    context_entry = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.{network.capitalize()}": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def clone_security_policy_command(client: Client,
                                  config_id: str,
                                  config_version: str,
                                  create_from_security_policy: str,
                                  policy_name: str,
                                  policy_prefix: str = '',
                                  check_existence_before_create="yes") -> tuple[str, dict, Union[list, dict]]:
    """
        Clone security policy property command
    Args:
        client: Client object with request
        config_id:
        config_version:
        create_from_security_policy:
        policy_name:
        check_existence_before_create: Continue execution if a Existing Record found without creating an new record

    Returns:
        human readable (markdown format), entry context and raw response
    """
    policy_name = policy_name.strip()
    if check_existence_before_create.lower() == "yes":
        raw_response: dict = client.list_security_policy(config_id=config_id,
                                                         config_version=config_version)
        lookupKey = 'policyName'
        lookupValue = policy_name
        returnDict = next((item for item in raw_response['policies']
                          if item[lookupKey].lower().strip() == lookupValue.lower()), None)
        if returnDict is not None:
            title = f'{INTEGRATION_NAME} - clone security policy command - found existing Security Policy'
            entry_context, human_readable_ec = clone_security_policy_command_ec(returnDict)
            context_entry = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig.Policy(val.PolicyName && val.PolicyName == obj.PolicyName)":
                    entry_context
            }
            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
            return human_readable, context_entry, raw_response

    if not policy_prefix:
        isDuplicated = True
        while isDuplicated:
            policy_prefix = generate_policy_prefix()
            isErrored = False
            try:
                raw_response = client.clone_security_policy(
                    config_id=arg_to_number(config_id),  # type: ignore[arg-type]
                    config_version=arg_to_number(config_version),  # type: ignore[arg-type]
                    create_from_security_policy=create_from_security_policy,
                    policy_name=policy_name,
                    policy_prefix=policy_prefix,
                )
            except Exception as e:
                isErrored = True
                if "You entered a Policy ID that already exists." not in str(e):
                    err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
                    return_error(err_msg, error=e)
            if not isErrored:
                isDuplicated = False
        if raw_response:
            title = f'{INTEGRATION_NAME} - clone security policy'
            entry_context, human_readable_ec = clone_security_policy_command_ec(raw_response)
            context_entry = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig.Policy(val.PolicyName && val.PolicyName == obj.PolicyName)":
                    entry_context
            }
            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
        return human_readable, context_entry, raw_response
    else:
        raw_response = client.clone_security_policy(
            config_id=arg_to_number(config_id),  # type: ignore[arg-type]
            config_version=arg_to_number(config_version),  # type: ignore[arg-type]
            create_from_security_policy=create_from_security_policy,
            policy_name=policy_name,
            policy_prefix=policy_prefix
        )
        title = f'{INTEGRATION_NAME} - clone security policy'
        entry_context, human_readable_ec = clone_security_policy_command_ec(raw_response)
        context_entry = {
            f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig.Policy(val.PolicyName && val.PolicyName == obj.PolicyName)":
                entry_context
        }
        human_readable = tableToMarkdown(
            name=title,
            t=human_readable_ec,
            removeNull=True,
        )

        return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def new_match_target_command(client: Client,
                             config_id: str,
                             config_version: str,
                             match_type: str,
                             bypass_network_lists: str,
                             default_file: str,
                             file_paths: str,
                             hostnames: str,
                             policy_id: str
                             ) -> tuple[str, dict, Union[list, dict]]:
    """
        New match target command
    Args:
        client:
        config_id
        config_version
        type
        bypass_network_lists
        default_file
        file_paths
        hostnames
        policy_id

    Returns:
        human readable (markdown format), entry context and raw response
    """
    networkList = []
    for network in argToList(bypass_network_lists):
        networkList.append({'id': network})
    hostnameList = []
    for hostname in hostnames.split(','):
        hostnameList.append(hostname)

    raw_response: dict = client.new_match_target(config_id=arg_to_number(config_id),  # type: ignore[arg-type]
                                                 config_version=arg_to_number(config_version),  # type: ignore[arg-type]
                                                 match_type=match_type,
                                                 bypass_network_lists=networkList,
                                                 default_file=default_file,
                                                 file_paths=argToList(file_paths),
                                                 hostnames=argToList(hostnameList),
                                                 policy_id=policy_id,
                                                 )

    title = f'{INTEGRATION_NAME} - create match target'
    entry_context, human_readable_ec = new_match_target_command_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig.Policy(val.PolicyId && val.PolicyId == obj.PolicyId)": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def activate_appsec_config_version_command(client: Client,
                                           config_id: str,
                                           config_version: str,
                                           acknowledged_invalid_hosts: str,
                                           notification_emails: str,
                                           action: str,
                                           network: str,
                                           note: str) -> tuple[str, dict, Union[list, dict]]:
    """
        Activate appsec config version command
    Args:
        config_id
        config_version
        acknowledged_invalid_hosts:
        notification_emails:
        action:
        network:
        note:
    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.activate_appsec_config_version(
        config_id=arg_to_number(config_id),  # type: ignore[arg-type]
        config_version=arg_to_number(config_version),  # type: ignore[arg-type]
        acknowledged_invalid_hosts=argToList(acknowledged_invalid_hosts),
        notification_emails=argToList(notification_emails),
        action=action,
        network=network,
        note=note,
    )

    title = f'{INTEGRATION_NAME} - activate appsec config version'
    entry_context, human_readable_ec = activate_appsec_config_version_command_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig.{network.capitalize()}": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def get_appsec_config_activation_status_command(client: Client,
                                                activation_id: str,
                                                sleep_time: str,
                                                retries: str) -> tuple[str, dict, Union[list, dict]]:
    """
        Get appsec config version activation status command
    Args:
        client:
        activationsId
        sleep_time
        retries

    Returns:
        human readable (markdown format), entry context and raw response
    """

    retry = 0
    while retry < int(retries):
        time.sleep(int(sleep_time))

        raw_response: dict = client.get_appsec_config_activation_status(activation_id=activation_id)
        if raw_response and raw_response['status'] == 'ACTIVATED':
            title = f'{INTEGRATION_NAME} - get appsec config version activation status'
            entry_context, human_readable_ec = get_appsec_config_activation_status_command_ec(raw_response)
            context_entry: dict = {
                f'{INTEGRATION_CONTEXT_NAME}.AppSecConfig'
                '(val.ActivationId && val.ActivationId == obj.ActivationId &&'
                ' val.Network && val.Network == obj.Network)': entry_context
            }
            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
            return human_readable, context_entry, raw_response
        retry += 1

    raise DemistoException(f'Could not get activation status. Number of retries: {retry}', res=raw_response)

# Created by D.S.


@logger
def get_appsec_config_latest_version_command(client: Client,
                                             sec_config_name: str,
                                             sleep_time: str,
                                             retries: str,
                                             skip_consistency_check: str) -> tuple[str, dict, Union[list, dict]]:
    """
        1) Get appsec config Id and latestVersion.
        2) Check latestVersion and stagingVersion, productionVersion consistency
        if latestVersion, stagingVersion, productionVersion are not the same value,
        wait sleep_time X seconds and retries Y times.
    Args:
        client: http api client
        sec_config_name: Name of the Security Configuration
        skip_consistency_check: Do not conduction LatestVersion, Staging Version, Production Version consistency check
        sleep_time: Number of seconds to wait before the next consistency check
        retries: Number of retries for the consistency check to be conducted

    Returns:
        human readable (markdown format), entry context and raw response
    """
    for _i in range(0, int(retries)):
        raw_response: dict = client.list_appsec_config()
        lookupKey = 'name'
        lookupValue = sec_config_name
        appsec_config_latest: dict = next(
            (item for item in raw_response['configurations'] if item[lookupKey].lower() == lookupValue.lower()), {})
        if appsec_config_latest == {}:
            error_msg = f'The Security Configuration "{sec_config_name}" is not found.'
            raise DemistoException(error_msg)
        latestVersion = appsec_config_latest.get("latestVersion", 0)
        stagingVersion = appsec_config_latest.get("stagingVersion")
        productionVersion = appsec_config_latest.get("productionVersion")
        if skip_consistency_check == 'yes' or (latestVersion == stagingVersion == productionVersion or int(latestVersion) == 1):
            title = f'{INTEGRATION_NAME} - get secuirty configuration Latest Version'
            entry_context, human_readable_ec = get_appsec_config_latest_version_command_ec(appsec_config_latest)
            appsec_config_latest = demisto.get(demisto.context(), f"{INTEGRATION_CONTEXT_NAME}.AppSec")
            context_entry: dict = {
                f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig(val.Name && val.Name == obj.Name)": entry_context
            }

            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
            return human_readable, context_entry, appsec_config_latest
        time.sleep(int(sleep_time))

    error_msg = f'inconsistent latestVersion vs stagingVersion vs productionVersion for Security Configuration: {sec_config_name}'
    raise DemistoException(error_msg)


# Created by D.S.
@logger
def get_security_policy_id_by_name_command(client: Client,
                                           config_id: str,
                                           config_version: str,
                                           policy_name: str,
                                           is_baseline_policy: str) -> tuple[str, dict, Union[list, dict]]:
    """
        get a security policy ID by Policy name
                    It is also used to get the policy ID of "Baseline Security Policy"
    Args:
        client:
        config_id
        versonId
        policy_name
        is_baseline_policy
    Returns:
        human readable (markdown format), entry context and raw response
    """
    raw_response: dict = client.list_security_policy(config_id=config_id,
                                                     config_version=config_version)

    lookupKey = "policyName"
    lookupValue = policy_name
    returnDict = next((item for item in raw_response['policies'] if item[lookupKey] == lookupValue), None)
    if returnDict is None:
        err_msg = f'Error in {INTEGRATION_NAME} - get a security policy ID by Policy name: Policy [{policy_name}] not found'
        raise DemistoException(err_msg, res=raw_response)

    title = f'{INTEGRATION_NAME} - get a security policy ID by Policy name'
    entry_context, human_readable_ec = get_security_policy_id_by_name_command_ec(returnDict, is_baseline_policy)
    entry_context[0]['Id'] = config_id
    if is_baseline_policy == "yes":
        context_entry = {
            f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig(val.Id && val.Id == obj.Id)": entry_context
        }
    else:
        context_entry = {
            f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig.Policy(val.PolicyId && val.PolicyId == obj.PolicyId)": entry_context
        }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def clone_appsec_config_version_command(client: Client,
                                        config_id: str,
                                        create_from_version: str,
                                        do_not_clone: str,
                                        rule_update: bool = True,
                                        ) -> tuple[str, dict, Union[list, dict]]:
    """
        Appsec Configurtion - create a new version by clone the latest version
    Args:
        config_id: AppSec configuration ID
        create_from_version: AppSec configuration version number to create from
        rule_update: Specifies whether the application rules should be migrated to the latest version.
        do_not_clone: Do not clone to create a new version, use in the test

    Returns:
        human readable (markdown format), entry context and raw response
    """
    if do_not_clone == 'yes':
        raw_response = {
            "version": create_from_version,
            "configId": config_id
        }
    else:
        raw_response = client.clone_appsec_config_version(config_id=config_id,
                                                          create_from_version=create_from_version,
                                                          rule_update=rule_update,
                                                          )

    title = f'{INTEGRATION_NAME} - Appsec Configurtion - create a new version by clone the latest version'
    entry_context, human_readable_ec = clone_appsec_config_version_command_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig(val.Id && val.Id == obj.Id)": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def patch_papi_property_rule_httpmethods_command(client: Client,
                                                 contract_id: str,
                                                 group_id: str,
                                                 property_id: str,
                                                 property_version: str,
                                                 validate_rules: str,
                                                 operation: str,
                                                 path: str,
                                                 value: dict,
                                                 ) -> tuple[str, dict, Union[list, dict]]:
    """
        Patch papi property All Versions by group_id and property_id command
    Args:
        contract_id:
        group_id:
        property_id:
        property_version:
        validate_rules:
        operation:
        path:
        value:

    Returns:
        human readable (markdown format), entry context and raw response
    """
    httpAllowedList = ['Post', 'Options', 'Put', 'Delete', 'Patch']
    (key, val), = value.items()
    index = httpAllowedList.index(key)
    allowed = val.lower() == 'yes'

    body = [
        {
            "op": operation,
            "path": path.replace("INDEX", str(index)),
            "value": allowed
        }
    ]
    time.sleep(5)
    raw_response: dict = client.patch_papi_property_rule(contract_id=contract_id,
                                                         group_id=group_id,
                                                         property_id=property_id,
                                                         property_version=property_version,
                                                         validate_rules=validate_rules,
                                                         body=body,
                                                         )

    title = f'{INTEGRATION_NAME} - patch papi property rule httpmethods command'
    entry_context, human_readable_ec = patch_papi_property_rule_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.
@logger
def get_papi_property_activation_status_command(client: Client,
                                                activation_id: int,
                                                property_id: int,
                                                sleep_time: str,
                                                retries: str) -> tuple[str, dict, Union[list, dict]]:
    """
        Get papi property activation status command - retry if the status is not "activate"
    Args:
        client:
        activationsId
        sleep_time
        retries

    Returns:
        human readable (markdown format), entry context and raw response
    """

    retry = 0
    while retry < int(retries):
        time.sleep(int(sleep_time))

        raw_response: dict = client.get_papi_property_activation_status(activation_id=activation_id,
                                                                        property_id=property_id)
        if raw_response and raw_response["activations"]["items"][0]['status'] == 'ACTIVE':
            network = raw_response["activations"]["items"][0].get('network')
            title = f'{INTEGRATION_NAME} - get papi property activation status'
            entry_context, human_readable_ec = get_papi_property_activation_status_command_ec(raw_response)
            context_entry: dict = {
                f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.{network.capitalize()}"
                f"(val.ActivationId && val.ActivationId == obj.ActivationId)": entry_context
            }
            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
            return human_readable, context_entry, raw_response
        retry += 1

    raise DemistoException(f'Could not get activation status. Number of retries: {retry}', res=raw_response)


# Created by D.S.
@logger
def get_papi_edgehostname_creation_status_command(client: Client,
                                                  contract_id: str,
                                                  group_id: str,
                                                  edgehostname_id: str,
                                                  options: str,
                                                  sleep_time: str,
                                                  retries: str) -> tuple[str, dict, Union[list, dict]]:
    """
        Get papi property activation status command - retry if the status is not "activate"
    Args:
        contract_id
        group_id
        edgehostname_id
        options
        sleep_time
        retries

    Returns:
        human readable (markdown format), entry context and raw response
    """

    retry = 0
    while retry < int(retries):
        time.sleep(int(sleep_time))

        raw_response: dict = client.get_papi_edgehostname_creation_status(contract_id=contract_id,
                                                                          group_id=group_id,
                                                                          edgehostname_id=edgehostname_id,
                                                                          options=options
                                                                          )

        if raw_response and raw_response["edgeHostnames"]["items"][0]['status'] == 'CREATED':
            title = f'{INTEGRATION_NAME} - get papi edgehostname creation status'
            entry_context, human_readable_ec = get_papi_edgehostname_creation_status_command_ec(raw_response)
            context_entry: dict = {
                f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.Edgehostnames"
                f"(val.EdgeHostnameId && val.EdgeHostnameId == obj.EdgeHostnameId)": entry_context
            }
            human_readable = tableToMarkdown(name=title,
                                             t=human_readable_ec,
                                             removeNull=True)
            return human_readable, context_entry, raw_response
        retry += 1

    raise DemistoException(f'Could not get creation status. Number of retries: {retry}', res=raw_response)


# Created by D.S. 2022-10-25
@logger
def modify_appsec_config_selected_hosts_command(client: Client,
                                                config_id: int,
                                                config_version: int,
                                                hostname_list: list,
                                                mode: str
                                                ) -> tuple[str, dict, Union[list, dict]]:
    """
        Update the list of selected hostnames for a configuration version.

    Args:
        config_id: A unique identifier for each configuration.
        config_version: A unique identifier for each version of a configuration.
        hostname_list:  A list hostnames is used to modifying the configuration.
        mode: The type of update you want to make to the evaluation hostname list.
            - Use "append" to add additional hostnames.
            - Use "remove" to delete the hostnames from the list.
            - Use "replace" to replace the existing list with the hostnames you pass in your request.

    Returns:
        human readable (markdown format), entry context and raw response
    """

    hostname_dict_list = []
    for hostname in hostname_list[0].split(','):
        hostname_dict_list.append({'hostname': hostname})
    raw_response: dict = client.modify_appsec_config_selected_hosts(config_id=config_id,
                                                                    config_version=config_version,
                                                                    hostname_list=hostname_dict_list,
                                                                    mode=mode
                                                                    )
    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Application Security Config selected hostname list has been modified.'
        return human_readable, {}, raw_response
    else:
        human_readable = f'{INTEGRATION_NAME} - Modify Application Security Config selected hostname list has failed.'
        return human_readable, {}, {}


@logger
def patch_papi_property_rule_siteshield_command(client: Client,
                                                contract_id: str,
                                                group_id: str,
                                                property_id: str,
                                                property_version: str,
                                                validate_rules: str,
                                                operation: str,
                                                path: str,
                                                ssmap: str
                                                ) -> tuple[str, dict, Union[list, dict]]:
    """
        Patch papi property default rule's site shield command
    Args:
        contract_id: Akamai contract Identity
        group_id: Akamai configuration group Identity
        property_id: Akamai Ion Property Identity
        property_version: Akamai Ion Property Version Identity
        validate_rules: Validate the rule or not - true or false
        operation: Json patch operation - add / delete / replace
        path: Json patch Rule path
        ssmap: siteshiled json format data

    Returns:
        human readable (markdown format), entry context and raw response
    """
    import json

    body = [
        {
            "op": operation,
            "path": path,
            "value": json.loads(ssmap)
        }
    ]

    raw_response: dict = client.patch_papi_property_rule(contract_id=contract_id,
                                                         group_id=group_id,
                                                         property_id=property_id,
                                                         property_version=property_version,
                                                         validate_rules=validate_rules,
                                                         body=body,
                                                         )

    title = f'{INTEGRATION_NAME} - Patch papi property site shield command'
    entry_context, human_readable_ec = patch_papi_property_rule_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


# Created by D.S.

@logger
def update_appsec_config_version_notes_command(client: Client,
                                               config_id: int,
                                               config_version: int,
                                               notes: str) -> tuple[str, dict, Union[list, dict]]:
    """
        Update application secuirty configuration version notes command
    Args:
        config_id: The ID of the application seucirty configuration
        config_version: The version number of the application seucirty configuration
        notes:  The notes need to be written into the application seucirty configuration version

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.update_appsec_config_version_notes(config_id=config_id,
                                                                   config_version=config_version,
                                                                   notes=notes
                                                                   )

    if raw_response:
        human_readable = f'{INTEGRATION_NAME} - Application Security Config version notes has been updated.'
        return human_readable, {}, raw_response
    else:
        human_readable = f'{INTEGRATION_NAME} - Update Application Security Config version notes has failed.'
        return human_readable, {}, {}


# created by D.S.
@logger
def new_or_renew_match_target_command(client: Client,
                                      config_id: str,
                                      config_version: str,
                                      match_type: str,
                                      bypass_network_lists: str,
                                      default_file: str,
                                      file_paths: str,
                                      hostnames: str,
                                      policy_id: str
                                      ) -> tuple[str, dict, Union[list, dict]]:
    """
        New match target if no existing found otherwise update the existing match target hostnames
        If there are multiple match targets found, the first one in the list will be updated
    Args:
        client:
        config_id: A unique identifier for each configuration.
        config_version: A unique identifier for each version of a configuration.
        match_type: The type of the match target
        bypass_network_lists: bypass network lists
        default_file: Describes the rule to match on paths.
        file_paths: Contains a list of file paths
        hostnames: A list of hostnames that need to be added into match target
        policy_id: Specifies the security policy to filter match targets

    Returns:
        human readable (markdown format), entry context and raw response
    """

    networkList = []
    for network in argToList(bypass_network_lists):
        networkList.append({'id': network})
    hostnameList = []
    for hostname in hostnames.split(','):
        hostnameList.append(hostname)

    # Get the list of match targets
    raw_response: dict = client.list_match_target(config_id=arg_to_number(config_id),  # type: ignore[arg-type]
                                                  config_version=arg_to_number(config_version),  # type: ignore[arg-type]
                                                  policy_id=policy_id,
                                                  includeChildObjectName='true'
                                                  )

    if not raw_response.get("matchTargets", {}).get("websiteTargets"):
        # If no list is found, create a new match target and add the hostname in there.
        raw_response = client.new_match_target(config_id=arg_to_number(config_id),  # type: ignore
                                               config_version=arg_to_number(config_version),  # type: ignore[arg-type]
                                               match_type=match_type,
                                               bypass_network_lists=networkList,
                                               default_file=default_file,
                                               file_paths=argToList(file_paths),
                                               hostnames=argToList(hostnameList),
                                               policy_id=policy_id
                                               )
        title = f'{INTEGRATION_NAME} - create new match target'
    else:
        # If a list is found, get the first match target in the list
        # Append hostnames into the first match target
        match_target_found = raw_response["matchTargets"]["websiteTargets"][0]
        existing_hostnames = raw_response["matchTargets"]["websiteTargets"][0]["hostnames"]
        for item in hostnameList:
            existing_hostnames.append(item)

        raw_response = client.modify_match_target(config_id=arg_to_number(config_id),  # type: ignore
                                                  config_version=arg_to_number(config_version),  # type: ignore[arg-type]
                                                  policy_id=policy_id,
                                                  match_target_id=match_target_found["targetId"],
                                                  match_type=match_type,
                                                  bypass_network_lists=networkList,
                                                  default_file=default_file,
                                                  file_paths=argToList(file_paths),
                                                  hostnames=argToList(existing_hostnames),
                                                  )
        title = f'{INTEGRATION_NAME} - update existing match target'

    # Process outputs
    entry_context, human_readable_ec = new_match_target_command_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig.Policy(val.PolicyId && val.PolicyId == obj.PolicyId)": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


@logger
def patch_papi_property_rule_command(client: Client,
                                     contract_id: str,
                                     group_id: str,
                                     property_id: str,
                                     property_version: str,
                                     validate_rules: str,
                                     operation: str,
                                     path: str,
                                     value: str,
                                     value_to_json: str
                                     ) -> tuple[str, dict, Union[list, dict]]:
    """
        Generic JSON patch command for Papi Property default rule
    Args:
        contract_id:
        group_id:
        property_id:
        property_version:
        validate_rules:
        operation:
        path:
        value:
        value_to_josn:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    import json

    body = [
        {
            "op": operation,
            "path": path,
            "value": json.loads(value) if value_to_json.lower() == "yes" else value
        }
    ]

    raw_response: dict = client.patch_papi_property_rule(contract_id=contract_id,
                                                         group_id=group_id,
                                                         property_id=property_id,
                                                         property_version=property_version,
                                                         validate_rules=validate_rules,
                                                         body=body,
                                                         )

    title = f'{INTEGRATION_NAME} - Patch papi property rule command'
    entry_context, human_readable_ec = patch_papi_property_rule_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )

    return human_readable, context_entry, raw_response


@logger
def get_papi_property_rule_command(client: Client,
                                   contract_id: str,
                                   property_id: str,
                                   property_version: int,
                                   group_id: str,
                                   validate_rules: str
                                   ) -> tuple[str, dict, Union[list, dict]]:
    """
        Get Papi Property default rule
    Args:
         contract_id:
         property_id:
         property_version:
         group_id:
         validateRules:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.get_papi_property_rule(contract_id=contract_id,
                                                       group_id=group_id,
                                                       property_id=property_id,
                                                       property_version=property_version,
                                                       validate_rules=validate_rules
                                                       )
    if raw_response:
        title = f'{INTEGRATION_NAME} - get papi property default rule command'
        entry_context = raw_response
        human_readable_ec = raw_response
        context_entry: dict = {
            f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.DefaultRule": entry_context
        }
        human_readable = tableToMarkdown(
            name=title,
            t=human_readable_ec,
            removeNull=True,
        )
        return human_readable, context_entry, raw_response
    else:
        human_readable = f'{INTEGRATION_NAME} - get papi property default rule command has failed.'
        return human_readable, {}, {}


# Created by D.S. 2022-11-25
def get_papi_property_by_name_command(client: Client,
                                      contract_id: str,
                                      group_id: str,
                                      property_name: str,) -> tuple[str, dict, Union[list, dict]]:
    """
        Get papi property within a group by property name
    Args:
        client: Client object with request
        contract_id: Unique identifier for the contract
        property_name: name of the property
        group_id: Unique identifier for the group

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_papi_property_bygroup(contract_id=contract_id,
                                                           group_id=group_id,
                                                           )
    lookupKey = 'propertyName'
    lookupValue = property_name
    returnDict = next((item for item in raw_response["properties"]["items"]
                       if item[lookupKey] == lookupValue), None)
    if returnDict is not None:
        raw_response = client.get_papi_property_bygroup(contract_id=contract_id,
                                                        group_id=group_id,
                                                        property_id=returnDict['propertyId'],
                                                        )
        title = f'{INTEGRATION_NAME} - get papi property by name command'
        entry_context, human_readable_ec = get_papi_property_bygroup_ec(raw_response['properties']['items'][0])
        context_entry: dict = {
            f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.Found": entry_context
        }
        human_readable = tableToMarkdown(
            name=title,
            t=human_readable_ec,
            removeNull=True,
        )
        return human_readable, context_entry, raw_response
    else:

        err_msg = f'{INTEGRATION_NAME} - get papi property command: Property {property_name} is not found'
        raise DemistoException(err_msg)


# Created by D.S. 2022-11-25
def get_papi_property_by_id_command(client: Client,
                                    contract_id: str,
                                    group_id: str,
                                    property_id: str,) -> tuple[str, dict, Union[list, dict]]:
    """
        Get papi property within a group by property name
    Args:
        client: Client object with request
        contract_id: Unique identifier of the contract
        property_id: Unique identifier of the property
        group_id: Unique identifier for the group

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.get_papi_property_bygroup(contract_id=contract_id,
                                                          group_id=group_id,
                                                          property_id=property_id,
                                                          )
    title = f'{INTEGRATION_NAME} - get papi property by id command'
    entry_context, human_readable_ec = get_papi_property_bygroup_ec(raw_response['properties']['items'][0])
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.Found": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


# Created by D.S. 2023-02-27
def list_papi_property_by_group_command(client: Client,
                                        contract_id: str,
                                        group_id: str,
                                        context_path: str = 'PapiProperty.ByGroup',
                                        ) -> tuple[str, dict, Union[list, dict]]:
    """
        Lists properties available for the current contract and group.
    Args:
        client: Client object with request
        contract_id: Unique identifier for the contract
        group_id: Unique identifier for the group
        context_path: Custom output context path

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_papi_property_bygroup(contract_id=contract_id,
                                                           group_id=group_id,
                                                           )
    title = f'{INTEGRATION_NAME} - list papi property by group command'
    entry_context = raw_response.get('properties', {}).get('items', [])
    human_readable_ec = entry_context
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.{context_path}"
        f"(val.GroupId && val.GroupId == obj.GroupId)": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


@logger
def new_papi_property_version_command(client: Client,
                                      contract_id: str,
                                      property_id: str,
                                      group_id: str,
                                      create_from_version: str) -> tuple[str, dict, Union[list, dict]]:
    """
        Create a new property version based on any previous version.
        All data from the createFromVersion populates the new version, including its rules and hostnames.
    Args:
        contract_id: Unique identifier for the contract.
        property_id: Unique identifier for the property.
        group_id: Unique identifier for the group.
        create_from_version: The property version on which to base the new version.

    Returns:
        human readable (markdown format), entry context and raw response
        {
            "versionLink": "/papi/v1/properties/prp_123456/versions/4?contractId=ctr_X-nYYYYY&groupId=grp_654321"
        }
    """

    raw_response: dict = client.new_papi_property_version(contract_id=contract_id,
                                                          property_id=property_id,
                                                          group_id=group_id,
                                                          create_from_version=create_from_version)
    title = f'{INTEGRATION_NAME} - new papi property version command'
    entry_context, human_readable_ec = new_papi_property_version_ec(raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.NewVersion": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


@logger
def list_papi_property_activations_command(client: Client,
                                           contract_id: str,
                                           property_id: str,
                                           group_id: str,) -> tuple[str, dict, Union[list, dict]]:
    """
        This lists all activations for all versions of a property, on both production and staging networks.

    Args:
        contract_id: Unique identifier for the contract.
        property_id: Unique identifier for the property.
        group_id: Unique identifier for the group.

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_papi_property_activations(contract_id=contract_id,
                                                               property_id=property_id,
                                                               group_id=group_id,)
    title = f'{INTEGRATION_NAME} - list papi property activations command'
    entry_context, human_readable_ec = list_papi_property_activations_ec(raw_response=raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.Activations"
        f"(val.PropertyId && val.PropertyId == obj.PropertyId)": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


@logger
def list_appsec_configuration_activation_history_command(client: Client,
                                                         config_id: int,) -> tuple[str, dict, Union[list, dict]]:
    """
        Lists the activation history for a configuration.
        The history is an array in descending order of submitDate.
        The most recent submitted activation lists first. Products: All.

    Args:
        config_id: Unique identifier for the contract.

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_appsec_configuration_activation_history(config_id=config_id)
    title = f'{INTEGRATION_NAME} - list appsec configuration activation history command'
    entry_context, human_readable_ec = list_appsec_configuration_activation_history_ec(raw_response=raw_response,
                                                                                       config_id=config_id)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.AppSecConfig"
        f"(val.Id && val.Id == obj.Id)": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


@logger
def list_papi_property_by_hostname_command(client: Client,
                                           hostname: str,
                                           network: str = None,
                                           contract_id: str = None,
                                           group_id: str = None,) -> tuple[str, dict, Union[list, dict]]:
    """
        This operation lists active property hostnames for all properties available in an account.

    Args:
        hostname: Filter the results by cnameFrom. Supports wildcard matches with *.
        network: Network of activated hostnames, either STAGING or PRODUCTION.
        contract_id: Unique identifier for the contract.
        group_id: Unique identifier for the group.

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_papi_property_by_hostname(hostname=hostname,
                                                               network=network,
                                                               contract_id=contract_id,
                                                               group_id=group_id,)

    title = f'{INTEGRATION_NAME} - list papi property by hostname command'
    entry_context, human_readable_ec = list_papi_property_by_hostname_ec(raw_response=raw_response, cname_from=hostname)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.PapiProperty.EdgeHostnames"
        f"(val.CNameFrom && val.CNameFrom == obj.CNameFrom)": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


# Created by D.S. 2023-03-30
@logger
def list_siteshield_maps_command(client: Client) -> tuple[str, dict, Union[list, dict]]:
    """
        Returns a list of all Site Shield maps that belong to your account.

    Args:
        client:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_siteshield_maps()

    title = f'{INTEGRATION_NAME} - list siteshield map command'
    entry_context, human_readable_ec = list_siteshield_maps_ec(raw_response=raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.SiteShieldMaps": entry_context
    }
    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


# Created by D.S. 2023-05-03
@logger
def get_cps_enrollment_deployment_command(client: Client,
                                          enrollment_id: int,
                                          environment: str = 'production',) -> tuple[str, dict, Union[list, dict]]:
    """
        Returns the certification/Enarollment deployment status for specific a environtment: production or staging.

    Args:
        client:
        enrollment_id: Unique Identifier of the Enrollment on which to perform the desired operation.
            And it can be retrived via list_enrollments_command
        environment: Environment where the certificate is deployed: production or staging

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.get_cps_enrollment_deployment(enrollment_id=enrollment_id, environment=environment)

    title = f'{INTEGRATION_NAME} - get cps enrollment deployment command'
    entry_context = raw_response
    human_readable_ec = raw_response
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Cps.Enrollments.Deployment": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    demisto.debug(f'{human_readable=} , {context_entry=} , {raw_response}')
    return human_readable, context_entry, raw_response


@logger
def list_cidr_blocks_command(client: Client,
                             last_action: str = '',
                             effective_date_gt: str = '') -> tuple[str, dict, Union[list, dict]]:
    """
        List all CIDR blocks for all services you are subscribed to.
        To see additional CIDR blocks, subscribe yourself to more services and run this operation again.

    Args:
        client:
        last_action: Whether a CIDR block was added, updated, or removed from service.
                     You can use this parameter as a sorting mechanism and return only CIDR blocks with a change status of add,
                     update, or delete.
                     Note that a status of delete means the CIDR block is no longer in service, and you can remove it from your
                     firewall rules.
        effective_date_gt: The ISO 8601 date the CIDR block starts serving traffic to your origin.
                           Expected format MM-DD-YYYY or YYYY-MM-DD.
                           Ensure your firewall rules are updated to allow this traffic to pass through before the effective date.

    Returns:
        human readable (markdown format), entry context and raw response
    """
    # if there is an effective_date_gt check that it is in the correct format. if yes, continue with the str (API need),
    # else raise ValueError
    if effective_date_gt:
        try_parsing_date(effective_date_gt, ['%Y-%m-%d', '%m-%d-%Y'])

    raw_response: dict = client.list_cidr_blocks(last_action=last_action, effective_date_gt=effective_date_gt)

    title = f'{INTEGRATION_NAME} - list cidr blocks command'
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.CdirBlocks": raw_response
    }

    human_readable = tableToMarkdown(
        name=title,
        t=raw_response,
        removeNull=True,
    )
    demisto.debug(f'{human_readable=} , {context_entry=} , {raw_response}')
    return human_readable, context_entry, raw_response


@logger
def update_cps_enrollment_command(client: Client,
                                  enrollment_id: str,
                                  updates: dict,
                                  enrollment: dict = {},
                                  allow_cancel_pending_changes: str = 'true',
                                  allow_staging_bypass: str = 'true',
                                  deploy_not_after: str = "",
                                  deploy_not_before: str = "",
                                  force_renewal: str = 'false',
                                  renewal_date_check_override: str = 'true',
                                  allow_missing_certificate_addition: str = 'false') -> tuple[str, dict, Union[list, dict]]:
    import json
    """
        Updates an enrollment with changes. Response type will vary depending on the type and impact of change.
        For example, changing SANs list may return HTTP 202 Accepted since the operation require a new certificate
        and network deployment operations, and thus cannot be completed without a change. On the contrary, for
        example a Technical Contact name change may return HTTP 200 OK assuming there are no active change and
        when the operation does not require a new certificate.
        Reference: https://techdocs.akamai.com/cps/reference/put-enrollment

        NOTES:
        Depending on the type of the modification, additional steps might be required to complete the update.
        These additional steps could be carrying out a "renew" change by resubmitting the CSR, acknowleging the
        warnings raised then waiting for the certificate to be deployed into PRODUCTION.
        However these additional steps are not included in this command. User needs to conduct those steps once
        the update command is completed.

    Args:
        client:
        enrollmentId:
            Enrollment ID on which to perform the desired operation.
            And it can be retrived via list_enrollments_command.
        enrollment:
            Enrollment info in dict format. If provided, the script will not make another API call to get the enrollmont info.
            if not, another API call will be issued to retrieve the Enrollment info.
        updates:
            the modification(s) to the enrollment in the dict format.
            Possible modification are:
            ra, validationType, certificateType, networkConfiguration, changeManagement,
            csr, org, adminContact, techContact, thirdParty, enableMultiStackedCertificates
            Sample "updates":
            {
                "thirdParty": {
                    "excludeSans": false
                }
            }
        allow_cancel_pending_changes:
            All pending changes to be cancelled when updating an enrollment.
        allow_staging_bypass:
            Bypass staging and push meta_data updates directly to production network. Current change will also be updated with
            the same changes.
        deploy_not_after:
            Don't deploy after this date (UTC). Sample: 2021-01-31T00:00:00.000Z
        deploy_not_before:
            Don't deploy before this date (UTC). Sample: 2021-01-31T00:00:00.000Z
        force_renewal:
            Force certificate renewal for Enrollment.
        renewal_date_check_override:
            CPS will automatically start a Change to renew certificates in time before they expire.
            This automatic Change is started when Certificate's expiration is within a renewal window,
            and system will protect against other changes started during this renewal window.
            Setting renewal_date_check_override=true will allow creating a Change during the renewal window,
            potentially running the risk of ending up with an expired certificate on the network.
        allow_missing_certificate_addition:
            Applicable for Third Party Dual Stack Enrollments, allows to update missing certificate. Option supported from v10.

    Returns:
        human readable (markdown format), entry context and raw response
    """
    # if there is a deploy_not_after check that it is in the correct format. if yes, continue with the str (API need),
    # else raise ValueError
    if deploy_not_after:
        try_parsing_date(deploy_not_after, ['%Y-%m-%dT%H:%M:%SZ'])
    # if there is a deploy_not_before check that it is in the correct format. if yes, continue with the str (API need),
    # else raise ValueError
    if deploy_not_before:
        try_parsing_date(deploy_not_before, ['%Y-%m-%dT%H:%M:%SZ'])

    if enrollment == {}:
        enrollment = client.get_enrollment_byid(enrollment_id=enrollment_id, json_version='11')
    # Remove the fields that are not supposed to be changed.
    enrollment.pop('id')
    enrollment.pop('productionSlots')
    enrollment.pop('stagingSlots')
    enrollment.pop('assignedSlots')
    enrollment.pop('location')
    enrollment.pop('autoRenewalStartTime')
    enrollment.pop('pendingChanges')
    if not isinstance(updates, dict):
        enrollment.update(json.loads(updates))
    raw_response: dict = client.update_cps_enrollment(enrollment_id=enrollment_id,
                                                      updates=enrollment,
                                                      allow_cancel_pending_changes=allow_cancel_pending_changes,
                                                      allow_staging_bypass=allow_staging_bypass,
                                                      deploy_not_after=deploy_not_after,
                                                      deploy_not_before=deploy_not_before,
                                                      force_renewal=force_renewal,
                                                      renewal_date_check_override=renewal_date_check_override,
                                                      allow_missing_certificate_addition=allow_missing_certificate_addition)

    title = f'{INTEGRATION_NAME} - update enrollment command'
    entry_context, human_readable_ec = update_cps_enrollment_ec(raw_response=raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Enrollment.Changes": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    demisto.debug(f'{human_readable=} , {context_entry=} , {raw_response}')
    return human_readable, context_entry, raw_response


@logger
def update_cps_enrollment_schedule_command(client: Client,
                                           enrollment_path: str = '',
                                           enrollment_id: str = '',
                                           change_id: str = '',
                                           deploy_not_before: str = '',
                                           deploy_not_after: str = None) -> tuple[str, dict, Union[list, dict]]:
    """
        Updates the current deployment schedule.
        Reference: https://techdocs.akamai.com/cps/reference/put-change-deployment-schedule

    Args:
        client:
        enrollment_path:
            Enrollment path found in the pending change location field.
            And it can be retrived via list_enrollments_command
        enrollment_id:
            Enrollment ID on which to perform the desired operation.
            And it can be retrived via list_enrollments_command.
        change_id:
            Chnage ID on which to perform the desired operation.
            And it can be retrived via list_enrollments_command.
        deploy_not_after:
            The time after, when the change will no longer be in effect.
            This value is an ISO-8601 timestamp. (UTC)
            Sample: 2021-01-31T00:00:00.000Z
        deploy_not_before:
            The time that you want change to take effect. If you do not set this, the change occurs immediately,
            although most changes take some time to take effect even when they are immediately effective.
            This value is an ISO-8601 timestamp. (UTC)
            Sample: 2021-01-31T00:00:00.000Z

    Returns:
        human readable (markdown format), entry context and raw response
    """
    # if there is a deploy_not_after check that it is in the correct format. if yes, continue with the str (API need),
    # else raise ValueError
    if deploy_not_after:
        try_parsing_date(deploy_not_after, ['%Y-%m-%dT%H:%M:%SZ'])
    # if there is a deploy_not_before check that it is in the correct format. if yes, continue with the str (API need),
    # else raise ValueError
    if deploy_not_before:
        try_parsing_date(deploy_not_before, ['%Y-%m-%dT%H:%M:%SZ'])

    if enrollment_path == enrollment_id == change_id == "":
        raise DemistoException('enrollment_path, enrollment_id, change_id can not all be blank.')
    raw_response: dict = client.update_cps_enrollment_schedule(enrollment_path=enrollment_path,
                                                               enrollment_id=enrollment_id,
                                                               change_id=change_id,
                                                               deploy_not_after=deploy_not_after,
                                                               deploy_not_before=deploy_not_before)

    title = f'{INTEGRATION_NAME} - update enrollment schedule command'
    entry_context, human_readable_ec = update_cps_enrollment_schedule_ec(raw_response=raw_response)
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Enrollment.Changes": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    demisto.debug(f'{human_readable=} , {context_entry=} , {raw_response}')
    return human_readable, context_entry, raw_response

# Created by D.S.


@logger
def get_cps_change_status_command(client: Client,
                                  enrollment_path: str = "",
                                  enrollment_id: str = "",
                                  change_id: str = "",) -> tuple[str, dict, Union[list, dict]]:
    """
        Gets the status of a pending change.

    Args:
        client:
        enrollment_path: Enrollment path found in the pending change location field.
            And it can be retrived via list_enrollments_command.
        enrollment_id: Unique Identifier of the Enrollment on which to perform the desired operation.
            And it can be retrived via list_enrollments_command.
        change_id: The change for this enrollment on which to perform the desired operation.
            And it can be retrived via list_enrollments_command.

    Returns:
        human readable (markdown format), entry context and raw response
    """
    if enrollment_path == enrollment_id == change_id == "":
        raise DemistoException('enrollment_path, enrollment_id, change_id can not all be blank.')

    raw_response: dict = client.get_cps_change_status(enrollment_path=enrollment_path,
                                                      enrollment_id=enrollment_id,
                                                      change_id=change_id)

    title = f'{INTEGRATION_NAME} - get cps change status command'
    entry_context = raw_response
    human_readable_ec = raw_response
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Enrollments.Change.Status": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    demisto.debug(f'{human_readable=} , {context_entry=} , {raw_response}')
    return human_readable, context_entry, raw_response


@logger
def cancel_cps_change_command(client: Client,
                              change_id: str = '0',
                              enrollment_id: str = '0',
                              change_path: str = "",
                              account_switch_key: str = "",
                              ) -> tuple[str, dict, Union[list, dict]]:
    """
        Cancels a pending change.
        Reference: https://techdocs.akamai.com/cps/reference/delete-enrollment-change
    Args:
        client:
        change_id: The change for this enrollment on which to perform the desired operation. Default is 0.
        enrollment_id: Enrollment on which to perform the desired operation. Default is 0.
        change_path: Change path on which to perform the desired operation.
         - Sample: /cps/v2/enrollments/100000/changes/88888888
         - Note: change_path is not listed in the reference as a parameter.
                 However it can be extracted directly from "list_enrollments_command".
                 This should be the most common useage when generate RestAPI's URL.
        account_switch_key: For customers who manage more than one account, this runs
            the operation from another account. The Identity and Access Management API
            provides a list of available account switch keys.
         - Sample: "1-5C0YLB:1-8BYUX"

        NOTE: There is no need to provice "change_id"/"enrollment_id" and "change_path"
              at the same time. "change_id"/"enrollment_id" can be used to generate
              "change_path" as well.

    Returns:
        human readable (markdown format), entry context and raw response
    """

    if not (change_id == '0' and enrollment_id == '0'):
        change_path = f'/cps/v2/enrollments/{enrollment_id}/changes/{change_id}'

    raw_response: dict = client.cancel_cps_change(change_path=change_path, account_switch_key=account_switch_key)

    title = f'{INTEGRATION_NAME} - cps cancel change'
    entry_context = raw_response
    human_readable_ec = raw_response
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Cps.Change.Canceled": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


# Created by D.S. 2024-06-18
@logger
def get_cps_enrollment_by_id_command(client: Client,
                                     enrollment_id: int) -> tuple[str, dict, Union[list, dict]]:
    """
        Returns the certification/Enarollment.

    Args:
        client:
        enrollment_id: Unique Identifier of the Enrollment on which to perform the desired operation.
            And it can be retrived via list_enrollments_command

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.get_cps_enrollment_by_id(enrollment_id=enrollment_id)

    title = f'{INTEGRATION_NAME} - get cps enrollment by id command'
    entry_context = raw_response
    human_readable_ec = raw_response
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Cps.Enrollments": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


@logger
def list_appsec_config_command(client: Client) -> tuple[str, dict, Union[list, dict]]:
    """
        Lists available security configurations.

    Args:
        client:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_appsec_config()
    title = f'{INTEGRATION_NAME} - list application configuration command'
    entry_context = raw_response
    human_readable_ec = raw_response
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.AppSecurity": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec.get("configurations", ""),
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


@logger
def list_dns_zones_command(client: Client) -> tuple[str, dict, Union[list, dict]]:
    """
        Lists all zones that the current user has access to manage.

    Args:
        client:

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_dns_zones()
    title = f'{INTEGRATION_NAME} - list dns zones command'
    entry_context = raw_response
    human_readable_ec = raw_response
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.EdgeDns.Zones": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec,
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


@logger
def list_dns_zone_recordsets_command(client: Client, zone: str) -> tuple[str, dict, Union[list, dict]]:
    """
        Lists all record sets for this Zone. It works only for PRIMARY and SECONDARY zones.

    Args:
        client:
        zone: The name of the zone.

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_dns_zone_recordsets(zone)
    title = f'{INTEGRATION_NAME} - list dns zones command'
    entry_context = raw_response
    human_readable_ec = raw_response
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.EdgeDns.ZoneRecordSets": entry_context
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec.get("recordsets"),
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


@logger
def list_cps_active_certificates_command(client: Client,
                                         contract_id: str,
                                         ) -> tuple[str, dict, Union[list, dict]]:
    """
        lists enrollments with active certificates. Note that the rate limit for this
        operation is 10 requests per minute per account.

    Args:
        client:
        contract_id: Unique Identifier of the contract on which to operate or view.

    Returns:
        human readable (markdown format), entry context and raw response
    """

    raw_response: dict = client.list_cps_active_certificates(contract_id=contract_id)

    title = f'{INTEGRATION_NAME} - cps list active certificates command'
    entry_context = raw_response
    human_readable_ec = raw_response
    context_entry: dict = {
        f"{INTEGRATION_CONTEXT_NAME}.Cps.Active.Certificates.Enrollments": entry_context.get("enrollments")
    }

    human_readable = tableToMarkdown(
        name=title,
        t=human_readable_ec.get("enrollments"),
        removeNull=True,
    )
    return human_readable, context_entry, raw_response


''' COMMANDS MANAGER / SWITCH PANEL '''


def main():
    params = demisto.params()
    verify_ssl = not params.get('insecure', False)
    proxy = params.get('proxy')
    client_token = params.get('credentials_client_token', {}).get('password') or params.get('clientToken')
    access_token = params.get('credentials_access_token', {}).get('password') or params.get('accessToken')
    client_secret = params.get('credentials_client_secret', {}).get('password') or params.get('clientSecret')
    if not (client_token and access_token and client_secret):
        raise DemistoException('Client token, Access token and Client secret must be provided.')
    client = Client(
        base_url=params.get('host'),
        verify=verify_ssl,
        proxy=proxy,
        auth=EdgeGridAuth(
            client_token=client_token,
            access_token=access_token,
            client_secret=client_secret
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
        f'{INTEGRATION_COMMAND_NAME}-get-domain': get_domain_command,
        f'{INTEGRATION_COMMAND_NAME}-create-domain': create_domain_command,
        f'{INTEGRATION_COMMAND_NAME}-create-datacenter': create_datacenter_command,
        f'{INTEGRATION_COMMAND_NAME}-update-property': update_property_command,
        f'{INTEGRATION_COMMAND_NAME}-get-change': get_change_command,
        f'{INTEGRATION_COMMAND_NAME}-update-change': update_change_command,
        f'{INTEGRATION_COMMAND_NAME}-check-group': check_group_command,
        f'{INTEGRATION_COMMAND_NAME}-create-group': create_group_command,
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
        f'{INTEGRATION_COMMAND_NAME}-patch-papi-property-rule-httpmethods': patch_papi_property_rule_httpmethods_command,
        f'{INTEGRATION_COMMAND_NAME}-get-papi-property-activation-status-command':
            get_papi_property_activation_status_command,
        f'{INTEGRATION_COMMAND_NAME}-get-papi-edgehostname-creation-status-command':
            get_papi_edgehostname_creation_status_command,
        f'{INTEGRATION_COMMAND_NAME}-acknowledge-warning-command': acknowledge_warning_command,
        f'{INTEGRATION_COMMAND_NAME}-get-production-deployment': get_production_deployment_command,
        f'{INTEGRATION_COMMAND_NAME}-get-change-history': get_change_history_command,
        f'{INTEGRATION_COMMAND_NAME}-modify-appsec-config-selected-hosts': modify_appsec_config_selected_hosts_command,
        f'{INTEGRATION_COMMAND_NAME}-patch-papi-property-rule-siteshield': patch_papi_property_rule_siteshield_command,
        f'{INTEGRATION_COMMAND_NAME}-update-appsec-config-version-notes': update_appsec_config_version_notes_command,
        f'{INTEGRATION_COMMAND_NAME}-new-or-renew-match-target': new_or_renew_match_target_command,
        f'{INTEGRATION_COMMAND_NAME}-patch-papi-property-rule-generic': patch_papi_property_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-get-papi-property-rule': get_papi_property_rule_command,
        f'{INTEGRATION_COMMAND_NAME}-acknowledge-pre-verification-warning': acknowledge_pre_verification_warning_command,
        f'{INTEGRATION_COMMAND_NAME}-list-papi-property-by-group': list_papi_property_by_group_command,
        f'{INTEGRATION_COMMAND_NAME}-get-papi-property-by-name': get_papi_property_by_name_command,
        f'{INTEGRATION_COMMAND_NAME}-get-papi-property-by-id': get_papi_property_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-new-papi-property-version': new_papi_property_version_command,
        f'{INTEGRATION_COMMAND_NAME}-list-papi-property-activations': list_papi_property_activations_command,
        f'{INTEGRATION_COMMAND_NAME}-list-appsec-configuration-activation-history':
            list_appsec_configuration_activation_history_command,
        f'{INTEGRATION_COMMAND_NAME}-list-papi-property-by-hostname': list_papi_property_by_hostname_command,
        f'{INTEGRATION_COMMAND_NAME}-list-siteshield-map': list_siteshield_maps_command,
        f'{INTEGRATION_COMMAND_NAME}-get-cps-enrollment-deployment': get_cps_enrollment_deployment_command,
        f'{INTEGRATION_COMMAND_NAME}-list-cidr-blocks': list_cidr_blocks_command,
        f'{INTEGRATION_COMMAND_NAME}-update-cps-enrollment': update_cps_enrollment_command,
        f'{INTEGRATION_COMMAND_NAME}-update-cps-enrollment-schedule': update_cps_enrollment_schedule_command,
        f'{INTEGRATION_COMMAND_NAME}-get-cps-change-status': get_cps_change_status_command,
        f'{INTEGRATION_COMMAND_NAME}-cancel-cps-change': cancel_cps_change_command,
        f'{INTEGRATION_COMMAND_NAME}-get-cps-enrollment-by-id': get_cps_enrollment_by_id_command,
        f'{INTEGRATION_COMMAND_NAME}-list-appsec-config': list_appsec_config_command,
        f'{INTEGRATION_COMMAND_NAME}-list-dns-zones': list_dns_zones_command,
        f'{INTEGRATION_COMMAND_NAME}-list-dns-zone-recordsets': list_dns_zone_recordsets_command,
        f'{INTEGRATION_COMMAND_NAME}-list-cps-active-certificates': list_cps_active_certificates_command,
    }
    try:
        readable_output, outputs, raw_response = commands[command](client=client, **demisto.args())
        return_outputs(readable_output, outputs, raw_response)

    except Exception as e:
        err_msg = f'Error in {INTEGRATION_NAME} Integration [{e}]'
        return_error(err_msg, error=e)


if __name__ == 'builtins':
    main()
