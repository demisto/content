import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
# pylint: disable=E9010, E9011
import traceback

from CommonServerUserPython import *
import requests
import re
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Scopes:
    graph = 'https://graph.microsoft.com/.default'
    security_center = 'https://api.securitycenter.windows.com/.default'
    security_center_apt_service = 'https://securitycenter.onmicrosoft.com/windowsatpservice/.default'
    management_azure = 'https://management.azure.com/.default'  # resource_manager


class Resources:
    graph = 'https://graph.microsoft.com/'
    security_center = 'https://api.securitycenter.microsoft.com/'
    security = 'https://api.security.microsoft.com/'
    management_azure = 'https://management.azure.com/'  # resource_manager
    manage_office = 'https://manage.office.com/'


# authorization types
OPROXY_AUTH_TYPE = 'oproxy'
SELF_DEPLOYED_AUTH_TYPE = 'self_deployed'

# grant types in self-deployed authorization
CLIENT_CREDENTIALS = 'client_credentials'
AUTHORIZATION_CODE = 'authorization_code'
REFRESH_TOKEN = 'refresh_token'  # guardrails-disable-line
DEVICE_CODE = 'urn:ietf:params:oauth:grant-type:device_code'
REGEX_SEARCH_URL = r'(?P<url>https?://[^\s]+)'
REGEX_SEARCH_ERROR_DESC = r"^[^:]+:\s(?P<desc>.*?)(?:\s*Trace ID:| Correlation ID:| Timestamp:|$)"
SESSION_STATE = 'session_state'

# Deprecated, prefer using AZURE_CLOUDS
TOKEN_RETRIEVAL_ENDPOINTS = {
    'com': 'https://login.microsoftonline.com',
    'gcc': 'https://login.microsoftonline.com',
    'gcc-high': 'https://login.microsoftonline.us',
    'dod': 'https://login.microsoftonline.us',
    'de': 'https://login.microsoftonline.de',
    'cn': 'https://login.chinacloudapi.cn',
}

# Deprecated, prefer using AZURE_CLOUDS
GRAPH_ENDPOINTS = {
    'com': 'https://graph.microsoft.com',
    'gcc': 'https://graph.microsoft.us',
    'gcc-high': 'https://graph.microsoft.us',
    'dod': 'https://dod-graph.microsoft.us',
    'de': 'https://graph.microsoft.de',
    'cn': 'https://microsoftgraph.chinacloudapi.cn'
}

# Deprecated, prefer using AZURE_CLOUDS
GRAPH_BASE_ENDPOINTS = {
    'https://graph.microsoft.com': 'com',
    # can't create an entry here for 'gcc' as the url is the same for both 'gcc' and 'gcc-high'
    'https://graph.microsoft.us': 'gcc-high',
    'https://dod-graph.microsoft.us': 'dod',
    'https://graph.microsoft.de': 'de',
    'https://microsoftgraph.chinacloudapi.cn': 'cn'
}

MICROSOFT_DEFENDER_FOR_ENDPOINT_TYPE = {
    "Worldwide": "com",
    "US Geo Proximity": "geo-us",
    "EU Geo Proximity": "geo-eu",
    "UK Geo Proximity": "geo-uk",
    "US GCC": "gcc",
    "US GCC-High": "gcc-high",
    "DoD": "dod",
}

MICROSOFT_DEFENDER_FOR_ENDPOINT_TYPE_CUSTOM = "Custom"
MICROSOFT_DEFENDER_FOR_ENDPOINT_DEFAULT_ENDPOINT_TYPE = "com"


# https://learn.microsoft.com/en-us/microsoft-365/security/defender/api-supported?view=o365-worldwide#endpoint-uris
# https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/gov?view=o365-worldwide#api
MICROSOFT_DEFENDER_FOR_ENDPOINT_API = {
    "com": "https://api.securitycenter.microsoft.com",
    "geo-us": "https://api.securitycenter.microsoft.com",
    "geo-eu": "https://api-eu.securitycenter.microsoft.com",
    "geo-uk": "https://api-uk.securitycenter.microsoft.com",
    "gcc": "https://api-gcc.securitycenter.microsoft.us",
    "gcc-high": "https://api-gov.securitycenter.microsoft.us",
    "dod": "https://api-gov.securitycenter.microsoft.us",
}

# https://learn.microsoft.com/en-us/graph/deployments#app-registration-and-token-service-root-endpoints
MICROSOFT_DEFENDER_FOR_ENDPOINT_TOKEN_RETRIVAL_ENDPOINTS = {
    'com': 'https://login.microsoftonline.com',
    'geo-us': 'https://login.microsoftonline.com',
    'geo-eu': 'https://login.microsoftonline.com',
    'geo-uk': 'https://login.microsoftonline.com',
    'gcc': 'https://login.microsoftonline.com',
    'gcc-high': 'https://login.microsoftonline.us',
    'dod': 'https://login.microsoftonline.us',
}

# https://learn.microsoft.com/en-us/graph/deployments#microsoft-graph-and-graph-explorer-service-root-endpoints
MICROSOFT_DEFENDER_FOR_ENDPOINT_GRAPH_ENDPOINTS = {
    'com': 'https://graph.microsoft.com',
    'geo-us': 'https://graph.microsoft.com',
    'geo-eu': 'https://graph.microsoft.com',
    'geo-uk': 'https://graph.microsoft.com',
    'gcc': 'https://graph.microsoft.com',
    'gcc-high': 'https://graph.microsoft.us',
    'dod': 'https://dod-graph.microsoft.us',
}

MICROSOFT_DEFENDER_FOR_ENDPOINT_APT_SERVICE_ENDPOINTS = {
    'com': 'https://securitycenter.onmicrosoft.com',
    'geo-us': 'https://securitycenter.onmicrosoft.com',
    'geo-eu': 'https://securitycenter.onmicrosoft.com',
    'geo-uk': 'https://securitycenter.onmicrosoft.com',
    'gcc': 'https://securitycenter.onmicrosoft.com',
    'gcc-high': 'https://securitycenter.onmicrosoft.us',
    'dod': 'https://securitycenter.onmicrosoft.us',
}

MICROSOFT_DEFENDER_FOR_APPLICATION_API = {
    "com": "https://api.securitycenter.microsoft.com",
    "gcc": "https://api-gcc.securitycenter.microsoft.us",
    "gcc-high": "https://api-gcc.securitycenter.microsoft.us",
}


MICROSOFT_DEFENDER_FOR_APPLICATION_TYPE = {
    "Worldwide": "com",
    "US GCC": "gcc",
    "US GCC-High": "gcc-high",
}

MICROSOFT_DEFENDER_FOR_APPLICATION_TOKEN_RETRIEVAL_ENDPOINTS = {
    'com': 'https://login.microsoftonline.com',
    'gcc': 'https://login.microsoftonline.com',
    'gcc-high': 'https://login.microsoftonline.us',
}

# Azure Managed Identities
MANAGED_IDENTITIES_TOKEN_URL = 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01'
MANAGED_IDENTITIES_SYSTEM_ASSIGNED = 'SYSTEM_ASSIGNED'
TOKEN_EXPIRED_ERROR_CODES = {50173, 700082, 70008, 54005, 7000222,
                             }  # See: https://login.microsoftonline.com/error?code=

# Moderate Retry Mechanism
MAX_DELAY_REQUEST_COUNTER = 6


class CloudEndpointNotSetException(Exception):
    pass


class CloudSuffixNotSetException(Exception):
    pass


class AzureCloudEndpoints:  # pylint: disable=too-few-public-methods,too-many-instance-attributes

    def __init__(self,  # pylint: disable=unused-argument
                 management=None,
                 resource_manager=None,
                 sql_management=None,
                 batch_resource_id=None,
                 gallery=None,
                 active_directory=None,
                 active_directory_resource_id=None,
                 active_directory_graph_resource_id=None,
                 microsoft_graph_resource_id=None,
                 active_directory_data_lake_resource_id=None,
                 vm_image_alias_doc=None,
                 media_resource_id=None,
                 ossrdbms_resource_id=None,
                 log_analytics_resource_id=None,
                 app_insights_resource_id=None,
                 app_insights_telemetry_channel_resource_id=None,
                 synapse_analytics_resource_id=None,
                 attestation_resource_id=None,
                 portal=None,
                 keyvault=None,
                 exchange_online=None):
        # Attribute names are significant. They are used when storing/retrieving clouds from config
        self.management = management
        self.resource_manager = resource_manager
        self.sql_management = sql_management
        self.batch_resource_id = batch_resource_id
        self.gallery = gallery
        self.active_directory = active_directory
        self.active_directory_resource_id = active_directory_resource_id
        self.active_directory_graph_resource_id = active_directory_graph_resource_id
        self.microsoft_graph_resource_id = microsoft_graph_resource_id
        self.active_directory_data_lake_resource_id = active_directory_data_lake_resource_id
        self.vm_image_alias_doc = vm_image_alias_doc
        self.media_resource_id = media_resource_id
        self.ossrdbms_resource_id = ossrdbms_resource_id
        self.log_analytics_resource_id = log_analytics_resource_id
        self.app_insights_resource_id = app_insights_resource_id
        self.app_insights_telemetry_channel_resource_id = app_insights_telemetry_channel_resource_id
        self.synapse_analytics_resource_id = synapse_analytics_resource_id
        self.attestation_resource_id = attestation_resource_id
        self.portal = portal
        self.keyvault = keyvault
        self.exchange_online = exchange_online

    def has_endpoint_set(self, endpoint_name):
        try:
            # Can't simply use hasattr here as we override __getattribute__ below.
            # Python 3 hasattr() only returns False if an AttributeError is raised, but we raise
            # CloudEndpointNotSetException. This exception is not a subclass of AttributeError.
            getattr(self, endpoint_name)
            return True
        except Exception:  # pylint: disable=broad-except
            return False

    def __getattribute__(self, name):
        val = object.__getattribute__(self, name)
        if val is None:
            raise CloudEndpointNotSetException("The endpoint '{}' for this cloud is not set but is used.")
        return val


class AzureCloudSuffixes:  # pylint: disable=too-few-public-methods,too-many-instance-attributes

    def __init__(self,  # pylint: disable=unused-argument
                 storage_endpoint=None,
                 storage_sync_endpoint=None,
                 keyvault_dns=None,
                 mhsm_dns=None,
                 sql_server_hostname=None,
                 azure_datalake_store_file_system_endpoint=None,
                 azure_datalake_analytics_catalog_and_job_endpoint=None,
                 acr_login_server_endpoint=None,
                 mysql_server_endpoint=None,
                 postgresql_server_endpoint=None,
                 mariadb_server_endpoint=None,
                 synapse_analytics_endpoint=None,
                 attestation_endpoint=None):
        # Attribute names are significant. They are used when storing/retrieving clouds from config
        self.storage_endpoint = storage_endpoint
        self.storage_sync_endpoint = storage_sync_endpoint
        self.keyvault_dns = keyvault_dns
        self.mhsm_dns = mhsm_dns
        self.sql_server_hostname = sql_server_hostname
        self.mysql_server_endpoint = mysql_server_endpoint
        self.postgresql_server_endpoint = postgresql_server_endpoint
        self.mariadb_server_endpoint = mariadb_server_endpoint
        self.azure_datalake_store_file_system_endpoint = azure_datalake_store_file_system_endpoint
        self.azure_datalake_analytics_catalog_and_job_endpoint = azure_datalake_analytics_catalog_and_job_endpoint
        self.acr_login_server_endpoint = acr_login_server_endpoint
        self.synapse_analytics_endpoint = synapse_analytics_endpoint
        self.attestation_endpoint = attestation_endpoint

    def __getattribute__(self, name):
        val = object.__getattribute__(self, name)
        if val is None:
            raise CloudSuffixNotSetException("The suffix '{}' for this cloud is not set but is used.")
        return val


class AzureCloud:  # pylint: disable=too-few-public-methods
    """ Represents an Azure Cloud instance """

    def __init__(self,
                 origin,
                 name,
                 abbreviation,
                 endpoints=None,
                 suffixes=None):
        self.name = name
        self.abbreviation = abbreviation
        self.origin = origin
        self.endpoints = endpoints or AzureCloudEndpoints()
        self.suffixes = suffixes or AzureCloudSuffixes()


AZURE_WORLDWIDE_CLOUD = AzureCloud(
    'Embedded',
    'AzureCloud',
    'com',
    endpoints=AzureCloudEndpoints(
        management='https://management.core.windows.net/',
        resource_manager='https://management.azure.com/',
        sql_management='https://management.core.windows.net:8443/',
        batch_resource_id='https://batch.core.windows.net/',
        gallery='https://gallery.azure.com/',
        active_directory='https://login.microsoftonline.com',
        active_directory_resource_id='https://management.core.windows.net/',
        active_directory_graph_resource_id='https://graph.windows.net/',
        microsoft_graph_resource_id='https://graph.microsoft.com/',
        active_directory_data_lake_resource_id='https://datalake.azure.net/',
        vm_image_alias_doc='https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/arm-compute/quickstart-templates/aliases.json',  # noqa: E501
        media_resource_id='https://rest.media.azure.net',
        ossrdbms_resource_id='https://ossrdbms-aad.database.windows.net',
        app_insights_resource_id='https://api.applicationinsights.io',
        log_analytics_resource_id='https://api.loganalytics.io',
        app_insights_telemetry_channel_resource_id='https://dc.applicationinsights.azure.com/v2/track',
        synapse_analytics_resource_id='https://dev.azuresynapse.net',
        attestation_resource_id='https://attest.azure.net',
        portal='https://portal.azure.com',
        keyvault='https://vault.azure.net',
        exchange_online='https://outlook.office365.com'
    ),
    suffixes=AzureCloudSuffixes(
        storage_endpoint='core.windows.net',
        storage_sync_endpoint='afs.azure.net',
        keyvault_dns='.vault.azure.net',
        mhsm_dns='.managedhsm.azure.net',
        sql_server_hostname='.database.windows.net',
        mysql_server_endpoint='.mysql.database.azure.com',
        postgresql_server_endpoint='.postgres.database.azure.com',
        mariadb_server_endpoint='.mariadb.database.azure.com',
        azure_datalake_store_file_system_endpoint='azuredatalakestore.net',
        azure_datalake_analytics_catalog_and_job_endpoint='azuredatalakeanalytics.net',
        acr_login_server_endpoint='.azurecr.io',
        synapse_analytics_endpoint='.dev.azuresynapse.net',
        attestation_endpoint='.attest.azure.net'))

AZURE_US_GCC_CLOUD = AzureCloud(
    'Embedded',
    'AzureUSGovernment',
    'gcc',
    endpoints=AzureCloudEndpoints(
        management='https://management.core.usgovcloudapi.net/',
        resource_manager='https://management.usgovcloudapi.net/',
        sql_management='https://management.core.usgovcloudapi.net:8443/',
        batch_resource_id='https://batch.core.usgovcloudapi.net/',
        gallery='https://gallery.usgovcloudapi.net/',
        active_directory='https://login.microsoftonline.com',
        active_directory_resource_id='https://management.core.usgovcloudapi.net/',
        active_directory_graph_resource_id='https://graph.windows.net/',
        microsoft_graph_resource_id='https://graph.microsoft.us/',
        vm_image_alias_doc='https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/arm-compute/quickstart-templates/aliases.json',  # noqa: E501
        media_resource_id='https://rest.media.usgovcloudapi.net',
        ossrdbms_resource_id='https://ossrdbms-aad.database.usgovcloudapi.net',
        app_insights_resource_id='https://api.applicationinsights.us',
        log_analytics_resource_id='https://api.loganalytics.us',
        app_insights_telemetry_channel_resource_id='https://dc.applicationinsights.us/v2/track',
        synapse_analytics_resource_id='https://dev.azuresynapse.usgovcloudapi.net',
        portal='https://portal.azure.us',
        keyvault='https://vault.usgovcloudapi.net',
        exchange_online='https://outlook.office365.com'
    ),
    suffixes=AzureCloudSuffixes(
        storage_endpoint='core.usgovcloudapi.net',
        storage_sync_endpoint='afs.azure.us',
        keyvault_dns='.vault.usgovcloudapi.net',
        mhsm_dns='.managedhsm.usgovcloudapi.net',
        sql_server_hostname='.database.usgovcloudapi.net',
        mysql_server_endpoint='.mysql.database.usgovcloudapi.net',
        postgresql_server_endpoint='.postgres.database.usgovcloudapi.net',
        mariadb_server_endpoint='.mariadb.database.usgovcloudapi.net',
        acr_login_server_endpoint='.azurecr.us',
        synapse_analytics_endpoint='.dev.azuresynapse.usgovcloudapi.net'))

AZURE_US_GCC_HIGH_CLOUD = AzureCloud(
    'Embedded',
    'AzureUSGovernment',
    'gcc-high',
    endpoints=AzureCloudEndpoints(
        management='https://management.core.usgovcloudapi.net/',
        resource_manager='https://management.usgovcloudapi.net/',
        sql_management='https://management.core.usgovcloudapi.net:8443/',
        batch_resource_id='https://batch.core.usgovcloudapi.net/',
        gallery='https://gallery.usgovcloudapi.net/',
        active_directory='https://login.microsoftonline.us',
        active_directory_resource_id='https://management.core.usgovcloudapi.net/',
        active_directory_graph_resource_id='https://graph.windows.net/',
        microsoft_graph_resource_id='https://graph.microsoft.us/',
        vm_image_alias_doc='https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/arm-compute/quickstart-templates/aliases.json',  # noqa: E501
        media_resource_id='https://rest.media.usgovcloudapi.net',
        ossrdbms_resource_id='https://ossrdbms-aad.database.usgovcloudapi.net',
        app_insights_resource_id='https://api.applicationinsights.us',
        log_analytics_resource_id='https://api.loganalytics.us',
        app_insights_telemetry_channel_resource_id='https://dc.applicationinsights.us/v2/track',
        synapse_analytics_resource_id='https://dev.azuresynapse.usgovcloudapi.net',
        portal='https://portal.azure.us',
        keyvault='https://vault.usgovcloudapi.net',
        exchange_online='https://outlook.office365.us'
    ),
    suffixes=AzureCloudSuffixes(
        storage_endpoint='core.usgovcloudapi.net',
        storage_sync_endpoint='afs.azure.us',
        keyvault_dns='.vault.usgovcloudapi.net',
        mhsm_dns='.managedhsm.usgovcloudapi.net',
        sql_server_hostname='.database.usgovcloudapi.net',
        mysql_server_endpoint='.mysql.database.usgovcloudapi.net',
        postgresql_server_endpoint='.postgres.database.usgovcloudapi.net',
        mariadb_server_endpoint='.mariadb.database.usgovcloudapi.net',
        acr_login_server_endpoint='.azurecr.us',
        synapse_analytics_endpoint='.dev.azuresynapse.usgovcloudapi.net'))

AZURE_DOD_CLOUD = AzureCloud(
    'Embedded',
    'AzureUSGovernment',
    'dod',
    endpoints=AzureCloudEndpoints(
        management='https://management.core.usgovcloudapi.net/',
        resource_manager='https://management.usgovcloudapi.net/',
        sql_management='https://management.core.usgovcloudapi.net:8443/',
        batch_resource_id='https://batch.core.usgovcloudapi.net/',
        gallery='https://gallery.usgovcloudapi.net/',
        active_directory='https://login.microsoftonline.us',
        active_directory_resource_id='https://management.core.usgovcloudapi.net/',
        active_directory_graph_resource_id='https://graph.windows.net/',
        microsoft_graph_resource_id='https://dod-graph.microsoft.us/',
        vm_image_alias_doc='https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/arm-compute/quickstart-templates/aliases.json',  # noqa: E501
        media_resource_id='https://rest.media.usgovcloudapi.net',
        ossrdbms_resource_id='https://ossrdbms-aad.database.usgovcloudapi.net',
        app_insights_resource_id='https://api.applicationinsights.us',
        log_analytics_resource_id='https://api.loganalytics.us',
        app_insights_telemetry_channel_resource_id='https://dc.applicationinsights.us/v2/track',
        synapse_analytics_resource_id='https://dev.azuresynapse.usgovcloudapi.net',
        portal='https://portal.azure.us',
        keyvault='https://vault.usgovcloudapi.net',
        exchange_online='https://outlook-dod.office365.us'

    ),
    suffixes=AzureCloudSuffixes(
        storage_endpoint='core.usgovcloudapi.net',
        storage_sync_endpoint='afs.azure.us',
        keyvault_dns='.vault.usgovcloudapi.net',
        mhsm_dns='.managedhsm.usgovcloudapi.net',
        sql_server_hostname='.database.usgovcloudapi.net',
        mysql_server_endpoint='.mysql.database.usgovcloudapi.net',
        postgresql_server_endpoint='.postgres.database.usgovcloudapi.net',
        mariadb_server_endpoint='.mariadb.database.usgovcloudapi.net',
        acr_login_server_endpoint='.azurecr.us',
        synapse_analytics_endpoint='.dev.azuresynapse.usgovcloudapi.net'))


AZURE_GERMAN_CLOUD = AzureCloud(
    'Embedded',
    'AzureGermanCloud',
    'de',
    endpoints=AzureCloudEndpoints(
        management='https://management.core.cloudapi.de/',
        resource_manager='https://management.microsoftazure.de',
        sql_management='https://management.core.cloudapi.de:8443/',
        batch_resource_id='https://batch.cloudapi.de/',
        gallery='https://gallery.cloudapi.de/',
        active_directory='https://login.microsoftonline.de',
        active_directory_resource_id='https://management.core.cloudapi.de/',
        active_directory_graph_resource_id='https://graph.cloudapi.de/',
        microsoft_graph_resource_id='https://graph.microsoft.de',
        vm_image_alias_doc='https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/arm-compute/quickstart-templates/aliases.json',  # noqa: E501
        media_resource_id='https://rest.media.cloudapi.de',
        ossrdbms_resource_id='https://ossrdbms-aad.database.cloudapi.de',
        portal='https://portal.microsoftazure.de',
        keyvault='https://vault.microsoftazure.de',
    ),
    suffixes=AzureCloudSuffixes(
        storage_endpoint='core.cloudapi.de',
        keyvault_dns='.vault.microsoftazure.de',
        mhsm_dns='.managedhsm.microsoftazure.de',
        sql_server_hostname='.database.cloudapi.de',
        mysql_server_endpoint='.mysql.database.cloudapi.de',
        postgresql_server_endpoint='.postgres.database.cloudapi.de',
        mariadb_server_endpoint='.mariadb.database.cloudapi.de'))

AZURE_CHINA_CLOUD = AzureCloud(
    'Embedded',
    'AzureChinaCloud',
    'cn',
    endpoints=AzureCloudEndpoints(
        management='https://management.core.chinacloudapi.cn/',
        resource_manager='https://management.chinacloudapi.cn',
        sql_management='https://management.core.chinacloudapi.cn:8443/',
        batch_resource_id='https://batch.chinacloudapi.cn/',
        gallery='https://gallery.chinacloudapi.cn/',
        active_directory='https://login.chinacloudapi.cn',
        active_directory_resource_id='https://management.core.chinacloudapi.cn/',
        active_directory_graph_resource_id='https://graph.chinacloudapi.cn/',
        microsoft_graph_resource_id='https://microsoftgraph.chinacloudapi.cn',
        vm_image_alias_doc='https://raw.githubusercontent.com/Azure/azure-rest-api-specs/main/arm-compute/quickstart-templates/aliases.json',  # noqa: E501
        media_resource_id='https://rest.media.chinacloudapi.cn',
        ossrdbms_resource_id='https://ossrdbms-aad.database.chinacloudapi.cn',
        app_insights_resource_id='https://api.applicationinsights.azure.cn',
        log_analytics_resource_id='https://api.loganalytics.azure.cn',
        app_insights_telemetry_channel_resource_id='https://dc.applicationinsights.azure.cn/v2/track',
        synapse_analytics_resource_id='https://dev.azuresynapse.azure.cn',
        portal='https://portal.azure.cn',
        keyvault='https://vault.azure.cn',
        exchange_online='https://partner.outlook.cn'
    ),
    suffixes=AzureCloudSuffixes(
        storage_endpoint='core.chinacloudapi.cn',
        keyvault_dns='.vault.azure.cn',
        mhsm_dns='.managedhsm.azure.cn',
        sql_server_hostname='.database.chinacloudapi.cn',
        mysql_server_endpoint='.mysql.database.chinacloudapi.cn',
        postgresql_server_endpoint='.postgres.database.chinacloudapi.cn',
        mariadb_server_endpoint='.mariadb.database.chinacloudapi.cn',
        acr_login_server_endpoint='.azurecr.cn',
        synapse_analytics_endpoint='.dev.azuresynapse.azure.cn'))


AZURE_CLOUD_NAME_MAPPING = {
    "Worldwide": "com",
    "Germany": "de",
    "China": "cn",
    "US GCC": "gcc",
    "US GCC-High": "gcc-high",
    "DoD": "dod",
}

AZURE_CLOUD_NAME_CUSTOM = "Custom"

AZURE_CLOUDS = {
    "com": AZURE_WORLDWIDE_CLOUD,
    "gcc": AZURE_US_GCC_CLOUD,
    "gcc-high": AZURE_US_GCC_HIGH_CLOUD,
    "dod": AZURE_DOD_CLOUD,
    "de": AZURE_GERMAN_CLOUD,
    "cn": AZURE_CHINA_CLOUD,
}


class AzureCloudNames:
    WORLDWIDE = "com"
    GERMANY = "de"
    CHINA = "cn"
    US_GCC = "gcc"
    US_GCC_HIGH = "gcc-high"
    DOD = "dod"
    CUSTOM = "custom"


def create_custom_azure_cloud(origin: str,
                              name: str | None = None,
                              abbreviation: str | None = None,
                              defaults: AzureCloud | None = None,
                              endpoints: dict | None = None,
                              suffixes: dict | None = None):
    defaults = defaults or AzureCloud(origin, name, abbreviation)
    endpoints = endpoints or {}
    suffixes = suffixes or {}
    return AzureCloud(
        origin,
        name or defaults.name,
        abbreviation or defaults.abbreviation,
        endpoints=AzureCloudEndpoints(
            management=endpoints.get('management', defaults.endpoints.management),
            resource_manager=endpoints.get('resource_manager', defaults.endpoints.resource_manager),
            sql_management=endpoints.get('sql_management', defaults.endpoints.sql_management),
            batch_resource_id=endpoints.get('batch_resource_id', defaults.endpoints.batch_resource_id),
            gallery=endpoints.get('gallery', defaults.endpoints.gallery),
            active_directory=endpoints.get('active_directory', defaults.endpoints.active_directory),
            active_directory_resource_id=endpoints.get('active_directory_resource_id',
                                                       defaults.endpoints.active_directory_resource_id),
            active_directory_graph_resource_id=endpoints.get(
                'active_directory_graph_resource_id', defaults.endpoints.active_directory_graph_resource_id),
            microsoft_graph_resource_id=endpoints.get('microsoft_graph_resource_id',
                                                      defaults.endpoints.microsoft_graph_resource_id),
            active_directory_data_lake_resource_id=endpoints.get(
                'active_directory_data_lake_resource_id', defaults.endpoints.active_directory_data_lake_resource_id),
            vm_image_alias_doc=endpoints.get('vm_image_alias_doc', defaults.endpoints.vm_image_alias_doc),
            media_resource_id=endpoints.get('media_resource_id', defaults.endpoints.media_resource_id),
            ossrdbms_resource_id=endpoints.get('ossrdbms_resource_id', defaults.endpoints.ossrdbms_resource_id),
            app_insights_resource_id=endpoints.get('app_insights_resource_id', defaults.endpoints.app_insights_resource_id),
            log_analytics_resource_id=endpoints.get('log_analytics_resource_id', defaults.endpoints.log_analytics_resource_id),
            app_insights_telemetry_channel_resource_id=endpoints.get(
                'app_insights_telemetry_channel_resource_id', defaults.endpoints.app_insights_telemetry_channel_resource_id),
            synapse_analytics_resource_id=endpoints.get(
                'synapse_analytics_resource_id', defaults.endpoints.synapse_analytics_resource_id),
            attestation_resource_id=endpoints.get('attestation_resource_id', defaults.endpoints.attestation_resource_id),
            portal=endpoints.get('portal', defaults.endpoints.portal),
            keyvault=endpoints.get('keyvault', defaults.endpoints.keyvault),
        ),
        suffixes=AzureCloudSuffixes(
            storage_endpoint=suffixes.get('storage_endpoint', defaults.suffixes.storage_endpoint),
            storage_sync_endpoint=suffixes.get('storage_sync_endpoint', defaults.suffixes.storage_sync_endpoint),
            keyvault_dns=suffixes.get('keyvault_dns', defaults.suffixes.keyvault_dns),
            mhsm_dns=suffixes.get('mhsm_dns', defaults.suffixes.mhsm_dns),
            sql_server_hostname=suffixes.get('sql_server_hostname', defaults.suffixes.sql_server_hostname),
            mysql_server_endpoint=suffixes.get('mysql_server_endpoint', defaults.suffixes.mysql_server_endpoint),
            postgresql_server_endpoint=suffixes.get('postgresql_server_endpoint', defaults.suffixes.postgresql_server_endpoint),
            mariadb_server_endpoint=suffixes.get('mariadb_server_endpoint', defaults.suffixes.mariadb_server_endpoint),
            azure_datalake_store_file_system_endpoint=suffixes.get(
                'azure_datalake_store_file_system_endpoint', defaults.suffixes.azure_datalake_store_file_system_endpoint),
            azure_datalake_analytics_catalog_and_job_endpoint=suffixes.get(
                'azure_datalake_analytics_catalog_and_job_endpoint',
                defaults.suffixes.azure_datalake_analytics_catalog_and_job_endpoint),
            acr_login_server_endpoint=suffixes.get('acr_login_server_endpoint', defaults.suffixes.acr_login_server_endpoint),
            synapse_analytics_endpoint=suffixes.get('synapse_analytics_endpoint', defaults.suffixes.synapse_analytics_endpoint),
            attestation_endpoint=suffixes.get('attestation_endpoint', defaults.suffixes.attestation_endpoint),
        ))


def microsoft_defender_for_endpoint_get_base_url(endpoint_type, url, is_gcc=None):
    # Backward compatible argument parsing, preserve the url and is_gcc functionality if provided, otherwise use endpoint_type.
    log_message_append = ""
    if is_gcc:  # Backward compatible.
        endpoint_type = "US GCC"
        log_message_append = f" ,Overriding endpoint to {endpoint_type}, backward compatible."
    elif (endpoint_type == MICROSOFT_DEFENDER_FOR_ENDPOINT_TYPE_CUSTOM or not endpoint_type) and not url:
        # When the integration was configured before our Azure Cloud support, the value will be None.
        if endpoint_type == MICROSOFT_DEFENDER_FOR_ENDPOINT_TYPE_CUSTOM:
            raise DemistoException("Endpoint type is set to 'Custom' but no URL was provided.")
        raise DemistoException("'Endpoint Type' is not set and no URL was provided.")
    endpoint_type = MICROSOFT_DEFENDER_FOR_ENDPOINT_TYPE.get(endpoint_type, 'com')
    url = url or MICROSOFT_DEFENDER_FOR_ENDPOINT_API[endpoint_type]
    demisto.info(f"Using url:{url}, endpoint type:{endpoint_type}{log_message_append}")
    return endpoint_type, url


def get_azure_cloud(params, integration_name):
    azure_cloud_arg = params.get('azure_cloud')
    if not azure_cloud_arg or azure_cloud_arg == AZURE_CLOUD_NAME_CUSTOM:
        # Backward compatibility before the azure cloud settings.
        if 'server_url' in params:
            return create_custom_azure_cloud(integration_name, defaults=AZURE_WORLDWIDE_CLOUD,
                                             endpoints={'resource_manager': params.get('server_url')
                                                        or 'https://management.azure.com'})
        if 'azure_ad_endpoint' in params:
            return create_custom_azure_cloud(integration_name, defaults=AZURE_WORLDWIDE_CLOUD,
                                             endpoints={
                                                 'active_directory': params.get('azure_ad_endpoint')
                                                 or 'https://login.microsoftonline.com'
                                             })
        # in multiple Graph integrations, the url is called 'url' or 'host' instead of 'server_url' and the default url is
        # different.
        if 'url' in params or 'host' in params:
            return create_custom_azure_cloud(integration_name, defaults=AZURE_WORLDWIDE_CLOUD,
                                             endpoints={'microsoft_graph_resource_id': params.get('url') or params.get('host')
                                                        or 'https://graph.microsoft.com'})

    # There is no need for backward compatibility support, as the integration didn't support it to begin with.
    return AZURE_CLOUDS.get(AZURE_CLOUD_NAME_MAPPING.get(azure_cloud_arg), AZURE_WORLDWIDE_CLOUD)  # type: ignore[arg-type]


class MicrosoftClient(BaseClient):
    def __init__(self, tenant_id: str = '',
                 auth_id: str = '',
                 enc_key: str | None = '',
                 token_retrieval_url: str = '{endpoint}/{tenant_id}/oauth2/v2.0/token',
                 app_name: str = '',
                 refresh_token: str = '',
                 auth_code: str = '',
                 scope: str = '{graph_endpoint}/.default',
                 grant_type: str = CLIENT_CREDENTIALS,
                 redirect_uri: str = 'https://localhost/myapp',
                 resource: str | None = '',
                 multi_resource: bool = False,
                 resources: list[str] = None,
                 verify: bool = True,
                 self_deployed: bool = False,
                 timeout: int | None = None,
                 azure_ad_endpoint: str = '{endpoint}',
                 azure_cloud: AzureCloud = AZURE_WORLDWIDE_CLOUD,
                 endpoint: str = "__NA__",  # Deprecated
                 certificate_thumbprint: str | None = None,
                 retry_on_rate_limit: bool = False,
                 private_key: str | None = None,
                 managed_identities_client_id: str | None = None,
                 managed_identities_resource_uri: str | None = None,
                 base_url: str | None = None,
                 command_prefix: str | None = "command_prefix",
                 *args, **kwargs):
        """
        Microsoft Client class that implements logic to authenticate with oproxy or self deployed applications.
        It also provides common logic to handle responses from Microsoft.
        Args:
            tenant_id: If self deployed it's the tenant for the app url, otherwise (oproxy) it's the token
            auth_id: If self deployed it's the client id, otherwise (oproxy) it's the auth id and may also
            contain the token url
            enc_key: If self deployed it's the client secret, otherwise (oproxy) it's the encryption key
            refresh_token: The current used refresh token.
            scope: The scope of the application (only if self deployed)
            resource: The resource of the application (only if self deployed)
            multi_resource: Where or not module uses a multiple resources (self-deployed, auth_code grant type only)
            resources: Resources of the application (for multi-resource mode)
            verify: Demisto insecure parameter
            self_deployed: Indicates whether the integration mode is self deployed or oproxy
            timeout: Connection timeout
            azure_ad_endpoint: Custom endpoint to Azure Active Directory URL
            azure_cloud: Azure Cloud.
            certificate_thumbprint: Certificate's thumbprint that's associated to the app
            private_key: Private key of the certificate
            managed_identities_client_id: The Azure Managed Identities client id
            managed_identities_resource_uri: The resource uri to get token for by Azure Managed Identities
            retry_on_rate_limit: If the http request returns with a 429 - Rate limit reached response,
                                 retry the request using a scheduled command.
            base_url: Optionally override the calculated Azure endpoint, used for self-deployed and backward-compatibility with
                      integration that supported national cloud before the *azure_cloud* parameter.
            command_prefix: The prefix for all integration commands.
        """
        self.command_prefix = command_prefix
        demisto.debug(f'Initializing MicrosoftClient with: {endpoint=} | {azure_cloud.abbreviation}')
        if endpoint != "__NA__":
            # Backward compatible.
            self.azure_cloud = AZURE_CLOUDS.get(endpoint, AZURE_WORLDWIDE_CLOUD)
        else:
            self.azure_cloud = azure_cloud

        super().__init__(*args, verify=verify, base_url=base_url, **kwargs)  # type: ignore[misc]

        self.retry_on_rate_limit = retry_on_rate_limit
        if retry_on_rate_limit and (429 not in self._ok_codes):
            self._ok_codes = self._ok_codes + (429,)
        if not self_deployed:
            auth_id_and_token_retrieval_url = auth_id.split('@')
            auth_id = auth_id_and_token_retrieval_url[0]
            if len(auth_id_and_token_retrieval_url) != 2:
                self.token_retrieval_url = 'https://oproxy.demisto.ninja/obtain-token'  # guardrails-disable-line
            else:
                self.token_retrieval_url = auth_id_and_token_retrieval_url[1]

            self.app_name = app_name
            self.auth_id = auth_id
            self.enc_key = enc_key
            self.refresh_token = refresh_token

        else:
            self.token_retrieval_url = token_retrieval_url.format(tenant_id=tenant_id,
                                                                  endpoint=self.azure_cloud.endpoints.active_directory
                                                                  .rstrip("/"))
            self.client_id = auth_id
            self.client_secret = enc_key
            self.auth_code = auth_code
            self.grant_type = grant_type
            self.resource = resource
            self.scope = scope.format(graph_endpoint=self.azure_cloud.endpoints.microsoft_graph_resource_id.rstrip("/"))
            self.redirect_uri = redirect_uri
            if certificate_thumbprint and private_key:
                try:
                    import msal  # pylint: disable=E0401
                    self.jwt = msal.oauth2cli.assertion.JwtAssertionCreator(
                        private_key,
                        'RS256',
                        certificate_thumbprint
                    ).create_normal_assertion(audience=self.token_retrieval_url, issuer=self.client_id)
                except ModuleNotFoundError:
                    raise DemistoException('Unable to use certificate authentication because `msal` is missing.')
            else:
                self.jwt = None

        self.tenant_id = tenant_id
        self.auth_type = SELF_DEPLOYED_AUTH_TYPE if self_deployed else OPROXY_AUTH_TYPE
        self.verify = verify
        self.azure_ad_endpoint = azure_ad_endpoint.format(
            endpoint=self.azure_cloud.endpoints.active_directory.rstrip("/"))
        self.timeout = timeout  # type: ignore

        self.multi_resource = multi_resource
        if self.multi_resource:
            self.resources = resources if resources else []
            self.resource_to_access_token: dict[str, str] = {}

        # for Azure Managed Identities purpose
        self.managed_identities_client_id = managed_identities_client_id
        self.managed_identities_resource_uri = managed_identities_resource_uri

    @staticmethod
    def is_command_executed_from_integration():
        ctx = demisto.callingContext.get('context', {})
        executed_commands = ctx.get('ExecutedCommands', [{'moduleBrand': 'Scripts'}])

        if executed_commands:
            return executed_commands[0].get('moduleBrand', "") != 'Scripts'

        return True

    def http_request(
            self, *args, resp_type='json', headers=None,
            return_empty_response=False, scope: str | None = None,
            resource: str = '', overwrite_rate_limit_retry=False, **kwargs):
        """
        Overrides Base client request function, retrieves and adds to headers access token before sending the request.

        Args:
            resp_type: Type of response to return. will be ignored if `return_empty_response` is True.
            headers: Headers to add to the request.
            return_empty_response: Return the response itself if the return_code is 206.
            scope: A scope to request. Currently, will work only with self-deployed app.
            resource (str): The resource identifier for which the generated token will have access to.
            overwrite_rate_limit_retry : Skip rate limit retry
        Returns:
            Response from api according to resp_type. The default is `json` (dict or list).
        """
        if 'ok_codes' not in kwargs and not self._ok_codes:
            kwargs['ok_codes'] = (200, 201, 202, 204, 206, 404)
        token = self.get_access_token(resource=resource, scope=scope)
        default_headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json',
            'Accept': 'application/json'
        }

        if headers:
            default_headers |= headers

        if self.timeout:
            kwargs['timeout'] = self.timeout

        should_http_retry_on_rate_limit = self.retry_on_rate_limit and not overwrite_rate_limit_retry
        if should_http_retry_on_rate_limit and not kwargs.get('error_handler'):
            kwargs['error_handler'] = self.handle_error_with_metrics

        response = super()._http_request(  # type: ignore[misc]
            *args, resp_type="response", headers=default_headers, **kwargs)

        if should_http_retry_on_rate_limit and MicrosoftClient.is_command_executed_from_integration():
            MicrosoftClient.create_api_metrics(response.status_code)
        # 206 indicates Partial Content, reason will be in the warning header.
        # In that case, logs with the warning header will be written.
        if response.status_code == 206:
            demisto.debug(str(response.headers))
        is_response_empty_and_successful = (response.status_code == 204)
        if is_response_empty_and_successful and return_empty_response:
            return response

        # Handle 404 errors instead of raising them as exceptions:
        if response.status_code == 404:
            try:
                error_message = response.json()
            except Exception:
                error_message = 'Not Found - 404 Response'
            raise NotFoundError(error_message)

        if should_http_retry_on_rate_limit and response.status_code == 429 and is_demisto_version_ge('6.2.0'):
            command_args = demisto.args()
            ran_once_flag = command_args.get('ran_once_flag')
            demisto.info(f'429 MS rate limit for command {demisto.command()}, where ran_once_flag is {ran_once_flag}')
            # We want to retry on rate limit only once
            if ran_once_flag:
                try:
                    error_message = response.json()
                except Exception:
                    error_message = 'Rate limit reached on retry - 429 Response'
                demisto.info(f'Error in retry for MS rate limit - {error_message}')
                raise DemistoException(error_message)

            else:
                demisto.info(f'Scheduling command {demisto.command()}')
                command_args['ran_once_flag'] = True
                return_results(MicrosoftClient.run_retry_on_rate_limit(command_args))
                sys.exit(0)

        try:
            if resp_type == 'json':
                return response.json()
            if resp_type == 'text':
                return response.text
            if resp_type == 'content':
                return response.content
            if resp_type == 'xml':
                try:
                    import defusedxml.ElementTree as defused_ET
                    defused_ET.fromstring(response.text)
                except ImportError:
                    demisto.debug('defused_ET is not supported, using ET instead.')
                    ET.fromstring(response.text)
            return response
        except ValueError as exception:
            raise DemistoException(f'Failed to parse json object from response: {response.content}', exception)

    def get_access_token(self, resource: str = '', scope: str | None = None) -> str:
        """
        Obtains access and refresh token from oproxy server or just a token from a self deployed app.
        Access token is used and stored in the integration context
        until expiration time. After expiration, new refresh token and access token are obtained and stored in the
        integration context.

        Args:
            resource: The resource identifier for which the generated token will have access to.
            scope: A scope to get instead of the default on the API.

        Returns:
            str: Access token that will be added to authorization header.
        """
        integration_context = get_integration_context()
        refresh_token = integration_context.get('current_refresh_token', '')
        # Set keywords. Default without the scope prefix.
        access_token_keyword = f'{scope}_access_token' if scope else 'access_token'
        valid_until_keyword = f'{scope}_valid_until' if scope else 'valid_until'

        access_token = integration_context.get(resource) if self.multi_resource else integration_context.get(access_token_keyword)

        valid_until = integration_context.get(valid_until_keyword)

        if access_token and valid_until and self.epoch_seconds() < valid_until:
            return access_token

        if self.auth_type == OPROXY_AUTH_TYPE:
            if self.multi_resource:
                expires_in = None
                for resource_str in self.resources:
                    access_token, current_expires_in, refresh_token = self._oproxy_authorize(resource_str)
                    self.resource_to_access_token[resource_str] = access_token
                    self.refresh_token = refresh_token
                    expires_in = current_expires_in if expires_in is None else \
                        min(expires_in, current_expires_in)  # type: ignore[call-overload]
                if expires_in is None:
                    raise DemistoException("No resource was provided to get access token from")
            else:
                access_token, expires_in, refresh_token = self._oproxy_authorize(scope=scope)

        else:
            access_token, expires_in, refresh_token = self._get_self_deployed_token(
                refresh_token, scope, integration_context)
        time_now = self.epoch_seconds()
        time_buffer = 5  # seconds by which to shorten the validity period
        if expires_in - time_buffer > 0:
            # err on the side of caution with a slightly shorter access token validity period
            expires_in = expires_in - time_buffer
        valid_until = time_now + expires_in
        integration_context.update({
            access_token_keyword: access_token,
            valid_until_keyword: valid_until,
            'current_refresh_token': refresh_token
        })

        # Add resource access token mapping
        if self.multi_resource:
            integration_context.update(self.resource_to_access_token)

        set_integration_context(integration_context)
        demisto.debug('Set integration context successfully.')

        if self.multi_resource:
            return self.resource_to_access_token[resource]

        return access_token

    def _raise_authentication_error(self, oproxy_response: requests.Response):
        """
        Raises an exception for authentication error with the Oproxy server.
        Args:
            oproxy_response: Raw response from the Oproxy server to parse.
        """
        msg = 'Error in Microsoft authorization.'
        try:
            demisto.info(
                f'Authentication failure from server: {oproxy_response.status_code} {oproxy_response.reason} '
                f'{oproxy_response.text}'
            )
            msg += f" Status: {oproxy_response.status_code},"
            search_microsoft_response = re.search(r'{.*}', oproxy_response.text)
            microsoft_response = self.extract_microsoft_error(json.loads(search_microsoft_response.group())) \
                if search_microsoft_response else ""
            err_str = microsoft_response or oproxy_response.text
            if err_str:
                msg += f' body: {err_str}'
            err_response = oproxy_response.json()
            server_msg = err_response.get('message', '') or f'{err_response.get("title", "")}. {err_response.get("detail", "")}'
            if server_msg:
                msg += f' Server message: {server_msg}'
        except Exception as ex:
            demisto.error(f'Failed parsing error response - Exception: {ex}')
        raise Exception(msg)

    def _oproxy_authorize_build_request(self, headers: dict[str, str], content: str,
                                        scope: str | None = None, resource: str = ''
                                        ) -> requests.Response:
        """
        Build the Post request sent to the Oproxy server.
        Args:
            headers: The headers of the request.
            content: The content for the request (usually contains the refresh token).
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.

        Returns: The response from the Oproxy server.

        """
        return requests.post(
            self.token_retrieval_url,
            headers=headers,
            json={
                'app_name': self.app_name,
                'registration_id': self.auth_id,
                'encrypted_token': self.get_encrypted(content, self.enc_key),
                'scope': scope,
                'resource': resource
            },
            verify=self.verify
        )

    def _oproxy_authorize(self, resource: str = '', scope: str | None = None) -> tuple[str, int, str]:
        """
        Gets a token by authorizing with oproxy.
        Args:
            scope: A scope to add to the request. Do not use it.
            resource: Resource to get.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        content = self.refresh_token or self.tenant_id
        headers = self._add_info_headers()
        context = get_integration_context()
        next_request_time = context.get("next_request_time", 0.0)
        delay_request_counter = min(int(context.get('delay_request_counter', 1)), MAX_DELAY_REQUEST_COUNTER)

        should_delay_request(next_request_time)
        oproxy_response = self._oproxy_authorize_build_request(headers, content, scope, resource)

        if not oproxy_response.ok:
            next_request_time = calculate_next_request_time(delay_request_counter=delay_request_counter)
            set_retry_mechanism_arguments(next_request_time=next_request_time, delay_request_counter=delay_request_counter,
                                          context=context)
            self._raise_authentication_error(oproxy_response)

        # In case of success, reset the retry mechanism arguments.
        set_retry_mechanism_arguments(context=context)
        # Oproxy authentication succeeded
        try:
            gcloud_function_exec_id = oproxy_response.headers.get('Function-Execution-Id')
            demisto.info(f'Google Cloud Function Execution ID: {gcloud_function_exec_id}')
            parsed_response = oproxy_response.json()
        except ValueError:
            raise Exception(
                'There was a problem in retrieving an updated access token.\n'
                'The response from the Oproxy server did not contain the expected content.'
            )

        return (parsed_response.get('access_token', ''), parsed_response.get('expires_in', 3595),
                parsed_response.get('refresh_token', ''))

    def _get_self_deployed_token(self,
                                 refresh_token: str = '',
                                 scope: str | None = None,
                                 integration_context: dict | None = None
                                 ) -> tuple[str, int, str]:
        if self.managed_identities_client_id:

            if not self.multi_resource:
                return self._get_managed_identities_token()

            expires_in = -1  # init variable as an int
            for resource in self.resources:
                access_token, expires_in, refresh_token = self._get_managed_identities_token(resource=resource)
                self.resource_to_access_token[resource] = access_token
            return '', expires_in, refresh_token

        if self.grant_type == AUTHORIZATION_CODE:
            if not self.multi_resource:
                return self._get_self_deployed_token_auth_code(refresh_token, scope=scope)
            expires_in = -1  # init variable as an int
            for resource in self.resources:
                access_token, expires_in, refresh_token = self._get_self_deployed_token_auth_code(refresh_token,
                                                                                                  resource)
                self.resource_to_access_token[resource] = access_token

            return '', expires_in, refresh_token
        elif self.grant_type == DEVICE_CODE:
            return self._get_token_device_code(refresh_token, scope, integration_context)
        else:
            # by default, grant_type is CLIENT_CREDENTIALS
            if self.multi_resource:
                expires_in = -1  # init variable as an int
                for resource in self.resources:
                    access_token, expires_in, refresh_token = self._get_self_deployed_token_client_credentials(
                        resource=resource)
                    self.resource_to_access_token[resource] = access_token
                return '', expires_in, refresh_token
            return self._get_self_deployed_token_client_credentials(scope=scope)

    def _get_self_deployed_token_client_credentials(self, scope: str | None = None,
                                                    resource: str | None = None) -> tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application in client credentials grant type.

        Args:
            scope: A scope to add to the headers. Else will get self.scope.
            resource: A resource to add to the headers. Else will get self.resource.
        Returns:
            tuple: An access token and its expiry.
        """
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': CLIENT_CREDENTIALS
        }

        if self.jwt:
            data.pop('client_secret', None)
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = self.jwt

        # Set scope.
        if self.scope or scope:
            data['scope'] = scope or self.scope

        if self.resource or resource:
            data['resource'] = resource or self.resource  # type: ignore

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))

        return access_token, expires_in, ''

    def _get_self_deployed_token_auth_code(
            self, refresh_token: str = '', resource: str = '', scope: str | None = None) -> tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.
        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = assign_params(
            client_id=self.client_id,
            client_secret=self.client_secret,
            resource=resource if resource else self.resource,
            redirect_uri=self.redirect_uri
        )

        if self.jwt:
            data.pop('client_secret', None)
            data['client_assertion_type'] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data['client_assertion'] = self.jwt

        if scope:
            data['scope'] = scope

        refresh_token = refresh_token or self._get_refresh_token_from_auth_code_param()
        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            if SESSION_STATE in self.auth_code:
                raise ValueError('Malformed auth_code parameter: Please copy the auth code from the redirected uri '
                                 'without any additional info and without the "session_state" query parameter.')
            data['grant_type'] = AUTHORIZATION_CODE
            data['code'] = self.auth_code

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_managed_identities_token(self, resource=None):
        """
        Gets a token based on the Azure Managed Identities mechanism
        in case user was configured the Azure VM and the other Azure resource correctly
        """
        try:
            # system assigned are restricted to one per resource and is tied to the lifecycle of the Azure resource
            # see https://learn.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview
            use_system_assigned = (self.managed_identities_client_id == MANAGED_IDENTITIES_SYSTEM_ASSIGNED)
            resource = resource or self.managed_identities_resource_uri

            demisto.debug('try to get Managed Identities token')

            params = {'resource': resource}
            if not use_system_assigned:
                params['client_id'] = self.managed_identities_client_id

            response_json = requests.get(MANAGED_IDENTITIES_TOKEN_URL, params=params, headers={'Metadata': 'True'}).json()
            access_token = response_json.get('access_token')
            expires_in = int(response_json.get('expires_in', 3595))
            if access_token:
                return access_token, expires_in, ''

            err = response_json.get('error_description')
        except Exception as e:
            err = f'{str(e)}'

        return_error(f'Error in Microsoft authorization with Azure Managed Identities: {err}')
        return None

    def _get_token_device_code(
        self, refresh_token: str = '', scope: str | None = None, integration_context: dict | None = None
    ) -> tuple[str, int, str]:
        """
        Gets a token by authorizing a self deployed Azure application.

        Returns:
            tuple: An access token, its expiry and refresh token.
        """
        data = {
            'client_id': self.client_id,
            'scope': scope
        }

        if refresh_token:
            data['grant_type'] = REFRESH_TOKEN
            data['refresh_token'] = refresh_token
        else:
            data['grant_type'] = DEVICE_CODE
            if integration_context:
                data['code'] = integration_context.get('device_code')

        response_json: dict = {}
        try:
            response = requests.post(self.token_retrieval_url, data, verify=self.verify)
            if response.status_code not in {200, 201}:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')

        access_token = response_json.get('access_token', '')
        expires_in = int(response_json.get('expires_in', 3595))
        refresh_token = response_json.get('refresh_token', '')

        return access_token, expires_in, refresh_token

    def _get_refresh_token_from_auth_code_param(self) -> str:
        refresh_prefix = "refresh_token:"
        if self.auth_code.startswith(refresh_prefix):  # for testing we allow setting the refresh token directly
            demisto.debug("Using refresh token set as auth_code")
            return self.auth_code[len(refresh_prefix):]
        return ''

    @staticmethod
    def run_retry_on_rate_limit(args_for_next_run: dict):
        return CommandResults(readable_output="Rate limit reached, rerunning the command in 1 min",
                              scheduled_command=ScheduledCommand(command=demisto.command(), next_run_in_seconds=60,
                                                                 args=args_for_next_run, timeout_in_seconds=900))

    def handle_error_with_metrics(self, res):
        MicrosoftClient.create_api_metrics(res.status_code)
        self.client_error_handler(res)

    @staticmethod
    def create_api_metrics(status_code):
        execution_metrics = ExecutionMetrics()
        ok_codes = (200, 201, 202, 204, 206)

        if not execution_metrics.is_supported() or demisto.command() in ['test-module', 'fetch-incidents']:
            return
        if status_code == 429:
            execution_metrics.quota_error += 1
        elif status_code in ok_codes:
            execution_metrics.success += 1
        else:
            execution_metrics.general_error += 1
        return_results(execution_metrics.metrics)

    def error_parser(self, error: requests.Response) -> str:
        """

        Args:
            error (requests.Response): response with error

        Returns:
            str: string of error

        """
        try:
            response = error.json()
            demisto.error(str(response))
            err_str = self.extract_microsoft_error(response)
            if err_str:
                return err_str
            # If no error message
            raise ValueError
        except ValueError:
            return error.text

    def extract_microsoft_error(self, response: dict) -> str | None:
        """
        Extracts the Microsoft error message from the JSON response.

        Args:
            response (dict): JSON response received from the microsoft server.

        Returns:
            str or None: Extracted Microsoft error message if found, otherwise returns None.
        """
        inner_error = response.get('error', {})
        error_codes = response.get("error_codes", [""])
        err_desc = response.get('error_description', '')

        if isinstance(inner_error, dict):
            err_str = f"{inner_error.get('code')}: {inner_error.get('message')}"
        else:
            err_str = inner_error
            re_search = re.search(REGEX_SEARCH_ERROR_DESC, err_desc)
            err_str += f". \n{re_search['desc']}" if re_search else ""

        if err_str:
            if set(error_codes).issubset(TOKEN_EXPIRED_ERROR_CODES):
                err_str += f"\nYou can run the ***{self.command_prefix}-auth-reset*** command " \
                           f"to reset the authentication process."
            return err_str
        # If no error message
        return None

    @staticmethod
    def epoch_seconds(d: datetime = None) -> int:
        """
        Return the number of seconds for given date. If no date, return current.

        Args:
            d (datetime): timestamp
        Returns:
             int: timestamp in epoch
        """
        if not d:
            d = MicrosoftClient._get_utcnow()
        return int((d - MicrosoftClient._get_utc_from_timestamp(0)).total_seconds())

    @staticmethod
    def _get_utcnow() -> datetime:
        return datetime.utcnow()

    @staticmethod
    def _get_utc_from_timestamp(_time) -> datetime:
        return datetime.utcfromtimestamp(_time)

    @staticmethod
    def get_encrypted(content: str, key: str | None) -> str:
        """
        Encrypts content with encryption key.
        Args:
            content: Content to encrypt
            key: encryption key from oproxy

        Returns:
            timestamp: Encrypted content
        """

        def create_nonce():
            return os.urandom(12)

        def encrypt(string, enc_key):
            """
            Encrypts string input with encryption key.
            Args:
                string: String to encrypt
                enc_key: Encryption key

            Returns:
                bytes: Encrypted value
            """
            # String to bytes
            try:
                enc_key = base64.b64decode(enc_key)
            except Exception as err:
                return_error(f"Error in Microsoft authorization: {str(err)}"
                             f" Please check authentication related parameters.", error=traceback.format_exc())

            # Create key
            aes_gcm = AESGCM(enc_key)
            # Create nonce
            nonce = create_nonce()
            # Create ciphered data
            data = string.encode()
            ct = aes_gcm.encrypt(nonce, data, None)
            return base64.b64encode(nonce + ct)

        now = MicrosoftClient.epoch_seconds()
        encrypted = encrypt(f'{now}:{content}', key).decode('utf-8')
        return encrypted

    @staticmethod
    def _add_info_headers() -> dict[str, str]:
        # pylint: disable=no-member
        headers = {}
        try:
            headers = get_x_content_info_headers()
        except Exception as e:
            demisto.error(f'Failed getting integration info: {str(e)}')

        return headers

    def device_auth_request(self) -> dict:
        response_json = {}
        try:
            response = requests.post(
                url=f'{self.azure_ad_endpoint}/organizations/oauth2/v2.0/devicecode',
                data={
                    'client_id': self.client_id,
                    'scope': self.scope
                },
                verify=self.verify
            )
            if not response.ok:
                return_error(f'Error in Microsoft authorization. Status: {response.status_code},'
                             f' body: {self.error_parser(response)}')
            response_json = response.json()
        except Exception as e:
            return_error(f'Error in Microsoft authorization: {str(e)}')
        set_integration_context({'device_code': response_json.get('device_code')})
        return response_json

    def start_auth(self, complete_command: str) -> str:
        response = self.device_auth_request()
        message = response.get('message', '')
        re_search = re.search(REGEX_SEARCH_URL, message)
        url = re_search['url'] if re_search else None
        user_code = response.get('user_code')

        return f"""### Authorization instructions
1. To sign in, use a web browser to open the page [{url}]({url})
and enter the code **{user_code}** to authenticate.
2. Run the **{complete_command}** command in the War Room."""


class NotFoundError(Exception):
    """Exception raised for 404 - Not Found errors.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message):
        self.message = message


def calculate_next_request_time(delay_request_counter: int) -> float:
    """
        Calculates the next request time based on the delay_request_counter.
        This is an implication of the Moderate Retry Mechanism for the Oproxy requests.
    """
    # The max delay time should be limited to ~60 sec.
    next_request_time = get_current_time() + timedelta(seconds=(2 ** delay_request_counter))
    return next_request_time.timestamp()


def set_retry_mechanism_arguments(context: dict, next_request_time: float = 0.0, delay_request_counter: int = 1):
    """
        Sets the next_request_time in the integration context.
        This is an implication of the Moderate Retry Mechanism for the Oproxy requests.
    """
    context = context or {}
    next_counter = delay_request_counter + 1

    context['next_request_time'] = next_request_time
    context['delay_request_counter'] = next_counter
    # Should reset the context retry arguments.
    if next_request_time == 0.0:
        context['delay_request_counter'] = 1
    set_integration_context(context)


def should_delay_request(next_request_time: float):
    """
        Checks if the request should be delayed based on context variables.
        This is an implication of the Moderate Retry Mechanism for the Oproxy requests.
    """
    now = get_current_time().timestamp()

    # If the next_request_time is 0 or negative, it means that the request should not be delayed because no error has occurred.
    if next_request_time <= 0.0:
        return
    # Checking if the next_request_time has passed.
    if now >= next_request_time:
        return
    raise Exception(f"The request will be delayed until {datetime.fromtimestamp(next_request_time)}")


def get_azure_managed_identities_client_id(params: dict) -> str | None:
    """
    Extract the Azure Managed Identities from the demisto params

    Args:
        params (dict): the demisto params

    Returns:
        Optional[str]: if the use_managed_identities are True
        the managed_identities_client_id or MANAGED_IDENTITIES_SYSTEM_ASSIGNED
        will return, otherwise - None

    """
    auth_type = params.get('auth_type') or params.get('authentication_type')
    if params and (argToBoolean(params.get('use_managed_identities') or auth_type == 'Azure Managed Identities')):
        client_id = params.get('managed_identities_client_id', {}).get('password')
        return client_id or MANAGED_IDENTITIES_SYSTEM_ASSIGNED
    return None


def generate_login_url(client: MicrosoftClient,
                       login_url: str = "https://login.microsoftonline.com/") -> CommandResults:
    missing = []
    if not client.client_id:
        missing.append("client_id")
    if not client.tenant_id:
        missing.append("tenant_id")
    if not client.scope:
        missing.append("scope")
    if not client.redirect_uri:
        missing.append("redirect_uri")
    if missing:
        raise DemistoException("Please make sure you entered the Authorization configuration correctly. "
                               f"Missing:{','.join(missing)}")

    login_url = urljoin(login_url, f'{client.tenant_id}/oauth2/v2.0/authorize?'
                        f'response_type=code&scope=offline_access%20{client.scope.replace(" ", "%20")}'
                        f'&client_id={client.client_id}&redirect_uri={client.redirect_uri}')

    result_msg = f"""### Authorization instructions
1. Click on the [login URL]({login_url}) to sign in and grant Cortex XSOAR permissions for your Azure Service Management.
You will be automatically redirected to a link with the following structure:
```REDIRECT_URI?code=AUTH_CODE&session_state=SESSION_STATE```
2. Copy the `AUTH_CODE` (without the `code=` prefix, and the `session_state` parameter)
and paste it in your instance configuration under the **Authorization code** parameter.
 """
    return CommandResults(readable_output=result_msg)


def get_from_args_or_params(args: dict[str, Any], params: dict[str, Any], key: str) -> Any:
    """
    Get a value from args or params, if the value is provided in both args and params, the value from args will be used.
    if the value is not provided in args or params, an exception will be raised.
    this function is used in commands that have a value that can be provided in the instance parameters or in the command,
    e.g in azure-key-vault-delete 'subscription_id' can be provided in the instance parameters or in the command.
    Args:
        args (Dict[str, Any]): Demisto args.
        params (Dict[str, Any]): Demisto params
        key (str): Key to get.
    """
    if value := args.get(key, params.get(key)):
        return value
    else:
        raise Exception(f'No {key} was provided. Please provide a {key} either in the \
instance configuration or as a command argument.')


def azure_tag_formatter(arg):
    """
    Formats a tag argument to the Azure format
    Args:
        arg (str): Tag argument as string
    Returns:
        str: Tag argument in Azure format
    """
    try:
        tag = json.loads(arg)
        tag_name = next(iter(tag))
        tag_value = tag[tag_name]
        return f"tagName eq '{tag_name}' and tagValue eq '{tag_value}'"
    except Exception as e:
        raise Exception(
            """Invalid tag format, please use the following format: '{"key_name":"value_name"}'""",
            e,
        ) from e


def reset_auth() -> CommandResults:
    """
    This command resets the integration context.
    After running the command, a new token/auth-code will need to be given by the user to regenerate the access token.
    :return: Message about resetting the authorization process.
    """
    demisto.debug(f"Reset integration-context, before resetting {get_integration_context()=}")
    set_integration_context({})
    return CommandResults(readable_output='Authorization was reset successfully. Please regenerate the credentials, '
                                          'and then click **Test** to validate the credentials and connection.')
