import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

"""Main file for RubrikPolaris Integration."""
import math
import re
import traceback
from copy import deepcopy
from datetime import date
from collections.abc import Callable

import jwt
import urllib3
from rubrik_polaris.exceptions import ProxyException
from rubrik_polaris.rubrik_polaris import PolarisClient

# Disable insecure warnings
urllib3.disable_warnings()

""" CONSTANTS """

INTEGRATION_NAME = "Rubrik Radar"
DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
HR_DATE_TIME_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
HUMAN_READABLE_DATE_TIME_FORMAT = "%b %d, %Y at %I:%M:%S %p"
USER_ACCESS_HYPERLINK = "{}sonar/user_intelligence?redirected_user_id={}"
EVENT_HYPERLINK = '{}events/details/{}?clusterUuid="{}"'
THREAT_MONITORING_HYPERLINK = "{}radar/threat_monitoring/{}"

DEFAULT_IS_FETCH = False
MAX_FETCH_MIN = 1
MAX_FETCH_MAX = 1000
DEFAULT_MAX_FETCH = 20
DEFAULT_LIMIT = 50
DEFAULT_SORT_BY = "ID"
DEFAULT_USER_ACCESS_SORT_BY = "RISK_LEVEL"
DEFAULT_FILE_CONTEXT_SORT_BY = "HITS"
ASCENDING_SORT_ORDER = "ASC"
DESCENDING_SORT_ORDER = "DESC"
DEFAULT_USER_ACCESS_SORT_ORDER = DESCENDING_SORT_ORDER
DEFAULT_FILE_CONTEXT_SORT_ORDER = DESCENDING_SORT_ORDER
DEFAULT_SORT_ORDER = "ASC"
DEFAULT_CLUSTER_CONNECTED = True
DEFAULT_SNAPSHOT_GROUP_BY = "Day"
DEFAULT_MISSED_SNAPSHOT_GROUP_BY = "DAY"
DEFAULT_EVENT_SORT_BY = "LAST_UPDATED"
DEFAULT_EVENT_SORT_ORDER = "DESC"
DEFAULT_SHOW_CLUSTER_SLA_ONLY = "True"
DEFAULT_SORT_BY_SLA_DOMAIN = "NAME"
DEFAULT_CLUSTER_SORT_BY = "ClusterName"
DEFAULT_REQUEST_NAME = f"PAXSOAR-{get_pack_version() or '1.6.0'}"
DEFAULT_PRINCIPAL_SUMMARY_CATEGORY = "USERS_WITH_SENSITIVE_ACCESS"
DEFAULT_RELIABILITY = "A - Completely reliable"
SCAN_ID = "Scan ID"
SNAPSHOT_ID = "Snapshot ID"
START_TIME = "Start Time"
LAST_ACCESS_TIME = "Last Access Time"
LAST_MODIFIED_TIME = "Last Modified Time"
CLUSTER_ID = "Cluster ID"
ACTIVITY_SERIES_ID = "Activity Series ID"
FREE_SPACE = "Free Space"
SLA_DOMAIN_NAME = "SLA Domain Name"
SNAPSHOT_IDS = "Snapshot IDs"
OBJECT_TYPE = "Object Type"
FILESET_OBJECT_TYPE = "FILESET"
VOLUME_GROUP_OBJECT_TYPE = "VOLUMEGROUP"
CLUSTER_NAME = "Cluster Name"
SNAPPABLE_ID = "Snappable ID"
SLA_DOMAIN = "SLA Domain"
OBJECT_NAME = "Object Name"
OBJECT_ID = "Object ID"
FILE_NAME = "File Name"
FILE_SIZE = "File Size in Bytes"
FILE_PATH = "File Path"
SUSPICIOUS_ACTIVITY = "Suspicious Activity"
ANOMALY_ID = "Anomaly ID"
IS_ANOMALY = "Is Anomaly"
ANOMALY_PROBABILITY = "Anomaly Probability"
SEVERITY = "Severity"
ENCRYPTION = "Encryption"
ANOMALY = "Anomaly"
ANOMALY_TYPE = "Anomaly Type"
TOTAL_SUSPICIOUS_FILES = "Total Suspicious Files"
TOTAL_RANSOMEWARE_NOTE = "Total Ransomware Note"
DETECTION_TIME = "Detection Time"
SNAPSHOT_TIME = "Snapshot Time"
ANOMALY_RESOLUTION_STATUS = "Resolution Status"
RANSOMEWARE_NOTE = "Ransomware Note"
RANSOMEWARE_ENCRYPTION = "Ransomware Encryption"
ACCESS_TYPE = "Access Type"
USER_ID = "User ID"
USER_FULL_NAME = "User Full Name"
USER_PRINCIPAL_NAME = "User Principal Name"
GROUPS = "Groups"
ACCESS_RISK_REASONS = "Access Risk Reason(s)"
INSECURE_REASONS = "Insecure Reason(s)"
RISK_LEVEL = "Risk Level"
TOTAL_SENSITIVE_FILES = "Total Sensitive Files"
TOTAL_SENSITIVE_HITS = "Total Sensitive Hits"
SENSITIVE_HITS_DELTA = "Sensitive Hits Delta"
TOTAL_SENSITIVE_OBJECTS = "Total Sensitive Objects"
HIGH_RISK_HITS = "High Risk Hits"
MEDIUM_RISK_HITS = "Medium Risk Hits"
LOW_RISK_HITS = "Low Risk Hits"
POLICY_NAME = "Policy Name"
VENDOR_NAME = "Rubrik Security Cloud"
GENERAL_INFO_KEY = "generalInfo"
SENSITIVE_INFO_KEY = "sensitiveInfo"
ANOMALY_INFO_KEY = "anomalyInfo"
THREAT_HUNT_INFO_KEY = "threatHuntInfo"
THREAT_MONITORING_INFO_KEY = "threatMonitoringInfo"

DAILY_HITS_CHANGE = "Daily Hits Change"
DEFAULT_EVENT_TYPES = ["ANOMALY", "THREAT_MONITORING"]
DEFAULT_ACTIVITY_STATUSES = ["SUCCESS", "PARTIAL_SUCCESS"]
DEFAULT_SEVERITIES = ["SEVERITY_CRITICAL"]
DEFAULT_EVENT_SEVERITIES = ["SEVERITY_CRITICAL", "SEVERITY_WARNING", "SEVERITY_INFO"]
START_CURSOR = "Start Cursor"
END_CURSOR = "End Cursor"
HAS_NEXT_PAGE = "Has Next Page"
HAS_PREVIOUS_PAGE = "Has Previous Page"
DEFAULT_FIRST_FETCH = "3 days"
DEFAULT_TIME_PERIOD = "7 days"
MAX_MATCHES_PER_OBJECT = 100
MAXIMUM_FILE_SIZE = 5000000
MAXIMUM_PAGINATION_LIMIT = 1000
DEFAULT_FETCH_TYPE = ["event", "threat monitoring object"]
EVENT_FETCH_TYPE = "event"
THREAT_MONITORING_FETCH_TYPE = "threat monitoring object"
IOC_MATCHES = ["MATCHES_FOUND", "NO_MATCHES", "UNSCANNED"]
QUERANTINE_STATUS = ["QUARANTINED_MATCHES", "NO_QUARANTINED_MATCHES"]
HUNT_STATUSES = ["ABORTED", "CANCELED", "CANCELING", "FAILED", "IN_PROGRESS", "PARTIALLY_SUCCEEDED", "PENDING", "SUCCEEDED"]
MAX_INT_VALUE = 2**31 - 1
MAX_LONG_VALUE = 2**63 - 1 - 512
DEFAULT_POLLING_NEXT_RUN_IN_SECONDS = 30
DEFAULT_POLLING_TIMEOUT = 300

MESSAGES = {
    "NO_RECORDS_FOUND": "No {} were found for the given argument(s).",
    "NO_RECORD_FOUND": "No {} was found for the given argument(s).",
    "NEXT_RECORD": 'Note: To retrieve the next set of results use, "next_page_token" =',
    "NEXT_PAGE_TOKEN": (
        'Note: To retrieve the next set of results, use **next_page_token** = "{}".'
        "\nIf **next_page_token** is provided, then it will reset the record numbers. "
        "For the initial use of **next_page_token**, please avoid specifying the **page_number**."
    ),
    "NO_RESPONSE": "No response was returned for the given argument(s).",
    "IP_NOT_FOUND": 'No details found for IP: "{}".',
    "DOMAIN_NOT_FOUND": 'No details found for domain: "{}".',
    "NO_OBJECT_FOUND": "No Objects Found",
    "INVALID_FETCH_EVENT_TYPE": f"Only the following event types are supported: {', '.join(DEFAULT_EVENT_TYPES)}",
    "INVALID_FETCH_TYPE": f"Only the following fetch types are supported: {', '.join(DEFAULT_FETCH_TYPE)}",
    "INVALID_FETCH_EVENT_SEVERITIES": f"Only the following event severities are supported: {', '.join(DEFAULT_EVENT_SEVERITIES)}",
}

OUTPUT_PREFIX = {
    "GLOBAL_SEARCH": "RubrikPolaris.GlobalSearchObject",
    "PAGE_TOKEN_GLOBAL_SEARCH": "RubrikPolaris.PageToken.GlobalSearchObject",
    "VM_OBJECT": "RubrikPolaris.VSphereVm",
    "PAGE_TOKEN_VM_OBJECT": "RubrikPolaris.PageToken.VSphereVm",
    "SONAR_POLICIES_LIST": "RubrikPolaris.SonarPolicy",
    "SONAR_ANALYZER_GROUP": "RubrikPolaris.SonarAnalyzerGroup",
    "SONAR_ON_DEMAND_SCAN": "RubrikPolaris.SonarOndemandScan",
    "RADAR_ANOMALY_CSV_ANALYSIS": "RubrikPolaris.RadarAnomalyCSV",
    "SONAR_CSV_DOWNLOAD": "RubrikPolaris.SonarCSVDownload",
    "GPS_SNAPSHOT_FILES": "RubrikPolaris.GPSSnapshotFile",
    "GPS_VM_EXPORT": "RubrikPolaris.GPSVMSnapshotExport",
    "USER_DOWNLOADS": "RubrikPolaris.UserDownload",
    "GPS_SLA_DOMAIN": "RubrikPolaris.GPSSLADomain",
    "GPS_SNAPSHOT_CREATE": "RubrikPolaris.GPSOndemandSnapshot",
    "GPS_SNAPSHOT_FILE_DOWNLOAD": "RubrikPolaris.GPSSnapshotFileDownload",
    "GPS_VM_LIVEMOUNT": "RubrikPolaris.GPSVMLiveMount",
    "GPS_VM_HOSTS": "RubrikPolaris.GPSVMHost",
    "PAGE_TOKEN_VM_HOSTS": "RubrikPolaris.PageToken.GPSVMHost",
    "CDM_CLUSTER": "Rubrik.CDM",
    "PAGE_TOKEN_GPS_SNAPSHOT_FILES": "RubrikPolaris.PageToken.GPSSnapshotFile",
    "RADAR_ANALYSIS_STATUS": "Rubrik.Radar",
    "EVENT": "RubrikPolaris.Event",
    "PAGE_TOKEN_EVENT": "RubrikPolaris.PageToken.Event",
    "SONAR_SENSITIVE_HITS": "Rubrik.Sonar",
    "OBJECT": "RubrikPolaris.Object",
    "PAGE_TOKEN_OBJECT": "RubrikPolaris.PageToken.Object",
    "RADAR_IOC_SCAN": "RubrikPolaris.RadarIOCScan",
    "GPS_ASYNC_RESULT": "RubrikPolaris.GPSAsyncResult",
    "GPS_CLUSTER": "RubrikPolaris.GPSCluster",
    "GPS_VM_RECOVER_FILES": "RubrikPolaris.GPSVMRecoverFiles",
    "USER_ACCESS": "RubrikPolaris.UserAccess",
    "PAGE_TOKEN_USER_ACCESS": "RubrikPolaris.PageToken.UserAccess",
    "FILE_CONTEXT": "RubrikPolaris.FileContext",
    "PAGE_TOKEN_FILE_CONTEXT": "RubrikPolaris.PageToken.FileContext",
    "SUSPICIOUS_FILE": "RubrikPolaris.SuspiciousFile",
    "IP": "RubrikPolaris.IP",
    "DOMAIN": "RubrikPolaris.Domain",
    "ANOMALY_UPDATE_STATUS": "RubrikPolaris.AnomalyStatus",
    "THREAT_MONITORING": "RubrikPolaris.ThreatMonitoring",
    "PAGE_TOKEN_THREAT_MONITORING": "RubrikPolaris.PageToken.ThreatMonitoring",
    "PAGE_TOKEN_THREAT_MONITORING_FILE": "RubrikPolaris.PageToken.ThreatMonitoringFile",
    "THREAT_MONITORING_FILE": "RubrikPolaris.ThreatMonitoringFile",
    "IOC_SCAN": "RubrikPolaris.IOCScan",
    "PAGE_TOKEN_IOC_SCAN": "RubrikPolaris.PageToken.IOCScan",
    "TURBO_IOC_SCAN": "RubrikPolaris.TurboIOCScan",
    "ADVANCE_IOC_SCAN": "RubrikPolaris.AdvanceIOCScan",
    "ANOMALY_CSV_ANALYSIS_V2": "RubrikPolaris.AnomalyCSVv2",
}

ERROR_MESSAGES = {
    "PROXY_ERROR": "Proxy Error: if the 'Use system proxy' checkbox in the integration configuration is selected, "
    "try clearing the checkbox, or check the provided proxies.",
    "INVALID_MAX_FETCH": f"The 'Fetch Limit' is not a valid integer."
    f" The minimum value is {MAX_FETCH_MIN} and the maximum is {MAX_FETCH_MAX}.",
    "INSECURE_NOT_SUPPORTED": f"Parameter 'Trust any certificate' is not supported by "
    f"integration {INTEGRATION_NAME}, please un-check it and try again. ",
    "MISSING_REQUIRED_FIELD": "'{}' field is required. Please provide correct input.",
    "NO_CREDENTIALS_PROVIDED": "Please provide either 'Service Account JSON' or "
    "'Rubrik Account'-'Email'-'Password' for authentication.",
    "SA_JSON_DECODE_ERR": "Unable to read 'Service Account JSON', please verify it's correctness.",
    "KEY_NOT_FOUND_IN_SA_JSON": "{} was not found in 'Service Account JSON', please verify it's correctness.",
    "INVALID_LIMIT": "'{}' is an invalid value for 'limit'. Value must be between 1 and 1000.",
    "INVALID_PAGE": "'{}' is an invalid value for 'page_number'. Value must be greater than zero.",
    "JSON_DECODE": "Failed to parse '{}' JSON string, please check it's format in the argument's help-text.",
    "INVALID_BOOLEAN": "'{}' is an invalid value for '{}'. Value must be in ['true', 'false'].",
    "INVALID_SORT_ORDER": "'{}' is an invalid value for 'sort_order'. Value must be 'ASC' or 'DESC'.",
    "INVALID_SELECT": "'{}' is an invalid value for '{}'. Value must be in {}.",
    "MISSING_EXPORT_DESTINATION": "host_id or host_compute_cluster_id must be provided.",
    "LEN_SNAPSHOT_NE_LEN_OBJECT": "'snapshot_id' for each 'snappable_id' should be provided separated by colon.",
    "NO_INDICATOR_SPECIFIED": "Please provide either 'ioc_type' and 'ioc_value' or 'advance_ioc' "
    "to specify the indicator to scan for.",
    "INVALID_FORMAT": "Invalid format for '{}', please check it's format in the argument's help-text. ",
    "IP_ADDRESS_REQUIRED": "IP Address is required for fetching snapshot files download results command",
    "FALSE_POSITIVE_REASON_ERROR": "Requires the {} argument when the {} argument is specified.",
    "FALSE_POSITIVE_TYPE_ERROR": "Requires the {} argument when {} argument is set to OTHER.",
    "FETCH_PARAM_REQUIRED": "Requires the '{}' parameter when fetch incidents is selected.",
    "MISSING_TWO_REQUIRED_FIELD": "Requires both '{}' and '{}' arguments. Please provide correct input.",
    "NEGATIVE_ARG_VALUE": "'{}' is an invalid value for '{}'. Value must be greater than zero.",
    "INVALID_INT_VALUE": "'{}' is an invalid value for '{}'. Value must be less than or equal to {}.",
}

DBOT_SCORE_MAPPING = {
    "unknown": 0,  # Unknown
    "no risk": 1,  # Good
    "low": 1,  # Good
    "medium": 2,  # Suspicious
    "high": 3,  # Bad
}

TOKEN_EXPIRY_TIME_SPAN = 86400
TOKEN_EXPIRY_BUFFER_TIME = 30

IOC_TYPE_ENUM = [
    "INDICATOR_OF_COMPROMISE_TYPE_HASH",
    "INDICATOR_OF_COMPROMISE_TYPE_YARA_RULE",
    "INDICATOR_OF_COMPROMISE_TYPE_PATH_OR_FILENAME",
]

ANOMALY_TYPE_ENUM = ["FILESYSTEM", "HYPERVISOR"]
FALSE_POSITIVE_TYPE_ENUM = [
    "FP_TYPE_UNSPECIFIED",
    "OS_UPDATE",
    "APPLICATION_UPDATE",
    "LOG_ROTATION",
    "OTHER",
    "NFA_SCHEDULED_MAINTENANCE",
    "NFA_UNSCHEDULED_MAINTENANCE",
]

IOC_TYPE_MAPPING = {
    "INDICATOR_OF_COMPROMISE_TYPE_HASH": "IOC_HASH",
    "INDICATOR_OF_COMPROMISE_TYPE_YARA_RULE": "IOC_YARA",
    "INDICATOR_OF_COMPROMISE_TYPE_PATH_OR_FILENAME": "IOC_FILE_PATTERN",
}

USER_ACCESS_QUERY = """query UserAccessPrincipalListQuery(
    $filter: PrincipalSummariesFilterInput,
    $timelineDate: String!,
    $sort: ListPrincipalsSummarySortInput,
    $first: Int, $after: String,
    $includeWhitelistedResults: Boolean) {
  principalSummaries(
    filter: $filter
    timelineDate: $timelineDate
    sort: $sort
    first: $first
    after: $after
    includeWhitelistedResults: $includeWhitelistedResults
  ) {
    edges {
      cursor
      node {
        principalId
        fullName
        upn
        riskLevel
        sensitiveFiles {
          ...SensitiveFilesTableCellFragment
          __typename
        }
        totalSensitiveHits {
          ...SummaryHitsFragment
          __typename
        }
        sensitiveObjectCount {
          ...SummaryCountFragment
          __typename
        }
        numDescendants
        domainName
        __typename
      }
      __typename
    }
    pageInfo {
      startCursor
      endCursor
      hasNextPage
      hasPreviousPage
      __typename
    }
    __typename
  }
}

fragment SensitiveFilesTableCellFragment on SensitiveFiles {
  highRiskFileCount {
    ...SummaryCountFragment
    __typename
  }
  mediumRiskFileCount {
    ...SummaryCountFragment
    __typename
  }
  lowRiskFileCount {
    ...SummaryCountFragment
    __typename
  }
  __typename
}

fragment SummaryCountFragment on SummaryCount {
  totalCount
  violatedCount
  __typename
}

fragment SummaryHitsFragment on SummaryHits {
  totalHits
  violatedHits
  __typename
}"""

USER_ACCESS_DETAIL_QUERY = """query UserAccessUserDetailsQuery(
    $sid: String!,
    $timelineDate: String!,
    $includeWhitelistedResults: Boolean) {
    principalDetails(
        sid: $sid
        timelineDate: $timelineDate
        includeWhitelistedResults: $includeWhitelistedResults
    ) {
        ...UserAccessUserSummaryFragment
        __typename
    }
}

fragment UserAccessUserSummaryFragment on PrincipalDetails {
    principalSummary {
        principalId
        fullName
        upn
        riskLevel
        riskReasons {
            accessRiskReasons
            insecureReasons
            __typename
        }
        sensitiveFiles {
            ...SensitiveFilesTableCellFragment
            __typename
        }
        totalSensitiveHits {
            ...SummaryHitsFragment
            __typename
        }
        sensitiveObjectCount {
            ...SummaryCountFragment
            __typename
        }
        numDescendants
        domainName
        __typename
    }
    directGroups {
        name
        sid
        __typename
    }
    __typename
}

fragment SensitiveFilesTableCellFragment on SensitiveFiles {
  highRiskFileCount {
    ...SummaryCountFragment
    __typename
  }
  mediumRiskFileCount {
    ...SummaryCountFragment
    __typename
  }
  lowRiskFileCount {
    ...SummaryCountFragment
    __typename
  }
  __typename
}

fragment SummaryCountFragment on SummaryCount {
  totalCount
  violatedCount
  __typename
}

fragment SummaryHitsFragment on SummaryHits {
  totalHits
  violatedHits
  __typename
}"""

POLICY_HITS_SUMMARY_CHART_QEURY = """query PrincipalPolicyHitsSummaryChartQuery(
    $sids: [String!]!,
    $day: String!,
    $historicalDeltaDays: Int!,
    $includeWhitelistedResults: Boolean) {
  sidsPolicyHitsSummary(
    sids: $sids
    day: $day
    historicalDeltaDays: $historicalDeltaDays
    includeWhitelistedResults: $includeWhitelistedResults
  ) {
    sidSummaries {
      principal
      summary {
        policyId
        policyName
        sidSensitiveFiles {
          totalFileCount {
            totalCount
            violatedCount
            __typename
          }
          __typename
        }
        sidAnalyzerHits {
          ...PrincipalSensitiveHitsFragment
          __typename
        }
        sidDeltaAnalyzerHits {
          ...PrincipalSensitiveHitsFragment
          __typename
        }
        sidRiskHits {
          ...PrincipalSensitiveHitsFragment
          __typename
        }
        sidDeltaRiskHits {
          ...PrincipalSensitiveHitsFragment
          __typename
        }
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment PrincipalSensitiveHitsFragment on SensitiveHits {
  highRiskHits {
    ...SummaryHitsFragment
    __typename
  }
  mediumRiskHits {
    ...SummaryHitsFragment
    __typename
  }
  lowRiskHits {
    ...SummaryHitsFragment
    __typename
  }
  totalHits {
    ...SummaryHitsFragment
    __typename
  }
  __typename
}

fragment SummaryHitsFragment on SummaryHits {
  totalHits
  violatedHits
  __typename
}"""

FILE_CONTEXT_QUERY = """query CrawlsFileListQuery(
    $snappableFid: String!,
    $snapshotFid: String!,
    $first: Int!,
    $after: String,
    $filters: ListFileResultFiltersInput,
    $sort: FileResultSortInput,
    $timezone: String!) {
  policyObj(snappableFid: $snappableFid, snapshotFid: $snapshotFid) {
    id: snapshotFid
    fileResultConnection(first: $first, after: $after, filter: $filters, sort: $sort, timezone: $timezone) {
      edges {
        cursor
        node {
          ...DiscoveryFileFragment
          __typename
        }
        __typename
      }
      pageInfo {
        endCursor
        hasNextPage
        __typename
      }
      __typename
    }
    __typename
  }
}

fragment DiscoveryFileFragment on FileResult {
  nativePath
  stdPath
  filename
  mode
  size
  lastAccessTime
  lastModifiedTime
  directory
  numDescendantFiles
  numDescendantErrorFiles
  numDescendantSkippedExtFiles
  numDescendantSkippedSizeFiles
  errorCode
  hits {
    totalHits
    violations
    violationsDelta
    totalHitsDelta
    __typename
  }
  filesWithHits {
    totalHits
    violations
    __typename
  }
  openAccessFilesWithHits {
    totalHits
    violations
    __typename
  }
  staleFilesWithHits {
    totalHits
    violations
    __typename
  }
  analyzerGroupResults {
    ...AnalyzerGroupResultFragment
    __typename
  }
  sensitiveFiles {
    highRiskFileCount {
      totalCount
      violatedCount
      __typename
    }
    mediumRiskFileCount {
      totalCount
      violatedCount
      __typename
    }
    lowRiskFileCount {
      totalCount
      violatedCount
      __typename
    }
    __typename
  }
  openAccessType
  stalenessType
  numActivities
  numActivitiesDelta
  __typename
}

fragment AnalyzerGroupResultFragment on AnalyzerGroupResult {
  analyzerGroup {
    groupType
    id
    name
    __typename
  }
  analyzerResults {
    hits {
      totalHits
      violations
      __typename
    }
    analyzer {
      id
      name
      analyzerType
      __typename
    }
    __typename
  }
  hits {
    totalHits
    violations
    violationsDelta
    totalHitsDelta
    __typename
  }
  __typename
}"""

SNAPPABLE_INVESTIGATIONS_QUERY = """query SnappableInvestigationsQuery($id: UUID!) {
  snapshot(snapshotFid: $id) {
    date
    cluster {
      id
      defaultAddress
      systemStatusAffectedNodes {
        ipAddress
      }
      name
      version
      status
      __typename
    }
    snappableNew {
      objectType
    }
    cdmId
    isQuarantined
    __typename
  }
}"""

ANOMALY_RESULT_QUERY = """query AnomalyResultQuery(
    $clusterUuid: UUID!, $snapshotId: String!) {
  anomalyResultOpt(clusterUuid: $clusterUuid, snapshotId: $snapshotId) {
    id
    snapshotFid
    managedId
    anomalyProbability
    workloadId
    location
    isAnomaly
    objectType
    severity
    detectionTime
    snapshotDate
    encryption
    resolutionStatus
    anomalyType
    anomalyInfo {
      strainAnalysisInfo {
        strainId
        totalAffectedFiles
        totalRansomwareNotes
        sampleAffectedFilesInfo {
          filePath
          lastModified
          fileSizeBytes
          __typename
        }
        sampleRansomwareNoteFilesInfo {
          filePath
          lastModified
          fileSizeBytes
          __typename
        }
        __typename
      }
      __typename
    }
    __typename
  }
}
"""

FILESET_DOWNLOAD_SNAPSHOT_FILES_MUTATION = """mutation PhysicalHostDownloadSnapshotFilesMutation(
    $config: FilesetDownloadFilesJobConfigInput!,
    $id: String!, $deltaTypeFilter: [DeltaType!],
    $nextSnapshotFid: UUID,
    $userNote: String) {
  filesetDownloadSnapshotFiles(
    input: {config: $config, id: $id, deltaTypeFilter: $deltaTypeFilter, nextSnapshotFid: $nextSnapshotFid, userNote: $userNote}
  ) {
    id
    status
    links {
      href
      rel
      __typename
    }
    __typename
  }
}"""

VOLUME_GROUP_DOWNLOAD_SNAPSHOT_FILES_MUTATION = """mutation RadarInvestigationVGDownloadFilesMutation(
    $input: DownloadVolumeGroupSnapshotFilesInput!) {
  downloadVolumeGroupSnapshotFiles(input: $input) {
    id
    status
    links {
      href
      rel
      __typename
    }
    __typename
  }
}
"""

ANOMALY_UPDATE_STATUS_MUTATION = """mutation AnomalyUpdateStatusMutation($input: ResolveAnomalyInput!) {
  resolveAnomaly(input: $input)
}"""

THREAT_MONITORING_MATCHED_OBJECT_LIST_QUERY = """query ThreatMonitoringMatchedObjectsQuery(
  $first: Int
  $after: String
  $last: Int
  $before: String
  $beginTime: DateTime
  $endTime: DateTime
  $clusterUuidFilter: [String!]
  $objectTypeFilter: [String!]
  $workloadNameSearch: String
  $matchTypeFilter: [IndicatorOfCompromiseKind!]
) {
  threatMonitoringMatchedObjects(
    first: $first
    after: $after
    last: $last
    before: $before
    beginTime: $beginTime
    endTime: $endTime
    clusterUuidFilter: $clusterUuidFilter
    objectTypeFilter: $objectTypeFilter
    workloadNameSearch: $workloadNameSearch
    matchTypeFilter: $matchTypeFilter
  ) {
    edges {
      cursor
      node {
        objectFid
        objectName
        objectType
        matchType
        filesMatched
        lastDetection
        cluster {
          id
          name
          __typename
        }
        __typename
      }
      __typename
    }
    stats {
      objectsWithMatches
      objectsWithNoMatches
      totalObjectsScanned
      __typename
    }
    pageInfo {
      startCursor
      endCursor
      hasNextPage
      hasPreviousPage
      __typename
    }
    __typename
  }
}
"""

THREAT_MONITORING_MATCHED_OBJECT_GET_QUERY = """query ThreatMonitoringObjectTypeQuery($fid: UUID!) {
  hierarchyObject(fid: $fid) {
    id
    name
    objectType
    slaAssignment
    slaPauseStatus
    effectiveSlaDomain {
      id
      name
      version
      __typename
    }
    snapshotDistribution {
      id
      totalCount
      scheduledCount
      onDemandCount
      retrievedCount
      __typename
    }
    effectiveRetentionSlaDomain {
      id
      name
      version
      __typename
    }
    configuredSlaDomain {
      id
      name
      version
      __typename
    }
    effectiveSlaSourceObject {
      fid
      name
      objectType
      __typename
    }
    logicalPath {
      fid
      name
      objectType
      __typename
    }
    physicalPath {
      fid
      name
      objectType
      __typename
    }
    numWorkloadDescendants
    allOrgs {
      id
      name
      description
      mfaStatus
      allUrls
      __typename
    }
    securityMetadata {
      lowSensitiveHits
      mediumSensitiveHits
      highSensitiveHits
      sensitivityStatus
      isLaminarEnabled
      dataTypeResults {
        id
        name
        totalHits
        totalViolatedHits
        __typename
      }
      __typename
    }
    __typename
  }
}
"""

DEPLOYMENT_VERSION_QUERY = """query DeploymentVersionQuery {
  deploymentVersion
}"""

THREAT_MONITORING_MATCHED_FILE_LIST_QUERY = """query ThreatMonitoringMatchedFiles(
  $first: Int
  $after: String
  $objectFid: UUID!
  $filenameSearchFilter: String
) {
  threatMonitoringMatchedFiles(
    first: $first
    after: $after
    objectFid: $objectFid
    filenameSearchFilter: $filenameSearchFilter
  ) {
    edges {
      cursor
      node {
        filepath
        detectedTime
        fileName
        fileSize
        matchedSnapshotDate
        matchedSnapshotFid
        isMatchedSnapshotExpired
        isFirstObservedSnapshotExpired
        matchType
        isQuarantinedInFirstObservedSnapshot
        objectFid
        firstObservedSnapshotFid
        firstObservedSnapshotDate
        objectType
        objectName
        matchId
        __typename
      }
      __typename
    }
    count
    pageInfo {
      startCursor
      endCursor
      hasNextPage
      hasPreviousPage
      __typename
    }
    __typename
  }
}
"""

THREAT_MONITORING_MATCHED_FILE_DETAILS_QUERY = """query ThreatMonitoringMatchedFileDetailsV2Query(
  $matchedSnapshotFid: UUID!,
  $filepath: String!
) {
  threatMonitoringMatchedFileDetailsV2(
    matchedSnapshotFid: $matchedSnapshotFid
    filepath: $filepath
  ) {
    matchedFileMd5
    matchedFileSha1
    matchedFileSha256
    iocDetails {
      matchType
      intelFeedName
      malwareName
      iocRuleAuthor
      malwareDescription
      iocHashHex
      iocStatus
      __typename
    }
    isQuarantinedInFirstObservedSnapshot
    detectedSnapshotDate
    firstDetectedSnapshotFid
    filePath
    fileName
    __typename
  }
}
"""

List_Threat_Hunts_Query = """
query ListThreatHuntsQuery(
  $clusterUuidFilter: [String!],
  $statusFilter: [ThreatHuntStatus!],
  $matchesFoundFilter: [ThreatHuntMatchesFound!],
  $quarantinedMatchesFilter: [ThreatHuntQuarantinedMatchType!],
  $beginTime: DateTime,
  $endTime: DateTime,
  $first: Int,
  $after: String
) {
  threatHunts(
    clusterUuidFilter: $clusterUuidFilter
    statusFilter: $statusFilter
    matchesFoundFilter: $matchesFoundFilter
    quarantinedMatchesFilter: $quarantinedMatchesFilter
    beginTime: $beginTime
    endTime: $endTime
    first: $first
    after: $after
  ) {
    edges {
      node {
        huntId
        name
        createdBy {
          id
          username
          email
          __typename
        }
        huntType
        startTime
        status
        stats {
          ...ThreatHuntStatsFragment
          __typename
        }
        huntDetails {
          startTime
          endTime
          cluster {
            id
            name
            __typename
          }
          config {
            name
            indicatorsOfCompromise {
              iocValue
              iocKind
              __typename
            }
            __typename
          }
          __typename
        }
        __typename
      }
      __typename
    }
    count
    pageInfo{
      endCursor
      hasNextPage
      hasPreviousPage
      startCursor
      __typename
    }
    __typename
  }
}

fragment ThreatHuntStatsFragment on ThreatHuntStats {
  totalProcessedSnapshots
  totalAffectedObjects
  totalAffectedSnapshots
  totalUniqueMatchedPaths
  totalSucceededScans
  totalSnapshotsScanned
  totalUniqueQuarantinedPaths
  totalObjectsScanned
  totalIocs
  __typename
}
"""

THREAT_HUNT_DETAILS_V2_QUERY = """query ThreatHuntDetailsV2Query($huntId: String!) {
  threatHuntObjectMetrics(huntId: $huntId) {
    totalObjectsScanned
    totalAffectedObjects
    totalUnaffectedObjects
    totalObjectsUnscannable
    unaffectedObjectsFromDb
    cleanRecoverableObjectLimit
    __typename
  }
  threatHuntDetailV2(huntId: $huntId) {
    totalObjectFids
    startTime
    endTime
    status
    totalMatchedSnapshots
    totalScannedSnapshots
    totalUniqueFileMatches
    clusters{
      id
      name
      type
      __typename
    }
    baseConfig {
      name
      notes
      maxMatchesPerSnapshot
      threatHuntType
      ioc {
        iocList {
          indicatorsOfCompromise {
            iocKind
            iocValue
            __typename
          }
          __typename
        }
        __typename
      }
      snapshotScanLimit {
        scanLimit {
          scanConfig {
            maxSnapshotsPerObject
            startTime
            endTime
            __typename
          }
          objectSnapshotConfig {
            objectFid
            snapshotFid
            __typename
          }
          __typename
        }
        __typename
      }
      fileScanCriteria {
        fileSizeLimits {
          maximumSizeInBytes
          minimumSizeInBytes
          __typename
        }
        fileTimeLimits {
          earliestCreationTime
          earliestModificationTime
          latestCreationTime
          latestModificationTime
          __typename
        }
        pathFilter {
          inclusions
          exclusions
          exemptions
          __typename
        }
        __typename
      }
      __typename
    }
    __typename
  }
}
"""

START_TURBO_THREAT_HUNT_MUTATION = """
mutation StartTurboThreatHunt($input: StartTurboThreatHuntInput!){
  startTurboThreatHunt(input: $input){
    huntId
    __typename
  }
}
"""

START_ADVANCE_THREAT_HUNT_MUTATION = """mutation StartAdvanceThreatHuntMutation($input: StartThreatHuntV2Input!) {
    startBulkThreatHunt(input: $input) {
        hunts {
            huntId
            huntName
            config {
                huntType
                clusterUuids
                objectFids
                __typename
            }
            status
            __typename
        }
        __typename
    }
}
"""

DOWNLOAD_ANOMALY_DETAILS_CSV_MUTATION = """
mutation DownloadAnomalyDetailsCsvMutation($input: DownloadAnomalyDetailsCsvInput!) {
    downloadAnomalyDetailsCsv(input: $input) {
        isSuccessful
        __typename
    }
}
"""

ALL_USER_DOWNLOADS_FILES_QUERY = """
query DownloadBarQuery {
  allUserFiles {
    downloads {
      externalId
      createdAt
      expiresAt
      completedAt
      creator
      filename
      type
      state
      __typename
    }
    __typename
  }
}
"""


class MyClient(PolarisClient):
    """Client class."""

    def auth(self):
        """Set access token for authorization."""
        self._access_token = self.get_api_token()
        if not self._access_token:
            self._access_token = self.authenticate()
            self.set_integration_context(self._access_token)

    @staticmethod
    def set_integration_context(access_token):
        """
        Set API token and expiry time in integration configuration context.

        Will raise value error if api-token is not found.
        """
        integration_context = {}
        api_token = jwt.decode(access_token, options={"verify_signature": False})
        integration_context["api_token"] = access_token
        integration_context["valid_until"] = (
            api_token.get("exp", int(time.time()) + TOKEN_EXPIRY_TIME_SPAN) - TOKEN_EXPIRY_BUFFER_TIME
        )
        set_integration_context(integration_context)

    @staticmethod
    def get_api_token() -> Any:
        """
        Retrieve API token from integration context.

        If API token is not found or expired it will return false
        """
        integration_context = get_integration_context()
        api_token = integration_context.get("api_token")
        valid_until = integration_context.get("valid_until")

        # Return API token from integration context, if found and not expired
        if api_token and valid_until and time.time() < valid_until:
            demisto.debug("[RubrikPolaris] Retrieved api-token from integration cache.")
            return api_token
        return False


""" HELPER FUNCTIONS """


def validate_required_arg(param_name, param_value):
    """
    Validate the required param is provided or not.

    Args:
        param_name: Name of the parameter to be validated
        param_value: Value of the required parameter

    Raises:
        ValueError if not provided
    Returns:
          Value of parameter
    """
    if not param_value:
        raise ValueError(ERROR_MESSAGES["MISSING_REQUIRED_FIELD"].format(param_name))
    else:
        return param_value


def convert_to_demisto_severity(severity: str = "XSOAR LOW") -> int:
    """
    Map the severity from the Rubrik Radar event to the user specified XSOAR severity level.

    :type severity: ``str``
    :param severity: XSOAR severity to map to

    :return: mapped incident severity level
    """
    demisto.info("SEVERITY TO CONVERT IS: " + severity)
    try:
        return {
            "XSOAR LOW": IncidentSeverity.LOW,
            "XSOAR MEDIUM": IncidentSeverity.MEDIUM,
            "XSOAR HIGH": IncidentSeverity.HIGH,
            "XSOAR CRITICAL": IncidentSeverity.CRITICAL,
        }[severity]
    except KeyError:
        raise ValueError(ERROR_MESSAGES["FETCH_PARAM_REQUIRED"].format("Event Critical Severity Level Mapping"))


def process_activity_nodes(activity_nodes: list, processed_incident):
    """
    Update processed incident data.

    :param activity_nodes: List of activity connection nodes
    :type activity_nodes: list

    :param processed_incident: the processed incident with event details
    :type processed_incident: dict

    :return: updated processed incident
    """
    for activity_node in activity_nodes:
        # Convert time to friendly display format
        display_time = datetime.strptime(activity_node.get("time", ""), DATE_TIME_FORMAT)
        stringified_display_time = display_time.strftime(HUMAN_READABLE_DATE_TIME_FORMAT)

        processed_incident["message"].append(  # type: ignore
            {
                "message": activity_node.get("message", ""),
                "id": activity_node.get("id", ""),
                "severity": activity_node.get("severity", ""),
                "time": stringified_display_time,
            }
        )

        file_changes_match = re.search(
            r"File Change: ([0-9]+) Added, ([0-9]+) Modified, ([0-9]+) Removed", activity_node.get("message", "")
        )
        if file_changes_match is not None:
            try:
                processed_incident["radar_files_added"] = file_changes_match.group(1)
                processed_incident["radar_files_modified"] = file_changes_match.group(2)
                processed_incident["radar_files_deleted"] = file_changes_match.group(3)

            except KeyError:
                demisto.info("Error Parsing Radar Anomaly File Change attributes")

    return processed_incident


def calc_pages(total_count: int, per_page_count: int) -> int:
    """
    Calculates the number of pages required to display all the items,
    considering the number of items to be displayed per page

    Args:
        total_count (int): The total number of items.
        per_page_count (int): The count of items per page.

    Returns:
        int: The total number of pages.
    """
    return math.ceil(total_count / per_page_count)


def prepare_context_hr_object_search(response: dict):
    """
    Prepare context output and human readable response for rubrik-polaris-object-search command.

    :type response: ``dict``
    :param response: edges from the response received from the API

    :return: context output and human readable for the command
    """
    hr = []
    context = []
    for node in response:
        cluster_name = sla_domain_name = ""
        node = node.get("node", {})
        context.append(remove_empty_elements(node))

        if node.get("cluster"):
            cluster_name = node.get("cluster", {}).get("name", "")
        if node.get("effectiveSlaDomain"):
            sla_domain_name = node.get("effectiveSlaDomain", {}).get("name", "")

        hr.append(
            {
                OBJECT_ID: node.get("id", ""),
                OBJECT_NAME: node.get("name", ""),
                "Cluster": cluster_name,
                "Type": node.get("objectType", ""),
                SLA_DOMAIN: sla_domain_name,
            }
        )
    return context, hr


def prepare_context_hr_sonar_policies(nodes: list):
    """
    Prepare context output and human readable response for rubrik-sonar-policies-list command.

    :type nodes: ``dict``
    :param nodes: nodes from the response received from the API

    :return: context output and human readable for the command
    """
    hr_content = []
    nodes = remove_empty_elements(nodes)
    for node in nodes:
        hr_content.append(
            {
                "ID": node.get("id", ""),
                "Name": node.get("name", ""),
                "Description": node.get("description", ""),
                "Analyzers": node.get("numAnalyzers"),
                "Objects": node.get("totalObjects"),
                "Creator Email": node.get("creator", {}).get("email", ""),
            }
        )
    hr_headers = ["ID", "Name", "Description", "Analyzers", "Objects", "Creator Email"]
    hr = tableToMarkdown("Sonar Policies", hr_content, hr_headers, removeNull=True)
    return nodes, hr


def prepare_context_hr_sonar_policy_analyzer_groups(nodes: list):
    """
    Prepare context output and human readable response for rubrik-sonar-policy-analyzer-groups-list command.

    :type nodes: ``dict``
    :param nodes: nodes from the response received from the API

    :return: context output and human readable for the command
    """
    hr_content = []
    nodes = remove_empty_elements(nodes)

    def stringify_analyzer(analyzer_id, analyzer_name, analyzer_type):
        """Convert analyzer response into human readable string."""
        return f"id: {analyzer_id}, Name: {analyzer_name}, Analyzer Type: {analyzer_type}"

    for node in nodes:
        analyzers = node.get("analyzers", [])

        analyzers_str_rep = "\n\n".join(
            [
                stringify_analyzer(analyzer.get("id", "n/a"), analyzer.get("name", "n/a"), analyzer.get("analyzerType", "n/a"))
                for analyzer in analyzers
            ]
        )
        hr_content.append(
            {
                "ID": node.get("id", ""),
                "Name": node.get("name", ""),
                "Group Type": node.get("groupType", ""),
                "Analyzers": analyzers_str_rep,
            }
        )
    hr_headers = ["ID", "Name", "Group Type", "Analyzers"]
    hr = tableToMarkdown("Sonar Policy Analyzer Groups", hr_content, hr_headers, removeNull=True)
    return nodes, hr


def prepare_context_hr_vm_object_metadata(response: dict):
    """
    Prepare context and hr for rubrik-polaris-vm-object-metadata-get.

    :type response: ``dict``
    :param response: Response received from API

    :return: context output and human readable for the command
    """
    hr = []
    response = remove_empty_elements(response)
    object_id = response.get("id")
    context = {"id": object_id, "metadata": response}
    del context["metadata"]["id"]

    hr.append(
        {
            OBJECT_ID: object_id,
            "Name": response.get("name", ""),
            SNAPPABLE_ID: response.get("reportSnappable", {}).get("id"),
            SLA_DOMAIN: response.get("effectiveSlaDomain", {}).get("name", ""),
            CLUSTER_NAME: response.get("cluster", {}).get("name", ""),
            "Total Snapshots": response.get("totalSnapshots", {}).get("count", ""),
            "Oldest Snapshot Date": response.get("oldestSnapshot", {}).get("date", ""),
            "Latest Snapshot Date": response.get("newestSnapshot", {}).get("date", ""),
        }
    )

    return context, hr


def prepare_context_hr_vm_object_list(response: dict):
    """
    Prepare context output and human readable response for rubrik-polaris-vm-object-list command.

    :type response: ``dict``
    :param response: edges from the response received from the API

    :return: context output and human readable for the command
    """
    hr = []
    context = []
    for edge in response:
        node = edge.get("node")
        hr.append(
            {
                OBJECT_ID: node.get("id", ""),
                "Name": node.get("name", ""),
                SNAPPABLE_ID: node.get("reportSnappable", {}).get("id") if node.get("reportSnappable") else None,
                "Cluster": node.get("cluster", {}).get("name", "") if node.get("cluster") else None,
                OBJECT_TYPE: node.get("objectType", ""),
                SLA_DOMAIN: node.get("effectiveSlaDomain", {}).get("name", "") if node.get("effectiveSlaDomain") else None,
                "Assignment": node.get("slaAssignment", ""),
                "Snapshots": node.get("snapshotDistribution", {}).get("totalCount", "")
                if node.get("snapshotDistribution")
                else None,
                "RBS Status": node.get("agentStatus", {}).get("agentStatus", "") if node.get("agentStatus") else None,
                "Source Storage": convert_bytes(
                    node.get("reportSnappable", {}).get("archiveStorage", "")
                    if node.get("reportSnappable")  # type: ignore[arg-type]
                    else None
                ),
                "Archival Storage": convert_bytes(
                    node.get("reportSnappable", {}).get("physicalBytes", "")
                    if node.get("reportSnappable")  # type: ignore[arg-type]
                    else None
                ),
            }
        )
        context.append(remove_empty_elements(node))
    return context, hr


def convert_bytes(bytes_val: int):
    """
    Convert bytes to mega/giga/tera bytes.

    :type bytes_val: ``int``
    :param bytes_val: Bytes to convert

    :return: Converted value
    """
    if bytes_val is None:
        return None
    elif bytes_val == 0:
        return 0
    elif bytes_val > 0:

        def count_digit(val):
            count = 0
            while val != 0:
                val //= 10
                count += 1
            return count

        if count_digit(bytes_val) >= 12:
            return f"{bytes_val / (10**12)} TB"
        elif count_digit(bytes_val) >= 9:
            return f"{bytes_val / (10**9)} GB"
        elif count_digit(bytes_val) >= 6:
            return f"{bytes_val / (10**6)} MB"
        elif count_digit(bytes_val) >= 3:
            return f"{bytes_val / (10**3)} KB"
        else:
            return f"{bytes_val} B"
    return None


def prepare_context_hr_sonar_ondemand_scan_status(nodes: list, crawl_id: str):
    """
    Prepare context output and human readable response for rubrik-sonar-ondemand-scan-status command.

    :type nodes: ``dict``
    :param nodes: nodes from the response received from the API

    :type crawl_id: ``str``
    :param crawl_id: crawl_id received in response

    :return: context output and human readable for the command
    """
    hr_content = []
    nodes = remove_empty_elements(nodes)
    context = {"crawlId": crawl_id, "Status": nodes}
    final_status = None
    for object_scan in context["Status"]:
        object_scan_status = object_scan.get("status")
        hr_content.append(
            {
                OBJECT_ID: object_scan.get("snappable", {}).get("id", ""),
                OBJECT_NAME: object_scan.get("snappable", {}).get("name", ""),
                "Scan Status": object_scan_status,
            }
        )
        if not final_status and object_scan_status == "IN_PROGRESS":
            final_status = "IN_PROGRESS"
        if object_scan_status == "FAIL":
            final_status = "FAIL"
    if not final_status:
        final_status = "COMPLETE"

    hr_header = f"### Sonar On-Demand Scan Status\nFinal status of scan with crawl ID {crawl_id} is {final_status}\n\n"
    hr_table = tableToMarkdown("", hr_content, [OBJECT_ID, OBJECT_NAME, "Scan Status"], removeNull=True)
    return context, hr_header + hr_table


def prepare_context_hr_vm_object_snapshot(response: dict):
    """
    Prepare context and hr for rubrik-polaris-vm-object-snapshot-list.

    :type response: ``dict``
    :param response: Response received from API

    :return: context output and human readable for the command
    """
    hr = []
    if response.get("missedSnapshotGroupByConnection"):
        del response["missedSnapshotGroupByConnection"]
    response = remove_empty_elements(response)
    object_id = response.get("id")
    context = {"id": object_id, "Snapshot": response}
    del context["Snapshot"]["id"]

    if response.get("snapshotGroupByConnection", {}).get("nodes"):
        nodes = response.get("snapshotGroupByConnection", {}).get("nodes")
        for node in nodes:
            sub_nodes = node.get("snapshotConnection", {}).get("nodes") if node.get("snapshotConnection") else None
            hr_data = {
                "Snapshot Details": f"Total Snapshots: {node.get('snapshotConnection').get('count')}"
                f"\nDate Range: From {node.get('groupByInfo').get('start')} to"
                f" {node.get('groupByInfo').get('end')}",
                SNAPSHOT_IDS: [],
            }
            ids = []
            for sub_node in sub_nodes:  # type: ignore[union-attr]
                ids.append(sub_node.get("id"))
            hr_data[SNAPSHOT_IDS] = ids
            hr.append(hr_data)

    return context, hr


def prepare_context_hr_gps_snapshot_files(edges: list, snapshot_id: str):
    """
    Prepare context output and human readable response for rubrik_gps_snapshot_files_list_command.

    :type edges: ``dict``
    :param edges: Response received from API

    :type snapshot_id: ``str``
    :param snapshot_id: snapshot_id passed as input

    :return: context output and human readable for the command
    """
    context = []
    hr_content = []

    edges = remove_empty_elements(edges)

    for edge in edges:
        node = edge.get("node")
        hr_content.append(
            {
                "File Name": node.get("filename", ""),
                "Absolute Path": node.get("absolutePath", ""),
                "Path": node.get("path", ""),
                "File Mode": node.get("fileMode", ""),
                "Last Modified": node.get("lastModified", ""),
            }
        )
        context.append(node)

    context_data = {"snapshotId": snapshot_id.lower(), "node": context}

    hr = tableToMarkdown(
        "GPS Snapshot Files", hr_content, ["File Name", "Absolute Path", "Path", "File Mode", "Last Modified"], removeNull=True
    )
    return context_data, hr


def validate_boolean_argument(arg_value: Union[str, bool], arg_name: str):
    """
    To validate boolean argument for all commands.

    :param arg_value: the value to evaluate
    :type arg_value: ``string|bool``

    :param arg_name: Argument name
    :type arg_name: ``string``

    :return: a boolean representatation of 'arg_value'
    """
    try:
        result = argToBoolean(arg_value)
    except ValueError:
        raise ValueError(ERROR_MESSAGES["INVALID_BOOLEAN"].format(arg_value, arg_name))

    return result


def validate_vm_export_args(args: Dict[str, Any]):
    """
    To validate arguments of rubrik-gps-vm-export.

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: Validated arguments for rubrik-gps-vm-export
    """
    vm_name = args.get("vm_name")
    object_id = validate_required_arg("object_id", args.get("object_id", ""))
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id", ""))
    datastore_id = validate_required_arg("datastore_id", args.get("datastore_id", ""))
    host_id = args.get("host_id", None)
    host_compute_cluster_id = args.get("host_compute_cluster_id", None)

    if not host_id and not host_compute_cluster_id:
        raise ValueError(ERROR_MESSAGES["MISSING_EXPORT_DESTINATION"])
    power_on = args.get("power_on")
    if power_on:
        power_on = validate_boolean_argument(power_on, "power_on")

    keep_mac_addresses = args.get("keep_mac_addresses")
    if keep_mac_addresses:
        keep_mac_addresses = validate_boolean_argument(keep_mac_addresses, "keep_mac_addresses")

    remove_network_devices = args.get("remove_network_devices")
    if remove_network_devices:
        remove_network_devices = validate_boolean_argument(remove_network_devices, "remove_network_devices")

    recover_tags = args.get("recover_tags")
    if recover_tags:
        recover_tags = validate_boolean_argument(recover_tags, "recover_tags")

    disable_network = args.get("disable_network")
    if disable_network:
        disable_network = validate_boolean_argument(disable_network, "disable_network")

    config = {
        "datastoreId": datastore_id,
        "hostId": host_id,
        "clusterId": host_compute_cluster_id,
        "shouldRecoverTags": recover_tags,
        "mountExportSnapshotJobCommonOptionsV2": {
            "keepMacAddresses": keep_mac_addresses,
            "removeNetworkDevices": remove_network_devices,
            "vmName": vm_name,
            "powerOn": power_on,
            "disableNetwork": disable_network,
        },
        "requiredRecoveryParameters": {"snapshotId": snapshot_id},
    }

    return remove_empty_elements(config), object_id


def validate_user_access_list_command_args(limit: int, sort_order: str, page_number: Optional[int] = 1):
    """
    To validate arguments of rubrik-sonar-user-access-list.

    :type limit: ``int``
    :param limit: Number of records to return.

    :type sort_order: ``str``
    :param sort_order: Sort order argument.

    :type page_number: ``Optional[int]``
    :param page_number: Page number argument.
    """
    # Validate limit argument.
    if not limit or not 0 <= limit <= MAXIMUM_PAGINATION_LIMIT:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))

    # Validate sort_order argument.
    if sort_order not in (ASCENDING_SORT_ORDER, DESCENDING_SORT_ORDER):
        raise ValueError(ERROR_MESSAGES["INVALID_SORT_ORDER"].format(sort_order))

    # Validate page number if supplied.
    if isinstance(page_number, int) and page_number < 1:
        raise ValueError(ERROR_MESSAGES["INVALID_PAGE"].format(page_number))


def prepare_context_hr_user_downloads(nodes: list):
    """
    Prepare context output and human readable response for rubrik-user-downloads-get command.

    :type nodes: ``dict``
    :param nodes: nodes from the response received from the API

    :return: context output and human readable for the command
    """
    hr_content = []
    nodes = remove_empty_elements(nodes)
    for node in nodes:
        hr_content.append(
            {
                "Download ID": node.get("id", ""),
                "Name": node.get("name", ""),
                "Status": node.get("status", ""),
                "Identifier": node.get("identifier", ""),
                "Creation Time": node.get("createTime", ""),
                "Completion Time": node.get("completeTime", ""),
            }
        )
    return nodes, hr_content


def prepare_context_hr_sla_domains_list(nodes):
    """
    Prepare context output and human readable response for rubrik-sonar-policies-list command.

    :type nodes: ``dict``
    :param nodes: nodes from the response received from the API

    :return: context output and human readable for the command
    """
    nodes = remove_empty_elements(nodes)
    hr_content = []
    context = []
    for node in nodes:
        context.append(node)
        base_frequency = node.get("baseFrequency", {})
        replication_specs = node.get("replicationSpecsV2", [])
        replication_target_1 = ""
        replication_target_2 = ""
        if replication_specs and isinstance(replication_specs, list):
            replication_target_1 = replication_specs[0].get("cluster", {}).get("name", "")
            if len(replication_specs) > 1:
                replication_target_2 = replication_specs[1].get("cluster", {}).get("name", "")

        hr_content.append(
            {
                "SLA Domain ID": node.get("id", ""),
                SLA_DOMAIN_NAME: node.get("name", ""),
                "Base Frequency": f"{base_frequency.get('duration')} {base_frequency.get('unit', '').capitalize()}",
                "Protected Object Count": node.get("protectedObjectCount"),
                "Archival Location": node.get("archivalSpec", {}).get("archivalLocationName"),
                "Description": node.get("description", ""),
                "Replication Target 1": replication_target_1,
                "Replication Target 2": replication_target_2,
            }
        )
    hr = tableToMarkdown(
        "GPS SLA Domains",
        hr_content,
        headers=[
            "SLA Domain ID",
            SLA_DOMAIN_NAME,
            "Base Frequency",
            "Protected Object Count",
            "Archival Location",
            "Description",
            "Replication Target 1",
            "Replication Target 2",
        ],
        removeNull=True,
    )
    return context, hr


def prepare_context_hr_gps_snapshot_download(response: dict):
    """
    Prepare context and hr for rubrik-polaris-gps-snapshot-files-download.

    :type response: ``dict``
    :param response: Response received from API

    :return: context output and human readable for the command
    """
    response = remove_empty_elements(response)
    id_ = response.get("id")
    status = response.get("status")
    href = response.get("links")[0].get("href")
    rel = response.get("links")[0].get("rel")

    context = {"id": id_, "status": status, "links": {"href": href, "rel": rel}}

    hr = {"ID": id_, "Status": status}
    return context, hr


def prepare_context_hr_vm_host_list(edges):
    """
    Prepare context output and human readable response for rubrik-gps-vm-host-list command.

    :type edges: ``dict``
    :param edges: edges from the response received from the API

    :return: context output and human readable for the command
    """
    edges = remove_empty_elements(edges)
    hr_content = []
    context = []
    for edge in edges:
        node = edge.get("node")
        physical_host = []
        context.append(node)
        for path in node.get("physicalPath"):
            physical_host.append({"id": path.get("fid"), "name": path.get("name"), "objectType": path.get("objectType")})
        hr_content.append({"VSphere Host ID": node.get("id"), "Name": node.get("name"), "Physical Host": physical_host})
    return context, hr_content


def prepare_context_hr_vm_datastore_list(edges, host_id):
    """
    Prepare context output and human readable response for rubrik-gps-vm-datastore-list command.

    :type edges: ``dict``
    :param edges: edges from the response received from the API

    :type host_id: ``str``
    :param host_id: Host ID that was queried for.

    :return: context output and human readable for the command
    """
    edges = remove_empty_elements(edges)
    hr_content = []
    context = {"id": host_id, "Datastore": []}
    for edge in edges:
        node = edge.get("node")
        context["Datastore"].append(node)
        hr_content.append(
            {
                "VSphere Datastore ID": node.get("id", ""),
                "Name": node.get("name", ""),
                "Capacity": convert_bytes(node.get("capacity", "")),
                FREE_SPACE: convert_bytes(node.get("freeSpace")),
                "Datastore Type": node.get("datastoreType", ""),
            }
        )
    hr = tableToMarkdown(
        "GPS VM Datastores",
        hr_content,
        headers=["VSphere Datastore ID", "Name", "Capacity", FREE_SPACE, "Datastore Type"],
        removeNull=True,
    )
    return context, hr


def prepare_context_hr_radar_analysis_status(activity_series: dict, activity_series_id: str, cluster_id: str):
    """
    Prepare context output and human readable response for rubrik-radar-analysis-status command.

    :type activity_series: ``dict``
    :param activity_series: activity_series from the response received from the API

    :type activity_series_id: ``dict``
    :param activity_series_id: activity_series_id received from user

    :type cluster_id: ``dict``
    :param cluster_id: cluster_id received from user

    :return: context output and human readable for the command
    """
    messages = []
    nodes = activity_series["activityConnection"]["nodes"]
    for node in nodes:
        messages.append(remove_empty_elements(node))

    context = {
        "ActivitySeriesId": activity_series_id.lower(),
        "ClusterId": cluster_id,
        "Message": messages,
        "EventComplete": "True" if activity_series.get("lastActivityStatus") == "Success" else "False",
    }
    hr_content = {
        ACTIVITY_SERIES_ID: activity_series_id.lower(),
        CLUSTER_ID: cluster_id,
        "Message": messages[0].get("message", ""),
        "Event Complete": "True" if activity_series.get("lastActivityStatus") == "Success" else "False",
    }
    hr_headers = [ACTIVITY_SERIES_ID, CLUSTER_ID, "Message", "Event Complete"]
    hr = tableToMarkdown("Radar Analysis Status", hr_content, hr_headers, removeNull=True)
    return context, hr


def prepare_context_hr_event_list(edges):
    """
    Prepare context output and human readable response for rubrik-event-list command.

    :type edges: ``list``
    :param edges: edges from the response received from the API

    :return: context output and human readable for the command
    """
    hr_content = []
    context = []
    for edge in edges:
        node = edge.get("node")
        node = remove_empty_elements(node)
        context.append(node)
        hr_content.append(
            {
                "Event ID": node.get("id", ""),
                ACTIVITY_SERIES_ID: node.get("activitySeriesId", ""),
                CLUSTER_ID: node.get("cluster", "").get("id", ""),
                OBJECT_ID: node.get("objectId", ""),
                OBJECT_NAME: node.get("objectName", ""),
                "Severity": node.get("severity", ""),
                "Progress": node.get("progress", ""),
                START_TIME: node.get("startTime", ""),
                "Last Updated": node.get("lastUpdated", ""),
                "Last Activity Type": node.get("lastActivityType", ""),
                "Last Activity Status": node.get("lastActivityStatus", ""),
            }
        )
    hr = tableToMarkdown(
        "Events",
        hr_content,
        headers=[
            "Event ID",
            ACTIVITY_SERIES_ID,
            CLUSTER_ID,
            OBJECT_ID,
            OBJECT_NAME,
            "Severity",
            "Progress",
            START_TIME,
            "Last Updated",
            "Last Activity Type",
            "Last Activity Status",
        ],
        removeNull=True,
    )
    return context, hr


def prepare_context_hr_sonar_sensitive_hits(response):
    """
    Prepare context output and human readable response for rubrik-sonar-sensitive-hits command.

    :type response: ``dict``
    :param response: The response received from the API

    :return: context output and human readable for the command
    """
    hr = []
    context = []
    policy_hits = {}  # type: ignore
    for data in response.get("rootFileResult", {}).get("analyzerGroupResults", []):
        policy_name = data.get("analyzerGroup", {}).get("name", "")
        policy_hits[policy_name] = {}

        for analyzer in data.get("analyzerResults", []):
            analyzer_name = analyzer.get("analyzer", {}).get("name", "")
            analyzer_hits = str(analyzer.get("hits", {}).get("totalHits", ""))
            policy_hits[policy_name][analyzer_name] = analyzer_hits

    root = response.get("rootFileResult")
    context.append(
        remove_empty_elements(
            {
                "id": response.get("id", ""),
                "totalHits": root.get("hits", {}).get("totalHits", ""),
                "policy_hits": policy_hits,
                "filesWithHits": root.get("filesWithHits", {}).get("totalHits", ""),
                "openAccessFiles": root.get("openAccessFiles", {}).get("totalHits", ""),
                "openAccessFolders": root.get("openAccessFolders", {}).get("totalHits", ""),
                "openAccessFilesWithHits": root.get("openAccessFilesWithHits", {}).get("totalHits", ""),
                "staleFiles": root.get("staleFiles", {}).get("totalHits", ""),
                "staleFilesWithHits": root.get("staleFilesWithHits", {}).get("totalHits", ""),
                "openAccessStaleFiles": root.get("openAccessStaleFiles", {}).get("totalHits", ""),
            }
        )
    )

    hr.append({"ID": context[0].get("id"), "Total Hits": context[0].get("totalHits")})
    return context, hr


def prepare_context_hr_object_snapshot_list(edges, object_id):
    """
    Prepare context output and human readable response for rubrik-polaris-object-snapshot-list command.

    :type object_id: ``str``
    :param object_id: ObjectID to get snapshots of.
    :type edges: ``list``
    :param edges: edges from the response received from the API

    :return: context output and human readable for the command
    """
    hr_content = []
    context = {"id": object_id, "Snapshot": []}
    for edge in edges:
        node = edge.get("node")
        context["Snapshot"].append(remove_empty_elements(node))
        hr_content.append(
            {
                SNAPSHOT_ID: node.get("id"),
                "Creation Date": node.get("date"),
                CLUSTER_NAME: node.get("cluster", {}).get("name"),
                SLA_DOMAIN_NAME: node.get("slaDomain", {}).get("name"),
            }
        )
    hr = tableToMarkdown(
        "Object Snapshots", hr_content, headers=[SNAPSHOT_ID, "Creation Date", CLUSTER_NAME, SLA_DOMAIN_NAME], removeNull=True
    )
    return context, hr


def prepare_context_hr_object_list(edges):
    """
    Prepare context output and human readable response for rubrik-polaris-object-list command.

    :type edges: ``list``
    :param edges: edges from the response received from the API

    :return: context output and human readable for the command
    """
    hr_content = []
    context = []
    for edge in edges:
        node = edge.get("node")
        node = remove_empty_elements(node)
        context.append(node)
        logical_path_names = []
        location = ""
        for path in node.get("logicalPath", []):
            logical_path_names.append(path.get("name"))
        for name in logical_path_names:
            if location:
                location = name + "\\" + location
            else:
                location = name
        hr_content.append(
            {
                OBJECT_ID: node.get("id"),
                OBJECT_NAME: node.get("name"),
                OBJECT_TYPE: node.get("objectType"),
                "Location": location,
                CLUSTER_NAME: node.get("cluster", {}).get("name"),
                SLA_DOMAIN_NAME: node.get("effectiveSlaDomain", {}).get("name"),
            }
        )
    hr = tableToMarkdown(
        "Objects",
        hr_content,
        headers=[OBJECT_ID, OBJECT_NAME, OBJECT_TYPE, "Location", CLUSTER_NAME, SLA_DOMAIN_NAME],
        removeNull=True,
    )
    return context, hr


def prepare_context_hr_async_result(response, request_id, ip_address):
    """
    Prepare context output and human readable response for rubrik-gps-async-result command.

    :type ip_address: str
    :param ip_address: IP Address to append with hyperlink

    :type: request_id: str
    :param request_id: Request ID to get results

    :type response: ``dict``
    :param response: The response received from the API

    :return: context output and human readable for the command
    """
    context = remove_empty_elements(response)
    hyper_link = ""
    for data in response.get("links"):
        link = data.get("href", "")
        rel = data.get("rel", "")
        if "DOWNLOAD_SNAPPABLE_FILE" in request_id and response.get("status") == "SUCCEEDED" and rel == "result":
            link = urljoin(f"https://{ip_address}", link)  # noqa: E231
        hyper_link += f"[{rel}]({urllib3.util.parse_url(link)})\n"
    hr = {"ID": response.get("id"), "Status": response.get("status"), "Node ID": response.get("nodeId"), "Links": hyper_link}

    readable_output = tableToMarkdown(
        name="GPS Asynchronous Request Result", t=hr, headers=["ID", "Status", "Node ID", "Links"], removeNull=True
    )
    return context, readable_output


def prepare_advance_ioc(advance_ioc, ioc):
    """
    Prepare formatted advance IOC.

    :param ioc: ioc value
    :param advance_ioc: unformatted advance ioc
    :return: formatted advance ioc
    """
    if advance_ioc:
        if not isinstance(advance_ioc, dict):
            raise ValueError(ERROR_MESSAGES["INVALID_FORMAT"].format("advance_ioc"))
        ioc = []
        for advance_ioc_key, advance_ioc_value in advance_ioc.items():
            if not isinstance(advance_ioc_value, list):
                advance_ioc_value = [advance_ioc_value]
            ioc.extend([{"iocType": str(advance_ioc_key).strip(), "iocValue": value} for value in advance_ioc_value])

    return ioc


def validate_ioc_scan_args(args: Dict[str, Any]) -> dict:
    """
    To validate arguments of rubrik-radar-ioc-scan.

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: Validated arguments for rubrik-radar-ioc-scan
    """
    cluster_id = validate_required_arg("cluster_id", args.get("cluster_id"))
    object_id = argToList(validate_required_arg("object_id", args.get("object_id")))

    scan_name = args.get("scan_name", DEFAULT_REQUEST_NAME)
    ioc_type = args.get("ioc_type")
    ioc_value = args.get("ioc_value")
    advance_ioc = args.get("advance_ioc")

    start_date = args.get("start_date")
    end_date = args.get("end_date")
    max_snapshots_per_object = arg_to_number(args.get("max_snapshots_per_object"), "max_snapshots_per_object")
    snapshot_id = argToList(args.get("snapshot_id"), ":")

    paths_to_include = argToList(args.get("paths_to_include"))
    paths_to_exclude = argToList(args.get("paths_to_exclude"))
    paths_to_exempt = argToList(args.get("paths_to_exempt"))
    requested_hash_types = argToList(args.get("requested_hash_types"))

    ioc = []
    if ioc_type:
        if ioc_type not in IOC_TYPE_ENUM:
            raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(ioc_type, "ioc_type", IOC_TYPE_ENUM))
        ioc.append({"iocType": ioc_type, "iocValue": ioc_value})
    if advance_ioc:
        try:
            advance_ioc = json.loads(advance_ioc)
        except json.JSONDecodeError:
            raise ValueError(ERROR_MESSAGES["JSON_DECODE"].format("advance_ioc"))

    if not ioc and not advance_ioc:
        raise ValueError(ERROR_MESSAGES["NO_INDICATOR_SPECIFIED"])

    ioc = prepare_advance_ioc(advance_ioc, ioc)
    snapshot_scan_limit = {}
    if start_date:
        start_date_ob = arg_to_datetime(validate_required_arg("start_date", args.get("start_date")), "start_date")
        snapshot_scan_limit["startTime"] = start_date_ob.strftime(DATE_TIME_FORMAT)  # type: ignore
    if end_date:
        end_date_ob = arg_to_datetime(validate_required_arg("end_date", args.get("end_date")), "end_date")
        snapshot_scan_limit["endTime"] = end_date_ob.strftime(DATE_TIME_FORMAT)  # type: ignore
    if max_snapshots_per_object:
        snapshot_scan_limit["maxSnapshotsPerObject"] = max_snapshots_per_object
    if snapshot_id:
        if len(snapshot_id) != len(object_id):
            raise ValueError(ERROR_MESSAGES["LEN_SNAPSHOT_NE_LEN_OBJECT"])
        snapshot_scan_limit["snapshotsToScanPerObject"] = [
            {"id": object_id[i], "snapshots": argToList(snapshot_id[i])} for i in range(len(snapshot_id))
        ]

    max_matches_per_snapshot = MAX_MATCHES_PER_OBJECT
    max_file_size = arg_to_number(args.get("max_file_size", MAXIMUM_FILE_SIZE), "max_file_size")
    return {
        "object_ids": object_id,
        "cluster_id": cluster_id,
        "indicators_of_compromise": ioc,
        "scan_name": scan_name,
        "snapshot_scan_limit": snapshot_scan_limit,
        "max_matches_per_snapshot": max_matches_per_snapshot,
        "path_to_include": paths_to_include,
        "path_to_exclude": paths_to_exclude,
        "path_to_exempt": paths_to_exempt,
        "maximum_file_size_to_scan": max_file_size,
        "requested_hash_types": requested_hash_types,
    }


def prepare_context_hr_radar_ioc_scan_results(data: dict):
    """
    Prepare context output and human readable response for rubrik-radar-ioc-scan-results command.

    :type data: ``dict``
    :param data: The data in response received from the API

    :return: context output and human readable for the command
    """
    outputs = remove_empty_elements(data)
    hr_content = []
    results = outputs.get("results", [])
    scan_status = "FINISHED"

    for result in results:
        object_id = result.get("objectId")
        for snapshot_result in result.get("snapshotResults", []):
            status = snapshot_result.get("status", "")
            if status == "MALWARE_SCAN_IN_SNAPSHOT_STATUS_ERROR":
                scan_status = "ERROR"
            if status == "MALWARE_SCAN_IN_SNAPSHOT_STATUS_PENDING" and scan_status != "ERROR":
                scan_status = "RUNNING"
            if not status and scan_status != "ERROR":
                scan_status = "UNKNOWN"

            scan_stats = snapshot_result.get("scanStats")
            scan_statistics = (
                f"Number of Files: {scan_stats.get('numFiles')}, "
                f"Number of Files Scanned: {scan_stats.get('numFilesScanned')}, "
                f"Total Files Scanned In Bytes: {scan_stats.get('totalFilesScannedSizeBytes')}"
            )
            hr_content.append(
                {
                    SNAPSHOT_ID: snapshot_result.get("snapshotId"),
                    "Snapshot Date": snapshot_result.get("snapshotDate"),
                    OBJECT_ID: object_id,
                    "Snapshot Scan Status": status,
                    "Scan Statistics": scan_statistics,
                    "Matches": len(snapshot_result.get("matches", [])),
                }
            )

    table_name = "Radar IOC Scan Results"
    metadata = f"Scan ID: {outputs.get('id')}\nStatus: {scan_status}"
    outputs["status"] = scan_status
    headers = [SNAPSHOT_ID, "Snapshot Date", OBJECT_ID, "Snapshot Scan Status", "Scan Statistics", "Matches"]
    readable_output = tableToMarkdown(table_name, hr_content, metadata=metadata, headers=headers, removeNull=True)

    return outputs, readable_output


def prepare_context_hr_cluster_list(nodes):
    """
    Prepare context output and human readable response for rubrik-gps-cluster-list command.

    :type nodes: ``list``
    :param nodes: nodes from the response received from the API

    :return: context output and human readable for the command
    """
    hr_content = []
    context = []
    for node in nodes:
        node = remove_empty_elements(node)
        context.append(node)
        ip_addresses = []
        for cluster_node in node.get("clusterNodeConnection", {}).get("nodes", []):
            ip_addresses.append(cluster_node.get("ipAddress"))
        hr_content.append(
            {
                CLUSTER_ID: node.get("id"),
                CLUSTER_NAME: node.get("name"),
                "Connection Status": node.get("status"),
                "Cluster Location": node.get("geoLocation", {}).get("address"),
                "Total Capacity": convert_bytes(node.get("metric", {}).get("totalCapacity")),
                FREE_SPACE: convert_bytes(node.get("metric", {}).get("availableCapacity")),
                "Protected Objects": node.get("snappableConnection", {}).get("count"),
                "Cluster Version": node.get("version"),
                "IP Address": ", ".join(ip_addresses),
            }
        )
    hr = tableToMarkdown(
        "GPS Clusters",
        hr_content,
        headers=[
            CLUSTER_ID,
            CLUSTER_NAME,
            "Connection Status",
            "Cluster Location",
            "Total Capacity",
            FREE_SPACE,
            "Protected Objects",
            "Cluster Version",
            "IP Address",
        ],
        removeNull=True,
    )
    return context, hr


def prepare_context_hr_ioc_scan_list(data: list):
    """
    Prepare the context output and human readable response for rubrik-radar-ioc-scan-list command.

    :type data: ``dict``
    :param data: data from response received from the API

    :return: context output and human readable for the command
    """
    hr_content = []
    for scan in data:
        hr_content.append(
            {
                SCAN_ID: scan.get("id", ""),
                START_TIME: scan.get("startTime", ""),
                "End Time": "Not Finished" if scan.get("endTime") is None else scan.get("endTime", ""),
                "Scanned Objects": ", ".join(
                    [snapshot.get("id", "") for snapshot in scan.get("snapshots", []) if isinstance(snapshot, dict)]
                ),
            }
        )
    hr = tableToMarkdown(
        "Radar IOC Scans", hr_content, headers=[SCAN_ID, START_TIME, "End Time", "Scanned Objects"], removeNull=True
    )
    return data, hr


def prepare_context_hr_user_access_list(
    edges: list,
    include_whitelisted_results: bool,
    user_email: str,
    base_url: str,
    page_number: int = 1,
    limit: int = DEFAULT_LIMIT,
) -> tuple[list[dict], str, int, set[str]]:
    """
    Prepare context output and human-readable response for rubrik-sonar-user-access-list command.

    :type edges: ``list``
    :param edges: Edges from the response received from the API.

    :type include_whitelisted_results: ``bool``
    :param include_whitelisted_results: Include whitelisted results in the API response.

    :type user_email: ``str``
    :param user_email: User email or user principal name.

    :type base_url: ``str``
    :param base_url: Base URL of the platform.

    :type page_number: ``int``
    :param page_number: The current page number.

    :type limit: ``int``
    :param limit: Limit the records for the output.

    :return: Context output, human-readable, the total pages and the risk levels for the command.
    """
    hr_content = []
    context: list[dict] = []
    risk_levels: set[str] = set()
    upn_match_count = 0
    for edge in edges:
        node = edge.get("node")
        node = remove_empty_elements(node)
        user_principal_name = node.get("upn")
        if user_email:
            if isinstance(user_principal_name, str) and user_email not in user_principal_name:
                continue
            # Found the match of the UPN with the user provide mail address.
            upn_match_count += 1
            # Skip the records as per the page number.
            if upn_match_count <= limit * (page_number - 1):
                continue
            # Limit the context and the HR output.
            if len(context) >= limit:
                continue
        context.append(node)
        sensitive_files = node.get("sensitiveFiles") or {}
        risk_level = node.get("riskLevel")
        if risk_level:
            risk_levels.add(risk_level)

        total_sensitive_files = 0
        # Go for totalHits if include_whitelisted_results is True else go for violatedHits.
        if include_whitelisted_results:
            sensitive_hits_key = "totalHits"
            sensitive_files_key = "totalCount"
        else:
            sensitive_hits_key = "violatedHits"
            sensitive_files_key = "violatedCount"

        for file_count in sensitive_files.values():
            if isinstance(file_count, dict):
                total_sensitive_files += file_count.get(sensitive_files_key) or 0

        user_id = node.get("principalId")
        hr_content.append(
            {
                USER_ID: f"[{user_id}]({USER_ACCESS_HYPERLINK.format(base_url, user_id)})",
                USER_FULL_NAME: node.get("fullName"),
                USER_PRINCIPAL_NAME: re.escape(node.get("upn") or ""),
                RISK_LEVEL: node.get("riskLevel"),
                TOTAL_SENSITIVE_OBJECTS: node.get("sensitiveObjectCount", {}).get(sensitive_files_key, 0),
                TOTAL_SENSITIVE_FILES: total_sensitive_files,
                TOTAL_SENSITIVE_HITS: node.get("totalSensitiveHits", {}).get(sensitive_hits_key) or 0,
            }
        )

    pages = calc_pages(per_page_count=limit, total_count=upn_match_count)  # type: ignore
    if user_email:
        record_start = limit * (page_number - 1) + 1
        record_end = record_start + len(context) - 1
        total_records = upn_match_count
    else:
        record_start = 1
        record_end = len(context)
        total_records = record_end
    hr = tableToMarkdown(
        f"User Access (Showing Records {record_start}-{record_end} out of {total_records})",
        hr_content,
        headers=[  # noqa: E225
            USER_ID,
            USER_FULL_NAME,
            USER_PRINCIPAL_NAME,
            RISK_LEVEL,
            TOTAL_SENSITIVE_OBJECTS,
            TOTAL_SENSITIVE_FILES,
            TOTAL_SENSITIVE_HITS,
        ],
        removeNull=True,  # noqa: E225
    )

    return context, hr, pages, risk_levels


def prepare_context_hr_user_access_get(
    principal_summary: Dict, policy_hits_context: list, base_url: str, include_whitelisted_results: bool
) -> tuple[list, str, str]:
    """
    Prepare context output and human-readable response for rubrik-sonar-user-access-get command.

    :type principal_summary: ``Dict``
    :param principal_summary: Edges from the response received from the API.

    :type policy_hits_context: ``list``
    :param policy_hits_context: Summary of the policy hits for the user.

    :type base_url: ``str``
    :param base_url: Base URL of the platform.

    :type include_whitelisted_results: ``bool``
    :param include_whitelisted_results: Include whitelisted results in the API response.

    :return: Context output and human-readable for the command.
    """
    access_hr_content = []
    policy_hits_hr_content: list = []
    context = []
    principal_summary = remove_empty_elements(principal_summary)
    policy_hits_context = remove_empty_elements(policy_hits_context)
    principal_summary["policy_hits_summary"] = policy_hits_context
    context.append(principal_summary)
    sensitive_files = principal_summary.get("sensitiveFiles") or {}

    total_sensitive_files = 0
    # Go for totalHits if include_whitelisted_results is True else go for violatedHits.
    if include_whitelisted_results:
        sensitive_hits_key = "totalHits"
        sensitive_files_key = "totalCount"
    else:
        sensitive_hits_key = "violatedHits"
        sensitive_files_key = "violatedCount"

    for file_count in sensitive_files.values():
        if isinstance(file_count, dict):
            total_sensitive_files += file_count.get(sensitive_files_key) or 0

    groups = [group.get("name") for group in principal_summary.get("directGroups", [])]
    access_risk_reasons = principal_summary.get("riskReasons", {}).get("accessRiskReasons", [])
    insecure_reasons = principal_summary.get("riskReasons", {}).get("insecureReasons", [])

    user_id = principal_summary.get("principalId")
    access_hr_content.append(
        {
            USER_ID: f"[{user_id}]({USER_ACCESS_HYPERLINK.format(base_url, user_id)})",
            USER_FULL_NAME: principal_summary.get("fullName"),
            USER_PRINCIPAL_NAME: re.escape(principal_summary.get("upn") or ""),
            RISK_LEVEL: principal_summary.get("riskLevel"),
            ACCESS_RISK_REASONS: ", ".join(access_risk_reasons),
            INSECURE_REASONS: ", ".join(insecure_reasons),
            GROUPS: ", ".join(groups),
            TOTAL_SENSITIVE_OBJECTS: principal_summary.get("sensitiveObjectCount", {}).get(sensitive_files_key, 0),
            TOTAL_SENSITIVE_FILES: total_sensitive_files,
            TOTAL_SENSITIVE_HITS: principal_summary.get("totalSensitiveHits", {}).get(sensitive_hits_key) or 0,
        }
    )

    access_hr = tableToMarkdown(
        "User Access",
        access_hr_content,
        headers=[
            USER_ID,
            USER_FULL_NAME,
            USER_PRINCIPAL_NAME,
            RISK_LEVEL,
            ACCESS_RISK_REASONS,
            INSECURE_REASONS,
            GROUPS,
            TOTAL_SENSITIVE_OBJECTS,
            TOTAL_SENSITIVE_FILES,
            TOTAL_SENSITIVE_HITS,
        ],
        removeNull=True,
    )

    for policy_hits in policy_hits_context:
        total_file_count_dict = policy_hits.get("sidSensitiveFiles", {}).get("totalFileCount", {})
        risk_hits_dict = policy_hits.get("sidAnalyzerHits", {})
        delta_risk_hits_dict = policy_hits.get("sidDeltaAnalyzerHits", {})

        policy_hits_hr_content.append(
            {
                POLICY_NAME: policy_hits.get("policyName") or "",
                TOTAL_SENSITIVE_FILES: total_file_count_dict.get(sensitive_files_key) or 0,
                TOTAL_SENSITIVE_HITS: risk_hits_dict.get("totalHits", {}).get(sensitive_hits_key) or 0,
                SENSITIVE_HITS_DELTA: delta_risk_hits_dict.get("totalHits", {}).get(sensitive_hits_key) or 0,
                HIGH_RISK_HITS: risk_hits_dict.get("highRiskHits", {}).get(sensitive_hits_key) or 0,
                MEDIUM_RISK_HITS: risk_hits_dict.get("mediumRiskHits", {}).get(sensitive_hits_key) or 0,
                LOW_RISK_HITS: risk_hits_dict.get("lowRiskHits", {}).get(sensitive_hits_key) or 0,
            }
        )

    policy_hits_hr = tableToMarkdown(
        "Sensitive Hits",
        policy_hits_hr_content,
        headers=[
            POLICY_NAME,
            TOTAL_SENSITIVE_FILES,
            TOTAL_SENSITIVE_HITS,
            SENSITIVE_HITS_DELTA,
            HIGH_RISK_HITS,
            MEDIUM_RISK_HITS,
            LOW_RISK_HITS,
        ],
        removeNull=True,
    )

    return context, access_hr, policy_hits_hr


def prepare_context_hr_file_context_list(edges: list, include_whitelisted_results: bool) -> tuple[list, str]:
    """
    Prepare context output and human-readable response for rubrik-sonar-file-context-list command.

    :type edges: ``list``
    :param edges: Edges from the response received from the API.

    :type include_whitelisted_results: ``bool``
    :param include_whitelisted_results: Include whitelisted results in the API response.

    :return: Context output and human-readable for the command.
    """
    hr_content = []
    context = []
    for edge in edges:
        node = edge.get("node")
        node = remove_empty_elements(node)
        context.append(node)
        last_access_time = node.get("lastAccessTime")
        last_modified_time = node.get("lastModifiedTime")

        # Go for totalHits if include_whitelisted_results is True else go for violatedHits.
        if include_whitelisted_results:
            total_sensitive_hits = node.get("hits", {}).get("totalHits") or 0
            daily_hits_change = node.get("hits", {}).get("totalHitsDelta") or 0
        else:
            total_sensitive_hits = node.get("hits", {}).get("violations") or 0
            daily_hits_change = node.get("hits", {}).get("violationsDelta") or 0

        hr_content.append(
            {
                FILE_NAME: node.get("filename"),
                FILE_SIZE: node.get("size"),
                TOTAL_SENSITIVE_HITS: total_sensitive_hits,
                DAILY_HITS_CHANGE: daily_hits_change,
                FILE_PATH: node.get("stdPath"),
                ACCESS_TYPE: node.get("openAccessType"),
                LAST_ACCESS_TIME: datetime.fromtimestamp(last_access_time, tz=timezone.utc).strftime(HR_DATE_TIME_FORMAT),
                LAST_MODIFIED_TIME: datetime.fromtimestamp(last_modified_time, tz=timezone.utc).strftime(HR_DATE_TIME_FORMAT),
            }
        )

    hr = tableToMarkdown(
        "File Context",
        hr_content,
        headers=[
            FILE_NAME,
            FILE_SIZE,
            TOTAL_SENSITIVE_HITS,
            DAILY_HITS_CHANGE,
            FILE_PATH,
            ACCESS_TYPE,
            LAST_ACCESS_TIME,
            LAST_MODIFIED_TIME,
        ],
        removeNull=True,
    )

    return context, hr


def prepare_context_hr_suspicious_file_list(snappable_investigations_data: dict, suspicious_file_data: dict) -> tuple[dict, str]:
    """
    Prepare context output and human-readable response for rubrik-radar-suspicious-file-list command.

    :type snappable_investigations_data: ``dict``
    :param snappable_investigations_data: Snappable investigations response received from the API.

    :type suspicious_file_data: ``dict``
    :param suspicious_file_data: Suspicious file data response received from the API.

    :return: Context output and human-readable for the command.
    """
    context = {}
    anomaly_information_hr_content = []
    suspicious_file_hr_content = []
    snappable_investigations_data = remove_empty_elements(snappable_investigations_data)
    suspicious_file_data = remove_empty_elements(suspicious_file_data)
    context.update(suspicious_file_data)
    cluster_data = snappable_investigations_data.get("cluster", {})
    if cluster_data:
        context["cluster"] = cluster_data
    snapshot_cdm_id = snappable_investigations_data.get("cdmId")
    if snapshot_cdm_id:
        context["cdmId"] = snapshot_cdm_id
    snappable_new = snappable_investigations_data.get("snappableNew", {})
    if snappable_new:
        context["snappableNew"] = snappable_new

    anomaly_information = {
        ANOMALY_ID: context.get("id"),
        IS_ANOMALY: context.get("isAnomaly"),
        ANOMALY_PROBABILITY: context.get("anomalyProbability"),
        SEVERITY: context.get("severity"),
        ENCRYPTION: context.get("encryption"),
        DETECTION_TIME: context.get("detectionTime"),
        SNAPSHOT_TIME: context.get("snapshotDate"),
        ANOMALY_RESOLUTION_STATUS: context.get("resolutionStatus"),
        ANOMALY_TYPE: context.get("anomalyType"),
    }

    anomaly_info_list: list = context.get("anomalyInfo", {}).get("strainAnalysisInfo", [])
    if not anomaly_info_list or not isinstance(anomaly_info_list, list):
        anomaly_information_hr_content.append(anomaly_information)
    else:
        anomaly_info: dict = anomaly_info_list[0]
        anomaly_information.update(
            {
                ANOMALY: anomaly_info.get("strainId"),
                TOTAL_SUSPICIOUS_FILES: anomaly_info.get("totalAffectedFiles"),
                TOTAL_RANSOMEWARE_NOTE: anomaly_info.get("totalRansomwareNotes"),
            }
        )
        anomaly_information_hr_content.append(anomaly_information)
        affected_files: list = anomaly_info.get("sampleAffectedFilesInfo", [])
        ransomeware_note_files: list = anomaly_info.get("sampleRansomwareNoteFilesInfo", [])
        if affected_files and isinstance(affected_files, list):
            for affected_file in affected_files:
                suspicious_file = {
                    FILE_PATH: affected_file.get("filePath"),
                    SUSPICIOUS_ACTIVITY: RANSOMEWARE_ENCRYPTION,
                    FILE_SIZE: affected_file.get("fileSizeBytes"),
                    LAST_MODIFIED_TIME: affected_file.get("lastModified"),
                }
                suspicious_file_hr_content.append(suspicious_file)
        if ransomeware_note_files and isinstance(ransomeware_note_files, list):
            for ransomeware_note_file in ransomeware_note_files:
                suspicious_file = {
                    FILE_PATH: ransomeware_note_file.get("filePath"),
                    SUSPICIOUS_ACTIVITY: RANSOMEWARE_NOTE,
                    FILE_SIZE: ransomeware_note_file.get("fileSizeBytes"),
                    LAST_MODIFIED_TIME: ransomeware_note_file.get("lastModified"),
                }
                suspicious_file_hr_content.append(suspicious_file)

    anomaly_hr = tableToMarkdown(
        "Anomaly Information",
        anomaly_information_hr_content,
        headers=[
            ANOMALY_ID,
            IS_ANOMALY,
            ANOMALY_PROBABILITY,
            SEVERITY,
            ENCRYPTION,
            ANOMALY,
            ANOMALY_TYPE,
            ANOMALY_RESOLUTION_STATUS,
            TOTAL_SUSPICIOUS_FILES,
            TOTAL_RANSOMEWARE_NOTE,
            DETECTION_TIME,
            SNAPSHOT_TIME,
        ],
        removeNull=True,
    )

    suspicious_file_hr = tableToMarkdown(
        "Suspicious Files",
        suspicious_file_hr_content,
        headers=[FILE_PATH, SUSPICIOUS_ACTIVITY, FILE_SIZE, LAST_MODIFIED_TIME],
        removeNull=True,
    )

    return context, f"{anomaly_hr}\n\n{suspicious_file_hr}"


def prepare_score_and_hr_for_reputation_command(response: dict, indicator_value: str, indicator_type: str) -> tuple[int, str]:
    """
    Prepare severity score and human-readable response for generic reputation command.

    :type response: ``dict``
    :param response: IP response received from the API.

    :type indicator_value: ``str``
    :param indicator_value: Indicator value.

    :type indicator_type: ``str``
    :param indicator_type: Indicator type.

    :return: Severity score and human-readable for the command.
    """
    sensitive_info = response.get(SENSITIVE_INFO_KEY, {})
    severity_str = sensitive_info.get("riskLevel", "unknown").lower()
    if "none" in severity_str:
        severity_str = "unknown"
    severity_score: int = DBOT_SCORE_MAPPING.get(severity_str, 0)
    general_info = response.get(GENERAL_INFO_KEY, {})
    severity_str = severity_str.replace(" risk", "")
    human_readable = tableToMarkdown(
        f"General Information for the given {severity_str} risk {indicator_type}: {indicator_value}",
        general_info,
        removeNull=True,
        headerTransform=pascalToSpace,
        url_keys=["redirectLink"],
    )
    human_readable += (
        "\n"
        + tableToMarkdown(
            "Sensitive Information", sensitive_info, headerTransform=pascalToSpace, removeNull=True, url_keys=["redirectLink"]
        )
        if sensitive_info
        else ""
    )
    anomalies_info = response.get(ANOMALY_INFO_KEY, {})
    human_readable += (
        "\n"
        + tableToMarkdown(
            "Anomaly Information", anomalies_info, headerTransform=pascalToSpace, removeNull=True, url_keys=["redirectLink"]
        )
        if anomalies_info
        else ""
    )
    threat_hunt_info = response.get(THREAT_HUNT_INFO_KEY, {})
    human_readable += (
        "\n"
        + tableToMarkdown(
            "Threat Hunt Information", threat_hunt_info, headerTransform=pascalToSpace, removeNull=True, url_keys=["redirectLink"]
        )
        if threat_hunt_info
        else ""
    )
    threat_monitoring_info = response.get(THREAT_MONITORING_INFO_KEY, {})
    human_readable += (
        "\n"
        + tableToMarkdown(
            "Threat Monitoring Information",
            threat_monitoring_info,
            headerTransform=pascalToSpace,
            removeNull=True,
            url_keys=["redirectLink"],
        )
        if threat_monitoring_info
        else ""
    )

    return severity_score, human_readable


def validate_ip_addresses(ips_list: List[str]) -> tuple[List[str], List[str]]:
    """
    Given a list of IP addresses, returns the invalid and valid ips.

    :type ips_list: ``List[str]``
    :param ips_list: List of ip addresses.

    :return: invalid_ip_addresses and valid_ip_addresses.
    :rtype: ``Tuple[List[str], List[str]]``
    """
    invalid_ip_addresses = []
    valid_ip_addresses = []
    for ip in ips_list:
        if is_ip_valid(ip, accept_v6_ips=True):
            valid_ip_addresses.append(ip)
        else:
            invalid_ip_addresses.append(ip)
    return invalid_ip_addresses, valid_ip_addresses


def validate_anomaly_status_update_command_args(
    anomaly_type: str, false_positive_type: Optional[str], false_positive_reason: Optional[str]
):
    """
    Validate the arguments of the rubrik_radar_anomaly_status_update_command.

    :type anomaly_type: ``str``
    :param anomaly_type: The type of the anomaly.

    :type false_positive_type: ``Optional[str]``
    :param false_positive_type: The type of the false positive.

    :type false_positive_reason: ``Optional[str]``
    :param false_positive_reason: The reason for marking the anomaly as a false positive.
    """

    if anomaly_type.upper() not in ANOMALY_TYPE_ENUM:
        raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(anomaly_type, "anomaly_type", ANOMALY_TYPE_ENUM))

    if false_positive_reason and not false_positive_type:
        raise ValueError(ERROR_MESSAGES["FALSE_POSITIVE_REASON_ERROR"].format("false_positive_type", "false_positive_reason"))

    if false_positive_type and false_positive_type.upper() not in FALSE_POSITIVE_TYPE_ENUM:
        raise ValueError(
            ERROR_MESSAGES["INVALID_SELECT"].format(false_positive_type, "false_positive_type", FALSE_POSITIVE_TYPE_ENUM)
        )

    if false_positive_type and false_positive_type.upper() == "OTHER" and not false_positive_reason:
        raise ValueError(ERROR_MESSAGES["FALSE_POSITIVE_TYPE_ERROR"].format("false_positive_reason", "false_positive_type"))


def validate_threat_monitoring_matched_object_list_command_args(
    start_time_obj: Optional[datetime], limit: Optional[int], match_types: list
):
    """
    Validate the arguments of the rubrik-threat-monitoring-matched-object-list command.

    :type start_time_obj: ``Optional[datetime]``
    :param start_time_obj: The start time of the query.

    :type limit: ``Optional[int]``
    :param limit: The number of results to return.

    :type match_types: ``list``
    :param match_types: The match types to filter by.
    """
    start_time_obj = validate_required_arg("start_time", start_time_obj)
    if not limit or not 1 <= limit <= MAXIMUM_PAGINATION_LIMIT:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))

    for match_type in match_types:
        if match_type not in IOC_TYPE_ENUM:
            raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(match_type, "match_type", IOC_TYPE_ENUM))


def prepare_context_hr_threat_monitoring_matched_object_list(edges: list) -> tuple:
    """
    Prepare human readable response and context for rubrik-threat-monitoring-matched-object-list.

    :type edges: ``list``
    :param edges: edges from the response received from the API.

    :return: human readable and context for the command.
    :rtype: ``tuple``
    """
    hr_content = []
    context = []
    for edge in edges:
        node = edge.get("node", {})
        node = remove_empty_elements(node)
        context.append(node)
        hr_content.append(
            {
                "Object ID": node.get("objectFid"),
                "Object Name": node.get("objectName"),
                "Object Type": node.get("objectType"),
                "Total Files Matched": node.get("filesMatched"),
                "Match Types": node.get("matchType"),
                "Last Detection Time": node.get("lastDetection"),
                "Cluster ID": node.get("cluster", {}).get("id"),
                "Cluster Name": node.get("cluster", {}).get("name"),
            }
        )
    hr = tableToMarkdown(
        "Threat Monitoring Object List",
        hr_content,
        headers=[
            "Object ID",
            "Object Name",
            "Object Type",
            "Total Files Matched",
            "Match Types",
            "Last Detection Time",
            "Cluster ID",
            "Cluster Name",
        ],
        removeNull=True,
    )
    return context, hr


def remove_typename(data: Union[dict, list]) -> Union[dict, list]:
    """
    Recursively remove "__typename" key from all the dict and list types.

    :type data: ``dict`` or ``list``
    :param data: The data which "__typename" key needs to be removed.

    :return: The data with "__typename" key removed.
    :rtype: ``dict`` or ``list``
    """
    if isinstance(data, dict):
        if "__typename" in data:
            data.pop("__typename")
        for key, value in data.items():
            if isinstance(value, (dict, list)):  # noqa: UP038
                data[key] = remove_typename(value)
    elif isinstance(data, list):
        for index, value in enumerate(data):
            if isinstance(value, (dict, list)):  # noqa: UP038
                data[index] = remove_typename(value)
    return data


def prepare_hr_threat_monitoring_matched_objects_get(threat_monitoring_data: dict) -> str:
    """
    Prepare human readable response for rubrik-threat-monitoring-matched-object-get command.

    :type threat_monitoring_data: ``dict``
    :param threat_monitoring_data: The response received from the API.

    :return: human readable for the command.
    :rtype: ``str``
    """
    threat_monitoring_data_copy = deepcopy(threat_monitoring_data)

    threat_monitoring_data_copy: dict = remove_typename(threat_monitoring_data_copy)  # type: ignore

    hr_content = {
        "ID": threat_monitoring_data.get("id"),
        "Name": threat_monitoring_data.get("name"),
        "Object Type": threat_monitoring_data.get("objectType"),
        "SLA Assignment": threat_monitoring_data.get("slaAssignment"),
        "Effective SLA Domain": threat_monitoring_data_copy.get("effectiveSlaDomain"),
        "SLA Pause Status": threat_monitoring_data.get("slaPauseStatus"),
        "Snapshot Distribution": threat_monitoring_data_copy.get("snapshotDistribution"),
        "Effective Retention SLA Domain": threat_monitoring_data_copy.get("effectiveRetentionSlaDomain"),
        "Configured SLA Domain": threat_monitoring_data_copy.get("configuredSlaDomain"),
        "Effective SLA Source Object": threat_monitoring_data_copy.get("effectiveSlaSourceObject"),
        "Logical Path": threat_monitoring_data_copy.get("logicalPath"),
        "Physical Path": threat_monitoring_data_copy.get("physicalPath"),
        "NumWorkload Descendants": threat_monitoring_data.get("numWorkloadDescendants"),
        "All Orgs": threat_monitoring_data_copy.get("allOrgs"),
        "Security Metadata": threat_monitoring_data_copy.get("securityMetadata"),
    }

    hr = tableToMarkdown(
        "Threat Monitoring Object Details",
        hr_content,
        headers=[
            "ID",
            "Name",
            "Object Type",
            "SLA Assignment",
            "Effective SLA Domain",
            "SLA Pause Status",
            "Snapshot Distribution",
            "Effective Retention SLA Domain",
            "Configured SLA Domain",
            "Effective SLA Source Object",
            "Logical Path",
            "Physical Path",
            "NumWorkload Descendants",
            "All Orgs",
            "Security Metadata",
        ],
        json_transform_mapping={
            "Effective SLA Domain": JsonTransformer(is_nested=True),
            "Snapshot Distribution": JsonTransformer(is_nested=True),
            "Effective Retention SLA Domain": JsonTransformer(is_nested=True),
            "Configured SLA Domain": JsonTransformer(is_nested=True),
            "Effective SLA Source Object": JsonTransformer(is_nested=True),
            "Logical Path": JsonTransformer(is_nested=True),
            "Physical Path": JsonTransformer(is_nested=True),
            "All Orgs": JsonTransformer(is_nested=True),
            "Security Metadata": JsonTransformer(is_nested=True),
        },
        removeNull=True,
    )
    return hr


def validate_threat_monitoring_matched_file_list_command_args(object_id: Optional[Any], limit: Optional[int]):
    """
    Validate the arguments of the rubrik-threat-monitoring-matched-file-list command.

    :type object_id: ``Optional[Any]``
    :param object_id: The object ID for the threat monitoring object.

    :type limit: ``Optional[int]``
    :param limit: The number of results to return.
    """
    validate_required_arg("object_id", object_id)
    if not limit or not 1 <= limit <= MAXIMUM_PAGINATION_LIMIT:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))


def prepare_context_hr_threat_monitoring_matched_file_list(edges: list) -> tuple[list, str]:
    """
    Prepare context and human-readable output for matched file list.

    :type edges: ``list``
    :param edges: edges from the response received from the API.

    :return: context and human-readable for the command.
    :rtype: ``tuple[list, str]``
    """
    context = []
    hr_rows = []
    for edge in edges:
        node = edge.get("node", {})
        context.append(remove_empty_elements(node))
        hr_rows.append(
            {
                "File Name": node.get("fileName"),
                "File Path": node.get("filepath"),
                "File Size": node.get("fileSize"),
                "Matched Snapshot ID": node.get("matchedSnapshotFid"),
                "Matched Snapshot Date": node.get("matchedSnapshotDate"),
                "Matched Snapshot Expired": node.get("isMatchedSnapshotExpired"),
            }
        )
    hr = tableToMarkdown(
        "Threat Monitoring File List",
        hr_rows,
        headers=[
            "File Name",
            "File Path",
            "File Size",
            "Matched Snapshot ID",
            "Matched Snapshot Date",
            "Matched Snapshot Expired",
        ],
        removeNull=True,
    )
    return context, hr


def validate_threat_monitoring_matched_file_get_command_args(matched_snapshot_id: str, file_path: str):
    """
    Validate the arguments of the rubrik-threat-monitoring-matched-file-get command.

    :type matched_snapshot_id: ``str``
    :param matched_snapshot_id: The ID of the snapshot to search for.

    :type file_path: ``str``
    :param file_path: The path of the file to search for.
    """
    if not matched_snapshot_id and not file_path:
        raise ValueError(ERROR_MESSAGES["MISSING_TWO_REQUIRED_FIELD"].format("matched_snapshot_id", "file_path"))
    validate_required_arg("matched_snapshot_id", matched_snapshot_id)
    validate_required_arg("file_path", file_path)


def prepare_context_hr_threat_monitoring_matched_file_get(file_details: Dict[str, Any]) -> str:
    """
    Prepare context and human-readable output for rubrik-threat-monitoring-matched-file-get command.

    :type file_details: ``Dict[str, Any]``
    :param file_details: File details from the API response.

    :return: A human-readable output.
    :rtype: ``str``
    """
    file_hashes = {
        "MD5": file_details.get("matchedFileMd5"),
        "SHA1": file_details.get("matchedFileSha1"),
        "SHA256": file_details.get("matchedFileSha256"),
    }

    # Add IOC Details if available
    ioc_details = deepcopy(file_details.get("iocDetails", []))
    ioc_details = remove_typename(ioc_details)

    # Prepare human readable output
    hr_content = {
        "File Name": file_details.get("fileName"),
        "File Path": file_details.get("filePath"),
        "File Hashes": file_hashes,
        "IOC Details": ioc_details,
        "First Detected Snapshot FID": file_details.get("firstDetectedSnapshotFid"),
        "Detected Snapshot Date": file_details.get("detectedSnapshotDate"),
        "Quarantined In First Observed Snapshot": file_details.get("isQuarantinedInFirstObservedSnapshot"),
    }

    hr = tableToMarkdown(
        "Threat Monitoring File Details",
        hr_content,
        headers=[
            "File Name",
            "File Path",
            "File Hashes",
            "IOC Details",
            "First Detected Snapshot FID",
            "Detected Snapshot Date",
            "Quarantined In First Observed Snapshot",
        ],
        json_transform_mapping={
            "File Hashes": JsonTransformer(is_nested=True),
            "IOC Details": JsonTransformer(is_nested=True),
        },
        removeNull=True,
    )

    return hr


def validate_comman_fetch_params(max_fetch: Optional[int], fetch_types: list):
    """
    Validate the arguments of the fetch commands.

    :type max_fetch: ``Optional[int]``
    :param max_fetch: The maximum number of incidents to fetch.

    :type fetch_type: ``list``
    :param fetch_type: The type of incidents to fetch.

    :return: None
    """
    if any(fetch_type not in DEFAULT_FETCH_TYPE for fetch_type in fetch_types):
        raise ValueError(MESSAGES["INVALID_FETCH_TYPE"])

    if (THREAT_MONITORING_FETCH_TYPE in fetch_types) and (not max_fetch or not MAX_FETCH_MIN <= max_fetch <= MAX_FETCH_MAX):
        raise ValueError(ERROR_MESSAGES["INVALID_MAX_FETCH"])


def validate_ioc_scan_list_v2_command_args(
    limit: Optional[int], ioc_match: Optional[list], quarantine_status: Optional[list], hunt_status: Optional[list]
):
    """
    Validate the arguments of the IOC scan list v2 command.

    :type limit: ``Optional[int]``
    :param limit: Limit value.

    :type ioc_match: ``Optional[list]``
    :param ioc_match: List of IOC match values.

    :type quarantine_status: ``Optional[list]``
    :param quarantine_status: List of quarantine status values.

    :type hunt_status: ``Optional[list]``
    :param hunt_status: List of hunt status values.

    :return: None
    :raises ValueError: If any argument is invalid.
    """
    if not limit or not 1 <= limit <= MAXIMUM_PAGINATION_LIMIT:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))

    if ioc_match:
        for i_match in ioc_match:
            if i_match not in IOC_MATCHES:
                raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(i_match, "ioc_match", IOC_MATCHES))

    if quarantine_status:
        for q_status in quarantine_status:
            if q_status not in QUERANTINE_STATUS:
                raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(q_status, "quarantine_status", QUERANTINE_STATUS))

    if hunt_status:
        for h_status in hunt_status:
            if h_status not in HUNT_STATUSES:
                raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(h_status, "hunt_status", HUNT_STATUSES))


def prepare_context_hr_ioc_scan_v2_list(edges: list) -> tuple:
    """
    Prepare context and human readable output for IOC scan list.

    :type edges: ``list``
    :param edges: List of edges from GraphQL response.

    :return: Tuple of context and human readable output.
    """
    hr_content = []
    context = []

    for edge in edges:
        node = edge.get("node", {})
        node = remove_empty_elements(node)
        context.append(node)
        hr_content.append(
            {
                "Hunt ID": node.get("huntId"),
                "Hunt Name": node.get("huntName"),
                "Hunt Type": node.get("huntType"),
                "Status": node.get("status"),
                "Start Time": node.get("startTime"),
            }
        )

    hr = tableToMarkdown(
        "IOC Scan List",
        hr_content,
        headers=[
            "Hunt ID",
            "Hunt Name",
            "Hunt Type",
            "Status",
            "Start Time",
        ],
        removeNull=True,
    )

    return context, hr


def prepare_hr_ioc_scan_results_v2(ioc_scan_data: dict) -> str:
    """
    Prepare human readable response for rubrik-ioc-scan-results-v2.

    :type ioc_scan_data: ``dict``
    :param ioc_scan_data: ioc scan data from the response received from the API.

    :return: human readable for the command.
    :rtype: ``str``
    """
    hr_content = []
    ioc_scan_data = deepcopy(ioc_scan_data)
    basic_config = ioc_scan_data.get("baseConfig", {})

    ioc_details = remove_typename(basic_config.get("ioc", {}).get("iocList", {}).get("indicatorsOfCompromise", []))
    object_metric = remove_typename(ioc_scan_data.get("threatHuntObjectMetrics", {}))
    scan_metric = {
        "totalMatchedSnapshots": ioc_scan_data.get("totalMatchedSnapshots"),
        "totalScannedSnapshots": ioc_scan_data.get("totalScannedSnapshots"),
        "totalUniqueFileMatches": ioc_scan_data.get("totalUniqueFileMatches"),
    }

    hr_content.append(
        {
            "Hunt Name": basic_config.get("name"),
            "Hunt Type": basic_config.get("threatHuntType"),
            "Status": ioc_scan_data.get("status"),
            "IOC Details": ioc_details,
            "Object Metrics": object_metric,
            "Scan Metrics": scan_metric,
            "Start Time": ioc_scan_data.get("startTime"),
            "End Time": ioc_scan_data.get("endTime"),
        }
    )
    hr = tableToMarkdown(
        "IOC Scan Data",
        hr_content,
        headers=[
            "Hunt Name",
            "Hunt Type",
            "Status",
            "IOC Details",
            "Object Metrics",
            "Scan Metrics",
            "Start Time",
            "End Time",
        ],
        json_transform_mapping={
            "IOC Details": JsonTransformer(is_nested=True),
            "Object Metrics": JsonTransformer(is_nested=True),
            "Scan Metrics": JsonTransformer(is_nested=True),
        },
        removeNull=True,
    )
    return hr


def validate_turbo_ioc_scan_command_args(ioc: list, max_snapshots_per_object: Optional[int]):
    """
    Validate the arguments of the turbo ioc scan command.

    :type ioc: ``list``
    :param ioc: list of IOC values.

    :type max_snapshots_per_object: ``Optional[int]``
    :param max_snapshots_per_object: The max snapshots per object value.

    :return: None
    """
    if not ioc:
        raise ValueError(ERROR_MESSAGES["MISSING_REQUIRED_FIELD"].format("ioc"))
    if max_snapshots_per_object is not None and max_snapshots_per_object < 1:
        raise ValueError(ERROR_MESSAGES["NEGATIVE_ARG_VALUE"].format(max_snapshots_per_object, "max_snapshots_per_object"))
    if max_snapshots_per_object is not None and max_snapshots_per_object > MAX_INT_VALUE:
        raise ValueError(
            ERROR_MESSAGES["INVALID_INT_VALUE"].format(max_snapshots_per_object, "max_snapshots_per_object", MAX_INT_VALUE)
        )


def prepare_ioc_and_validate_advance_ioc_scan_args(
    ioc_type: Any,
    ioc_value: Any,
    advance_ioc: Any,
    max_matches_per_snapshot: Optional[int],
    max_snapshots_per_object: Optional[int],
    min_file_size: Optional[int],
    max_file_size: Optional[int],
) -> list:
    """
    Prepare and validate the arguments of the advance ioc scan command.

    :type ioc_type: ``Any``
    :param ioc_type: Type of IOC.

    :type ioc_value: ``Any``
    :param ioc_value: Value of IOC.

    :type advance_ioc: ``Any``
    :param advance_ioc: Advance IOC.

    :type max_matches_per_snapshot: ``Optional[int]``
    :param max_matches_per_snapshot: Maximum matches per snapshot.

    :type max_snapshots_per_object: ``Optional[int]``
    :param max_snapshots_per_object: Maximum snapshots per object.

    :type min_file_size: ``Optional[int]``
    :param min_file_size: Minimum file size.

    :type max_file_size: ``Optional[int]``
    :param max_file_size: Maximum file size.

    :return: List of IOCs.
    :rtype: ``list``
    """
    if ioc_type and ioc_type not in IOC_TYPE_ENUM:
        raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(ioc_type, "ioc_type", IOC_TYPE_ENUM))

    if not (ioc_type and ioc_value) and not advance_ioc:
        raise ValueError(ERROR_MESSAGES["NO_INDICATOR_SPECIFIED"])

    if max_matches_per_snapshot is not None and max_matches_per_snapshot < 1:
        raise ValueError(ERROR_MESSAGES["NEGATIVE_ARG_VALUE"].format(max_matches_per_snapshot, "max_matches_per_snapshot"))
    if max_matches_per_snapshot is not None and max_matches_per_snapshot > MAX_INT_VALUE:
        raise ValueError(
            ERROR_MESSAGES["INVALID_INT_VALUE"].format(max_matches_per_snapshot, "max_matches_per_snapshot", MAX_INT_VALUE)
        )
    if max_snapshots_per_object is not None and max_snapshots_per_object < 1:
        raise ValueError(ERROR_MESSAGES["NEGATIVE_ARG_VALUE"].format(max_snapshots_per_object, "max_snapshots_per_object"))
    if max_snapshots_per_object is not None and max_snapshots_per_object > MAX_INT_VALUE:
        raise ValueError(
            ERROR_MESSAGES["INVALID_INT_VALUE"].format(max_snapshots_per_object, "max_snapshots_per_object", MAX_INT_VALUE)
        )
    if min_file_size is not None and min_file_size < 1:
        raise ValueError(ERROR_MESSAGES["NEGATIVE_ARG_VALUE"].format(min_file_size, "min_file_size"))
    if min_file_size is not None and min_file_size > MAX_LONG_VALUE:
        raise ValueError(ERROR_MESSAGES["INVALID_INT_VALUE"].format(min_file_size, "min_file_size", MAX_LONG_VALUE))
    if max_file_size is not None and max_file_size < 1:
        raise ValueError(ERROR_MESSAGES["NEGATIVE_ARG_VALUE"].format(max_file_size, "max_file_size"))
    if max_file_size is not None and max_file_size > MAX_LONG_VALUE:
        raise ValueError(ERROR_MESSAGES["INVALID_INT_VALUE"].format(max_file_size, "max_file_size", MAX_LONG_VALUE))

    iocs = []
    if advance_ioc:
        try:
            advance_ioc_dict = json.loads(advance_ioc)
            for ioc_type, ioc_values in advance_ioc_dict.items():
                if isinstance(ioc_values, list):
                    for value in ioc_values:
                        iocs.append({"iocKind": IOC_TYPE_MAPPING.get(ioc_type), "iocValue": value})
                else:
                    iocs.append({"iocKind": IOC_TYPE_MAPPING.get(ioc_type), "iocValue": ioc_values})
        except json.JSONDecodeError:
            raise ValueError(ERROR_MESSAGES["JSON_DECODE"].format("advance_ioc"))
    else:
        iocs.append({"iocKind": IOC_TYPE_MAPPING.get(ioc_type), "iocValue": ioc_value})

    return iocs


""" COMMAND FUNCTIONS """


def test_module(client: PolarisClient, params: Dict[str, Any]) -> str:
    """Tests validity of provided parameters'.

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``PolarisClient``
    :param client: Rubrik polaris client to use

    :type params: ``dict``
    :param params: params obtained from demisto.params()

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """
    is_fetch = params.get("isFetch", DEFAULT_IS_FETCH)

    client._query_raw(raw_query=DEPLOYMENT_VERSION_QUERY, operation_name="DeploymentVersionQuery", variables={}, timeout=60)
    if is_fetch:
        fetch_incidents(client, {}, params)

    return "ok"


def fetch_events(client: PolarisClient, last_run: dict, params: dict, max_fetch: Optional[int]) -> tuple[dict, list]:
    """
    Fetch Rubrik Anomaly incidents.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type last_run: ``dict``
    :param last_run: last run object obtained from demisto.getLastRun()

    :type params: ``dict``
    :param params: arguments obtained from demisto.params()

    :type max_fetch: ``Optional[int]``
    :param max_fetch: The maximum number of incidents to fetch.

    :return: tuple of next run object and list of incidents
    :rtype: ``tuple[dict, list]``
    """
    event_types = argToList(params.get("event_types"), transform=lambda s: s.strip())
    event_severities = argToList(params.get("event_severities"), transform=lambda s: s.strip())

    event_types = [event_type.upper() for event_type in event_types if event_type]
    event_severities = [event_severity.upper() for event_severity in event_severities if event_severity]

    if not event_types:
        event_types = DEFAULT_EVENT_TYPES
    elif any(event_type not in DEFAULT_EVENT_TYPES for event_type in event_types):
        raise ValueError(MESSAGES["INVALID_FETCH_EVENT_TYPE"])

    if not event_severities:
        event_severities = DEFAULT_SEVERITIES
    elif any(event_severity not in DEFAULT_EVENT_SEVERITIES for event_severity in event_severities):
        raise ValueError(MESSAGES["INVALID_FETCH_EVENT_SEVERITIES"])

    event_last_run = last_run
    last_run_time = event_last_run.get("last_fetch", None)
    next_page_token = event_last_run.get("next_page_token", "")

    evnet_next_run = event_last_run.copy()

    if last_run_time is None:
        # if the last run has not been set (i.e on the first run)
        # check to see if a first_fetch value has been provided. If it hasn't
        # return the current time
        first_fetch = params.get("first_fetch", DEFAULT_FIRST_FETCH)
        first_fetch = arg_to_datetime(first_fetch, "First fetch time")
        last_run_time = first_fetch.strftime(DATE_TIME_FORMAT)  # type: ignore
        evnet_next_run["last_fetch"] = last_run_time
    # removed manual fetch interval as this feature is built in XSOAR 6.0.0 and onwards

    filters = {"lastActivityStatus": DEFAULT_ACTIVITY_STATUSES, "severity": event_severities}

    events = client.list_event_series(
        activity_type=",".join(event_types),
        start_date=last_run_time,
        sort_order="ASC",
        first=max_fetch,
        after=next_page_token,
        filters=filters,
    )

    activity_series_connection = events.get("data", {}).get("activitySeriesConnection", {})

    new_next_page_token = activity_series_connection.get("pageInfo", {}).get("endCursor", "")
    if new_next_page_token:
        evnet_next_run["next_page_token"] = new_next_page_token

    incidents = []

    edges = activity_series_connection.get("edges", [])
    for event in edges:
        processed_incident = {"incidentClassification": "RubrikRadar", "message": [], "severity": IncidentSeverity.UNKNOWN}
        node = event.get("node", {})

        processed_incident.update(node)
        processed_incident["eventCompleted"] = "True" if node.get("lastActivityStatus", "") == "Success" else False
        activity_connection = node.get("activityConnection", {})
        activity_nodes = activity_connection.get("nodes", [])
        processed_incident = process_activity_nodes(activity_nodes, processed_incident)

        base_url = str(client._baseurl).removesuffix("api")
        activity_series_id = node.get("activitySeriesId", "")
        cluster_id = node.get("cluster", {}).get("id", "")
        processed_incident["incident_link"] = EVENT_HYPERLINK.format(base_url, activity_series_id, cluster_id)

        # Map Severity Level
        severity = node.get("severity", "")
        if severity == "Critical" or severity == "Warning":
            if params.get(f"radar_{severity.lower()}_severity_mapping"):
                severity_mapping = params.get(f"radar_{severity.lower()}_severity_mapping", "XSOAR LOW")
            else:
                severity_mapping = "XSOAR LOW"

            processed_incident["severity"] = convert_to_demisto_severity(severity_mapping)

        else:
            processed_incident["severity"] = IncidentSeverity.LOW

        incidents.append(
            {
                "name": f"Rubrik Radar Anomaly - {processed_incident.get('objectName', '')}",
                "occurred": processed_incident.get("lastUpdated", ""),
                "rawJSON": json.dumps(processed_incident),
                "severity": processed_incident["severity"],
            }
        )
    return evnet_next_run, incidents


def fetch_threat_monitoring_objects(
    client: PolarisClient, last_run: dict, params: dict, max_fetch: Optional[int]
) -> tuple[dict, list]:
    """
    Fetch Rubrik threat monitoring objects as incidents.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type last_run: ``dict``
    :param last_run: last run object obtained from demisto.getLastRun()

    :type params: ``dict``
    :param params: arguments obtained from demisto.params()

    :type max_fetch: ``Optional[int]``
    :param max_fetch: The maximum number of incidents to fetch.

    :return: tuple of next run object and list of incidents
    :rtype: ``tuple[dict, list]``
    """
    match_types = argToList(params.get("threat_monitoring_match_types"), transform=lambda s: s.strip())
    object_types = argToList(params.get("threat_monitoring_object_types"), transform=lambda s: s.strip())

    threat_monitoring_last_run = last_run.get("threat_monitoring", {})
    last_run_time = threat_monitoring_last_run.get("last_fetch", None)
    next_page_token = threat_monitoring_last_run.get("next_page_token", "")
    match_type_filter = threat_monitoring_last_run.get("match_type_filter", [])
    object_type_filter = threat_monitoring_last_run.get("object_type_filter", [])
    already_fetched = threat_monitoring_last_run.get("already_fetched", [])

    threat_monitoring_next_run = threat_monitoring_last_run.copy()

    if last_run_time is None:
        # if the last run has not been set (i.e on the first run)
        # check to see if a first_fetch value has been provided. If it hasn't
        # return the current time
        first_fetch = params.get("first_fetch", DEFAULT_FIRST_FETCH)
        first_fetch = arg_to_datetime(first_fetch, "First fetch time")
        last_run_time = first_fetch.strftime(DATE_TIME_FORMAT)  # type: ignore
        threat_monitoring_next_run["last_fetch"] = last_run_time

    for match_type in match_types:
        if match_type not in IOC_TYPE_ENUM:
            raise ValueError(ERROR_MESSAGES["INVALID_SELECT"].format(match_type, "match_type", IOC_TYPE_ENUM))

    ioc_match_type = []
    for match_type in match_types:
        ioc_match_type.append(IOC_TYPE_MAPPING.get(match_type))

    ioc_match_type.sort()
    if isinstance(object_types, list):
        object_types.sort()
    if ioc_match_type != match_type_filter or object_types != object_type_filter:
        next_page_token = ""

    threat_monitoring_filters = {
        "matchTypeFilter": ioc_match_type,
        "objectTypeFilter": object_types,
        "after": next_page_token,
        "beginTime": last_run_time,
        "first": max_fetch,
    }

    remove_nulls_from_dictionary(threat_monitoring_filters)

    threat_monitoring_response = client._query_raw(
        raw_query=THREAT_MONITORING_MATCHED_OBJECT_LIST_QUERY,
        operation_name="ThreatMonitoringMatchedObjectsQuery",
        variables=threat_monitoring_filters,
        timeout=60,
    )

    edges = []
    page_info = {}
    threat_monitoring_data = threat_monitoring_response.get("data", {})
    if threat_monitoring_data is not None:
        edges = threat_monitoring_data.get("threatMonitoringMatchedObjects", {}).get("edges", [])
        page_info = threat_monitoring_data.get("threatMonitoringMatchedObjects", {}).get("pageInfo", {})

    page_cursor = remove_empty_elements(page_info)
    new_next_page_token = page_cursor.get("endCursor")
    if new_next_page_token:
        threat_monitoring_next_run["next_page_token"] = new_next_page_token

    if params.get("threat_monitoring_severity_mapping"):
        severity_mapping = params.get("threat_monitoring_severity_mapping", "XSOAR HIGH")
    else:
        severity_mapping = "XSOAR HIGH"

    incident_severity = convert_to_demisto_severity(severity_mapping)

    incidents = []

    for threat_object in edges:
        node = threat_object.get("node", {})

        if node.get("objectFid") in already_fetched:
            continue
        already_fetched.append(node.get("objectFid"))

        processed_incident = {
            "incidentClassification": "RubrikThreatMonitoringObject",
            "message": [],
            "severity": incident_severity,
        }
        processed_incident.update(node)

        base_url = str(client._baseurl).removesuffix("api")
        processed_incident["incident_link"] = THREAT_MONITORING_HYPERLINK.format(base_url, node.get("objectFid", ""))

        incidents.append(
            {
                "name": f"Rubrik Radar Threat Monitoring Object - {processed_incident.get('objectName', '')}",
                "occurred": processed_incident.get("lastDetection", ""),
                "rawJSON": json.dumps(processed_incident),
                "severity": processed_incident.get("severity"),
            }
        )

    threat_monitoring_next_run["match_type_filter"] = ioc_match_type
    threat_monitoring_next_run["object_type_filter"] = object_types
    threat_monitoring_next_run["already_fetched"] = already_fetched
    return threat_monitoring_next_run, incidents


def fetch_incidents(client: PolarisClient, last_run: dict, params: dict) -> tuple[dict, list]:
    """
    Fetch Rubrik Anomaly incidents.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type last_run: ``dict``
    :param last_run: last run object obtained from demisto.getLastRun()

    :type params: ``dict``
    :param params: arguments obtained from demisto.params()

    :return: tuple of next run object and list of incidents
    :rtype: ``tuple[dict, list]``
    """
    max_fetch = arg_to_number(params.get("max_fetch", DEFAULT_MAX_FETCH), "Fetch Limit")
    fetch_types = argToList(params.get("rsc_fetch_types", DEFAULT_FETCH_TYPE), transform=lambda s: s.strip().lower())

    validate_comman_fetch_params(max_fetch, fetch_types)

    total_incidents = []
    next_run = last_run
    if fetch_types == [EVENT_FETCH_TYPE]:
        evnet_next_run, incidents = fetch_events(client, last_run, params, max_fetch)
        total_incidents.extend(incidents)
        next_run = evnet_next_run
    elif fetch_types == [THREAT_MONITORING_FETCH_TYPE]:
        threat_monitoring_next_run, incidents = fetch_threat_monitoring_objects(client, last_run, params, max_fetch)
        total_incidents.extend(incidents)
        next_run["threat_monitoring"] = threat_monitoring_next_run
    else:
        new_max_fetch = max_fetch // 2  # type: ignore
        threat_monitoring_next_run, incidents = fetch_threat_monitoring_objects(client, last_run, params, new_max_fetch)
        total_incidents.extend(incidents)
        new_max_fetch = max_fetch - len(incidents)  # type: ignore
        evnet_next_run, incidents = fetch_events(client, last_run, params, new_max_fetch)
        total_incidents.extend(incidents)
        evnet_next_run["threat_monitoring"] = threat_monitoring_next_run
        next_run = evnet_next_run
    return next_run, total_incidents


def cdm_cluster_location_command(client: PolarisClient, args: Dict[str, Any]):
    """
    Find the CDM GeoLocation of a CDM Cluster.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    cluster_id = validate_required_arg("clusterId", args.get("clusterId"))

    raw_response = client.get_cdm_cluster_location(cluster_id)

    if raw_response == "No Location Configured":
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    hr_content = {"Location": raw_response}
    hr = tableToMarkdown("CDM Cluster Location", hr_content, headers="Location", removeNull=True)

    context = {"ClusterId": cluster_id.lower(), "Cluster": {"Location": raw_response}}

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["CDM_CLUSTER"],
        outputs_key_field="ClusterId",
        readable_output=hr,
        outputs=context,
        raw_response=raw_response,
    )


def cdm_cluster_connection_state_command(client: PolarisClient, args: Dict[str, Any]):
    """
    Find the CDM Connection State of a CDM Cluster.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    cluster_id = validate_required_arg("clusterId", args.get("clusterId"))

    raw_response = client.get_cdm_cluster_connection_status(cluster_id)

    hr_content = {"Connection State": raw_response}
    hr = tableToMarkdown("CDM Cluster Connection State", hr_content, headers="Connection State", removeNull=True)

    context = {"ClusterId": cluster_id.lower(), "Cluster": {"ConnectionState": raw_response}}

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["CDM_CLUSTER"],
        outputs_key_field="ClusterId",
        readable_output=hr,
        outputs=context,
        raw_response=raw_response,
    )


def radar_analysis_status_command(client: PolarisClient, args: Dict[str, Any]):
    """
    Check the Radar Event for updates.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    activity_series_id = validate_required_arg("activitySeriesId", args.get("activitySeriesId"))
    cluster_id = validate_required_arg("clusterId", args.get("clusterId"))

    raw_response = client.get_analysis_status(activity_series_id, cluster_id)

    activity_series = raw_response.get("data", {}).get("activitySeries", {})
    if not activity_series.get("activityConnection", {}).get("nodes", []):
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("radar analysis status"))

    context, hr = prepare_context_hr_radar_analysis_status(activity_series, activity_series_id, cluster_id)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["RADAR_ANALYSIS_STATUS"],
        outputs_key_field="ActivitySeriesId",
        readable_output=hr,
        outputs=context,
        raw_response=raw_response,
    )


def sonar_sensitive_hits_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Collect sensitive hits object information.

    :type client: PolarisClient
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    incident = demisto.incidents("CustomFields")

    # objectName is an optional value for the command. When not set,
    # look up the value in the incident custom fields
    object_name = args.get("objectName", None)
    if not object_name:
        try:
            object_name = incident.get("rubrikpolarisobjectname")
        except AttributeError:
            pass

    search_time_period = arg_to_number(args.get("searchTimePeriod", 7))
    response = client.get_sensitive_hits(search_time_period=search_time_period, object_name=object_name)
    data = response.get("data", {}).get("policyObj")
    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("sensitive hits"))

    context, hr = prepare_context_hr_sonar_sensitive_hits(data)
    headers = ["ID", "Total Hits"]
    readable_output = tableToMarkdown(name="Sensitive Hits", t=hr, headers=headers, removeNull=True)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["SONAR_SENSITIVE_HITS"],
        outputs_key_field="id",
        outputs=context,
        raw_response=response,
        readable_output=readable_output,
    )


def rubrik_polaris_object_search_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Search for Rubrik discovered objects of any type, return zero or more matches.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    sort_by = args.get("sort_by", DEFAULT_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)
    object_name = validate_required_arg("object_name", args.get("object_name"))

    if not limit or limit <= 0 or limit > 1000:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))
    filters = {"field": "REGEX", "texts": object_name}
    next_page_token = args.get("next_page_token")
    response = client.search_object(filters=filters, first=limit, sort_by=sort_by, sort_order=sort_order, after=next_page_token)

    edges = response.get("data", {}).get("globalSearchResults", {}).get("edges", {})
    if not edges:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("global search objects"))

    context, hr = prepare_context_hr_object_search(edges)
    table_name = "Global Objects"
    header = [OBJECT_ID, OBJECT_NAME, "Cluster", "Type", SLA_DOMAIN]

    page_cursor = response.get("data", {}).get("globalSearchResults", {}).get("pageInfo", {})
    next_page_context = {
        "next_page_token": page_cursor.get("endCursor", ""),
        "name": "rubrik-polaris-object-search",
        "has_next_page": page_cursor.get("hasNextPage", ""),
    }
    if next_page_context.get("has_next_page"):
        readable_output = (
            f"{tableToMarkdown(table_name, hr, header, removeNull=True)}\n "
            f"{MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}"
            ""
        )
    else:
        readable_output = tableToMarkdown(table_name, hr, header, removeNull=True)

    outputs = {
        f"{OUTPUT_PREFIX['GLOBAL_SEARCH']}(val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_GLOBAL_SEARCH']}(val.name == obj.name)": remove_empty_elements(next_page_context),
    }

    return CommandResults(outputs=outputs, raw_response=response, readable_output=readable_output)


def rubrik_sonar_policies_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    List available policies in Rubrik Polaris - Sonar.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    raw_response = client.list_policies()
    nodes = raw_response.get("data", {}).get("policies", {}).get("nodes", [])
    if not nodes:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("sonar policies"))
    context, hr = prepare_context_hr_sonar_policies(nodes)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["SONAR_POLICIES_LIST"],
        outputs_key_field="id",
        readable_output=hr,
        outputs=context,
        raw_response=raw_response,
    )


def rubrik_sonar_policy_analyzer_groups_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    List available analyzer group policies in Rubrik Polaris - Sonar.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    raw_response = client.list_policy_analyzer_groups()
    nodes = raw_response.get("data", {}).get("analyzerGroups", {}).get("nodes", [])
    if not nodes:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("sonar policy analyzer groups"))
    context, hr = prepare_context_hr_sonar_policy_analyzer_groups(nodes)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["SONAR_ANALYZER_GROUP"],
        outputs_key_field="id",
        readable_output=hr,
        outputs=context,
        raw_response=raw_response,
    )


def rubrik_sonar_ondemand_scan_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Request/Trigger an on demand scan of a system in Rubrik Polaris - Sonar.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    scan_name = args.get("scan_name", "")
    snappable_ids = argToList(args.get("objects_to_scan", ""))
    analyzer_groups = args.get("sonar_policy_analyzer_groups")

    if not scan_name:
        scan_name = date.today().strftime("%m/%d/%Y") + " Classification"

    snappable_ids = validate_required_arg("objects_to_scan", snappable_ids)
    analyzer_groups = validate_required_arg("sonar_policy_analyzer_groups", analyzer_groups)

    try:
        analyzer_groups_list = json.loads(analyzer_groups)
        analyzer_groups_list = validate_required_arg("sonar_policy_analyzer_groups", analyzer_groups_list)
    except json.JSONDecodeError:
        raise ValueError(ERROR_MESSAGES["JSON_DECODE"].format("sonar_policy_analyzer_groups"))

    raw_response = client.trigger_on_demand_scan(
        scan_name, [{"snappableFid": snappable_id} for snappable_id in snappable_ids], analyzer_groups_list
    )

    outputs = raw_response.get("data", {}).get("startCrawl", {})
    if not outputs:
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    hr_content = {"Crawl ID": outputs.get("crawlId", "")}
    hr = tableToMarkdown("Sonar On-Demand Scan", hr_content, headers="Crawl ID", removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["SONAR_ON_DEMAND_SCAN"],
        outputs_key_field="crawlId",
        readable_output=hr,
        outputs=outputs,
        raw_response=raw_response,
    )


def rubrik_polaris_vm_object_metadata_get_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve details for a Vsphere object based on the provided object ID.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResults object
    """
    object_id = validate_required_arg("object_id", args.get("object_id"))

    response = client.get_object_metadata(object_id=object_id)

    data = response.get("data", {}).get("vSphereDetailData", {})

    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vm object metadata"))

    context, hr = prepare_context_hr_vm_object_metadata(data)
    table_name = "VM Object Data"
    header = [
        OBJECT_ID,
        "Name",
        SNAPPABLE_ID,
        SLA_DOMAIN,
        CLUSTER_NAME,
        "Total Snapshots",
        "Oldest Snapshot Date",
        "Latest Snapshot Date",
    ]

    readable_output = tableToMarkdown(table_name, hr, header, removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["VM_OBJECT"],
        outputs_key_field="id",
        outputs=context,
        raw_response=response,
        readable_output=readable_output,
    )


def rubrik_polaris_vm_objects_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve a list of all the objects of the Vsphere Vm known to the Rubrik.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    if not limit or limit <= 0 or limit > 1000:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))
    sort_by = args.get("sort_by", DEFAULT_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)
    is_relic = args.get("is_relic")
    is_replicated = args.get("is_replicated")
    filters = []
    if is_relic:
        is_relic = validate_boolean_argument(is_relic, "is_relic")
        filters.append({"field": "IS_RELIC", "texts": [str(is_relic)]})
    if is_replicated:
        is_replicated = validate_boolean_argument(is_replicated, "is_replicated")
        filters.append({"field": "IS_REPLICATED", "texts": [str(is_replicated)]})
    next_page_token = args.get("next_page_token")
    response = client.list_vm_objects(filters=filters, first=limit, sort_by=sort_by, sort_order=sort_order, after=next_page_token)

    edges = response.get("data", {}).get("vSphereVmNewConnection", {}).get("edges", {})
    if not edges:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vm objects list"))

    context, hr = prepare_context_hr_vm_object_list(edges)
    table_name = "Objects List"
    header = [
        OBJECT_ID,
        "Name",
        SNAPPABLE_ID,
        "Cluster",
        OBJECT_TYPE,
        SLA_DOMAIN,
        "Assignment",
        "Snapshots",
        "RBS Status",
        "Source Storage",
        "Archival Storage",
    ]

    page_cursor = response.get("data", {}).get("vSphereVmNewConnection", {}).get("pageInfo", {})
    next_page_context = {
        "next_page_token": page_cursor.get("endCursor", ""),
        "name": "rubrik-polaris-vm-objects-list",
        "has_next_page": page_cursor.get("hasNextPage", ""),
    }
    if next_page_context.get("has_next_page"):
        readable_output = (
            f"{tableToMarkdown(table_name, hr, header, removeNull=True)}\n "
            f"{MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}"
            ""
        )
    else:
        readable_output = tableToMarkdown(table_name, hr, header, removeNull=True)

    outputs = {
        f"{OUTPUT_PREFIX['VM_OBJECT']}(val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_VM_OBJECT']}(val.name == obj.name)": remove_empty_elements(next_page_context),
    }

    return CommandResults(outputs=outputs, raw_response=response, readable_output=readable_output)


def rubrik_polaris_vm_object_snapshot_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Search for a Rubrik snapshot of an object based on the arguments.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    object_id = validate_required_arg("object_id", args.get("object_id"))

    start_date = end_date = ""
    start_date_ob = arg_to_datetime(validate_required_arg("start_date", args.get("start_date")))
    if start_date_ob:
        start_date = start_date_ob.strftime(DATE_TIME_FORMAT)

    end_date_ob = arg_to_datetime(validate_required_arg("end_date", args.get("end_date")))
    if end_date_ob:
        end_date = end_date_ob.strftime(DATE_TIME_FORMAT)

    timezone_offset = validate_required_arg("timezone_offset", args.get("timezone_offset"))
    cluster_connected = args.get("cluster_connected", DEFAULT_CLUSTER_CONNECTED)
    if cluster_connected:
        cluster_connected = validate_boolean_argument(cluster_connected, "cluster_connected")

    snapshot_group_by = args.get("snapshot_group_by", DEFAULT_SNAPSHOT_GROUP_BY)
    missed_snapshot_by = args.get("missed_snapshot_group_by", DEFAULT_MISSED_SNAPSHOT_GROUP_BY)
    time_range = {"start": start_date, "end": end_date}
    response = client.get_object_snapshot(
        snapshot_group_by=snapshot_group_by,
        missed_snapshot_group_by=missed_snapshot_by,
        object_id=object_id,
        time_range=time_range,
        timezone_offset=timezone_offset,
        cluster_connected=cluster_connected,
    )

    data = response.get("data", {}).get("snappable", {})
    if not data.get("snapshotGroupByConnection", {}).get("nodes"):
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vm object snapshots"))

    context, hr = prepare_context_hr_vm_object_snapshot(data)
    table_name = "VM Object Snapshots"
    header = ["Snapshot Details", SNAPSHOT_IDS]

    readable_output = tableToMarkdown(table_name, hr, header, removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["VM_OBJECT"],
        outputs_key_field="id",
        outputs=context,
        raw_response=response,
        readable_output=readable_output,
    )


def rubrik_sonar_ondemand_scan_status_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the status of a scanned system in Polaris Sonar.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    crawl_id = args.get("crawl_id")

    if not crawl_id:
        raise ValueError(ERROR_MESSAGES["MISSING_REQUIRED_FIELD"].format("crawl_id"))
    raw_response = client.get_on_demand_scan_status(crawl_id)
    nodes = raw_response.get("data", {}).get("crawl", {}).get("crawlObjConnection", {}).get("nodes", [])
    response_crawl_id = raw_response.get("data", {}).get("crawl", {}).get("id", "")

    if not nodes:
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    context, hr = prepare_context_hr_sonar_ondemand_scan_status(nodes, response_crawl_id)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["SONAR_ON_DEMAND_SCAN"],
        outputs_key_field="crawlId",
        readable_output=hr,
        outputs=context,
        raw_response=raw_response,
    )


def rubrik_sonar_ondemand_scan_result_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the download link for an on-demand scan of a system in Rubrik Polaris - Sonar.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    crawl_id = validate_required_arg("crawl_id", args.get("crawl_id", ""))
    file_type = validate_required_arg("file_type", args.get("file_type"))

    raw_response = client.get_on_demand_scan_result(crawl_id, {"fileType": file_type})
    outputs = raw_response.get("data", {}).get("downloadResultsCsv", {})

    if not outputs or not outputs.get("downloadLink"):
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    hr_content = {"Scan result CSV Download Link": f"Download the [CSV]({outputs.get('downloadLink')}) file to see the result."}
    hr = tableToMarkdown("Sonar On-Demand Scan Result", hr_content, headers="Scan result CSV Download Link", removeNull=True)
    context = {"crawlId": crawl_id.lower(), "Result": outputs}

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["SONAR_ON_DEMAND_SCAN"],
        outputs_key_field="crawlId",
        readable_output=hr,
        outputs=context,
        raw_response=raw_response,
    )


def rubrik_radar_anomaly_csv_analysis_command(client: PolarisClient, args: Dict[str, Any]) -> list[Union[CommandResults, Any]]:
    """
    Request for the analysis and retrieve the download link for the Radar CSV analyzed file.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    cluster_id = validate_required_arg("cluster_id", args.get("cluster_id"))
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id"))
    object_id = validate_required_arg("object_id", args.get("object_id"))
    download_file = argToBoolean(args.get("download_file", False))

    response = client.get_csv_result(cluster_id=cluster_id, snappable_id=object_id, snapshot_id=snapshot_id)

    data = response.get("data", {})
    download_data = data.get("investigationCsvDownloadLink", {})
    if not download_data:
        return [CommandResults(readable_output=MESSAGES["NO_RESPONSE"])]
    context = {"clusterId": cluster_id, "snapshotId": snapshot_id, "objectId": object_id}
    context.update(data)
    table_name = "Radar Anomaly CSV Analysis"
    hr = [f"Download the analyzed [CSV]({download_data.get('downloadLink')}) file."]
    readable_output = tableToMarkdown(table_name, hr, ["CSV Download Link"], removeNull=True)

    result = [
        CommandResults(
            outputs_prefix=OUTPUT_PREFIX["RADAR_ANOMALY_CSV_ANALYSIS"],
            outputs_key_field=["clusterId", "snapshotId", "objectId"],
            outputs=context,
            raw_response=response,
            readable_output=readable_output,
        )
    ]

    if download_file:
        file_content = requests.request("GET", download_data.get("downloadLink")).text
        extract_file_name = re.search(r"[^\/]+\.csv", download_data.get("downloadLink"))
        file_name = ""
        if extract_file_name:
            file_name = extract_file_name.group()

        file_result = fileResult(filename=file_name, data=file_content)

        result.append(file_result)

    return result


def rubrik_sonar_csv_download_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Request for the analysis and retrieve the download link for the Radar CSV analyzed file.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id"))
    object_id = validate_required_arg("object_id", args.get("object_id"))
    file_type = args.get("file_type")
    filters = None
    if file_type:
        filters = {"fileType": file_type}
    response = client.get_csv_download(snappable_id=object_id, snapshot_id=snapshot_id, filters=filters)
    data = response.get("data", {})
    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])
    context = {"snapshotId": snapshot_id, "objectId": object_id}
    context.update(data)
    table_name = "Sonar CSV Download"
    if data.get("downloadSnapshotResultsCsv", {}).get("isSuccessful"):
        hr = ["Success"]
    else:
        hr = ["Failed"]
    readable_output = tableToMarkdown(table_name, hr, ["Download Status"], removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["SONAR_CSV_DOWNLOAD"],
        outputs_key_field=["snapshotId", "objectId"],
        outputs=context,
        raw_response=response,
        readable_output=readable_output,
    )


def rubrik_gps_snapshot_files_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of the available files that can be downloaded.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id", ""))
    search_prefix = args.get("search_prefix", "")
    path = args.get("path", "")

    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    if not limit or limit <= 0 or limit > 1000:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))

    next_page_token = args.get("next_page_token")

    raw_response = client.get_snapshot_files(
        snapshot_id=snapshot_id, search_prefix=search_prefix, path=path, first=limit, after=next_page_token
    )

    outputs = raw_response.get("data", {}).get("browseSnapshotFileConnection", {}).get("edges", [])
    page_cursor = raw_response.get("data", {}).get("browseSnapshotFileConnection", {}).get("pageInfo", {})

    if not outputs:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("files"))

    context, hr = prepare_context_hr_gps_snapshot_files(outputs, snapshot_id)
    next_page_context = {
        "next_page_token": page_cursor.get("endCursor", ""),
        "name": "rubrik-gps-snapshot-files-list",
        "has_next_page": page_cursor.get("hasNextPage", ""),
    }
    outputs = {
        f"{OUTPUT_PREFIX['GPS_SNAPSHOT_FILES']}(val.snapshotId == obj.snapshotId)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_GPS_SNAPSHOT_FILES']}(val.name == obj.name)": remove_empty_elements(next_page_context),
    }
    if page_cursor.get("hasNextPage"):
        hr += f"{MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}"

    return CommandResults(readable_output=hr, outputs=outputs, raw_response=raw_response)


def rubrik_gps_vm_export_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Request to initiate an export of a snapshot of a virtual machine.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    config, object_id = validate_vm_export_args(args)

    raw_response = client.export_vm_snapshot(config, object_id)
    outputs = raw_response.get("data", {})

    if not outputs:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vm export"))

    snapshot_export_request_id = outputs.get("vSphereVMExportSnapshotV2", {}).get("id", "")
    hr_content = {"Snapshot Export Request ID": snapshot_export_request_id}
    hr = tableToMarkdown("GPS VM Export", hr_content, headers="Snapshot Export Request ID", removeNull=True)

    context = {"id": snapshot_export_request_id}

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["GPS_VM_EXPORT"],
        outputs_key_field="id",
        readable_output=hr,
        outputs=context,
        raw_response=raw_response,
    )


def rubrik_user_downloads_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the user downloads. This would return the current and past download history.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    response = client.get_user_downloads()
    data = response.get("data", {})
    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("user downloads"))

    context, hr = prepare_context_hr_user_downloads(data.get("getUserDownloads", []))
    table_name = "User Downloads"
    headers = ["Download ID", "Name", "Status", "Identifier", "Creation Time", "Completion Time"]
    readable_output = tableToMarkdown(table_name, hr, headers, removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["USER_DOWNLOADS"],
        outputs_key_field="id",
        outputs=context,
        raw_response=response,
        readable_output=readable_output,
    )


def rubrik_sonar_csv_result_download_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the download link for the requested Sonar CSV Snapshot file.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    download_id = arg_to_number(validate_required_arg("download_id", args.get("download_id")))

    response = client.get_csv_result_download(download_id=download_id)

    data = response.get("data", {})
    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])
    context = {"downloadId": download_id}
    context.update(data)
    table_name = "Sonar CSV Result"
    url_ = data.get("getDownloadUrl", {}).get("url")
    hr = [f"Download the [CSV]({url_}) file to see the result."]
    readable_output = tableToMarkdown(table_name, hr, ["Download URL"], removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["SONAR_CSV_DOWNLOAD"],
        outputs_key_field="downloadId",
        outputs=context,
        raw_response=response,
        readable_output=readable_output,
    )


def rubrik_gps_sla_domain_list(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    List available SLA Domains Rubrik Polaris - GPS.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    name = args.get("name", "")
    cluster_uuid = args.get("cluster_id", "")
    object_type = argToList(args.get("object_type"))
    show_cluster_slas_only = args.get("show_cluster_slas_only", DEFAULT_SHOW_CLUSTER_SLA_ONLY)
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)
    sort_by = args.get("sort_by", DEFAULT_SORT_BY_SLA_DOMAIN)
    filters = []

    if name:
        filters.append({"field": "NAME", "text": name})
    if cluster_uuid:
        filters.append({"field": "CLUSTER_UUID", "text": cluster_uuid})

    if object_type:
        filters.append({"field": "OBJECT_TYPE", "objectTypeList": object_type})

    if show_cluster_slas_only:
        show_cluster_slas_only = validate_boolean_argument(show_cluster_slas_only, "show_cluster_slas_only")
        filters.append({"field": "SHOW_CLUSTER_SLAS_ONLY", "text": str(show_cluster_slas_only).lower()})

    nodes = list(
        client.list_sla_domains(filters=filters, sort_order=sort_order, sort_by=sort_by, show_protected_object_count=True)
    )

    if not nodes:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("sla domains"))

    context, hr = prepare_context_hr_sla_domains_list(nodes)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["GPS_SLA_DOMAIN"],
        outputs_key_field="id",
        outputs=context,
        raw_response=nodes,
        readable_output=hr,
    )


def rubrik_gps_vm_snapshot_create(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Trigger an on-demand vm snapshot.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    object_id = validate_required_arg("object_id", args.get("object_id", ""))
    sla_domain_id = args.get("sla_domain_id", "")

    raw_response = client.create_vm_snapshot(object_id, sla_domain_id)

    outputs = raw_response.get("data", {}).get("vsphereOnDemandSnapshot", {})
    outputs = remove_empty_elements(outputs)
    if not outputs or not outputs.get("id"):
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    hr_content = {"On-Demand Snapshot Request ID": outputs.get("id"), "Status": outputs.get("status")}
    hr = tableToMarkdown("GPS VM Snapshot", hr_content, headers=["On-Demand Snapshot Request ID", "Status"], removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["GPS_SNAPSHOT_CREATE"],
        outputs_key_field="id",
        outputs=outputs,
        raw_response=raw_response,
        readable_output=hr,
    )


def rubrik_gps_snapshot_files_download_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Request to download the snapshot file from the backup.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id"))
    file_path = argToList(validate_required_arg("file_path", args.get("file_path")))
    object_type: str = args.get("object_type", "VmwareVm")

    parsed_object_type: str = object_type.upper().replace("_", "")
    if parsed_object_type.find(FILESET_OBJECT_TYPE) != -1:
        download_file_filters = {"config": {"sourceDirs": file_path}, "id": snapshot_id}
        response = client._query_raw(
            raw_query=FILESET_DOWNLOAD_SNAPSHOT_FILES_MUTATION,
            operation_name="PhysicalHostDownloadSnapshotFilesMutation",
            variables=download_file_filters,
            timeout=60,
        )
        data = response.get("data", {}).get("filesetDownloadSnapshotFiles", {})
    elif parsed_object_type.find(VOLUME_GROUP_OBJECT_TYPE) != -1:
        download_file_filters = {"input": {"config": {"paths": file_path}, "id": snapshot_id}}
        response = client._query_raw(
            raw_query=VOLUME_GROUP_DOWNLOAD_SNAPSHOT_FILES_MUTATION,
            operation_name="RadarInvestigationVGDownloadFilesMutation",
            variables=download_file_filters,
            timeout=60,
        )
        data = response.get("data", {}).get("downloadVolumeGroupSnapshotFiles", {})
    else:
        response = client.request_download_snapshot_files(snapshot_id=snapshot_id, paths=file_path)
        data = response.get("data", {}).get("vsphereVmDownloadSnapshotFiles", {})

    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    context, hr = prepare_context_hr_gps_snapshot_download(data)
    table_name = "Snapshot File Request ID"

    readable_output = tableToMarkdown(table_name, hr, headers=["ID", "Status"], removeNull=True)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["GPS_SNAPSHOT_FILE_DOWNLOAD"],
        outputs_key_field="id",
        outputs=context,
        raw_response=response,
        readable_output=readable_output,
    )


def rubrik_gps_vm_livemount(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Trigger a live mount of a virtual machine snapshot in Rubrik Polaris - GPS.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    snappable_id = validate_required_arg("snappable_id", args.get("snappable_id"))
    should_recover_tags = args.get("should_recover_tags", True)
    power_on = args.get("power_on", True)
    keep_mac_addresses = args.get("keep_mac_addresses", False)
    remove_network_devices = args.get("remove_network_devices", False)
    host_id = args.get("host_id")
    cluster_id = args.get("cluster_id")
    resource_pool_id = args.get("resource_pool_id")
    snapshot_fid = args.get("snapshot_fid")
    vm_name = args.get("vm_name")
    vnic_bindings = args.get("vnic_bindings")
    recovery_point = args.get("recovery_point")

    if vnic_bindings:
        try:
            vnic_bindings = json.loads(args.get("vnic_bindings"))  # type: ignore[arg-type]
        except json.JSONDecodeError as exception:
            raise Exception(f"Could not able to parse the provided JSON data. Error: {exception!s}") from exception
    if power_on:
        power_on = validate_boolean_argument(power_on, "power_on")
    if keep_mac_addresses:
        keep_mac_addresses = validate_boolean_argument(keep_mac_addresses, "keep_mac_addresses")
    if remove_network_devices:
        remove_network_devices = validate_boolean_argument(remove_network_devices, "remove_network_devices")
    if should_recover_tags:
        should_recover_tags = validate_boolean_argument(should_recover_tags, "should_recover_tags")

    raw_response = client.create_vm_livemount_v2(
        snappable_id,
        should_recover_tags,
        power_on,
        keep_mac_addresses,
        remove_network_devices,
        host_id,
        cluster_id,
        resource_pool_id,
        snapshot_fid,
        vm_name,
        vnic_bindings,
        recovery_point,
    )

    outputs = raw_response.get("data", {}).get("vsphereVmInitiateLiveMountV2", {})
    outputs = remove_empty_elements(outputs)
    if not outputs or not outputs.get("id"):
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    hr_content = {"VM Live Mount Request ID": outputs.get("id")}
    hr = tableToMarkdown("GPS VM Livemount", hr_content, headers=["VM Live Mount Request ID"], removeNull=True)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["GPS_VM_LIVEMOUNT"],
        outputs_key_field="id",
        outputs=outputs,
        raw_response=raw_response,
        readable_output=hr,
    )


def rubrik_gps_vm_host_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of available Vsphere Hosts.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    host_name = args.get("name")
    cluster_id = args.get("cluster_id")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    next_token = args.get("next_page_token")
    sort_by = args.get("sort_by", DEFAULT_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)

    if not limit or limit <= 0 or limit > 1000:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))

    filters = []
    if host_name:
        filters.append({"field": "NAME", "texts": [host_name]})
    if cluster_id:
        filters.append({"field": "CLUSTER_ID", "texts": [cluster_id]})
    response = client.list_vsphere_hosts(first=limit, filters=filters, after=next_token, sort_by=sort_by, sort_order=sort_order)
    data = response.get("data", {}).get("vSphereHostConnection", {}).get("edges", [])
    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vm hosts"))

    context, hr = prepare_context_hr_vm_host_list(data)
    table_name = "GPS VM Hosts"
    headers = ["VSphere Host ID", "Name", "Physical Host"]
    readable_output = tableToMarkdown(table_name, hr, headers, removeNull=True)

    page_cursor = response.get("data", {}).get("vSphereHostConnection", {}).get("pageInfo", {})
    next_page_context = {
        "next_page_token": page_cursor.get("endCursor", ""),
        "name": "rubrik-gps-vm-host-list",
        "has_next_page": page_cursor.get("hasNextPage", ""),
    }
    if next_page_context.get("has_next_page"):
        readable_output += f"\n {MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}\n"

    outputs = {
        f"{OUTPUT_PREFIX['GPS_VM_HOSTS']}(val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_VM_HOSTS']}(val.name == obj.name)": remove_empty_elements(next_page_context),
    }

    return CommandResults(outputs=outputs, raw_response=response, readable_output=readable_output)


def rubrik_gps_vm_datastore_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of the available datastores on a Vsphere Host.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    name = args.get("name", "")
    host_id = args.get("host_id", "")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    next_page_token = args.get("next_page_token")
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)
    sort_by = args.get("sort_by", DEFAULT_SORT_BY)
    filters = []

    if name:
        filters.append({"field": "REGEX", "texts": name})
    if not limit or limit <= 0 or limit > 1000:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))

    response = client.list_vsphere_datastores(
        host_id=host_id, first=limit, after=next_page_token, filters=filters, sort_by=sort_by, sort_order=sort_order
    )

    edges = response.get("data", {}).get("vSphereHost", {}).get("descendantConnection", {}).get("edges", [])
    if not edges:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("vm datastores"))

    context, hr = prepare_context_hr_vm_datastore_list(edges, host_id)

    page_cursor = response.get("data", {}).get("vSphereHost", {}).get("descendantConnection", {}).get("pageInfo", {})
    next_page_context = {
        "next_page_token": page_cursor.get("endCursor", ""),
        "name": "rubrik-gps-vm-datastore-list",
        "has_next_page": page_cursor.get("hasNextPage", ""),
    }
    if next_page_context.get("has_next_page"):
        hr += f"\n {MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}\n"

    outputs = {
        f"{OUTPUT_PREFIX['GPS_VM_HOSTS']}(val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_VM_HOSTS']}(val.name == obj.name)": {"Datastore": remove_empty_elements(next_page_context)},
    }

    return CommandResults(outputs=outputs, raw_response=response, readable_output=hr)


def rubrik_event_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of events.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    activity_status = args.get("activity_status", "")
    activity_type = args.get("activity_type", "")
    severity = args.get("severity", "")
    object_name = args.get("object_name", "")
    object_type = args.get("object_type", "")
    cluster_ids = args.get("cluster_id", "")
    start_date = end_date = ""
    start_date_ob = arg_to_datetime(args.get("start_date"))
    if start_date_ob:
        start_date = start_date_ob.strftime(DATE_TIME_FORMAT)

    end_date_ob = arg_to_datetime(args.get("end_date"))
    if end_date_ob:
        end_date = end_date_ob.strftime(DATE_TIME_FORMAT)

    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    sort_by = args.get("sort_by", DEFAULT_EVENT_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_EVENT_SORT_ORDER)
    next_page_token = args.get("next_page_token")

    if not limit or limit <= 0 or limit > 1000:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))

    response = client.list_event_series(
        object_type=object_type,
        activity_status=activity_status,
        activity_type=activity_type,
        severity=severity,
        cluster_id=cluster_ids,
        start_date=start_date,
        end_date=end_date,
        object_name=object_name,
        first=limit,
        sort_by=sort_by,
        sort_order=sort_order,
        after=next_page_token,
    )

    edges = response.get("data", {}).get("activitySeriesConnection", {}).get("edges", [])
    if not edges:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("events"))

    context, hr = prepare_context_hr_event_list(edges)

    page_cursor = response.get("data", {}).get("activitySeriesConnection", {}).get("pageInfo", {})
    next_page_context = {
        "next_page_token": page_cursor.get("endCursor", ""),
        "name": "rubrik-event-list",
        "has_next_page": page_cursor.get("hasNextPage", ""),
    }
    if next_page_context.get("has_next_page"):
        hr += f"\n {MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}\n"

    outputs = {
        f"{OUTPUT_PREFIX['EVENT']}(val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_EVENT']}(val.name == obj.name)": remove_empty_elements(next_page_context),
    }

    return CommandResults(outputs=outputs, raw_response=response, readable_output=hr)


def rubrik_polaris_object_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of Rubrik objects, based on the provided filters.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    type_filter = validate_required_arg("type_filter", args.get("type_filter", ""))
    cluster_id = args.get("cluster_id", "")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    sort_by = args.get("sort_by", DEFAULT_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)
    next_page_token = args.get("next_page_token")
    filters = {}
    if cluster_id:
        filters = {"field": "CLUSTER_ID", "texts": argToList(cluster_id)}

    if not limit or limit <= 0 or limit > 1000:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))

    response = client.list_objects(
        first=limit, type_filter=type_filter, sort_order=sort_order, sort_by=sort_by, after=next_page_token, filters=filters
    )
    data = response.get("data", {}).get("inventoryRoot", {}).get("descendantConnection", {})
    edges = data.get("edges", [])
    if not edges:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("objects"))

    context, hr = prepare_context_hr_object_list(edges)

    page_cursor = data.get("pageInfo", {})
    next_page_context = {
        "next_page_token": page_cursor.get("endCursor", ""),
        "name": "rubrik-polaris-object-list",
        "has_next_page": page_cursor.get("hasNextPage", ""),
    }
    if next_page_context.get("has_next_page"):
        hr += f"\n {MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}\n"

    outputs = {
        f"{OUTPUT_PREFIX['OBJECT']}(val.id == obj.id)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_OBJECT']}(val.name == obj.name)": remove_empty_elements(next_page_context),
    }

    return CommandResults(outputs=outputs, raw_response=response, readable_output=hr)


def rubrik_polaris_object_snapshot_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve Rubrik snapshot(s) of an object, based on the provided object ID.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    object_id = validate_required_arg("object_id", args.get("object_id", ""))
    snapshot_type = args.get("snapshot_type", "")

    start_date = end_date = ""
    start_date_ob = arg_to_datetime(args.get("start_date"))
    if start_date_ob:
        start_date = start_date_ob.strftime(DATE_TIME_FORMAT)

    end_date_ob = arg_to_datetime(args.get("end_date"))
    if end_date_ob:
        end_date = end_date_ob.strftime(DATE_TIME_FORMAT)

    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)
    next_page_token = args.get("next_page_token")

    if not limit or limit <= 0 or limit > 1000:
        raise ValueError(ERROR_MESSAGES["INVALID_LIMIT"].format(limit))
    snapshot_filter = {"field": "SNAPSHOT_TYPE", "typeFilters": argToList(snapshot_type)}
    response = client.list_object_snapshots(
        object_id=object_id,
        first=limit,
        sort_order=sort_order,
        after=next_page_token,
        start_date=start_date,
        end_date=end_date,
        snapshot_filter=snapshot_filter,
    )
    edges = response.get("data", {}).get("snapshotsListConnection", {}).get("edges", [])
    if not edges:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("object snapshots"))

    context, hr = prepare_context_hr_object_snapshot_list(edges, object_id)

    page_cursor = response.get("data", {}).get("snapshotsListConnection", {}).get("pageInfo", {})
    next_page_context = {
        "next_page_token": page_cursor.get("endCursor", ""),
        "name": "rubrik-polaris-object-snapshot-list",
        "has_next_page": page_cursor.get("hasNextPage", ""),
    }
    if next_page_context.get("has_next_page"):
        hr += f"\n {MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}\n"

    outputs = {
        f"{OUTPUT_PREFIX['OBJECT']}(val.id == obj.id)": remove_empty_elements(context),
        f"{OUTPUT_PREFIX['PAGE_TOKEN_OBJECT']}(val.name == obj.name)": {"Snapshot": remove_empty_elements(next_page_context)},
    }

    return CommandResults(outputs=outputs, raw_response=response, readable_output=hr)


def rubrik_radar_ioc_scan_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Trigger an IOC scan of a system.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    prepared_args = validate_ioc_scan_args(args)

    raw_response = client.trigger_ioc_scan(**prepared_args)

    outputs = raw_response.get("data", {}).get("startMalwareDetection", {})
    outputs = remove_empty_elements(outputs)
    if not outputs or not outputs.get("id"):
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    hr_content = {SCAN_ID: outputs.get("id"), "Status": outputs.get("status")}
    hr = tableToMarkdown("Radar IOC Scan", hr_content, headers=[SCAN_ID, "Status"], removeNull=True)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["RADAR_IOC_SCAN"],
        outputs_key_field="id",
        outputs=outputs,
        raw_response=raw_response,
        readable_output=hr,
    )


def rubrik_radar_ioc_scan_results_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve Rubrik Radar results of IOC scans.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    scan_id = validate_required_arg("scan_id", args.get("scan_id"))
    cluster_id = validate_required_arg("cluster_id", args.get("cluster_id"))

    response = client.get_ioc_scan_result(scan_id=scan_id, cluster_id=cluster_id)

    data = response.get("data", {}).get("malwareDetectionTaskResult", {})
    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    context, hr = prepare_context_hr_radar_ioc_scan_results(data)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["RADAR_IOC_SCAN"],
        outputs_key_field="id",
        outputs=context,
        raw_response=response,
        readable_output=hr,
    )


def rubrik_gps_async_result_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the result of an asynchronous request.

    This command will retrieve the result of requests made by commands "rubrik-gps-snapshot-files-download",
    "rubrik-gps-vm-livemount", "rubrik-gps-vm-export" and "rubrik-gps-vm-snapshot-create".

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    request_id = validate_required_arg("request_id", args.get("request_id"))
    cluster_id = validate_required_arg("cluster_id", args.get("cluster_id"))
    ip_address = args.get("cluster_ip_address", "")

    response = client.get_async_request_result(request_id=request_id, cluster_id=cluster_id)

    data = response.get("data", {}).get("vSphereVMAsyncRequestStatus", {})
    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    if "DOWNLOAD_SNAPPABLE_FILE" in request_id and not ip_address:
        raise ValueError(ERROR_MESSAGES["IP_ADDRESS_REQUIRED"])

    context, hr = prepare_context_hr_async_result(data, request_id, ip_address)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["GPS_ASYNC_RESULT"],
        outputs_key_field="id",
        outputs=context,
        raw_response=response,
        readable_output=hr,
    )


def rubrik_gps_cluster_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of the available rubrik clusters.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    name = args.get("name", "")
    cluster_type = args.get("type", "")
    sort_by = args.get("sort_by", DEFAULT_CLUSTER_SORT_BY)
    sort_order = args.get("sort_order", DEFAULT_SORT_ORDER)
    filters = {}
    if cluster_type:
        filters["type"] = argToList(cluster_type)
    if name:
        filters["name"] = argToList(name)

    nodes = list(client.list_clusters(sort_order=sort_order, sort_by=sort_by, filters=filters))
    if not nodes:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("clusters"))

    context, hr = prepare_context_hr_cluster_list(nodes)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["GPS_CLUSTER"],
        outputs_key_field="id",
        outputs=context,
        raw_response=nodes,
        readable_output=hr,
    )


def rubrik_radar_ioc_scan_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    List the IOC scan information on a Rubrik cluster.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    cluster_id = validate_required_arg("cluster_id", args.get("cluster_id"))

    raw_response = client.get_ioc_scan_list(cluster_id=cluster_id)

    data = raw_response.get("data", {}).get("malwareScans", {}).get("data", [])
    data = remove_empty_elements(data)
    if not data:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("ioc scans"))

    outputs, hr = prepare_context_hr_ioc_scan_list(data)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["RADAR_IOC_SCAN"],
        outputs_key_field="id",
        outputs=outputs,
        raw_response=raw_response,
        readable_output=hr,
    )


def rubrik_gps_vm_recover_files(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Recover files from a backup snapshot, back into a Vsphere VM.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``dict``
    :param args: arguments obtained from demisto.args()

    :return: CommandResult object
    """
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id"))
    cluster_id = validate_required_arg("cluster_id", args.get("cluster_id"))
    paths_to_recover = validate_required_arg("paths_to_recover", argToList(args.get("paths_to_recover")))
    restore_path = validate_required_arg("restore_path", args.get("restore_path"))
    destination_object_id = args.get("destination_object_id")

    restore_config = [{"path": path_to_recover, "restorePath": restore_path} for path_to_recover in paths_to_recover]

    raw_response = client.recover_vsphere_vm_files(
        snapshot_id=snapshot_id, cluster_id=cluster_id, restore_config=restore_config, destination_object_id=destination_object_id
    )

    outputs = raw_response.get("data", {}).get("vsphereVMRecoverFilesNew", {})
    outputs = remove_empty_elements(outputs)
    if not outputs:
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    hr_content = {"Recover Files Request ID": outputs.get("id")}
    hr = tableToMarkdown("GPS VM Recover Files", hr_content, headers=["Recover Files Request ID"], removeNull=True)
    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["GPS_VM_RECOVER_FILES"],
        outputs_key_field="id",
        outputs=outputs,
        raw_response=raw_response,
        readable_output=hr,
    )


def rubrik_sonar_user_access_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of user access, based on the provided filters.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use.

    :type args: ``dict``
    :param args: Arguments for the command.

    :return: CommandResult object.
    """
    user_name = args.get("user_name", "")
    user_email = args.get("user_email", "")
    search_time_period: datetime = arg_to_datetime(
        args.get("search_time_period", "7 days"),  # type: ignore
        arg_name="search_time_period",
    )
    if search_time_period.tzinfo is None:
        search_time_period = search_time_period.replace(tzinfo=timezone.utc)
    search_time_period_iso = search_time_period.replace(microsecond=0).isoformat()
    risk_levels = argToList(args.get("risk_levels", []))
    group_id = args.get("group_id", "")
    include_whitelisted_results = argToBoolean(args.get("include_whitelisted_results", False))
    principal_summary_category = args.get("principal_summary_category", DEFAULT_PRINCIPAL_SUMMARY_CATEGORY)
    page_number = arg_to_number(args.get("page_number", 1), "page_number")
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT), "limit")
    sort_by = args.get("sort_by", DEFAULT_USER_ACCESS_SORT_BY)
    sort_order = str(args.get("sort_order", DEFAULT_USER_ACCESS_SORT_ORDER)).upper()
    next_page_token = args.get("next_page_token")

    validate_user_access_list_command_args(limit, sort_order, page_number)  # type: ignore

    # Prepare filter.
    filters = {
        "filter": {
            "principalType": "USER",
            "policyIds": [],
            "riskLevel": risk_levels,
            "principalName": user_name,
            "groupId": group_id,
            "principalSummaryCategory": principal_summary_category,
        },
        "timelineDate": search_time_period_iso,
        "sort": {"sortBy": sort_by, "sortOrder": sort_order},
        "includeWhitelistedResults": include_whitelisted_results,
        "first": limit if not user_email else MAXIMUM_PAGINATION_LIMIT,
    }
    if next_page_token:
        filters["after"] = next_page_token

    response = client._query_raw(
        raw_query=USER_ACCESS_QUERY, operation_name="UserAccessPrincipalListQuery", variables=filters, timeout=60
    )

    response["xsoar_risk_levels"] = []
    data = response.get("data", {}).get("principalSummaries", {})
    edges = data.get("edges", [])
    page_cursor = remove_empty_elements(data.get("pageInfo", {}))
    page_cursor.pop("__typename", None)
    page_cursor.update({"name": "rubrik-sonar-user-access-list"})
    record_hr = ""
    if page_cursor.get("hasNextPage"):
        record_hr = f"\n{MESSAGES['NEXT_PAGE_TOKEN'].format(page_cursor.get('endCursor'))}"
    outputs = {f"{OUTPUT_PREFIX['PAGE_TOKEN_USER_ACCESS']}(val.name == obj.name)": page_cursor}
    if not edges:
        page_cursor.update({"has_next_upn_page": False, "next_upn_page_number": 1})
        return CommandResults(
            outputs=outputs, raw_response=response, readable_output=MESSAGES["NO_RECORDS_FOUND"].format("user accesses")
        )

    base_url = str(client._baseurl).removesuffix("api")
    context, hr, pages, risk_levels = prepare_context_hr_user_access_list(
        edges,
        include_whitelisted_results,
        user_email,
        base_url,
        page_number,  # type: ignore
        limit,  # type: ignore
    )

    response["xsoar_risk_levels"] = list(risk_levels)

    if context:
        outputs[f"{OUTPUT_PREFIX['USER_ACCESS']}(val.principalId == obj.principalId)"] = context
        next_upn_page_number = 1
        has_next_upn_page = False
        if user_email:
            if page_number < pages:  # type: ignore
                next_upn_page_number = page_number + 1  # type: ignore
                has_next_upn_page = True
            else:
                next_upn_page_number = pages or 1
                hr = hr + record_hr
        elif record_hr:
            hr = hr + record_hr
        page_cursor.update({"has_next_upn_page": has_next_upn_page, "next_upn_page_number": next_upn_page_number})
    else:
        hr = MESSAGES["NO_RECORDS_FOUND"].format("user accesses")
        if record_hr:
            hr += f"\n{record_hr}"
        page_cursor.update({"has_next_upn_page": False, "next_upn_page_number": pages or 1})

    return CommandResults(outputs=outputs, raw_response=response, readable_output=hr)


def rubrik_sonar_user_access_get_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the of user access for the provided user_id.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use.

    :type args: ``dict``
    :param args: Arguments for the command.

    :return: CommandResult object.
    """
    user_id = validate_required_arg("user_id", args.get("user_id"))
    search_time_period: datetime = arg_to_datetime(
        args.get("search_time_period", "7 days"),  # type: ignore
        arg_name="search_time_period",
    )
    if search_time_period.tzinfo is None:
        search_time_period = search_time_period.replace(tzinfo=timezone.utc)
    search_time_period_iso = search_time_period.replace(microsecond=0).isoformat()
    historical_delta_days = arg_to_number(args.get("historical_delta_days", "7"), arg_name="historical_delta_days", required=True)
    include_whitelisted_results = argToBoolean(args.get("include_whitelisted_results", False))

    # Prepare filter for user access query.
    access_filters = {
        "sid": user_id,
        "timelineDate": search_time_period_iso,
        "includeWhitelistedResults": include_whitelisted_results,
    }

    access_response = client._query_raw(
        raw_query=USER_ACCESS_DETAIL_QUERY, operation_name="UserAccessUserDetailsQuery", variables=access_filters, timeout=60
    )
    principal_details = access_response.get("data", {}).get("principalDetails", {})
    principal_summary = deepcopy(principal_details.get("principalSummary", {}))
    if not principal_summary.get("principalId"):
        return CommandResults(readable_output=MESSAGES["NO_RESPONSE"])

    principal_summary["directGroups"] = principal_details.get("directGroups", [])

    # Prepare filter for policy hits query.
    policy_hits_filters = {
        "sids": [user_id],
        "day": (search_time_period_iso.split("T")[0] + "T00:00:00+00:00"),
        "historicalDeltaDays": historical_delta_days,
        "includeWhitelistedResults": include_whitelisted_results,
    }
    policy_hits_response = client._query_raw(
        raw_query=POLICY_HITS_SUMMARY_CHART_QEURY,
        operation_name="PrincipalPolicyHitsSummaryChartQuery",
        variables=policy_hits_filters,
        timeout=60,
    )
    policy_hits_summaries = policy_hits_response.get("data", {}).get("sidsPolicyHitsSummary", {}).get("sidSummaries", [])

    if not isinstance(policy_hits_summaries, list) or not policy_hits_summaries:
        policy_hits_context: list = []
    else:
        policy_hits_context: list = deepcopy(policy_hits_summaries[0].get("summary") or [])  # type: ignore

    base_url = str(client._baseurl).removesuffix("api")
    access_context, access_hr, policy_hr = prepare_context_hr_user_access_get(
        principal_summary, policy_hits_context, base_url, include_whitelisted_results
    )
    outputs = {f"{OUTPUT_PREFIX['USER_ACCESS']}(val.principalId == obj.principalId)": access_context}

    return CommandResults(outputs=outputs, raw_response=access_response, readable_output=f"{access_hr}\n\n{policy_hr}")


def rubrik_sonar_file_context_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of file context, based on the provided filters.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use.

    :type args: ``dict``
    :param args: Arguments for the command.

    :return: CommandResult object.
    """
    object_id = validate_required_arg("object_id", args.get("object_id"))
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id"))
    file_name = args.get("file_name", "")
    file_path = args.get("file_path", "")
    user_id = args.get("user_id")
    user_ids = []
    if user_id:
        user_ids.append(user_id)
    include_whitelisted_results = argToBoolean(args.get("include_whitelisted_results", False))
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT), "limit")
    sort_by = args.get("sort_by", DEFAULT_FILE_CONTEXT_SORT_BY)
    sort_order = str(args.get("sort_order", DEFAULT_FILE_CONTEXT_SORT_ORDER)).upper()
    next_page_token = args.get("next_page_token")

    validate_user_access_list_command_args(limit, sort_order)  # type: ignore

    # Prepare filter.
    filters = {
        "snappableFid": object_id,
        "snapshotFid": snapshot_id,
        "filters": {
            "sids": user_ids,
            "fileType": "HITS",
            "searchText": file_name,
            "snappablePaths": [{"snappableFid": object_id, "stdPath": file_path}],
            "whitelistEnabled": not include_whitelisted_results,
        },
        "sort": {"sortBy": sort_by, "sortOrder": sort_order},
        "timezone": "UTC",
        "first": limit,
    }
    if next_page_token:
        filters["after"] = next_page_token

    response = client._query_raw(
        raw_query=FILE_CONTEXT_QUERY, operation_name="CrawlsFileListQuery", variables=filters, timeout=60
    )
    data = response.get("data", {}).get("policyObj", {}).get("fileResultConnection", {})
    edges = data.get("edges", [])
    if not edges:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("file contexts"))

    context, hr = prepare_context_hr_file_context_list(edges, include_whitelisted_results)

    page_cursor = remove_empty_elements(data.get("pageInfo", {}))
    page_cursor.pop("__typename", None)
    page_cursor.update({"name": "rubrik-sonar-file-context-list"})
    if page_cursor.get("hasNextPage"):
        hr += f"\n{MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}"

    outputs = {
        f"{OUTPUT_PREFIX['FILE_CONTEXT']}(val.stdPath == obj.stdPath)": context,
        f"{OUTPUT_PREFIX['PAGE_TOKEN_FILE_CONTEXT']}(val.name == obj.name)": page_cursor,
    }

    return CommandResults(outputs=outputs, raw_response=response, readable_output=hr)


def rubrik_radar_suspicious_file_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of suspicious files, based on the provided filters.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use.

    :type args: ``dict``
    :param args: Arguments for the command.

    :return: CommandResult object.
    """
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id"))

    # Prepare filter for the SNAPPABLE_INVESTIGATIONS_QUERY.
    snappable_investigations_filters = {"id": snapshot_id}

    snappable_investigations_response = client._query_raw(
        raw_query=SNAPPABLE_INVESTIGATIONS_QUERY,
        operation_name="SnappableInvestigationsQuery",
        variables=snappable_investigations_filters,
        timeout=60,
    )

    snappable_investigations_data = snappable_investigations_response.get("data", {}).get("snapshot", {})
    raw_response = deepcopy(snappable_investigations_response)
    if not snappable_investigations_data:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORD_FOUND"].format("snapshot"), raw_response=snappable_investigations_response
        )

    snapshot_cdm_id = snappable_investigations_data.get("cdmId", "")
    cluster_id = snappable_investigations_data.get("cluster", {}).get("id", "")
    if not snapshot_cdm_id or not cluster_id:
        return CommandResults(
            readable_output=MESSAGES["NO_RECORD_FOUND"].format("snapshot"), raw_response=snappable_investigations_response
        )

    # Prepare filter for the ANOMALY_RESULT_QUERY.
    suspicious_file_filters = {"snapshotId": snapshot_cdm_id, "clusterUuid": cluster_id}

    suspicious_file_response = client._query_raw(
        raw_query=ANOMALY_RESULT_QUERY, operation_name="AnomalyResultQuery", variables=suspicious_file_filters, timeout=60
    )
    suspicious_file_data = suspicious_file_response.get("data", {}).get("anomalyResultOpt", {})
    raw_response["data"]["anomalyResultOpt"] = deepcopy(suspicious_file_data)
    if not suspicious_file_data:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("suspicious files"), raw_response=raw_response)

    context, hr = prepare_context_hr_suspicious_file_list(snappable_investigations_data, suspicious_file_data)

    outputs = {f"{OUTPUT_PREFIX['SUSPICIOUS_FILE']}(val.id == obj.id)": remove_empty_elements(context)}

    return CommandResults(outputs=outputs, raw_response=raw_response, readable_output=hr)


def ip_command(client: PolarisClient, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Retrieve the detail information of given ip(s).

    :type client: ``Client``
    :param client: Object of Client class.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``List[CommandResults]``
    :return: List of standard command result.
    """
    ips_list = argToList(args.get("ip"))
    ips = []

    for raw_ip in ips_list:
        ip = raw_ip.strip('"').strip()
        if ip:
            ips.append(ip)

    if not ips:
        raise ValueError(ERROR_MESSAGES["MISSING_REQUIRED_FIELD"].format("ip"))

    invalid_ips, valid_ips = validate_ip_addresses(ips)
    if invalid_ips:
        return_warning(
            "The following IP Addresses were found invalid: {}".format(", ".join(invalid_ips)), exit=len(invalid_ips) == len(ips)
        )

    command_results = []

    for ip in valid_ips:
        raw_resp = requests.get(
            f"{client._baseurl}/thirdparty/workload_summary",
            params={"search_string": ip, "search_type": "ipv6" if is_ipv6_valid(ip) else "ipv4"},
            headers=client.prepare_headers(),
            verify=client._verify,
            proxies=client._proxies,
            timeout=60,
        )
        raw_resp.raise_for_status()
        response = raw_resp.json()

        if MESSAGES["NO_OBJECT_FOUND"] in response.get(GENERAL_INFO_KEY, {}).get("fid", MESSAGES["NO_OBJECT_FOUND"]):
            return_warning(MESSAGES["IP_NOT_FOUND"].format(ip))
            continue

        ip_response = deepcopy(response)
        ip_response = remove_empty_elements(ip_response)
        severity_score, ip_hr_output = prepare_score_and_hr_for_reputation_command(ip_response, ip, "IP")
        ip_response["ip"] = ip

        dbot_score = Common.DBotScore(
            indicator=ip,
            indicator_type=DBotScoreType.IP,
            integration_name=VENDOR_NAME,
            score=severity_score,
            reliability=demisto.params().get("integration_reliability", DEFAULT_RELIABILITY),
        )
        dbot_score.integration_name = VENDOR_NAME

        ip_indicator = Common.IP(
            ip=ip,
            updated_date=response.get("threatMonitoringInfo", {}).get("latestThreatMonitoring", {}).get("monitoringScanTime"),
            dbot_score=dbot_score,
        )

        command_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["IP"],
            outputs_key_field="ip",
            outputs=ip_response,
            raw_response=response,
            readable_output=ip_hr_output,
            indicator=ip_indicator,
        )

        command_results.append(command_result)

    return command_results


def domain_command(client: PolarisClient, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Retrieve the detail information of given domain(s).

    :type client: ``Client``
    :param client: Object of Client class.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``List[CommandResults]``
    :return: List of standard command result.
    """
    domain_list = argToList(args.get("domain"))
    domains = []

    for raw_domain in domain_list:
        domain = raw_domain.strip('"').strip()
        if domain:
            domains.append(domain)

    if not domains:
        raise ValueError(ERROR_MESSAGES["MISSING_REQUIRED_FIELD"].format("domain"))
    command_results = []

    for domain in domains:
        raw_resp = requests.get(
            f"{client._baseurl}/thirdparty/workload_summary",
            params={"search_string": domain, "search_type": "name"},
            headers=client.prepare_headers(),
            verify=client._verify,
            proxies=client._proxies,
            timeout=60,
        )
        raw_resp.raise_for_status()
        response = raw_resp.json()

        if MESSAGES["NO_OBJECT_FOUND"] in response.get(GENERAL_INFO_KEY, {}).get("fid", MESSAGES["NO_OBJECT_FOUND"]):
            return_warning(MESSAGES["DOMAIN_NOT_FOUND"].format(domain))
            continue

        domain_response = deepcopy(response)
        domain_response = remove_empty_elements(domain_response)
        severity_score, domain_hr_output = prepare_score_and_hr_for_reputation_command(domain_response, domain, "domain")
        domain_response["domain"] = domain

        dbot_score = Common.DBotScore(
            indicator=domain,
            indicator_type=DBotScoreType.DOMAIN,
            integration_name=VENDOR_NAME,
            score=severity_score,
            reliability=demisto.params().get("integration_reliability", DEFAULT_RELIABILITY),
        )
        dbot_score.integration_name = VENDOR_NAME

        domain_indicator = Common.Domain(
            domain=domain,
            updated_date=response.get("threatMonitoringInfo", {}).get("latestThreatMonitoring", {}).get("monitoringScanTime"),
            dbot_score=dbot_score,
        )

        command_result = CommandResults(
            outputs_prefix=OUTPUT_PREFIX["DOMAIN"],
            outputs_key_field="domain",
            outputs=domain_response,
            raw_response=response,
            readable_output=domain_hr_output,
            indicator=domain_indicator,
        )

        command_results.append(command_result)

    return command_results


def rubrik_radar_anomaly_status_update_command(client: PolarisClient, args: Dict[str, Any]):
    """
    Update the status of a radar anomaly.

    :type client: ``Client``
    :param client: Object of Client class.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    anomaly_type = validate_required_arg("anomaly_type", args.get("anomaly_type"))
    workload_id = validate_required_arg("workload_id", args.get("workload_id"))
    anomaly_id = validate_required_arg("anomaly_id", args.get("anomaly_id"))
    false_positive_type = args.get("false_positive_type")
    false_positive_reason = args.get("false_positive_reason")

    validate_anomaly_status_update_command_args(anomaly_type, false_positive_type, false_positive_reason)

    params = {"anomalyType": anomaly_type.upper(), "workloadId": workload_id, "anomalyId": anomaly_id}

    if false_positive_type:
        false_positive_params = {"falsePositiveType": false_positive_type.upper()}
        if false_positive_type.upper() == "OTHER":
            false_positive_params["otherReason"] = false_positive_reason
        params.update({"falsePositiveReport": false_positive_params})

    input_params = {"input": params}

    anomaly_status_update_response = client._query_raw(
        raw_query=ANOMALY_UPDATE_STATUS_MUTATION, operation_name="AnomalyUpdateStatusMutation", variables=input_params, timeout=60
    )
    ec = {
        "command_name": "rubrik-radar-anomaly-update-status",
        "anomaly_id": anomaly_id,
        "anomaly_type": anomaly_type,
        "workload_id": workload_id,
    }
    if false_positive_type:
        ec["false_positive_type"] = false_positive_type
        if false_positive_type.upper() == "OTHER":
            ec["false_positive_reason"] = false_positive_reason
        hr_output = f"### Anomaly detection with the ID {anomaly_id} marked as false positive successfully."
    else:
        ec["is_resloved"] = True
        hr_output = f"### Anomaly detection with the ID {anomaly_id} resolved successfully."

    return CommandResults(
        readable_output=hr_output,
        raw_response=anomaly_status_update_response,
        outputs=remove_empty_elements(ec),
        outputs_prefix=OUTPUT_PREFIX["ANOMALY_UPDATE_STATUS"],
        outputs_key_field=["command_name", "anomaly_id", "workload_id"],
    )


def rubrik_threat_monitoring_matched_object_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Get the list of matched objects in the threat monitoring.

    :type client: ``Client``
    :param client: Object of Client class.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """
    limit = arg_to_number(args.get("limit", "50"))
    next_page_token = args.get("next_page_token")
    start_time_obj = arg_to_datetime(args.get("start_time", "7 days"))
    cluster_uuids = argToList(args.get("cluster_id"))
    object_types = argToList(args.get("object_type"))
    object_name = args.get("object_name")
    match_types = argToList(args.get("match_type"))

    validate_threat_monitoring_matched_object_list_command_args(start_time_obj, limit, match_types)

    ioc_match_type = []
    for match_type in match_types:
        ioc_match_type.append(IOC_TYPE_MAPPING.get(match_type))

    threat_monitoring_filters = {
        "clusterUuidFilter": cluster_uuids,
        "matchTypeFilter": ioc_match_type,
        "objectTypeFilter": object_types,
        "workloadNameSearch": object_name,
        "first": limit,
        "after": next_page_token,
    }

    if start_time_obj:
        start_time = start_time_obj.strftime(DATE_TIME_FORMAT)  # type: ignore
        threat_monitoring_filters["beginTime"] = start_time

    remove_nulls_from_dictionary(threat_monitoring_filters)

    threat_monitoring_response = client._query_raw(
        raw_query=THREAT_MONITORING_MATCHED_OBJECT_LIST_QUERY,
        operation_name="ThreatMonitoringMatchedObjectsQuery",
        variables=threat_monitoring_filters,
        timeout=60,
    )

    edges = []
    page_info, stats_info = {}, {}
    threat_monitoring_data = threat_monitoring_response.get("data", {})
    if threat_monitoring_data is not None:
        edges = threat_monitoring_data.get("threatMonitoringMatchedObjects", {}).get("edges", [])
        page_info = threat_monitoring_data.get("threatMonitoringMatchedObjects", {}).get("pageInfo", {})
        stats_info = threat_monitoring_data.get("threatMonitoringMatchedObjects", {}).get("stats", {})

    page_cursor = remove_empty_elements(page_info)
    page_cursor.pop("__typename", None)
    page_cursor.update(
        {
            "name": "rubrik-threat-monitoring-matched-object-list",
            "total_matched_count": stats_info.get("objectsWithMatches"),
        }
    )

    outputs = {f"{OUTPUT_PREFIX['PAGE_TOKEN_THREAT_MONITORING']}(val.name == obj.name)": page_cursor}

    if not edges:
        return CommandResults(
            outputs=outputs,
            raw_response=threat_monitoring_response,
            readable_output=MESSAGES["NO_RECORDS_FOUND"].format("threat monitoring objects"),
        )

    context, hr = prepare_context_hr_threat_monitoring_matched_object_list(edges)

    if page_cursor.get("hasNextPage"):
        hr += f"\n{MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}"

    outputs[f"{OUTPUT_PREFIX['THREAT_MONITORING']}(val.objectFid == obj.objectFid)"] = context

    return CommandResults(outputs=remove_empty_elements(outputs), raw_response=threat_monitoring_response, readable_output=hr)


def rubrik_threat_monitoring_matched_object_get_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Get the matched object in the threat monitoring.

    :type client: ``Client``
    :param client: Object of Client class.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """
    object_id = args.get("object_id", "").strip()
    object_id = validate_required_arg("object_id", object_id)

    threat_monitoring_get_filters = {
        "fid": object_id,
    }

    threat_monitoring_response = client._query_raw(
        raw_query=THREAT_MONITORING_MATCHED_OBJECT_GET_QUERY,
        operation_name="ThreatMonitoringObjectTypeQuery",
        variables=threat_monitoring_get_filters,
        timeout=60,
    )

    threat_monitoring_data = threat_monitoring_response.get("data", {})
    if threat_monitoring_data:
        threat_monitoring_data = threat_monitoring_data.get("hierarchyObject", {})

    if not threat_monitoring_data:
        return CommandResults(readable_output=MESSAGES["NO_RECORD_FOUND"].format("threat monitoring object"))

    hr = prepare_hr_threat_monitoring_matched_objects_get(threat_monitoring_data)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["THREAT_MONITORING"],
        outputs_key_field="id",
        outputs=remove_empty_elements(threat_monitoring_data),
        raw_response=threat_monitoring_response,
        readable_output=hr,
    )


def rubrik_threat_monitoring_matched_file_list_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Get the list of matched files for a threat monitoring object.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :rtype: ``CommandResults``
    :return: Standard command result.
    """
    object_id = args.get("object_id", "").strip()
    limit = arg_to_number(args.get("limit", "50"))
    next_page_token = args.get("next_page_token")
    file_name = args.get("file_name")

    validate_threat_monitoring_matched_file_list_command_args(object_id, limit)

    variables = {
        "objectFid": object_id,
        "first": limit,
        "after": next_page_token,
        "filenameSearchFilter": file_name,
    }
    remove_nulls_from_dictionary(variables)

    response = client._query_raw(
        raw_query=THREAT_MONITORING_MATCHED_FILE_LIST_QUERY,
        operation_name="ThreatMonitoringMatchedFiles",
        variables=variables,
        timeout=60,
    )

    edges = []
    data, page_info = {}, {}

    file_list_response = response.get("data", {})
    if file_list_response:
        data = file_list_response.get("threatMonitoringMatchedFiles", {})
        edges = data.get("edges", [])
        page_info = data.get("pageInfo", {})

    page_cursor = remove_empty_elements(page_info)
    page_cursor.pop("__typename", None)
    page_cursor.update(
        {
            "name": "rubrik-threat-monitoring-matched-file-list",
            "total_matched_count": data.get("count"),
        }
    )

    outputs = {f"{OUTPUT_PREFIX['PAGE_TOKEN_THREAT_MONITORING_FILE']}(val.name == obj.name)": page_cursor}

    if not edges:
        return CommandResults(
            outputs=outputs, raw_response=response, readable_output=MESSAGES["NO_RECORDS_FOUND"].format("threat monitoring files")
        )

    context, hr = prepare_context_hr_threat_monitoring_matched_file_list(edges)

    if page_cursor.get("hasNextPage"):
        hr += f"\n{MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}"

    outputs[f"{OUTPUT_PREFIX['THREAT_MONITORING_FILE']}(val.matchId == obj.matchId)"] = context

    return CommandResults(outputs=remove_empty_elements(outputs), raw_response=response, readable_output=hr)


def rubrik_threat_monitoring_matched_file_get_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Get the details of a matched file in the threat monitoring.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :return: CommandResults object containing the results
    :rtype: ``CommandResults``
    """
    # Get and validate arguments
    matched_snapshot_id = args.get("matched_snapshot_id", "").strip()
    file_path = args.get("file_path", "").strip()

    # Validate required arguments
    validate_threat_monitoring_matched_file_get_command_args(matched_snapshot_id, file_path)

    # Prepare variables for the GraphQL query
    variables = {"matchedSnapshotFid": matched_snapshot_id, "filepath": file_path}

    # Make the API call
    response = client._query_raw(
        raw_query=THREAT_MONITORING_MATCHED_FILE_DETAILS_QUERY,
        operation_name="ThreatMonitoringMatchedFileDetailsV2Query",
        variables=variables,
        timeout=60,
    )

    # Extract the file details from the response
    file_details = {}
    data = response.get("data", {})
    if data:
        file_details = data.get("threatMonitoringMatchedFileDetailsV2", {})

    if not file_details:
        return CommandResults(readable_output=MESSAGES["NO_RECORDS_FOUND"].format("matched file details"), raw_response=response)

    # Prepare human readable output
    hr_content = prepare_context_hr_threat_monitoring_matched_file_get(file_details)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["THREAT_MONITORING_FILE"],
        outputs_key_field=["fileName", "filePath"],
        outputs=remove_empty_elements(file_details),
        raw_response=response,
        readable_output=hr_content,
    )


def rubrik_ioc_scan_list_v2_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve the list of IOC scans.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :return: Standard command result.
    """
    cluster_id = argToList(args.get("cluster_id"))
    limit = arg_to_number(args.get("limit", DEFAULT_LIMIT))
    next_page_token = args.get("next_page_token")
    start_time_obj = arg_to_datetime(args.get("start_time", DEFAULT_TIME_PERIOD))
    end_time_obj = arg_to_datetime(args.get("end_time"))
    ioc_match = argToList(args.get("ioc_match"))
    quarantine_status = argToList(args.get("quarantine_status"))
    hunt_status = argToList(args.get("hunt_status"))

    validate_ioc_scan_list_v2_command_args(limit, ioc_match, quarantine_status, hunt_status)

    ioc_scan_filters = {
        "first": limit,
        "after": next_page_token,
        "matchesFoundFilter": ioc_match,
        "quarantinedMatchesFilter": quarantine_status,
        "statusFilter": hunt_status,
        "clusterUuidFilter": cluster_id,
    }

    if start_time_obj:
        start_time = start_time_obj.strftime(DATE_TIME_FORMAT)
        ioc_scan_filters["beginTime"] = start_time
    if end_time_obj:
        end_time = end_time_obj.strftime(DATE_TIME_FORMAT)
        ioc_scan_filters["endTime"] = end_time

    remove_nulls_from_dictionary(ioc_scan_filters)

    response = client._query_raw(
        raw_query=List_Threat_Hunts_Query, operation_name="ListThreatHuntsQuery", variables=ioc_scan_filters, timeout=60
    )

    edges = []
    data, page_info = {}, {}
    ioc_scan_data = response.get("data", {})
    if ioc_scan_data:
        data = ioc_scan_data.get("threatHunts", {})
        edges = data.get("edges", [])
        page_info = data.get("pageInfo", {})

    page_cursor = remove_empty_elements(page_info)
    page_cursor.pop("__typename", None)
    page_cursor.update(
        {
            "name": "rubrik-ioc-scan-list-v2",
            "total_matched_count": data.get("count"),
        }
    )

    outputs = {f"{OUTPUT_PREFIX['PAGE_TOKEN_IOC_SCAN']}(val.name == obj.name)": page_cursor}

    if not edges:
        return CommandResults(
            outputs=outputs, raw_response=response, readable_output=MESSAGES["NO_RECORDS_FOUND"].format("ioc scans")
        )

    context, hr = prepare_context_hr_ioc_scan_v2_list(edges)

    if page_cursor.get("hasNextPage"):
        hr += f"\n{MESSAGES['NEXT_RECORD']} {page_cursor.get('endCursor')}"

    outputs[f"{OUTPUT_PREFIX['IOC_SCAN']}(val.huntId == obj.huntId)"] = context

    return CommandResults(outputs=remove_empty_elements(outputs), raw_response=response, readable_output=hr)


def rubrik_ioc_scan_results_v2_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Retrieve details of the Turbo and Advance Threat Hunt.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """
    hunt_id = validate_required_arg("hunt_id", args.get("hunt_id"))

    ioc_scan_filters = {"huntId": hunt_id}

    response = client._query_raw(
        raw_query=THREAT_HUNT_DETAILS_V2_QUERY, operation_name="ThreatHuntDetailsV2Query", variables=ioc_scan_filters, timeout=60
    )

    ioc_scan_data = {}
    response_data = deepcopy(response.get("data", {}))
    if response_data:
        ioc_scan_data = response_data.get("threatHuntDetailV2", {})
        ioc_scan_data["threatHuntObjectMetrics"] = response_data.get("threatHuntObjectMetrics", {})
        ioc_scan_data["hunt_id"] = hunt_id

    if not ioc_scan_data:
        return CommandResults(raw_response=response, readable_output=MESSAGES["NO_RECORD_FOUND"].format("ioc scan result"))

    hr = prepare_hr_ioc_scan_results_v2(ioc_scan_data)

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["IOC_SCAN"],
        outputs_key_field="hunt_id",
        outputs=remove_empty_elements(ioc_scan_data),
        raw_response=response,
        readable_output=hr,
    )


def rubrik_turbo_ioc_scan_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Start a new turbo threat hunt.

    :type client: ``PolarisClient``
    :param client: Object of Client class.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """
    ioc = argToList(args.get("ioc"), transform=lambda s: s.strip())
    scan_name = args.get("scan_name", DEFAULT_REQUEST_NAME)
    cluster_ids = argToList(args.get("cluster_id"), transform=lambda s: s.strip())
    start_time_obj = arg_to_datetime(args.get("start_time"))
    end_time_obj = arg_to_datetime(args.get("end_time"))
    max_snapshots_per_object = arg_to_number(args.get("max_snapshots_per_object"))

    validate_turbo_ioc_scan_command_args(ioc, max_snapshots_per_object)

    indicators_of_compromise = [{"iocKind": "IOC_HASH", "iocValue": ioc} for ioc in ioc]

    scan_config = {}
    if start_time_obj:
        scan_config["startTime"] = start_time_obj.strftime(DATE_TIME_FORMAT)
    if end_time_obj:
        scan_config["endTime"] = end_time_obj.strftime(DATE_TIME_FORMAT)
    if max_snapshots_per_object:
        scan_config["maxSnapshotsPerObject"] = max_snapshots_per_object  # type: ignore

    if not cluster_ids:
        cluster_ids = []

    input_data = {
        "config": {
            "baseConfig": {
                "name": scan_name,
                "threatHuntType": "TURBO_THREAT_HUNT",
                "ioc": {"iocList": {"indicatorsOfCompromise": indicators_of_compromise}},
                "snapshotScanLimit": {"scanConfig": scan_config},
            },
            "objectsToScan": [{"objectType": "CDM_CLUSTER", "objectIds": cluster_ids}],
        }
    }

    response = client._query_raw(
        raw_query=START_TURBO_THREAT_HUNT_MUTATION,
        operation_name="StartTurboThreatHunt",
        variables={"input": input_data},
        timeout=60,
    )

    data = response.get("data", {})
    hunt_data = data.get("startTurboThreatHunt", {})

    readable_output = f"#### The new Turbo Threat Hunt started with ID: {hunt_data.get('huntId')}"

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["TURBO_IOC_SCAN"],
        outputs_key_field="huntId",
        outputs=hunt_data,
        raw_response=response,
        readable_output=readable_output,
    )


def rubrik_advance_ioc_scan_command(client: PolarisClient, args: Dict[str, Any]) -> CommandResults:
    """
    Trigger an advance threat hunt.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use.

    :type args: ``Dict[str, Any]``
    :param args: Arguments provided by user.

    :return: Standard command result.
    :rtype: ``CommandResults``
    """
    object_ids = validate_required_arg("object_id", argToList(args.get("object_id")))
    ioc_type = args.get("ioc_type")
    ioc_value = args.get("ioc_value")
    scan_name = args.get("scan_name", DEFAULT_REQUEST_NAME)
    advance_ioc = args.get("advance_ioc")
    start_time_obj = arg_to_datetime(args.get("start_date"))
    end_time_obj = arg_to_datetime(args.get("end_date"))
    max_matches_per_snapshot = arg_to_number(args.get("max_matches_per_snapshot"), "max_matches_per_snapshot")
    max_snapshots_per_object = arg_to_number(args.get("max_snapshots_per_object"), "max_snapshots_per_object")
    min_file_size = arg_to_number(args.get("min_file_size"), "min_file_size")
    max_file_size = arg_to_number(args.get("max_file_size"), "max_file_size")
    paths_to_include = argToList(args.get("paths_to_include"))
    paths_to_exclude = argToList(args.get("paths_to_exclude"))
    paths_to_exempt = argToList(args.get("paths_to_exempt"))

    iocs = prepare_ioc_and_validate_advance_ioc_scan_args(
        ioc_type, ioc_value, advance_ioc, max_matches_per_snapshot, max_snapshots_per_object, min_file_size, max_file_size
    )

    input_data = {
        "baseConfig": {
            "name": scan_name,
            "threatHuntType": "THREAT_HUNT_V2",
            "ioc": {"iocList": {"indicatorsOfCompromise": iocs}},
            "fileScanCriteria": {
                "fileSizeLimits": {"maximumSizeInBytes": max_file_size, "minimumSizeInBytes": min_file_size},
                "pathFilter": {"inclusions": paths_to_include, "exclusions": paths_to_exclude, "exemptions": paths_to_exempt},
            },
            "maxMatchesPerSnapshot": max_matches_per_snapshot,
            "snapshotScanLimit": {"scanConfig": {"maxSnapshotsPerObject": max_snapshots_per_object}},
        },
        "objectFids": object_ids,
    }

    if start_time_obj:
        start_time = start_time_obj.strftime(DATE_TIME_FORMAT)
        input_data["baseConfig"]["snapshotScanLimit"]["scanConfig"]["startTime"] = start_time
    if end_time_obj:
        end_time = end_time_obj.strftime(DATE_TIME_FORMAT)
        input_data["baseConfig"]["snapshotScanLimit"]["scanConfig"]["endTime"] = end_time

    remove_nulls_from_dictionary(input_data)

    raw_response = client._query_raw(
        raw_query=START_ADVANCE_THREAT_HUNT_MUTATION,
        operation_name="StartAdvanceThreatHuntMutation",
        variables={"input": input_data},
        timeout=60,
    )

    data = raw_response.get("data", {})
    hunts_data = data.get("startBulkThreatHunt", {}).get("hunts", [])

    hr = f"#### The new advance Threat Hunt started with ID: {hunts_data[0].get('huntId')}."

    return CommandResults(
        outputs_prefix=OUTPUT_PREFIX["ADVANCE_IOC_SCAN"],
        outputs_key_field="huntId",
        outputs=hunts_data,
        raw_response=raw_response,
        readable_output=hr,
    )


def rubrik_anomaly_csv_analysis_v2_command(client: PolarisClient, args: Dict[str, Any]) -> List[CommandResults]:
    """
    Scheduled polling command to download anomaly details CSV file.

    This command implements a three-step polling workflow:
    1. First execution: Triggers CSV download using downloadAnomalyDetailsCsv mutation.
    2. Polling iterations: Polls allUserFiles query until file status becomes READY.
    3. Final step: Downloads the file data using external_id through REST API and returns the CSV file.

    :type client: ``PolarisClient``
    :param client: Rubrik Polaris client to use

    :type args: ``Dict[str, Any]``
    :param args: Command arguments obtained from demisto.args().

    :rtype: ``List[CommandResults]``
    :return: List of CommandResults.
    """
    cluster_id = validate_required_arg("cluster_id", args.get("cluster_id"))
    snapshot_id = validate_required_arg("snapshot_id", args.get("snapshot_id"))
    object_id = validate_required_arg("object_id", args.get("object_id"))

    polling = argToBoolean(args.get("polling", False))

    is_successful = True
    if not polling:
        input_data = {
            "clusterUuid": cluster_id,
            "snapshotId": snapshot_id,
            "workloadId": object_id,
        }

        response = client._query_raw(
            raw_query=DOWNLOAD_ANOMALY_DETAILS_CSV_MUTATION,
            operation_name="DownloadAnomalyDetailsCsvMutation",
            variables={"input": input_data},
            timeout=60,
        )

        data = response.get("data", {})
        download_data = data.get("downloadAnomalyDetailsCsv", {})
        if not download_data:
            return [CommandResults(readable_output=f"#### {MESSAGES['NO_RESPONSE']}", outputs={})]
        is_successful = download_data.get("isSuccessful", False)

        outputs = {
            "clusterId": cluster_id,
            "snapshotId": snapshot_id,
            "objectId": object_id,
            "isSuccessful": is_successful,
        }

        hr = "#### Successfully analyzed the CSV file." if is_successful else "#### Failed to analyze the CSV file."

        result = [
            CommandResults(
                outputs_prefix=OUTPUT_PREFIX["ANOMALY_CSV_ANALYSIS_V2"],
                outputs_key_field=["clusterId", "snapshotId", "objectId"],
                outputs=outputs,
                readable_output=hr,
                raw_response=response,
            )
        ]

    target_file_name = f"snapshot_{snapshot_id}"
    external_id = ""

    if polling:
        user_files_response = client._query_raw(
            raw_query=ALL_USER_DOWNLOADS_FILES_QUERY,
            operation_name="DownloadBarQuery",
            variables={},
            timeout=60,
        )

        data = user_files_response.get("data", {})
        user_files = data.get("allUserFiles", [])

        for user_file in user_files:
            downloaded_files = user_file.get("downloads", [])
            downloaded_files = downloaded_files[::-1]
            for file_info in downloaded_files:
                if file_info.get("filename") == target_file_name:
                    file_state = file_info.get("state", "").lower()
                    if file_state == "ready":
                        external_id = file_info.get("externalId", "")
                        break
                    if file_state == "failed":
                        is_successful = False
                        break

        # Attempt to download the file if external_id is available
        file_result = None
        if external_id:
            base_url = str(client._baseurl).removesuffix("api")
            download_url = urljoin(base_url, f"file-downloads/{external_id}")
            response = requests.get(
                download_url,
                headers=client.prepare_headers(),
                verify=client._verify,
                proxies=client._proxies,
                timeout=60,
            )
            response.raise_for_status()

            file_result = fileResult(
                filename=f"{target_file_name}.csv", data=response.content, file_type=EntryType.ENTRY_INFO_FILE
            )

        # Determine human-readable message based on status
        if not is_successful:
            hr = "#### Failed to download the analyzed CSV file."
        elif file_result:
            hr = "#### Successfully downloaded the analyzed CSV file."
        else:
            hr = "#### Polling for CSV file availability. The command will automatically retry..."

        # Prepare outputs and results
        outputs = {
            "clusterId": cluster_id,
            "snapshotId": snapshot_id,
            "objectId": object_id,
            "isSuccessful": is_successful,
            "externalId": external_id,
        }

        result = [
            CommandResults(
                outputs_prefix=OUTPUT_PREFIX["ANOMALY_CSV_ANALYSIS_V2"],
                outputs_key_field=["clusterId", "snapshotId", "objectId"],
                outputs=outputs,
                readable_output=hr,
                raw_response=user_files_response,
            )
        ]

        if file_result:
            result.append(file_result)

    return result


def run_polling_command(client, args: dict, command_name: str, search_function: Callable) -> List[CommandResults]:
    """
    For Scheduling command.

    :param client: Rubrik Polaris client to use.
    :param args: Command arguments.
    :param command_name: Name of the command.
    :param search_function: Callable object of command.
    :return: List of CommandResults.
    """
    result = search_function(client, args)
    outputs = result[0].outputs or {}

    if not outputs.get("isSuccessful"):
        return result

    if not outputs.get("externalId"):
        polling_args = {"polling": True, **args}
        scheduled_command = ScheduledCommand(
            command=command_name,
            next_run_in_seconds=DEFAULT_POLLING_NEXT_RUN_IN_SECONDS,
            args=polling_args,
            timeout_in_seconds=DEFAULT_POLLING_TIMEOUT,
        )
        command_results = CommandResults(scheduled_command=scheduled_command)

        return [result, command_results]

    return result


def trim_spaces_from_args(args):
    """
    Trim spaces from values of the args dict.

    :param args: Dict to trim spaces from
    :type args: dict
    :return:
    """
    for key, val in args.items():
        if isinstance(val, str):
            args[key] = val.strip()

    return args


def create_client_object(service_account_json, username, domain, password, proxies, insecure):
    """
    Create a client object using the authentication information.

    :param service_account_json: Service Account JSON to authenticate
    :param username: Username to authenticate
    :param domain: Domain of the host
    :param password: Password to authenticate
    :param proxies: Proxy values to authenticate
    :param insecure: authentication security

    :return: client object
    :raises: Exception as relevant
    """
    if service_account_json:
        try:
            client = MyClient(json_data=service_account_json, proxies=proxies, insecure=insecure, user_agent=DEFAULT_REQUEST_NAME)
        except json.JSONDecodeError:
            raise ValueError(ERROR_MESSAGES["SA_JSON_DECODE_ERR"])
        except KeyError as e:
            raise ValueError(ERROR_MESSAGES["KEY_NOT_FOUND_IN_SA_JSON"].format(str(e)))
        except ProxyException:
            raise ProxyException(ERROR_MESSAGES["PROXY_ERROR"])
    elif domain and username and password:
        try:
            client = MyClient(
                domain=domain,
                username=username,
                password=password,
                proxies=proxies,
                insecure=insecure,
                user_agent=DEFAULT_REQUEST_NAME,
            )
        except ProxyException:
            raise ProxyException(ERROR_MESSAGES["PROXY_ERROR"])
    else:
        raise ValueError(ERROR_MESSAGES["NO_CREDENTIALS_PROVIDED"])

    return client


def main() -> None:
    """Drive all the tasks to be performed."""
    params = demisto.params()

    domain = params.get("url")
    service_account_json = params.get("service_account_json")
    username = password = ""
    if params.get("email"):
        username = params.get("email").get("identifier", "").strip()
        password = params.get("email").get("password")
    insecure = params.get("insecure", False)
    proxy = params.get("proxy", False)
    demisto.info(f"Command being called is {demisto.command()}")
    try:
        proxies = {"http": "", "https": ""}
        if proxy:
            # method from common server python to add default http prefix to proxies if no protocol is specified
            ensure_proxy_has_http_prefix()
            proxies = {
                "http": os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy", "") or "",
                "https": os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy", "") or "",
            }
        client = create_client_object(service_account_json, username, domain, password, proxies, insecure)

        client.auth()
        if demisto.command() == "test-module":
            # This is the call made when pressing the integration Test button.
            return_results(test_module(client, params))
        elif demisto.command() == "fetch-incidents":
            last_run = demisto.getLastRun()
            next_run, incidents = fetch_incidents(client, last_run, params)
            demisto.info(f"Fetched {len(incidents)} new incidents")
            demisto.incidents(incidents)
            demisto.setLastRun(next_run)
        else:
            COMMAND_TO_FUNCTION = {
                "rubrik-cdm-cluster-location": cdm_cluster_location_command,
                "rubrik-cdm-cluster-connection-state": cdm_cluster_connection_state_command,
                "rubrik-radar-analysis-status": radar_analysis_status_command,
                "rubrik-sonar-sensitive-hits": sonar_sensitive_hits_command,
                "rubrik-polaris-object-search": rubrik_polaris_object_search_command,
                "rubrik-sonar-policies-list": rubrik_sonar_policies_list_command,
                "rubrik-sonar-policy-analyzer-groups-list": rubrik_sonar_policy_analyzer_groups_list_command,
                "rubrik-polaris-vm-object-metadata-get": rubrik_polaris_vm_object_metadata_get_command,
                "rubrik-polaris-vm-objects-list": rubrik_polaris_vm_objects_list_command,
                "rubrik-sonar-ondemand-scan": rubrik_sonar_ondemand_scan_command,
                "rubrik-sonar-ondemand-scan-status": rubrik_sonar_ondemand_scan_status_command,
                "rubrik-sonar-ondemand-scan-result": rubrik_sonar_ondemand_scan_result_command,
                "rubrik-polaris-vm-object-snapshot-list": rubrik_polaris_vm_object_snapshot_list_command,
                "rubrik-radar-anomaly-csv-analysis": rubrik_radar_anomaly_csv_analysis_command,
                "rubrik-sonar-csv-download": rubrik_sonar_csv_download_command,
                "rubrik-gps-snapshot-files-list": rubrik_gps_snapshot_files_list_command,
                "rubrik-gps-vm-export": rubrik_gps_vm_export_command,
                "rubrik-user-downloads-list": rubrik_user_downloads_list_command,
                "rubrik-gps-sla-domain-list": rubrik_gps_sla_domain_list,
                "rubrik-sonar-csv-result-download": rubrik_sonar_csv_result_download_command,
                "rubrik-gps-vm-snapshot-create": rubrik_gps_vm_snapshot_create,
                "rubrik-gps-snapshot-files-download": rubrik_gps_snapshot_files_download_command,
                "rubrik-gps-vm-livemount": rubrik_gps_vm_livemount,
                "rubrik-gps-vm-host-list": rubrik_gps_vm_host_list_command,
                "rubrik-gps-vm-datastore-list": rubrik_gps_vm_datastore_list_command,
                "rubrik-event-list": rubrik_event_list_command,
                "rubrik-polaris-object-list": rubrik_polaris_object_list_command,
                "rubrik-polaris-object-snapshot-list": rubrik_polaris_object_snapshot_list_command,
                "rubrik-radar-ioc-scan": rubrik_radar_ioc_scan_command,
                "rubrik-radar-ioc-scan-results": rubrik_radar_ioc_scan_results_command,
                "rubrik-radar-ioc-scan-list": rubrik_radar_ioc_scan_list_command,
                "rubrik-gps-async-result": rubrik_gps_async_result_command,
                "rubrik-gps-cluster-list": rubrik_gps_cluster_list_command,
                "rubrik-gps-vm-recover-files": rubrik_gps_vm_recover_files,
                "rubrik-sonar-user-access-list": rubrik_sonar_user_access_list_command,
                "rubrik-sonar-user-access-get": rubrik_sonar_user_access_get_command,
                "rubrik-sonar-file-context-list": rubrik_sonar_file_context_list_command,
                "rubrik-radar-suspicious-file-list": rubrik_radar_suspicious_file_list_command,
                "rubrik-radar-anomaly-status-update": rubrik_radar_anomaly_status_update_command,
                "ip": ip_command,
                "domain": domain_command,
                "rubrik-threat-monitoring-matched-object-list": rubrik_threat_monitoring_matched_object_list_command,
                "rubrik-threat-monitoring-matched-object-get": rubrik_threat_monitoring_matched_object_get_command,
                "rubrik-threat-monitoring-matched-file-list": rubrik_threat_monitoring_matched_file_list_command,
                "rubrik-threat-monitoring-matched-file-get": rubrik_threat_monitoring_matched_file_get_command,
                "rubrik-ioc-scan-list-v2": rubrik_ioc_scan_list_v2_command,
                "rubrik-ioc-scan-results-v2": rubrik_ioc_scan_results_v2_command,
                "rubrik-turbo-ioc-scan": rubrik_turbo_ioc_scan_command,
                "rubrik-advance-ioc-scan": rubrik_advance_ioc_scan_command,
            }
            if COMMAND_TO_FUNCTION.get(demisto.command()):
                args = demisto.args()
                remove_nulls_from_dictionary(trim_spaces_from_args(args))

                return_results(COMMAND_TO_FUNCTION[demisto.command()](client, args))
            elif demisto.command() == "rubrik-anomaly-csv-analysis-v2":
                args = demisto.args()
                remove_nulls_from_dictionary(trim_spaces_from_args(args))

                return_results(
                    run_polling_command(
                        client=client,
                        args=args,
                        search_function=rubrik_anomaly_csv_analysis_v2_command,
                        command_name="rubrik-anomaly-csv-analysis-v2",
                    )
                )
            else:
                raise NotImplementedError(f"Command {demisto.command()} is not implemented")
    # Log exceptions and return errors
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f"Failed to execute {demisto.command()} command.\nError:\n{e!s}")  # noqa: E231


""" ENTRY POINT """

if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
