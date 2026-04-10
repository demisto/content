import uuid

from CommonServerPython import *
import demistomock as demisto
from urllib import parse

DEMISTO_OCCURRED_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
WIZ_API_TIMEOUT = 300  # Increase timeout for Wiz API
WIZ_HTTP_QUERIES_LIMIT = 500  # Request limit during run
WIZ_API_LIMIT = 500  # limit number of returned records from the Wiz API
WIZ = "wiz"

WIZ_VERSION = "1.4.0"
INTEGRATION_GUID = "8864e131-72db-4928-1293-e292f0ed699f"
NOT_DEFINED = "Not Defined"

DEFAULT_FETCH_ISSUE_STATUS = ["OPEN", "IN_PROGRESS"]


class ValidationType:
    """Class representing field names for validation results"""

    IS_VALID = "is_valid"
    ERROR_MESSAGE = "error_message"
    VALUE = "value"
    SEVERITY_LIST = "severity_list"
    MINUTES_VALUE = "minutes_value"
    DAYS_VALUE = "days_value"
    STATUS_LIST = "status_list"


class ValidationResponse:
    """Class for standardized validation responses"""

    def __init__(self, is_valid=True, error_message=None, value=None):
        self.is_valid = is_valid
        self.error_message = error_message
        self.value = value
        self.days_value = None
        self.minutes_value = None
        self.severity_list = None
        self.status_list = None

    def to_dict(self):
        """Convert the response to a dictionary"""
        return {
            ValidationType.IS_VALID: self.is_valid,
            ValidationType.ERROR_MESSAGE: self.error_message,
            ValidationType.VALUE: self.value,
            ValidationType.DAYS_VALUE: self.days_value,
            ValidationType.MINUTES_VALUE: self.minutes_value,
            ValidationType.SEVERITY_LIST: self.severity_list,
            ValidationType.STATUS_LIST: self.status_list,
        }

    @classmethod
    def create_success(cls, value=None):
        """Create a successful validation response"""
        return cls(is_valid=True, error_message=None, value=value)

    @classmethod
    def create_error(cls, error_message):
        """Create a failed validation response"""
        return cls(is_valid=False, error_message=error_message, value=None)


def get_integration_user_agent():
    integration_user_agent = f"{INTEGRATION_GUID}/xsoar/{WIZ_VERSION}"
    return integration_user_agent


# Standard headers
HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": get_integration_user_agent()}

HEADERS = {"Content-Type": "application/json", "User-Agent": get_integration_user_agent()}

TOKEN = None
URL = ""
AUTH_E = ""
AUTH_DEFAULT = "auth"  # NEED TO BE REMOVED AFTER THAT AUTH0 IS DEPRECATED
COGNITO_PREFIX = ["auth.app", "auth.gov", "auth.test"]
AUTH0_PREFIX = ["auth", "auth0.gov", "auth0.test"]
URL_SUFFIX = "wiz.io/oauth/token"
URL_SUFFIX_FED = "wiz.us/oauth/token"

# Issues Queries
PULL_ISSUES_QUERY = """
query IssuesTable(
  $filterBy: IssueFilters
  $first: Int
  $after: String
  $orderBy: IssueOrder
) {
  issues:issuesV2(filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy) {
    nodes {
      id
      sourceRule{
        __typename
        ... on Control {
          id
          name
          description
          resolutionRecommendation
          securitySubCategories {
            title
            category {
              name
              framework {
                name
              }
            }
          }
        }
        ... on CloudEventRule{
          id
          name
          description
          sourceType
          type
        }
        ... on CloudConfigurationRule{
          id
          name
          description
          remediationInstructions
          serviceType
        }
      }
      type
      createdAt
      updatedAt
      dueAt
      projects {
        id
        name
        slug
        projectOwners{
          name
        }
        securityChampions{
          name
        }
        businessUnit
        riskProfile {
          businessImpact
        }
      }
      status
      severity
      entitySnapshot {
        id
        type
        nativeType
        name
        status
        cloudPlatform
        cloudProviderURL
        providerId
        region
        resourceGroupExternalId
        subscriptionExternalId
        subscriptionName
        subscriptionTags
        tags
        externalId
      }
      serviceTickets {
        externalId
        name
        url
      }
      notes {
        id
        createdAt
        updatedAt
        text
        user {
          name
          email
        }
        serviceAccount {
          name
        }
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""
PULL_ISSUE_WITH_EVIDENCE_PARAM_QUERY = """
query IssuesTable(
  $filterBy: IssueFilters
  $first: Int
  $after: String
  $orderBy: IssueOrder
) {
  issues:issuesV2(filterBy: $filterBy
    first: $first
    after: $after
    orderBy: $orderBy) {
    nodes {
      evidenceQuery
      threatDetectionDetails{
        ...ThreatDetectionDetailsDetections
        ...ThreatDetectionDetailsActorsResources
        ...ThreatDetectionDetailsMainDetection
        ...ThreatDetectionDetailsCloudEventGroups
      }
      type
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
fragment ThreatDetectionDetailsDetections on ThreatDetectionIssueDetails {
  detections(first: 500) {
    nodes {
      primaryResource {
        id
        type
        name
        externalId
      }
      actors {
        id
        name
        externalId
        providerUniqueId
        type
      }
      startedAt
      id
      severity
      description(format: MARKDOWN)
      primaryResource {
        region
        cloudAccount {
          id
          name
          externalId
          cloudProvider
        }
      }
      ruleMatch {
        rule {
          id
          name
          securitySubCategories {
            id
            title
            category {
              id
              name
              framework {
                id
              }
            }
          }
        }
      }
    }
  }
}

fragment ThreatDetectionDetailsActorsResources on ThreatDetectionIssueDetails {
  actors {
    id
    name
    externalId
    providerUniqueId
    type
  }
  resources {
    id
    name
    externalId
    providerUniqueId
    type
    nativeType
  }
}

fragment ThreatDetectionDetailsMainDetection on ThreatDetectionIssueDetails {
  mainDetection {
    id
    startedAt
    severity
    description(format: MARKDOWN)
    ruleMatch {
      rule {
        id
        name
        origins
      }
    }
  }
}

fragment ThreatDetectionDetailsCloudEventGroups on ThreatDetectionIssueDetails {
  cloudEventGroups(first: 500) {
    nodes {
      id
      name
      firstEventAt
      lastEventAt
      status
      kind
      origin
      groupType
      description
      cloudEvents {
        ...CloudEventGroupCloudEventResponse
      }
    }
  }
}

fragment CloudEventGroupCloudEventResponse on CloudEvent {
  id
  category
  externalName
  isForeignActorIP
  rawAuditLogRecord
  errorMessage
  timestamp
  origin
  path
  kind
  cloudPlatform
  actor {
    id
    externalId
    name
    type
    email
    userAgent
    accessKeyId
    providerUniqueId
    inactiveInLast90Days
    friendlyName
    hasAdminKubernetesPrivileges
    hasAdminPrivileges
    hasHighKubernetesPrivileges
    hasHighPrivileges
    isExternalCloudAccount
    actingAs {
      id
      name
      friendlyName
      externalId
      providerUniqueId
      type
    }
  }
  actorIP
  actorIPMeta {
    relatedAttackGroupNames
    city
    country
    countryCode
    reputation
    autonomousSystemOrganization
  }
  subjectResource {
    id
    type
    name
    nativeType
    externalId
    providerUniqueId
    region
    cloudAccount {
      id
      name
      externalId
      cloudProvider
    }
    containerService {
      id
      name
      type
      providerUniqueId
    }
    containerServiceGraphEntity {
      id
      name
      type
      providerUniqueId
    }
    kubernetesClusterGraphEntity {
      id
      name
      type
      providerUniqueId
    }
    kubernetesCluster {
      id
      name
      type
      providerUniqueId
    }
    kubernetesNamespaceGraphEntity {
      id
      name
      providerUniqueId
    }
    kubernetesNamespace {
      id
      name
      providerUniqueId
    }
    kubernetesControllerGraphEntity {
      id
      name
      type
      providerUniqueId
    }
    kubernetesController {
      id
      name
      type
      providerUniqueId
    }
    openToAllInternet
  }
  errorCode
  statusDetails {
    errorReason
    providerErrorMessage
    providerErrorCode
  }
  status
  matchedRules {
    rule {
      builtInId
      name
      id
    }
  }
  ...CloudEventExtraDetails
}

fragment CloudEventExtraDetails on CloudEvent {
  extraDetails {
    ...CloudEventRuntimeDetails
    ...CloudEventAdmissionReviewDetails
    ...CloudEventFimDetails
    ...CloudEventImageIntegrityDetails
    ...CloudEventCICDScanDetails
  }
  trigger {
    ...CloudEventSensorRulesMatch
    ...CloudEventAdmissionReviewTriggerDetails
  }
}

fragment CloudEventRuntimeDetails on CloudEventRuntimeDetails {
  sensor {
    id
    name
    lastSeenAt
    firstSeenAt
    sensorVersion
    definitionsVersion
    status
    ipAddress
    type
    workload {
      id
      name
      sensorName
    }
    cluster {
      id
      name
      type
    }
  }
  processTree {
    ...CloudEventRuntimeProcessBasicDetails
    userName
    userId
    hash
    executionTime
    stdin
    stdout
    name
    wizResponse
    enforcementResult {
      action
      errorMessage
    }
    containerGraphEntity {
      ...ProcessResourceGraphEntity
      properties
    }
    container {
      id
      name
      externalId
      imageGraphEntity {
        ...ProcessResourceGraphEntity
      }
      image {
        id
        externalId
      }
      podGraphEntity {
        ...ProcessResourceGraphEntity
      }
      pod {
        id
        name
        externalId
        ips
        namespace
        namespaceGraphEntity {
          ...ProcessResourceGraphEntity
        }
      }
      kubernetesControllerGraphEntity {
        ...ProcessResourceGraphEntity
      }
      kubernetesController {
        id
        name
        externalId
        type
      }
      kubernetesClusterGraphEntity {
        ...ProcessResourceGraphEntity
      }
      kubernetesCluster {
        id
        name
        externalId
      }
      serviceAccount
      ecsContainerDetails {
        ecsTask {
          id
          externalId
        }
        ecsTaskGraphEntity {
          ...ProcessResourceGraphEntity
        }
        ecsCluster {
          id
          name
          externalId
        }
        ecsClusterGraphEntity {
          ...ProcessResourceGraphEntity
        }
        ecsService {
          id
          name
          externalId
        }
        ecsServiceGraphEntity {
          ...ProcessResourceGraphEntity
        }
      }
    }
  }
  hostGraphEntity {
    properties
    ...ProcessResourceGraphEntity
  }
  host {
    id
    externalId
    type
    hostname
    kernelVersion
    computeInstanceGroupGraphEntity {
      id
      name
      type
    }
  }
  rawDetails
  runtimeExecutionDataId
  type
  context {
    ... on CloudEventRuntimeTypeFileContext {
      fileName
    }
    ... on CloudEventRuntimeTypeNetworkConnectContext {
      remoteIP
      remotePort
    }
    ... on CloudEventRuntimeTypeDNSQueryContext {
      query
    }
    ... on CloudEventRuntimeTypeProcessStartContext {
      commandLine
    }
    ... on CloudEventRuntimeTypeIMDSQueryContext {
      query
    }
    ... on CloudEventRuntimeTypeChangeDirectoryContext {
      path
    }
  }
}

fragment CloudEventRuntimeProcessBasicDetails on CloudEventRuntimeProcess {
  id
  command
  path
  executionTime
}

fragment ProcessResourceGraphEntity on GraphEntity {
  id
  name
  type
}

fragment CloudEventAdmissionReviewDetails on CloudEventAdmissionReviewDetails {
  verdict
  policyEnforcement
  reviewDuration
  infoMatches
  lowMatches
  mediumMatches
  highMatches
  criticalMatches
  totalMatches
  policies {
    ...CICDScanPolicyDetails
  }
  cloudConfigurationFindings {
    cloudConfigurationRule {
      id
      shortId
      name
      severity
      cloudProvider
    }
    passedPolicies {
      ...CICDScanPolicyDetails
    }
    failedPolicies {
      ...CICDScanPolicyDetails
    }
  }
}

fragment CICDScanPolicyDetails on CICDScanPolicy {
  id
  name
  description
  policyLifecycleEnforcements {
    enforcementMethod
    deploymentLifecycle
  }
  params {
    __typename
    ... on CICDScanPolicyParamsIAC {
      severityThreshold
    }
    ... on CICDScanPolicyParamsVulnerabilities {
      severity
    }
    ... on CICDScanPolicyParamsSensitiveData {
      dataFindingSeverityThreshold
    }
    ... on CICDScanPolicyParamsHostConfiguration {
      hostConfigurationSeverity
      rulesScope {
        type
        securityFrameworks {
          id
          name
        }
      }
      failCountThreshold
      passPercentageThreshold
    }
  }
}

fragment CloudEventFimDetails on CloudEventFimDetails {
  previousHash
}

fragment CloudEventImageIntegrityDetails on CloudEventImageIntegrityAdmissionReviewDetails {
  verdict
  policyEnforcement
  reviewDuration
  policies {
    ...CICDScanPolicyDetails
  }
  images {
    id
    name
    imageVerdict
    sources
    digest
    policiesFailedBasedOnNoMatchingValidators {
      id
      name
    }
    imageIntegrityValidators {
      imageIntegrityValidator {
        ...ImageSignatureValidatorDetails
      }
      verdict
      failedPolicies {
        ...CICDScanPolicyDetails
      }
      passedPolicies {
        ...CICDScanPolicyDetails
      }
      extraDetails {
        ... on ImageIntegrityAdmissionReviewImageValidatorExtraDetailsWizScan {
          cicdScan {
            id
            status {
              verdict
            }
          }
        }
      }
    }
  }
}

fragment ImageSignatureValidatorDetails on ImageIntegrityValidator {
  id
  name
  description
  imagePatterns
  projects {
    id
    isFolder
    slug
    name
  }
  value {
    method
    notary {
      certificate
    }
    cosign {
      method
      key
      certificate
      certificateChain
    }
    wizScan {
      maxAgeHours
      policyId
      serviceAccountIds
    }
  }
}

fragment CloudEventCICDScanDetails on CloudEventCICDScanDetails {
  cicdScanPolicyEnforcement: policyEnforcement
  scanDuration
  trigger
  tags {
    key
    value
  }
  createdBy {
    serviceAccount {
      id
      name
    }
    user {
      id
      name
      email
    }
  }
  cliDetails {
    ...CICDScanCLIDetailsFragment
  }
  codeAnalyzerDetails {
    taskUrl
    commit {
      author
      infoURL
      messageSnippet
      ref
      sha
    }
    webhookEvent {
      createdAt
      hookID
      payload
      processedAt
      receivedAt
      source
      sourceRequestID
      type
      wizRequestID
    }
    pullRequest {
      author
      title
      baseCommit {
        sha
        ref
        infoURL
      }
      headCommit {
        sha
        ref
        infoURL
      }
      bodySnippet
      infoURL
      analytics {
        additions
        deletions
        changedFiles
        commits
      }
    }
  }
  warnedPolicies {
    ...CICDScanPolicyDetails
  }
  failedPolicies {
    ...CICDScanPolicyDetails
  }
  passedPolicies {
    ...CICDScanPolicyDetails
  }
  policies {
    ...CICDScanPolicyDetails
  }
  secretDetails {
    failedPolicyMatches {
      policy {
        __typename
        id
        name
      }
    }
    secrets {
      id
      contains {
        name
        type
      }
      details {
        __typename
      }
      failedPolicyMatches {
        policy {
          __typename
          id
          name
        }
      }
      description
      lineNumber
      offset
      path
      snippet
      type
      severity
      hasAdminPrivileges
      hasHighPrivileges
      relatedEntities {
        id
        type
        name
        properties
      }
    }
  }
  iacDetails {
    ruleMatches {
      rule {
        id
        shortId
        name
        description
        cloudProvider
      }
      deletedRuleFallback: rule {
        id
        name
      }
      severity
      failedResourceCount
      failedPolicyMatches {
        policy {
          id
        }
      }
      matches {
        resourceName
        fileName
        lineNumber
        matchContent
        expected
        found
      }
    }
    scanStatistics {
      infoMatches
      lowMatches
      highMatches
      mediumMatches
      criticalMatches
      totalMatches
    }
  }
  hostConfigurationDetails {
    ...HostConfigurationDetails
  }
  vulnerabilityDetails {
    vulnerableSBOMArtifactsByNameVersion {
      ...CICDSbomArtifactsByNameVersion
    }
    cpes {
      name
      version
      path
      vulnerabilities {
        ...CICDScanDiskScanVulnerabilityDetails
      }
      detectionMethod
    }
    osPackages {
      name
      version
      vulnerabilities {
        ...CICDScanDiskScanVulnerabilityDetails
      }
      detectionMethod
    }
    libraries {
      name
      version
      path
      vulnerabilities {
        ...CICDScanDiskScanVulnerabilityDetails
      }
      detectionMethod
    }
    applications {
      name
      vulnerabilities {
        path
        pathType
        version
        vulnerability {
          ...CICDScanDiskScanVulnerabilityDetails
        }
      }
      detectionMethod
    }
  }
  dataDetails {
    dataFindingsWithFullClassifierInfo: findings {
      dataClassifier {
        id
        name
        category
        originalDataClassifierOverridden
      }
      ...CICDScanDataFindingDetails
    }
    dataFindings: findings {
      dataClassifier {
        id
        name
      }
      ...CICDScanDataFindingDetails
    }
  }
  status {
    details
    state
    verdict
  }
  policies {
    __typename
    id
    name
    params {
      __typename
    }
  }
}

fragment CICDScanCLIDetailsFragment on CICDScanCLIDetails {
  scanOriginResource {
    name
    __typename
    ... on CICDScanOriginIAC {
      subTypes
      name
    }
    ... on CICDScanOriginContainerImage {
      digest
      id
      name
    }
  }
  scanOriginResourceType
  clientName
  clientVersion
  buildParams {
    commitUrl
    branch
    commitHash
    committedBy
    platform
    repository
    extraDetails {
      ... on CICDBuildParamsContainerImage {
        dockerfilePath
        dockerfileContents
      }
    }
  }
}

fragment HostConfigurationDetails on CICDHostConfigurationScanResult {
  hostConfigurationFrameworks {
    framework {
      id
      name
    }
    matches {
      policyMatch {
        policy {
          id
        }
      }
    }
  }
  hostConfigurationFindings {
    rule {
      description
      name
      id
      securitySubCategories {
        id
        resolutionRecommendation
        title
        description
        category {
          id
          name
          framework {
            id
            name
            enabled
          }
        }
      }
    }
    status
    severity
    failedPolicyMatches {
      policy {
        id
      }
    }
  }
}

fragment CICDSbomArtifactsByNameVersion on CICDDiskScanResultSBOMArtifactsByNameVersion {
  id
  name
  version
  filePath
  vulnerabilityFindings {
    fixedVersion
    remediation
    severities {
      criticalCount
      highCount
      infoCount
      lowCount
      mediumCount
    }
    findings {
      id
      vulnerabilityExternalId
      vulnerableAsset {
        ... on VulnerableAssetRepositoryBranch {
          id
          type
          name
          providerUniqueId
          repositoryName
        }
      }
      remediationPullRequestAvailable
      remediationPullRequestConnector {
        id
        name
        type {
          id
          name
        }
      }
      severity
    }
  }
  layerMetadata {
    id
    isBaseLayer
    details
  }
  type {
    ...SBOMArtifactTypeFragment
  }
}

fragment SBOMArtifactTypeFragment on SBOMArtifactType {
  group
  codeLibraryLanguage
  osPackageManager
  hostedTechnology {
    id
    name
    icon
  }
  plugin
}

fragment CICDScanDiskScanVulnerabilityDetails on DiskScanVulnerability {
  name
  severity
  fixedVersion
  source
  score
  exploitabilityScore
  hasExploit
  hasCisaKevExploit
  cisaKevReleaseDate
  cisaKevDueDate
  epssProbability
  epssPercentile
  epssSeverity
  publishDate
  fixPublishDate
  gracePeriodEnd
  gracePeriodRemainingHours
  failedPolicyMatches {
    policy {
      id
      name
      params {
        ... on CICDScanPolicyParamsHostConfiguration {
          failCountThreshold
          passPercentageThreshold
          rulesScope {
            type
          }
        }
      }
    }
  }
  weightedSeverity
  finding {
    id
    version
  }
}

fragment CICDScanDataFindingDetails on CICDDiskScanResultDataFinding {
  matchCount
  severity
  examples {
    path
    matchCount
    value
  }
}

fragment CloudEventSensorRulesMatch on CloudEventSensorRulesMatch {
  sensorEngineRules {
    rule {
      id
      name
      description
      MITRETactics
      MITRETechniques
    }
    version
  }
  fileReputationHashMatch {
    name
    md5
    sha1
    sha256
    sampleFirstSeen
    sampleLastSeen
    scannerMatch
    scannerCount
    scannerPercent
    trustFactor
    malwareClassification {
      isGeneric
      type
      platform
      subPlatform
      family
      vulnerability {
        id
      }
    }
  }
  connectivityReputation {
    source {
      ip
      port
    }
    destination {
      ip
      ipReputation
      port
    }
    process {
      ...CloudEventRuntimeProcessBasicDetails
    }
  }
  dnsQueryReputation {
    domain
    domainReputation
    process {
      ...CloudEventRuntimeProcessBasicDetails
    }
  }
}

fragment CloudEventAdmissionReviewTriggerDetails on CloudEventAdmissionReview {
  cloudConfigurationRuleMatches {
    cloudConfigurationRule {
      id
    }
    cicdScanPolicies {
      id
      name
      params {
        __typename
      }
    }
  }
}
"""
PULL_ISSUES_DEFAULT_VARIABLES = {"orderBy": {"field": "SEVERITY", "direction": "DESC"}}
PULL_ISSUES_TEST_VARIABLES = test_variables = {
    "first": 1,
    "filterBy": {"status": ["OPEN", "IN_PROGRESS"]},
    "orderBy": {"field": "SEVERITY", "direction": "DESC"},
}
PULL_ISSUE_EVIDENCE_QUERY = """
  query GraphSearch(
    $query: GraphEntityQueryInput
    $controlId: ID
    $projectId: String!
    $first: Int
    $after: String
    $fetchTotalCount: Boolean!
    $quick: Boolean = true
    $fetchPublicExposurePaths: Boolean = false
    $fetchInternalExposurePaths: Boolean = false
    $fetchIssueAnalytics: Boolean = false
    $fetchLateralMovement: Boolean = false
    $fetchKubernetes: Boolean = false
  ) {
    graphSearch(
      query: $query
      controlId: $controlId
      projectId: $projectId
      first: $first
      after: $after
      quick: $quick
    ) {
      totalCount @include(if: $fetchTotalCount)
      maxCountReached @include(if: $fetchTotalCount)
      pageInfo {
        endCursor
        hasNextPage
      }
      nodes {
        entities {
          ...PathGraphEntityFragment
          userMetadata {
            isInWatchlist
            isIgnored
            note
          }
          technologies {
            id
            icon
          }
          publicExposures(first: 10) @include(if: $fetchPublicExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          otherSubscriptionExposures(first: 10)
            @include(if: $fetchInternalExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          otherVnetExposures(first: 10)
            @include(if: $fetchInternalExposurePaths) {
            nodes {
              ...NetworkExposureFragment
            }
          }
          lateralMovementPaths(first: 10) @include(if: $fetchLateralMovement) {
            nodes {
              id
              pathEntities {
                entity {
                  ...PathGraphEntityFragment
                }
              }
            }
          }
          kubernetesPaths(first: 10) @include(if: $fetchKubernetes) {
            nodes {
              id
              path {
                ...PathGraphEntityFragment
              }
            }
          }
        }
        aggregateCount
      }
    }
  }

  fragment PathGraphEntityFragment on GraphEntity {
    id
    name
    type
    properties
    issueAnalytics: issues(filterBy: { status: [IN_PROGRESS, OPEN] })
      @include(if: $fetchIssueAnalytics) {
      highSeverityCount
      criticalSeverityCount
    }
  }


  fragment NetworkExposureFragment on NetworkExposure {
    id
    portRange
    sourceIpRange
    destinationIpRange
    path {
      ...PathGraphEntityFragment
    }
    applicationEndpoints {
      ...PathGraphEntityFragment
    }
  }
    """
PULL_ISSUE_EVIDENCE_PARAMS = {
    "quick": True,
    "fetchPublicExposurePaths": False,
    "fetchInternalExposurePaths": False,
    "fetchIssueAnalytics": False,
    "fetchLateralMovement": False,
    "fetchKubernetes": False,
    "first": 5,
    "projectId": "*",
    "query": None,
    "fetchTotalCount": False,
}
UPDATE_ISSUE_QUERY = """
mutation UpdateIssue(
    $issueId: ID!
    $patch: UpdateIssuePatch
    $override: UpdateIssuePatch
  ) {
    updateIssue(input: { id: $issueId, patch: $patch, override: $override }) {
      issue {
        id
        notes {
          ...IssueNoteDetails
        }
        status
        dueAt
        resolutionReason
      }
    }
  }

  fragment IssueNoteDetails on IssueNote {
    id
    text
    updatedAt
    createdAt
    user {
      id
      email
    }
    serviceAccount {
      id
      name
    }
  }
"""
CREATE_COMMENT_QUERY = """
mutation CreateIssueComment($input: CreateIssueNoteInput!) {
    createIssueNote(input: $input) {
      issueNote {
        createdAt
        id
        text
        user {
          id
          email
        }
      }
    }
  }
    """
DELETE_NOTE_QUERY = """
    mutation DeleteIssueNote($input: DeleteIssueNoteInput!) {
    deleteIssueNote(input: $input) {
      _stub
    }
  }
    """

# Resources Queries
PULL_RESOURCES_ID_NATIVE_QUERY = """
query CloudResourceSearch($filterBy: CloudResourceFilters, $first: Int, $after: String) {
  cloudResources(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""
PULL_CLOUD_RESOURCES_NATIVE_QUERY = """
query CloudResourceSearch($filterBy: CloudResourceFilters, $first: Int, $after: String) {
  cloudResources(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      name
      type
      subscriptionId
      subscriptionExternalId
      graphEntity {
        id
        providerUniqueId
        name
        type
        projects {
          id
        }
        properties
        firstSeen
        lastSeen
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""

# Forensics Queries
COPY_TO_FORENSICS_ACCOUNT_MUTATION = """
        mutation CopyResourceForensicsToExternalAccount($input: CopyResourceForensicsToExternalAccountInput!) {
          copyResourceForensicsToExternalAccount(input: $input) {
            systemActivityGroupId
          }
        }
    """

# Project Queries
PULL_PROJECTS_QUERY = """
query ProjectsTable($filterBy: ProjectFilters, $first: Int, $after: String, $orderBy: ProjectOrder) {
  projects(filterBy: $filterBy, first: $first, after: $after, orderBy: $orderBy) {
    nodes {
      id
      name
      isFolder
      archived
      businessUnit
      description
      projectOwners {
        id
        name
        email
      }
      securityChampions {
        id
        name
        email
      }
    }
  }
}"""


class WizInputParam:
    ISSUE_ID = "issue_id"
    ISSUE_TYPE = "issue_type"
    ENTITY_TYPE = "entity_type"
    RESOURCE_ID = "resource_id"
    RESOURCE_NAME = "resource_name"
    SEVERITY = "severity"
    REJECT_REASON = "reject_reason"
    REJECT_NOTE = "reject_note"
    RESOLUTION_REASON = "resolution_reason"
    RESOLUTION_NOTE = "resolution_note"
    REOPEN_NOTE = "reopen_note"
    NOTE = "note"
    DUE_AT = "due_at"
    VM_ID = "vm_id"
    PROJECT_NAME = "project_name"
    SEARCH = "search"
    SUBSCRIPTION_EXTERNAL_IDS = "subscription_external_ids"
    PROVIDER_UNIQUE_IDS = "provider_unique_ids"
    STATUS = "status"


class WizStatus:
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    REJECTED = "REJECTED"
    RESOLVED = "RESOLVED"

    @classmethod
    def values(cls):
        """Get all available detection origins"""
        return [getattr(cls, attr) for attr in dir(cls) if not attr.startswith("_") and not callable(getattr(cls, attr))]


class WizSeverity:
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

    @classmethod
    def values(cls):
        """Get all available detection origins"""
        return [getattr(cls, attr) for attr in dir(cls) if not attr.startswith("_") and not callable(getattr(cls, attr))]


class WizIssueType:
    TOXIC_COMBINATION = "TOXIC_COMBINATION"
    CLOUD_CONFIGURATION = "CLOUD_CONFIGURATION"
    THREAT_DETECTION = "THREAT_DETECTION"

    @classmethod
    def values(cls):
        """Get all available detection origins"""
        return [getattr(cls, attr) for attr in dir(cls) if not attr.startswith("_") and not callable(getattr(cls, attr))]


def set_authentication_endpoint(auth_endpoint):
    global AUTH_E
    AUTH_E = generate_auth_urls(AUTH_DEFAULT)[1] if auth_endpoint == "" else auth_endpoint


def set_api_endpoint(api_endpoint):
    global URL
    URL = api_endpoint


def generate_auth_urls(prefix):
    auth_url = f"{prefix}.{URL_SUFFIX}"
    http_auth_url = f"https://{auth_url}"
    return auth_url, http_auth_url


def generate_auth_urls_fed(prefix):
    auth_url = f"{prefix}.{URL_SUFFIX_FED}"
    http_auth_url = f"https://{auth_url}"
    return auth_url, http_auth_url


def get_token():
    """
    Retrieve the token using the credentials
    """
    audience = ""
    cognito_list = []
    for cognito_prefix in COGNITO_PREFIX:
        cognito_list.extend(generate_auth_urls(cognito_prefix))
        cognito_list.extend(generate_auth_urls_fed(cognito_prefix))

    auth0_list = []
    for auth0_prefix in AUTH0_PREFIX:
        auth0_list.extend(generate_auth_urls(auth0_prefix))

    # check Wiz portal auth endpoint - Cognito or Auth0
    if AUTH_E in cognito_list:
        audience = "wiz-api"
    elif AUTH_E in auth0_list:
        audience = "beyond-api"
    else:
        raise Exception("Not a valid authentication endpoint")

    demisto_params = demisto.params()
    said = demisto_params.get("credentials").get("identifier")
    sasecret = demisto_params.get("credentials").get("password")
    auth_payload = parse.urlencode(
        {"grant_type": "client_credentials", "audience": audience, "client_id": said, "client_secret": sasecret}
    )
    response = requests.post(AUTH_E, headers=HEADERS_AUTH, data=auth_payload)

    if response.status_code != requests.codes.ok:
        raise Exception(f"Error authenticating to Wiz [{response.status_code}] - {response.text}")
    try:
        response_json = response.json()
        TOKEN = response_json.get("access_token")
        if not TOKEN:
            demisto.debug(json.dumps(response_json))
            message = "Could not retrieve token from Wiz: {}".format(response_json.get("message"))
            raise Exception(message)
    except ValueError as exception:
        demisto.debug(exception)
        raise Exception("Could not parse API response")
    HEADERS["Authorization"] = "Bearer " + TOKEN

    return TOKEN


def checkAPIerrors(query, variables):
    if not TOKEN:
        get_token()

    data = {"variables": variables, "query": query}

    demisto.info(f"Invoking the API with {json.dumps(data)}")

    response = requests.post(url=URL, json=data, headers=HEADERS)
    response_json = response.json()

    demisto.info(f"Wiz API response status code is {response.status_code}")
    demisto.debug(f"The response is {response_json}")

    error_message = ""
    if "errors" in response_json:
        error_message = f"Wiz API error details: {get_error_output(response_json)}"

    elif "data" in response_json and "issues" in response_json["data"] and len(response_json["data"]["issues"].get("nodes")) == 0:
        demisto.info("No Issue(/s) available to fetch.")

    if error_message:
        demisto.error("An error has occurred using:\n" f"\tQuery: {query}\n" f"\tVariables: {variables}\n" f"\t{error_message}")
        demisto.error(error_message)
        raise Exception(f"{error_message}\nCheck 'server.log' instance file to get additional information")
    return response_json


def translate_severity(issue):
    """
    Translate issue severity to demisto
    Might take risk grade into account in the future
    """
    severity = demisto.get(issue, WizInputParam.SEVERITY)
    if severity == "CRITICAL":
        return 4
    if severity == "HIGH":
        return 3
    if severity == "MEDIUM":
        return 2
    if severity == "LOW":
        return 1
    if severity == "INFORMATIONAL":
        return 0.5
    return None


def build_incidents(issue):
    if issue is None:
        demisto.debug("build_incidents: Received None issue")
        return {}

    try:
        issue_id = issue.get("id", "unknown")

        source_rule = issue.get("sourceRule")

        if source_rule is None:
            demisto.debug("build_incidents: sourceRule is None")
            rule_name = "No sourceRule"
        else:
            rule_name = source_rule.get("name", "No sourceRule")
            demisto.debug(f"build_incidents: rule_name: {rule_name}")

        incident_name = f"{rule_name or 'Unknown Rule'} - {issue_id}"
        created_at = issue.get("createdAt", "")
        severity = translate_severity(issue)

        incident = {
            "name": incident_name,
            "occurred": created_at,
            "rawJSON": json.dumps(issue),
            "severity": severity,
        }

        demisto.debug(f"build_incidents: Successfully created incident for {issue_id} " f"using {incident}")
        return incident

    except Exception as e:
        issue_id = issue.get("id", "unknown") if issue else "unknown"
        raise Exception(f"build_incidents: Error processing issue {issue_id}: {str(e)}")


def validate_wiz_enum_parameter(parameter_value, enum_class, parameter_name):
    """
    Generic validation function for Wiz enum parameters

    Args:
        parameter_value (str or list): The parameter value(s) to validate
        enum_class: The enum class that contains valid values (e.g., WizIssueType)
        parameter_name (str): The human-readable parameter name for error messages (e.g., "issue type")

    Returns:
        ValidationResponse: Response with validation results
    """
    if not parameter_value:
        return ValidationResponse.create_success()

    values = argToList(parameter_value)

    valid_values = enum_class.values()
    invalid_values = [v for v in values if v not in valid_values]

    if invalid_values:
        error_msg = (
            f"Invalid {parameter_name}(s): {', '.join(invalid_values)}. Valid {parameter_name}s are: {', '.join(valid_values)}"
        )
        demisto.error(error_msg)
        return ValidationResponse.create_error(error_msg)

    return ValidationResponse.create_success(values)


def validate_issue_type(issue_type):
    """
    Validates if the issue type is supported

    Args:
        issue_type (str or list): The issue_type(s) to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    return validate_wiz_enum_parameter(issue_type, WizIssueType, "issue type")


def validate_severity(severity):
    """
    Validates if the severity is supported

    Args:
        severity (str or list): The severity(s) to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    return validate_wiz_enum_parameter(severity, WizSeverity, "severity")


def validate_status(status):
    """
    Validates if the status is supported

    Args:
        status (str or list): The status(es) to validate

    Returns:
        ValidationResponse: Response with validation results
    """
    return validate_wiz_enum_parameter(status, WizStatus, "status")


def validate_all_issues_parameters(parameters_dict):
    """
    Validates all parameters in a centralized function

    Args:
        parameters_dict (dict): Dictionary containing all parameters to validate

    Returns:
        tuple: (success, error_message, validated_values)
            - success (bool): True if all validations pass
            - error_message (str): Error message if validation fails
            - validated_values (dict): Dictionary of validated values
    """
    validated_values = {}

    # Extract parameters from dictionary
    issue_type = parameters_dict.get(WizInputParam.ISSUE_TYPE)
    status = parameters_dict.get(WizInputParam.STATUS)
    severity = parameters_dict.get(WizInputParam.SEVERITY)

    issue_type_validation = validate_issue_type(issue_type)
    if not issue_type_validation.is_valid:
        return False, issue_type_validation.error_message, None
    validated_values[WizInputParam.ISSUE_TYPE] = issue_type_validation.value

    status_validation = validate_status(status)
    if not status_validation.is_valid:
        return False, status_validation.error_message, None
    validated_values[WizInputParam.STATUS] = status_validation.value

    severity_validation = validate_severity(severity)
    if not severity_validation.is_valid:
        return False, severity_validation.error_message, None
    validated_values[WizInputParam.SEVERITY] = severity_validation.value

    return True, None, validated_values


def apply_wiz_filter(variables, filter_value, api_field, equals_wrapper=True, nested_path=None):
    """
    Generic function to apply filters to Wiz API query variables

    Args:
        variables (dict): The query variables to modify
        filter_value (str or list): The filter value(s) to apply
        api_field (str): The API field name (e.g., WizApiVariables.ORIGIN)
        equals_wrapper (bool): Whether to wrap the value in {"equals": [values]} structure
        nested_path (str): Additional nested path for complex filters (e.g., "relatedEntity")

    Returns:
        dict: Updated variables with the filter applied
    """
    if not filter_value:
        return variables

    # Initialize filterBy if it doesn't exist
    if "filterBy" not in variables:
        variables["filterBy"] = {}

    # Convert single values to list for consistency
    if isinstance(filter_value, str):
        value_list = [filter_value]
    elif isinstance(filter_value, list):
        value_list = filter_value
    else:
        value_list = [filter_value]

    # Handle nested paths (e.g., for threats that use relatedEntity.cloudPlatform)
    filter_target = variables["filterBy"]
    if nested_path:
        if nested_path not in filter_target:
            filter_target[nested_path] = {}
        filter_target = filter_target[nested_path]

    # Apply the filter with or without equals wrapper
    if equals_wrapper:
        filter_target[api_field] = {"equals": value_list}
    else:
        filter_target[api_field] = value_list

    return variables


def apply_severity_filter(variables, severity_list, is_detection=True):
    """Adds the severity filter to the query variables"""
    return apply_wiz_filter(variables, severity_list, "severity", equals_wrapper=False)


def apply_status_filter(variables, status_list):
    """Adds the status filter to the query variables"""
    return apply_wiz_filter(variables, status_list, "status", equals_wrapper=False)


def apply_issue_type_filter(variables, type_list):
    """Adds the status filter to the query variables"""
    return apply_wiz_filter(variables, type_list, "type", equals_wrapper=False)


def apply_all_issue_filters(variables, validated_values):
    """
    Applies all filters to the query variables in a centralized function

    Args:
        variables (dict): Base query variables
        validated_values (dict): Dictionary of validated values

    Returns:
        dict: Updated query variables with all filters applied
    """
    variables = apply_severity_filter(variables, validated_values.get(WizInputParam.SEVERITY))
    variables = apply_status_filter(variables, validated_values.get(WizInputParam.STATUS))
    variables = apply_issue_type_filter(variables, validated_values.get(WizInputParam.ISSUE_TYPE))

    return variables


def get_fetch_issues_variables(max_fetch, last_run):
    demisto_params = demisto.params()
    parameters_dict = {
        WizInputParam.ISSUE_TYPE: demisto_params.get(WizInputParam.ISSUE_TYPE),
        WizInputParam.STATUS: demisto_params.get(WizInputParam.STATUS),
        WizInputParam.SEVERITY: demisto_params.get(WizInputParam.SEVERITY),
    }

    # Using default fetch parameters
    if (
        not parameters_dict[WizInputParam.ISSUE_TYPE]
        and not parameters_dict[WizInputParam.STATUS]
        and not parameters_dict[WizInputParam.SEVERITY]
    ):
        demisto.info("No issue type, status or severity provided, fetching default issues")
        parameters_dict = {
            WizInputParam.STATUS: DEFAULT_FETCH_ISSUE_STATUS,
        }

    validation_success, error_message, validated_values = validate_all_issues_parameters(parameters_dict)
    if not validation_success or error_message:
        return_error(error_message)
        return None

    issue_variables: Dict[str, Any] = PULL_ISSUES_DEFAULT_VARIABLES.copy()
    issue_variables["first"] = max_fetch
    issue_variables["filterBy"] = {"createdAt": {"after": last_run}, "relatedEntity": {}}

    return apply_all_issue_filters(issue_variables, validated_values)


def fetch_issues(max_fetch):
    """
    Fetch all Issues (OOB XSOAR Fetch)
    """

    if max_fetch > 500:
        max_fetch = 500

    last_run = demisto.getLastRun().get("time")
    if not last_run:  # first time fetch
        last_run = dateparser.parse(demisto.params().get("first_fetch", "7 days").strip())
        last_run = last_run.isoformat()[:-3] + "Z"

    query = PULL_ISSUES_QUERY
    variables = get_fetch_issues_variables(max_fetch, last_run)
    demisto.info(f"Fetching Issues for {variables}")

    api_start_run_time = datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)
    response_json = checkAPIerrors(query, variables)

    issues = response_json["data"]["issues"]["nodes"]
    while response_json["data"]["issues"]["pageInfo"]["hasNextPage"]:
        variables["after"] = response_json["data"]["issues"]["pageInfo"]["endCursor"]
        response_json = checkAPIerrors(query, variables)
        if response_json["data"]["issues"]["nodes"] != []:
            issues += response_json["data"]["issues"]["nodes"]

    incidents = []
    for issue in issues:
        incident = build_incidents(issue=issue)
        demisto.debug(f"Preparing to add incident: {incident}")
        incidents.append(incident)

    demisto.incidents(incidents)
    demisto.setLastRun({"time": api_start_run_time})

    if incidents:
        demisto.info(f"Successfully fetched and created {len(incidents)} incidents - Set last run time to {api_start_run_time}.")
    else:
        demisto.info(f"No new incidents to fetch - Set last run time to {api_start_run_time}.")


def get_issue(issue_id):
    demisto.info(f"Issue id is {issue_id}\n")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        demisto.debug(message)
        return message

    issue_variables = {"first": 5, "filterBy": {"id": issue_id}}

    response_json = checkAPIerrors(PULL_ISSUES_QUERY, issue_variables)

    demisto.debug(f"The API response is {response_json}")

    issues = {}
    if response_json["data"]["issues"]["nodes"] != []:
        issues = response_json["data"]["issues"]["nodes"]
    else:
        demisto.info(f"There was no result for Issue ID: {issue_id}")

    return issues


def get_filtered_issues(entity_type, resource_id, severity, issue_type, limit):
    """
    Retrieves Filtered Issues
    """
    demisto.info(
        f"Entity type is {entity_type}\n"
        f"Resource ID is {resource_id}\n"
        f"Severity is {severity}\n"
        f"Issue type is {issue_type}"
    )
    error_msg = ""

    if not severity and not entity_type and not resource_id and not issue_type:
        error_msg = (
            "You should pass (at least) one of the following parameters:\n\tentity_type\n\tresource_id"
            "\n\tseverity\n\tissue_type\n"
        )

    if entity_type and resource_id:
        error_msg = f"{error_msg}You cannot pass entity_type and resource_id together\n"

    if error_msg:
        demisto.error(error_msg)
        return error_msg

    issue_variables = {}
    query = PULL_ISSUES_QUERY

    if entity_type:
        issue_variables = {
            "first": limit,
            "filterBy": {
                "status": ["OPEN", "IN_PROGRESS"],
                "relatedEntity": {"type": [entity_type]},
            },
            "orderBy": {"field": "SEVERITY", "direction": "DESC"},
        }
    elif resource_id:
        get_resource_graph_id_helper_variables = {
            "projectId": "*",
            "query": {"type": ["CLOUD_RESOURCE"], "where": {"providerUniqueId": {"EQUALS": resource_id}}},
        }
        get_resource_graph_id_helper_query = """
            query GraphEntityResourceFilterAutosuggest(
                $query: GraphEntityQueryInput
                $projectId: String!
              ) {
                graphSearch(
                    first: 100, query: $query, quick: true, projectId: $projectId
                ) {
                    nodes {
                        entities {
                            id
                            name
                            type
                        }
                    }
                }
            }
        """
        graph_resource_response_json = checkAPIerrors(get_resource_graph_id_helper_query, get_resource_graph_id_helper_variables)
        if graph_resource_response_json["data"]["graphSearch"]["nodes"] != []:
            graph_resource_id = graph_resource_response_json["data"]["graphSearch"]["nodes"][0]["entities"][0]["id"]
            issue_variables = {
                "first": limit,
                "filterBy": {"status": ["OPEN", "IN_PROGRESS"], "relatedEntity": {"id": graph_resource_id}},
                "orderBy": {"field": "SEVERITY", "direction": "DESC"},
            }
        else:
            demisto.info("Resource not found.")
            return "Resource not found."

    if severity:
        if "filterBy" not in issue_variables:
            issue_variables["filterBy"] = {"severity": []}
            issue_variables["first"] = limit
        if severity.upper() == "CRITICAL":
            issue_variables["filterBy"]["severity"] = ["CRITICAL"]
        elif severity.upper() == "HIGH":
            issue_variables["filterBy"]["severity"] = ["CRITICAL", "HIGH"]
        elif severity.upper() == "MEDIUM":
            issue_variables["filterBy"]["severity"] = ["CRITICAL", "HIGH", "MEDIUM"]
        elif severity.upper() == "LOW":
            issue_variables["filterBy"]["severity"] = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        elif severity.upper() == "INFORMATIONAL":
            issue_variables["filterBy"]["severity"] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        else:
            demisto.info(
                "You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL "
                "in upper or lower case."
            )
            return (
                "You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL in "
                "upper or lower case."
            )

    if issue_type:
        if "filterBy" not in issue_variables:
            issue_variables["filterBy"] = {}
            issue_variables["first"] = limit

        issue_variables["filterBy"]["type"] = [issue_type]

    demisto.info(f"Query is {query}")
    demisto.info(f"Issue variables is {issue_variables}")

    response_json = checkAPIerrors(query, issue_variables)

    demisto.info(f"The API response is {response_json}")

    issues = {}
    if response_json["data"]["issues"]["nodes"] != []:
        issues = response_json["data"]["issues"]["nodes"]
    while response_json["data"]["issues"]["pageInfo"]["hasNextPage"]:
        issue_variables["after"] = response_json["data"]["issues"]["pageInfo"]["endCursor"]
        response_json = checkAPIerrors(query, issue_variables)
        if response_json["data"]["issues"]["nodes"] != []:
            issues += response_json["data"]["issues"]["nodes"]

    return issues


def get_resources(search, entity_type, subscription_external_ids, provider_unique_ids):
    """
    Retrieves Resources
    """
    demisto.info(
        f"Entity type is {entity_type}\n"
        f"Search is {search}\n"
        f"Subscription External IDs is {subscription_external_ids}\n"
        f"Provider Unique IDs is {provider_unique_ids}"
    )
    error_msg = ""

    if not search and not entity_type and not subscription_external_ids and not provider_unique_ids:
        error_msg = (
            f"You should pass (at least) one of the following parameters:\n\t{WizInputParam.SEARCH}\n\t"
            f"{WizInputParam.ENTITY_TYPE}\n\t{WizInputParam.SUBSCRIPTION_EXTERNAL_IDS}\n\t"
            f"{WizInputParam.PROVIDER_UNIQUE_IDS}\n"
        )

    if error_msg:
        demisto.error(error_msg)
        return error_msg

    variables: Dict[str, Any] = {"first": WIZ_API_LIMIT, "filterBy": {}}

    if search:
        variables["filterBy"]["search"] = search
    if entity_type:
        variables["filterBy"]["type"] = [entity_type]
    if subscription_external_ids:
        subscription_external_ids_formatted = [str(x) for x in re.split(r"[,\s]+", subscription_external_ids.strip())]
        variables["filterBy"]["subscriptionExternalId"] = subscription_external_ids_formatted
    if provider_unique_ids:
        provider_unique_ids_formatted = [str(x) for x in re.split(r"[,\s]+", provider_unique_ids.strip())]
        variables["filterBy"]["providerUniqueId"] = provider_unique_ids_formatted

    try:
        response_json = checkAPIerrors(PULL_CLOUD_RESOURCES_NATIVE_QUERY, variables)
    except DemistoException:
        demisto.debug(
            f"could not find resources with this entity_type {entity_type}, search {search}, "
            f"subscription_external_ids {subscription_external_ids}, provider_unique_ids {provider_unique_ids}"
        )
        return {}

    if response_json["data"]["cloudResources"]["nodes"] is None or not response_json["data"]["cloudResources"]["nodes"]:
        demisto.info("Resources Not Found")
        return "Resources Not Found"
    else:
        return response_json


def get_resource(resource_id, resource_name):
    """
    Retrieves Resource Details
    """

    demisto.debug("get_resource, enter")

    if resource_name and resource_id:
        demisto.error("You cannot pass both resource_name and resource_id together")
        return "You should pass exactly one of resource_name or resource_id"

    if not resource_name and not resource_id:
        demisto.error("You must pass either resource_name or resource_id")
        return "You should pass exactly one of resource_name or resource_id"

    resource_search = resource_name if resource_name else resource_id
    variables = {"first": WIZ_API_LIMIT, "filterBy": {"search": resource_search}}
    try:
        response_json = checkAPIerrors(PULL_CLOUD_RESOURCES_NATIVE_QUERY, variables)
    except DemistoException:
        demisto.debug(f"could not find resource with this resource_name {resource_name}")
        return {}

    if response_json["data"]["cloudResources"]["nodes"] is None or not response_json["data"]["cloudResources"]["nodes"]:
        demisto.info("Resource Not Found")
        return "Resource Not Found"
    else:
        return response_json


def reject_issue(issue_id, reject_reason, reject_comment):
    """
    Reject a Wiz Issue
    """
    return reject_or_resolve_issue(issue_id, reject_reason, reject_comment, "REJECTED")


def resolve_issue(issue_id, resolution_reason, resolution_note):
    """
    Reject a Wiz Issue
    """
    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    issue_object = _get_issue(issue_id, is_evidence=False)

    issue_type = issue_object["data"]["issues"]["nodes"][0]["type"]

    if issue_type != "THREAT_DETECTION":
        demisto.error(f"Only a Threat Detection Issue can be resolved.\nReceived an Issue of type {issue_type}.")
        return f"Only a Threat Detection Issue can be resolved.\nReceived an Issue of type {issue_type}."

    return reject_or_resolve_issue(issue_id, resolution_reason, resolution_note, "RESOLVED")


def reject_or_resolve_issue(issue_id, reject_or_resolve_reason, reject_or_resolve_comment, status):
    """
    Reject a Wiz Issue
    """
    demisto.debug(f"reject_issue with status: {status}, enter")
    operation = "reject" if status == "REJECTED" else "resolution"

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    if not reject_or_resolve_reason or not reject_or_resolve_comment:
        demisto.error(f"You should pass all of: Issue ID, {operation} reason and {operation} note.")
        return f"You should pass all of: Issue ID, {operation} reason and {operation} note."

    variables = {
        "issueId": issue_id,
        "patch": {"status": status, "note": reject_or_resolve_comment, "resolutionReason": reject_or_resolve_reason},
    }
    query = UPDATE_ISSUE_QUERY

    response = checkAPIerrors(query, variables)

    return response


def reopen_issue(issue_id, reopen_note):
    """
    Re-open a Wiz Issue
    """

    demisto.debug("reopen_issue, enter")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    variables = {"issueId": issue_id, "patch": {"status": "OPEN"}}
    query = UPDATE_ISSUE_QUERY

    response = checkAPIerrors(query, variables)

    if reopen_note:
        set_issue_comment(issue_id, reopen_note)

    return response


def issue_in_progress(issue_id):
    """
    Set a Wiz Issue to In Progress
    """

    return _set_status(issue_id, "IN_PROGRESS")


def _set_status(issue_id, status):
    """
    Set a Wiz Issue to In Progress
    """

    demisto.debug(f"_set_status to {status}, enter")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    variables = {"issueId": issue_id, "patch": {"status": status}}
    query = UPDATE_ISSUE_QUERY

    response = checkAPIerrors(query, variables)

    return response


def _get_issue(issue_id, is_evidence=False):
    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    issue_variables = {
        "first": 1,
        "filterBy": {"id": issue_id},
    }

    issue_query = PULL_ISSUE_WITH_EVIDENCE_PARAM_QUERY if is_evidence else PULL_ISSUES_QUERY

    issue_response = checkAPIerrors(issue_query, issue_variables)

    return issue_response


def set_issue_comment(issue_id, comment):
    """
    Set a note on Wiz Issue
    """

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    issue_variables = {"input": {"issueId": issue_id, "text": comment}}
    issue_query = CREATE_COMMENT_QUERY

    response = checkAPIerrors(issue_query, issue_variables)

    return response


def get_error_output(wiz_api_response):
    error_output_message = ""
    first_error_message = ""
    if "errors" in wiz_api_response:
        for error_dict in wiz_api_response["errors"]:
            if "message" in error_dict:
                error_message = error_dict["message"]

                # Do not print duplicate errors
                if first_error_message and first_error_message == error_message:
                    continue
                if not first_error_message:
                    first_error_message = error_message

                error_output_message = error_output_message + error_message + "\n"

    return error_output_message if error_output_message else wiz_api_response


def clear_issue_note(issue_id):
    """
    Clear the note from a Wiz Issue
    """

    demisto.debug("clear_issue_note, enter")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    issue_object = _get_issue(issue_id)

    issue_notes = issue_object["data"]["issues"]["nodes"][0]["notes"]
    demisto.info(f"The issue notes are: {issue_notes}")

    query = DELETE_NOTE_QUERY
    for note in issue_notes:
        variables = {"input": {"id": note["id"]}}

        response = checkAPIerrors(query, variables)

    return response


def set_issue_due_date(issue_id, due_at):
    """
    Set a due date for a Wiz Issue
    """

    demisto.debug("set_issue_due_date, enter")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    if not due_at:
        demisto.error("issue_id and due_at parameters must be provided.")
        return "issue_id and due_at parameters must be provided."

    format = "%Y-%m-%d"
    try:
        datetime.strptime(due_at, format)
        demisto.info("This is the correct date string format.")
    except ValueError:
        demisto.error("This is the incorrect. It should be YYYY-MM-DD")
        return "The date format is the incorrect. It should be YYYY-MM-DD"
    due_at = due_at + "T00:00:00.000Z"

    variables = {"issueId": issue_id, "patch": {"dueAt": due_at}}
    query = UPDATE_ISSUE_QUERY

    try:
        response = checkAPIerrors(query, variables)
    except DemistoException:
        demisto.debug(f"could not find Issue with ID {issue_id}")
        return {}

    return response


def clear_issue_due_date(issue_id):
    """
    Clear a due date for a Wiz Issue
    """

    demisto.debug("clear_issue_due_date, enter")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    issue_query = UPDATE_ISSUE_QUERY
    issue_variables = {"issueId": issue_id, "override": {"dueAt": None}}

    issue_response = checkAPIerrors(issue_query, issue_variables)

    return issue_response


def get_issue_evidence(issue_id):
    """
    Get evidence on a Wiz Issue
    """

    demisto.debug("get_issue_evidence, enter")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    # Getting the Issue Evidence Query
    issue_object = _get_issue(issue_id, is_evidence=True)

    if not issue_object["data"]["issues"]["nodes"]:
        return f"Issue not found: {issue_id}"

    issue_type = issue_object["data"]["issues"]["nodes"][0]["type"]

    if issue_type == "THREAT_DETECTION":
        if issue_object["data"]["issues"]["nodes"][0]["threatDetectionDetails"] is not None:
            return issue_object["data"]["issues"]["nodes"][0]["threatDetectionDetails"]
        else:
            return f"No issue threat detection details evidence for Issue ID: {issue_id}"

    query_for_evidence = issue_object["data"]["issues"]["nodes"][0]["evidenceQuery"]

    if not query_for_evidence:
        return f"No issue evidence for Issue ID: {issue_id}"

    # Creating the query/variables to get the Issue Evidence
    query = PULL_ISSUE_EVIDENCE_QUERY
    variables = PULL_ISSUE_EVIDENCE_PARAMS
    variables["query"] = query_for_evidence

    try:
        response = checkAPIerrors(query, variables)
    except Exception as e:
        error_message = f"Failed getting Issue evidence on ID {issue_id}.\nError details: {str(e)}"
        demisto.error(error_message)
        raise Exception(error_message)

    if response.get("data", {}).get("graphSearch", {}).get("nodes") is None:
        return "Resource Not Found"
    elif len(response.get("data", {}).get("graphSearch", {}).get("nodes")) == 0:
        return "No Evidence Found"
    else:
        return response["data"]["graphSearch"]["nodes"][0].get("entities", {})


def get_project_team(project_name):
    """
    Get the Project Owners and Security Champions details
    """

    demisto.debug("wiz-get-project-team, enter")

    if not project_name:
        demisto.error("You should pass a Project name")
        return "You should pass an Project name."

    # find VM on the graph
    project_variables = {
        "first": 20,
        "filterBy": {"search": project_name, "includeArchived": False},
        "orderBy": {"field": "SECURITY_SCORE", "direction": "ASC"},
    }

    try:
        response_json = checkAPIerrors(PULL_PROJECTS_QUERY, project_variables)
    except DemistoException:
        demisto.debug(f"Error with finding Project with name {project_name}")
        return {}

    nodes = response_json.get("data", {}).get("projects", {}).get("nodes", [])

    if not nodes:
        demisto.error(f"Project with name {project_name} does not exist")
        return {}

    return nodes


def copy_to_forensics_account(resource_id):
    """
    Copy resource Volumes to a Forensics Account
    """
    demisto.info(f"resource id is {resource_id}\n")
    demisto.debug("copy_to_forensics_account, enter")

    if not is_valid_uuid(resource_id):
        variables = {"first": 1, "filterBy": {"providerUniqueId": [resource_id]}}
        resource_id_response = checkAPIerrors(PULL_RESOURCES_ID_NATIVE_QUERY, variables)
        if resource_id_response["data"] is None or not resource_id_response["data"]["cloudResources"]["nodes"]:
            demisto.error(f"Resource with ID {resource_id} not found.")
            return f"Resource with ID {resource_id} not found."
        else:
            resource_id = resource_id_response["data"]["cloudResources"]["nodes"][0]["id"]

    copy_to_forensics_account_variables = {"input": {"id": resource_id}}

    response_json = checkAPIerrors(COPY_TO_FORENSICS_ACCOUNT_MUTATION, copy_to_forensics_account_variables)
    demisto.debug(f"The API response is {response_json}")

    if response_json["data"] is None and response_json["errors"] is not None:
        demisto.error(f"Resource with ID {resource_id} was not copied to Forensics Account.")
        return f"Resource with ID {resource_id} was not copied to Forensics Account. error: {response_json['errors']}"
    elif not response_json["data"]["copyResourceForensicsToExternalAccount"]["systemActivityGroupId"]:
        demisto.info(f"Resource with ID {resource_id} was not copied to Forensics Account.")
        return {}
    else:
        return response_json


def is_valid_uuid(uuid_string):
    if not isinstance(uuid_string, str):
        uuid_string = str(uuid_string)
    try:
        uuid_obj = uuid.UUID(uuid_string)
        return str(uuid_obj) == uuid_string
    except ValueError:
        return False
    except Exception:
        return False


def is_valid_issue_id(issue_id):
    if not issue_id:
        demisto.error("You should pass an Issue ID.")
        return False, "You should pass an Issue ID."

    if not is_valid_uuid(issue_id):
        demisto.error("Wrong format: The Issue ID should be in UUID format.")
        return False, "Wrong format: The Issue ID should be in UUID format."

    return True, f"The Issue ID {issue_id} is in a valid format"


def main():
    params = demisto.params()
    set_authentication_endpoint(params.get("auth_endpoint"))
    set_api_endpoint(params.get("api_endpoint", ""))
    try:
        command = demisto.command()
        if command == "test-module":
            auth_token = get_token()
            if "error" not in auth_token:
                test_response = checkAPIerrors(PULL_ISSUES_QUERY, PULL_ISSUES_TEST_VARIABLES)

                if "errors" not in test_response:
                    demisto.results("ok")
                else:
                    demisto.results(test_response)
            else:
                demisto.results("Invalid token")

        elif command == "fetch-incidents":
            max_fetch = int(demisto.params().get("max_fetch"))
            fetch_issues(max_fetch=max_fetch)

        elif command == "wiz-get-issues":
            demisto_args = demisto.args()
            issue_type = demisto_args.get(WizInputParam.ISSUE_TYPE)
            resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
            severity = demisto_args.get(WizInputParam.SEVERITY)
            entity_type = demisto_args.get(WizInputParam.ENTITY_TYPE)
            issues = get_filtered_issues(
                issue_type=issue_type,
                resource_id=resource_id,
                severity=severity,
                entity_type=entity_type,
                limit=WIZ_API_LIMIT,
            )
            if isinstance(issues, str):
                #  this means the Issue is an error
                command_result = CommandResults(readable_output=issues, raw_response=issues)
            else:
                command_result = CommandResults(outputs_prefix="Wiz.Manager.Issues", outputs=issues, raw_response=issues)
            return_results(command_result)

        elif command == "wiz-get-resource":
            demisto_args = demisto.args()
            resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
            resource_name = demisto_args.get(WizInputParam.RESOURCE_NAME)
            resource = get_resource(resource_id=resource_id, resource_name=resource_name)
            command_result = CommandResults(
                outputs_prefix="Wiz.Manager.Resource", readable_output=resource, outputs=resource, raw_response=resource
            )
            return_results(command_result)

        elif command == "wiz-get-resources":
            demisto_args = demisto.args()
            resources_search = demisto_args.get(WizInputParam.SEARCH)
            resources_entity_type = demisto_args.get(WizInputParam.ENTITY_TYPE)
            resources_subscription_external_ids = demisto_args.get(WizInputParam.SUBSCRIPTION_EXTERNAL_IDS)
            resources_provider_unique_ids = demisto_args.get(WizInputParam.PROVIDER_UNIQUE_IDS)
            resources = get_resources(
                search=resources_search,
                entity_type=resources_entity_type,
                subscription_external_ids=resources_subscription_external_ids,
                provider_unique_ids=resources_provider_unique_ids,
            )
            command_result = CommandResults(readable_output=resources, raw_response=resources)
            return_results(command_result)

        elif command == "wiz-reject-issue":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            resolution_reason = demisto_args.get(WizInputParam.REJECT_REASON)
            resolution_note = demisto_args.get(WizInputParam.REJECT_NOTE)
            issue_response = reject_issue(issue_id=issue_id, reject_reason=resolution_reason, reject_comment=resolution_note)
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-reopen-issue":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            reopen_note = demisto_args.get(WizInputParam.REOPEN_NOTE)
            issue_response = reopen_issue(issue_id=issue_id, reopen_note=reopen_note)
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-resolve-issue":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            resolution_reason = demisto_args.get(WizInputParam.RESOLUTION_REASON)
            resolution_note = demisto_args.get(WizInputParam.RESOLUTION_NOTE)
            issue_response = resolve_issue(
                issue_id=issue_id, resolution_reason=resolution_reason, resolution_note=resolution_note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-get-issue":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_result = get_issue(
                issue_id=issue_id,
            )
            command_result = CommandResults(readable_output=issue_result, raw_response=issue_result)
            return_results(command_result)

        elif command == "wiz-issue-in-progress":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = issue_in_progress(issue_id=issue_id)
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-set-issue-note":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            note = demisto_args.get(WizInputParam.NOTE)
            issue_response = set_issue_comment(issue_id=issue_id, comment=note)
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-clear-issue-note":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = clear_issue_note(issue_id=issue_id)
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-get-issue-evidence":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = get_issue_evidence(issue_id=issue_id)
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-set-issue-due-date":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            due_at = demisto_args.get("due_at")
            issue_response = set_issue_due_date(issue_id=issue_id, due_at=due_at)
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-clear-issue-due-date":
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = clear_issue_due_date(issue_id=issue_id)
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == "wiz-get-project-team":
            demisto_args = demisto.args()
            project_name = demisto_args.get(WizInputParam.PROJECT_NAME)
            projects_response = get_project_team(project_name=project_name)
            command_result = CommandResults(readable_output=projects_response, raw_response=projects_response)
            return_results(command_result)

        elif command == "wiz-rescan-machine-disk":
            return_results(
                CommandResults(readable_output="This command is deprecated", raw_response="This command is deprecated")
            )

        elif command == "wiz-copy-to-forensics-account":
            demisto_args = demisto.args()
            resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
            copy_mutation_response = copy_to_forensics_account(resource_id=resource_id)
            command_result = CommandResults(readable_output=copy_mutation_response, raw_response=copy_mutation_response)
            return_results(command_result)
        else:
            raise Exception("Unrecognized command: " + command)
    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(f"An error occurred: {str(err)}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
