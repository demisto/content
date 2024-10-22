import uuid

from CommonServerPython import *
import demistomock as demisto
from urllib import parse

DEMISTO_OCCURRED_FORMAT = '%Y-%m-%dT%H:%M:%SZ'
WIZ_API_TIMEOUT = 300  # Increase timeout for Wiz API
WIZ_HTTP_QUERIES_LIMIT = 500  # Request limit during run
WIZ_API_LIMIT = 500  # limit number of returned records from the Wiz API
WIZ = 'wiz'

WIZ_VERSION = '1.3.2'
INTEGRATION_GUID = '8864e131-72db-4928-1293-e292f0ed699f'


def get_integration_user_agent():
    integration_user_agent = f'{INTEGRATION_GUID}/xsoar/{WIZ_VERSION}'
    return integration_user_agent


# Standard headers
HEADERS_AUTH = {"Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": get_integration_user_agent()}

HEADERS = {"Content-Type": "application/json",
           "User-Agent": get_integration_user_agent()}

TOKEN = None
URL = ''
AUTH_E = ''
AUTH_DEFAULT = "auth"  # NEED TO BE REMOVED AFTER THAT AUTH0 IS DEPRECATED
COGNITO_PREFIX = [
    "auth.app",
    "auth.gov",
    "auth.test"
]
AUTH0_PREFIX = [
    "auth",
    "auth0.gov",
    "auth0.test"
]
URL_SUFFIX = 'wiz.io/oauth/token'
URL_SUFFIX_FED = 'wiz.us/oauth/token'

# Pull Issues
PULL_ISSUES_QUERY = ("""
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
          controlDescription: description
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
          cloudEventRuleDescription: description
          sourceType
          type
        }
        ... on CloudConfigurationRule{
          id
          name
          cloudConfigurationRuleDescription: description
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
""")
PULL_ISSUE_WITH_EVIDENCE_PARAM_QUERY = ("""
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
""")
PULL_ISSUES_TEST_VARIABLES = test_variables = {
    'first': 1,
    'filterBy': {
        'status': [
            'OPEN',
            'IN_PROGRESS'
        ]
    },
    'orderBy': {
        'field': 'SEVERITY',
        'direction': 'DESC'
    }
}

# Pull Issue Evidence
PULL_ISSUE_EVIDENCE_QUERY = ("""
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
    """)
PULL_ISSUE_EVIDENCE_PARAMS = {
    'quick': True,
    'fetchPublicExposurePaths': False,
    'fetchInternalExposurePaths': False,
    'fetchIssueAnalytics': False,
    'fetchLateralMovement': False,
    'fetchKubernetes': False,
    'first': 5,
    'projectId': '*',
    'query': None,
    'fetchTotalCount': False
}
UPDATE_ISSUE_QUERY = ("""
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
""")
CREATE_COMMENT_QUERY = ("""
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
    """)
DELETE_NOTE_QUERY = ("""
    mutation DeleteIssueNote($input: DeleteIssueNoteInput!) {
    deleteIssueNote(input: $input) {
      _stub
    }
  }
    """)

# Pull Resources
PULL_RESOURCES_QUERY = ("""
        query GraphSearch(
            $query: GraphEntityQueryInput
            $controlId: ID
            $projectId: String!
            $first: Int
            $after: String
            $fetchTotalCount: Boolean!
            $quick: Boolean
            $fetchPublicExposurePaths: Boolean = false
            $fetchInternalExposurePaths: Boolean = false
            $fetchIssueAnalytics: Boolean = false
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
                        id
                        name
                        type
                        properties
                        userMetadata {
                            isInWatchlist
                            isIgnored
                            note
                        }
                        issueAnalytics: issues(filterBy: { status: [IN_PROGRESS, OPEN] })
                            @include(if: $fetchIssueAnalytics) {
                            lowSeverityCount
                            mediumSeverityCount
                            highSeverityCount
                            criticalSeverityCount
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
                        }
                        aggregateCount
                    }
                }
            }

            fragment NetworkExposureFragment on NetworkExposure {
                id
                portRange
                sourceIpRange
                destinationIpRange
                path {
                    id
                    name
                    type
                    properties
                    issueAnalytics: issues(filterBy: { status: [IN_PROGRESS, OPEN] })
                        @include(if: $fetchIssueAnalytics) {
                            lowSeverityCount
                            mediumSeverityCount
                            highSeverityCount
                            criticalSeverityCount
                        }
                }
            }
    """)
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
PULL_RESOURCES_VARIABLES = {
    "fetchPublicExposurePaths": True,
    "fetchInternalExposurePaths": False,
    "fetchIssueAnalytics": False,
    "first": 50,
    "query": {
        "type": [
            "CLOUD_RESOURCE"
        ],
        "select": True,
        "where": {
            "providerUniqueId": {
                "EQUALS": []
            }
        }
    },
    "projectId": "*",
    "fetchTotalCount": True,
    "quick": True
}

# Copy to forensics account
COPY_TO_FORENSICS_ACCOUNT_MUTATION = """
        mutation CopyResourceForensicsToExternalAccount($input: CopyResourceForensicsToExternalAccountInput!) {
          copyResourceForensicsToExternalAccount(input: $input) {
            systemActivityGroupId
          }
        }
    """


class WizInputParam:
    ISSUE_ID = 'issue_id'
    ISSUE_TYPE = 'issue_type'
    ENTITY_TYPE = 'entity_type'
    RESOURCE_ID = 'resource_id'
    RESOURCE_NAME = 'resource_name'
    SEVERITY = 'severity'
    REJECT_REASON = 'reject_reason'
    REJECT_NOTE = 'reject_note'
    RESOLUTION_REASON = 'resolution_reason'
    RESOLUTION_NOTE = 'resolution_note'
    REOPEN_NOTE = 'reopen_note'
    NOTE = 'note'
    DUE_AT = 'due_at'
    VM_ID = 'vm_id'
    PROJECT_NAME = 'project_name'


class WizStatus:
    OPEN = 'OPEN'
    IN_PROGRESS = 'IN PROGRESS'
    REJECTED = 'REJECTED'


def set_authentication_endpoint(auth_endpoint):
    global AUTH_E
    AUTH_E = generate_auth_urls(AUTH_DEFAULT)[1] if auth_endpoint == '' else auth_endpoint


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
    audience = ''
    cognito_list = []
    for cognito_prefix in COGNITO_PREFIX:
        cognito_list.extend(generate_auth_urls(cognito_prefix))
        cognito_list.extend(generate_auth_urls_fed(cognito_prefix))

    auth0_list = []
    for auth0_prefix in AUTH0_PREFIX:
        auth0_list.extend(generate_auth_urls(auth0_prefix))

    # check Wiz portal auth endpoint - Cognito or Auth0
    if AUTH_E in cognito_list:
        audience = 'wiz-api'
    elif AUTH_E in auth0_list:
        audience = 'beyond-api'
    else:
        raise Exception('Not a valid authentication endpoint')

    demisto_params = demisto.params()
    said = demisto_params.get('credentials').get('identifier')
    sasecret = demisto_params.get('credentials').get('password')
    auth_payload = parse.urlencode({
        'grant_type': 'client_credentials',
        'audience': audience,
        'client_id': said,
        'client_secret': sasecret
    })
    response = requests.post(AUTH_E, headers=HEADERS_AUTH, data=auth_payload)

    if response.status_code != requests.codes.ok:
        raise Exception('Error authenticating to Wiz [%d] - %s' % (response.status_code, response.text))
    try:
        response_json = response.json()
        TOKEN = response_json.get('access_token')
        if not TOKEN:
            demisto.debug(json.dumps(response_json))
            message = 'Could not retrieve token from Wiz: {}'.format(response_json.get("message"))
            raise Exception(message)
    except ValueError as exception:
        demisto.debug(exception)
        raise Exception('Could not parse API response')
    HEADERS["Authorization"] = "Bearer " + TOKEN

    return TOKEN


def checkAPIerrors(query, variables):
    if not TOKEN:
        get_token()

    data = {"variables": variables, "query": query}

    demisto.info(f"Invoking the API with is {json.dumps(data)}")

    result = requests.post(url=URL, json=data, headers=HEADERS)

    demisto.info(f"Result is {result}")
    demisto.info(f"Result Json is {result.json()}")

    error_message = ""
    if "errors" in result.json():
        error_message = f"Wiz API error details: {get_error_output(result.json())}"

    elif "data" in result.json() and "issues" in result.json()['data'] and len(result.json()['data']['issues'].get('nodes')) == 0:
        demisto.info("No Issue(/s) available to fetch.")

    if error_message:
        demisto.error("An error has occurred using:\n"
                      f"\tQuery: {query}\n"
                      f"\tVariables: {variables}\n"
                      f"\t{error_message}")
        demisto.error(error_message)
        raise Exception(f"{error_message}\nCheck 'server.log' instance file to get additional information")
    return result.json()


def translate_severity(issue):
    """
    Translate issue severity to demisto
    Might take risk grade into account in the future
    """
    severity = demisto.get(issue, WizInputParam.SEVERITY)
    if severity == 'CRITICAL':
        return 4
    if severity == 'HIGH':
        return 3
    if severity == 'MEDIUM':
        return 2
    if severity == 'LOW':
        return 1
    if severity == 'INFORMATIONAL':
        return 0.5
    return None


def build_incidents(issue):
    if issue is None:
        return {}

    return {
        'name': issue.get('sourceRule', {}).get('name', 'No sourceRule') + ' - ' + issue.get('id'),
        'occurred': issue['createdAt'],
        'rawJSON': json.dumps(issue),
        'severity': translate_severity(issue)
    }


def fetch_issues(max_fetch):
    """
    Fetch all Issues (OOB XSOAR Fetch)
    """

    if max_fetch > 500:
        max_fetch = 500

    last_run = demisto.getLastRun().get('time')
    if not last_run:  # first time fetch
        last_run = dateparser.parse(demisto.params().get('first_fetch', '7 days').strip())
        last_run = (last_run.isoformat()[:-3] + 'Z')

    query = PULL_ISSUES_QUERY
    variables = {
        "first": max_fetch,
        "filterBy": {
            "status": [
                "OPEN",
                "IN_PROGRESS"
            ],

            "createdAt": {
                "after":
                    last_run
            },
            "relatedEntity":
                {}
        },
        "orderBy": {
            "field":
                "SEVERITY",
            "direction":
                "DESC"
        }
    }

    response_json = checkAPIerrors(query, variables)

    issues = response_json['data']['issues']['nodes']
    while response_json['data']['issues']['pageInfo']['hasNextPage']:
        variables['after'] = response_json['data']['issues']['pageInfo']['endCursor']
        response_json = checkAPIerrors(query, variables)
        if response_json['data']['issues']['nodes'] != []:
            issues += (response_json['data']['issues']['nodes'])

    incidents = []
    for issue in issues:
        incident = build_incidents(issue=issue)
        incidents.append(incident)

    demisto.incidents(incidents)
    demisto.setLastRun(
        {'time': datetime.now().strftime(DEMISTO_OCCURRED_FORMAT)})


def get_issue(issue_id):
    demisto.info(f"Issue id is {issue_id}\n")

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        demisto.debug(message)
        return message

    issue_variables = {
        "first": 5,
        "filterBy": {
            "id": issue_id
        }
    }

    response_json = checkAPIerrors(PULL_ISSUES_QUERY, issue_variables)

    demisto.debug(f"The API response is {response_json}")

    issues = {}
    if response_json['data']['issues']['nodes'] != []:
        issues = response_json['data']['issues']['nodes']
    else:
        demisto.info(f"There was no result for Issue ID: {issue_id}")

    return issues


def get_filtered_issues(entity_type, resource_id, severity, issue_type, limit):
    """
    Retrieves Filtered Issues
    """
    demisto.info(f"Entity type is {entity_type}\n"
                 f"Resource ID is {resource_id}\n"
                 f"Severity is {severity}\n"
                 f"Issue type is {issue_type}")
    error_msg = ''

    if not severity and not entity_type and not resource_id and not issue_type:
        error_msg = "You should pass (at least) one of the following parameters:\n\tentity_type\n\tresource_id" \
                    "\n\tseverity\n\tissue_type\n"

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
                "status": [
                    "OPEN",
                    "IN_PROGRESS"
                ],
                "relatedEntity": {
                    "type": [
                        entity_type
                    ]
                },
            },
            "orderBy": {
                "field":
                    "SEVERITY",
                "direction":
                    "DESC"
            }
        }
    elif resource_id:
        get_resource_graph_id_helper_variables = {
            "projectId": "*",
            "query": {
                "type": [
                    "CLOUD_RESOURCE"
                ],
                "where": {
                    "providerUniqueId": {
                        "EQUALS":
                            resource_id
                    }
                }
            }
        }
        get_resource_graph_id_helper_query = ("""
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
        """)
        graph_resource_response_json = checkAPIerrors(get_resource_graph_id_helper_query,
                                                      get_resource_graph_id_helper_variables)
        if graph_resource_response_json['data']['graphSearch']['nodes'] != []:
            graph_resource_id = graph_resource_response_json['data']['graphSearch']['nodes'][0]['entities'][0]['id']
            issue_variables = \
                {"first": limit,
                 "filterBy": {"status": ["OPEN", "IN_PROGRESS"],
                              "relatedEntity":
                                  {"id": graph_resource_id}},
                 "orderBy": {"field": "SEVERITY", "direction": "DESC"}}
        else:
            demisto.info("Resource not found.")
            return "Resource not found."

    if severity:
        if 'filterBy' not in issue_variables.keys():
            issue_variables['filterBy'] = {"severity": []}
            issue_variables['first'] = limit
        if severity.upper() == 'CRITICAL':
            issue_variables['filterBy']['severity'] = ['CRITICAL']
        elif severity.upper() == 'HIGH':
            issue_variables['filterBy']['severity'] = ['CRITICAL', 'HIGH']
        elif severity.upper() == 'MEDIUM':
            issue_variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM']
        elif severity.upper() == 'LOW':
            issue_variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        elif severity.upper() == 'INFORMATIONAL':
            issue_variables['filterBy']['severity'] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
        else:
            demisto.info("You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL "
                         "in upper or lower case.")
            return ("You should only use these severity types: CRITICAL, HIGH, MEDIUM, LOW or INFORMATIONAL in "
                    "upper or lower case.")

    if issue_type:
        if 'filterBy' not in issue_variables.keys():
            issue_variables['filterBy'] = {}
            issue_variables['first'] = limit

        issue_variables['filterBy']['type'] = [issue_type]

    demisto.info(f"Query is {query}")
    demisto.info(f"Issue variables is {issue_variables}")

    response_json = checkAPIerrors(query, issue_variables)

    demisto.info(f"The API response is {response_json}")

    issues = {}
    if response_json['data']['issues']['nodes'] != []:
        issues = response_json['data']['issues']['nodes']
    while response_json['data']['issues']['pageInfo']['hasNextPage']:

        issue_variables['after'] = response_json['data']['issues']['pageInfo']['endCursor']
        response_json = checkAPIerrors(query, issue_variables)
        if response_json['data']['issues']['nodes'] != []:
            issues += (response_json['data']['issues']['nodes'])

    return issues


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

    if resource_name:
        variables = {
            "first": WIZ_API_LIMIT,
            "filterBy": {
                "search": resource_name
            }
        }
        try:
            response_json = checkAPIerrors(PULL_CLOUD_RESOURCES_NATIVE_QUERY, variables)
        except DemistoException:
            demisto.debug(f"could not find resource with this resource_name {resource_name}")
            return {}

        if response_json['data']['cloudResources']['nodes'] is None or not response_json['data']['cloudResources']['nodes']:
            demisto.info("Resource Not Found")
            return "Resource Not Found"
        else:
            return response_json
    # to get resource by resource_id
    variables = {
        "fetchPublicExposurePaths": True,
        "fetchInternalExposurePaths": False,
        "fetchIssueAnalytics": False,
        "first": 50,
        "query": {
            "type": [
                "CLOUD_RESOURCE"
            ],
            "select": True,
            "where": {
                "providerUniqueId": {
                    "EQUALS": [resource_id]
                }
            }
        },
        "projectId": "*",
        "fetchTotalCount": True,
        "quick": True
    }

    try:
        response_json = checkAPIerrors(PULL_RESOURCES_QUERY, variables)
    except DemistoException:
        demisto.debug(f"could not find resource with ID {resource_id}")
        return {}

    if response_json['data']['graphSearch']['nodes'] is None or not response_json['data']['graphSearch']['nodes']:
        demisto.info("Resource Not Found")
        return {}
    else:
        return response_json['data']['graphSearch']['nodes'][0]['entities'][0]


def reject_issue(issue_id, reject_reason, reject_comment):
    """
    Reject a Wiz Issue
    """
    return reject_or_resolve_issue(issue_id, reject_reason, reject_comment, 'REJECTED')


def resolve_issue(issue_id, resolution_reason, resolution_note):
    """
    Reject a Wiz Issue
    """
    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    issue_object = _get_issue(issue_id, is_evidence=False)

    issue_type = issue_object['data']['issues']['nodes'][0]['type']

    if issue_type != 'THREAT_DETECTION':
        demisto.error(f"Only a Threat Detection Issue can be resolved.\nReceived an Issue of type {issue_type}.")
        return f"Only a Threat Detection Issue can be resolved.\nReceived an Issue of type {issue_type}."

    return reject_or_resolve_issue(issue_id, resolution_reason, resolution_note, 'RESOLVED')


def reject_or_resolve_issue(issue_id, reject_or_resolve_reason, reject_or_resolve_comment, status):
    """
    Reject a Wiz Issue
    """
    demisto.debug(f"reject_issue with status: {status}, enter")
    operation = "reject" if status == 'REJECTED' else "resolution"

    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    if not reject_or_resolve_reason or not reject_or_resolve_comment:
        demisto.error(f"You should pass all of: Issue ID, {operation} reason and {operation} note.")
        return f"You should pass all of: Issue ID, {operation} reason and {operation} note."

    variables = {
        'issueId': issue_id,
        'patch': {
            'status': status,
            'note': reject_or_resolve_comment,
            'resolutionReason': reject_or_resolve_reason
        }
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

    variables = {
        'issueId': issue_id,
        'patch': {
            'status': 'OPEN'
        }
    }
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

    variables = {
        'issueId': issue_id,
        'patch': {
            'status': status
        }
    }
    query = UPDATE_ISSUE_QUERY

    response = checkAPIerrors(query, variables)

    return response


def _get_issue(issue_id, is_evidence=False):
    is_valid_id, message = is_valid_issue_id(issue_id)
    if not is_valid_id:
        return message

    issue_variables = {
        'first': 1,
        'filterBy': {
            'id': issue_id
        },
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

    issue_variables = {
        "input": {
            "issueId": issue_id,
            "text": comment
        }
    }
    issue_query = CREATE_COMMENT_QUERY

    response = checkAPIerrors(issue_query, issue_variables)

    return response


def get_error_output(wiz_api_response):
    error_output_message = ''
    first_error_message = ''
    if 'errors' in wiz_api_response:
        for error_dict in wiz_api_response['errors']:
            if 'message' in error_dict:
                error_message = error_dict['message']

                # Do not print duplicate errors
                if first_error_message and first_error_message == error_message:
                    continue
                if not first_error_message:
                    first_error_message = error_message

                error_output_message = error_output_message + error_message + '\n'

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

    issue_notes = issue_object['data']['issues']['nodes'][0]['notes']
    demisto.info(f"The issue notes are: {issue_notes}")

    query = DELETE_NOTE_QUERY
    for note in issue_notes:
        variables = {
            "input": {
                "id": note['id']
            }
        }

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
    due_at = due_at + 'T00:00:00.000Z'

    variables = {
        'issueId': issue_id,
        'patch': {
            'dueAt': due_at
        }
    }
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
    issue_variables = {
        'issueId': issue_id,
        'override': {
            'dueAt': None
        }
    }

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

    if not issue_object['data']['issues']['nodes']:
        return f"Issue not found: {issue_id}"

    issue_type = issue_object['data']['issues']['nodes'][0]['type']

    if issue_type == 'THREAT_DETECTION':
        if issue_object['data']['issues']['nodes'][0]['threatDetectionDetails'] is not None:
            return issue_object['data']['issues']['nodes'][0]['threatDetectionDetails']
        else:
            return f"No issue threat detection details evidence for Issue ID: {issue_id}"

    query_for_evidence = issue_object['data']['issues']['nodes'][0]['evidenceQuery']

    if not query_for_evidence:
        return f"No issue evidence for Issue ID: {issue_id}"

    # Creating the query/variables to get the Issue Evidence
    query = PULL_ISSUE_EVIDENCE_QUERY
    variables = PULL_ISSUE_EVIDENCE_PARAMS
    variables['query'] = query_for_evidence

    try:
        response = checkAPIerrors(query, variables)
    except Exception as e:
        error_message = f"Failed getting Issue evidence on ID {issue_id}.\nError details: {str(e)}"
        demisto.error(error_message)
        raise Exception(error_message)

    if response.get('data', {}).get('graphSearch', {}).get('nodes') is None:
        return "Resource Not Found"
    elif len(response.get('data', {}).get('graphSearch', {}).get('nodes')) == 0:
        return "No Evidence Found"
    else:
        return response['data']['graphSearch']['nodes'][0].get('entities', {})


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
        "filterBy": {
            "search": project_name
        },
        "orderBy": {
            "field": "SECURITY_SCORE",
            "direction": "ASC"
        },
        "analyticsSelection": {}
    }
    project_query = (  # pragma: no cover
        """
    query ProjectsTable(
        $filterBy: ProjectFilters
        $first: Int
        $after: String
        $orderBy: ProjectOrder
        $analyticsSelection: ProjectIssueAnalyticsSelection
    ) {
        projects(
        filterBy: $filterBy
        first: $first
        after: $after
        orderBy: $orderBy
        ) {
        nodes {
            id
            name
            description
            businessUnit
            archived
            slug
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
            cloudAccountCount
            repositoryCount
            securityScore
            riskProfile {
            businessImpact
            }
            teamMemberCount
            issueAnalytics(selection: $analyticsSelection) {
            issueCount
            scopeSize
            informationalSeverityCount
            lowSeverityCount
            mediumSeverityCount
            highSeverityCount
            criticalSeverityCount
            }
        }
        pageInfo {
            hasNextPage
            endCursor
        }
        }
    }
    """)

    try:
        response_json = checkAPIerrors(project_query, project_variables)
    except DemistoException:
        demisto.debug(f"Error with finding Project with name {project_name}")
        return {}

    project_response = response_json.get('data', {}).get('projects', {}).get('nodes')

    demisto.info(f"Validating if Project with name \"{project_name}\" exists.")
    if not project_response:
        demisto.debug(f"Project with name {project_name} does not exist")
        return {}

    else:
        project_team = {
            "projectOwners": project_response[0]['projectOwners'],
            "securityChampions": project_response[0]['securityChampions']
        }
        return project_team


def copy_to_forensics_account(resource_id):
    """
    Copy resource Volumes to a Forensics Account
    """
    demisto.info(f"resource id is {resource_id}\n")
    demisto.debug("copy_to_forensics_account, enter")

    if not is_valid_uuid(resource_id):
        variables = {
            "first": 1,
            "filterBy": {
                "providerUniqueId": [resource_id]
            }
        }
        resource_id_response = checkAPIerrors(PULL_RESOURCES_ID_NATIVE_QUERY, variables)
        if resource_id_response['data'] is None or not resource_id_response['data']['cloudResources']['nodes']:
            demisto.error(f"Resource with ID {resource_id} not found.")
            return f"Resource with ID {resource_id} not found."
        else:
            resource_id = resource_id_response['data']['cloudResources']['nodes'][0]['id']

    copy_to_forensics_account_variables = {
        "input": {
            "id": resource_id
        }
    }

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
    set_authentication_endpoint(params.get('auth_endpoint'))
    set_api_endpoint(params.get('api_endpoint', ''))
    try:
        command = demisto.command()
        if command == 'test-module':
            auth_token = get_token()
            if 'error' not in auth_token:
                test_response = checkAPIerrors(PULL_ISSUES_QUERY, PULL_ISSUES_TEST_VARIABLES)

                if 'errors' not in test_response:
                    demisto.results('ok')
                else:
                    demisto.results(test_response)
            else:
                demisto.results("Invalid token")

        elif command == 'fetch-incidents':
            max_fetch = int(demisto.params().get('max_fetch'))
            fetch_issues(
                max_fetch=max_fetch
            )

        elif command == 'wiz-get-issues':
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
                command_result = CommandResults(outputs_prefix="Wiz.Manager.Issues", outputs=issues,
                                                raw_response=issues)
            return_results(command_result)

        elif command == "wiz-get-resource":
            demisto_args = demisto.args()
            resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
            resource_name = demisto_args.get(WizInputParam.RESOURCE_NAME)
            resource = get_resource(resource_id=resource_id, resource_name=resource_name)
            if resource_id:
                command_result = CommandResults(outputs_prefix="Wiz.Manager.Resource", outputs=resource,
                                                raw_response=resource)
            else:
                command_result = CommandResults(readable_output=resource, raw_response=resource)
            return_results(command_result)

        elif command == 'wiz-reject-issue':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            resolution_reason = demisto_args.get(WizInputParam.REJECT_REASON)
            resolution_note = demisto_args.get(WizInputParam.REJECT_NOTE)
            issue_response = reject_issue(
                issue_id=issue_id,
                reject_reason=resolution_reason,
                reject_comment=resolution_note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-reopen-issue':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            reopen_note = demisto_args.get(WizInputParam.REOPEN_NOTE)
            issue_response = reopen_issue(
                issue_id=issue_id,
                reopen_note=reopen_note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-resolve-issue':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            resolution_reason = demisto_args.get(WizInputParam.RESOLUTION_REASON)
            resolution_note = demisto_args.get(WizInputParam.RESOLUTION_NOTE)
            issue_response = resolve_issue(
                issue_id=issue_id,
                resolution_reason=resolution_reason,
                resolution_note=resolution_note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-get-issue':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_result = get_issue(
                issue_id=issue_id,
            )
            command_result = CommandResults(readable_output=issue_result, raw_response=issue_result)
            return_results(command_result)

        elif command == 'wiz-issue-in-progress':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = issue_in_progress(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-set-issue-note':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            note = demisto_args.get(WizInputParam.NOTE)
            issue_response = set_issue_comment(
                issue_id=issue_id,
                comment=note
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-clear-issue-note':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = clear_issue_note(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-get-issue-evidence':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = get_issue_evidence(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-set-issue-due-date':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            due_at = demisto_args.get('due_at')
            issue_response = set_issue_due_date(
                issue_id=issue_id,
                due_at=due_at
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-clear-issue-due-date':
            demisto_args = demisto.args()
            issue_id = demisto_args.get(WizInputParam.ISSUE_ID)
            issue_response = clear_issue_due_date(
                issue_id=issue_id
            )
            command_result = CommandResults(readable_output=issue_response, raw_response=issue_response)
            return_results(command_result)

        elif command == 'wiz-get-project-team':
            demisto_args = demisto.args()
            project_name = demisto_args.get(WizInputParam.PROJECT_NAME)
            projects_response = get_project_team(
                project_name=project_name
            )
            command_result = CommandResults(readable_output=projects_response, raw_response=projects_response)
            return_results(command_result)

        elif command == 'wiz-rescan-machine-disk':
            return_results(CommandResults(readable_output="This command is deprecated",
                           raw_response="This command is deprecated"))

        elif command == 'wiz-copy-to-forensics-account':
            demisto_args = demisto.args()
            resource_id = demisto_args.get(WizInputParam.RESOURCE_ID)
            copy_mutation_response = copy_to_forensics_account(
                resource_id=resource_id
            )
            command_result = CommandResults(readable_output=copy_mutation_response, raw_response=copy_mutation_response)
            return_results(command_result)

        else:
            raise Exception('Unrecognized command: ' + command)
    except Exception as err:
        demisto.error(traceback.format_exc())
        return_error(f"An error occurred: {str(err)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
