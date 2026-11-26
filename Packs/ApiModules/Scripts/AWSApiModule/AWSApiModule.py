import boto3
from boto3 import Session
from botocore.config import Config
from botocore.client import BaseClient as BotoClient
from botocore.exceptions import ClientError
import demistomock as demisto  # noqa: F401

from concurrent.futures import ThreadPoolExecutor
from enum import Enum

from CommonServerPython import *

from CommonServerUserPython import *

from COOCApiModule import *  # noqa: E402

STS_ENDPOINTS = {
    "us-gov-west-1": "https://sts.us-gov-west-1.amazonaws.com",
    "us-gov-east-1": "https://sts.us-gov-east-1.amazonaws.com",
}  # See: https://docs.aws.amazon.com/general/latest/gr/sts.html

# COOC (AWSIntegration) client defaults
DEFAULT_MAX_RETRIES: int = 5
DEFAULT_MAX_WORKERS: int = 5
DEFAULT_SESSION_NAME = "cortex-session"
DEFAULT_PROXYDOME_CERTFICATE_PATH = os.getenv("EGRESSPROXY_CA_PATH") or "/etc/certs/egress.crt"
DEFAULT_PROXYDOME = os.getenv("CRTX_HTTP_PROXY") or "10.181.0.100:11117"
DEFAULT_REGION = "us-east-1"

# Commands whose boto3 service name can't be derived from the command name (aws-<service>-...).
COMMAND_SERVICE_MAP = {
    "aws-billing-cost-usage-list": "ce",
    "aws-billing-forecast-list": "ce",
    "aws-billing-budgets-list": "budgets",
    "aws-billing-budget-notification-list": "budgets",
}

REQUIRED_ACTIONS: list[str] = [
    "ec2:RevokeSecurityGroupEgress",
    "ec2:ModifyImageAttribute",
    "ec2:ModifyInstanceAttribute",
    "ec2:ModifySnapshotAttribute",
    "ec2:RevokeSecurityGroupIngress",
    "ec2:CreateSnapshot",
    "ec2:DescribeVpcs",
    "ec2:DescribeSubnets",
    "ec2:DescribeIpamResourceDiscoveries",
    "ec2:DescribeIpamResourceDiscoveryAssociations",
    "ec2:DescribeImages",
    "ec2:CreateImage",
    "ec2:DeregisterImage",
    "ec2:CopyImage",
    "ec2:DescribeSnapshots",
    "ec2:DeleteSnapshot",
    "ec2:CopySnapshot",
    "ec2:DescribeRegions",
    "eks:ListClusters",
    "eks:DescribeCluster",
    "eks:AssociateAccessPolicy",
    "eks:CreateAccessEntry",
    "eks:TagResource",
    "eks:UpdateAccessEntry",
    "ec2:CreateSecurityGroup",
    "ec2:CreateNetworkAcl",
    "ec2:GetIpamDiscoveredPublicAddresses",
    "ec2:CreateTags",
    "ec2:DeleteSecurityGroup",
    "ec2:DescribeAddresses",
    "ec2:AllocateAddress",
    "ec2:AssociateAddress",
    "ec2:DisassociateAddress",
    "ec2:ReleaseAddress",
    "ec2:DescribeInstances",
    "ec2:DescribeInstanceStatus",
    "ec2:DescribeSecurityGroups",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:ModifyInstanceMetadataOptions",
    "ec2:MonitorInstances",
    "ec2:UnmonitorInstances",
    "ec2:RebootInstances",
    "ec2:DescribeIamInstanceProfileAssociations",
    "ec2:GetPasswordData",
    "ec2:DescribeReservedInstances",
    "ec2:StartInstances",
    "ec2:StopInstances",
    "ec2:TerminateInstances",
    "ec2:RunInstances",
    "ec2:ModifyNetworkInterfaceAttribute",
    "ec2:CreateFleet",
    "ec2:DeleteFleets",
    "ec2:DescribeFleets",
    "ec2:DescribeFleetInstances",
    "ec2:ModifyFleet",
    "eks:UpdateClusterConfig",
    "ec2:DescribeVolumes",
    "ec2:ModifyVolume",
    "ec2:CreateVolume",
    "ec2:AttachVolume",
    "ec2:DetachVolume",
    "ec2:DeleteVolume",
    "ec2:DescribeLaunchTemplates",
    "ec2:CreateLaunchTemplate",
    "ec2:DeleteLaunchTemplate",
    "ec2:DeleteVpc",
    "ec2:CreateVpcEndpoint",
    "ec2:DescribeInternetGateways",
    "ec2:DetachInternetGateway",
    "ec2:DeleteInternetGateway",
    "ec2:DeleteSubnet",
    "ec2:CreateNetworkAclEntry",
    "ec2:DescribeKeyPairs",
    "ec2:AllocateHosts",
    "ec2:ReleaseHosts",
    "ec2:CreateTrafficMirrorSession",
    "ssm:ListAssociationVersions",
    "ssm:DescribeAssociation",
    "ssm:ListAssociations",
    "ssm:GetInventory",
    "ssm:AddTagsToResource",
    "ssm:RemoveTagsFromResource",
    "ssm:ListTagsForResource",
    "ssm:ListDocuments",
    "ssm:DescribeDocument",
    "ssm:DescribeAutomationExecutions",
    "ssm:StartAutomationExecution",
    "ssm:GetAutomationExecution",
    "ssm:StopAutomationExecution",
    "ssm:ListCommands",
    "ssm:CancelCommand",
    "ssm:SendCommand",
    "ssm:DescribeParameters",
    "kms:CreateGrant",
    "kms:Decrypt",
    "kms:DescribeKey",
    "kms:GenerateDataKey",
    "kms:EnableKeyRotation",
    "secretsmanager:CreateSecret",
    "secretsmanager:RotateSecret",
    "secretsmanager:TagResource",
    "rds:AddTagsToResource",
    "rds:CreateTenantDatabase",
    "rds:ModifyDBCluster",
    "rds:DescribeDBInstances",
    "rds:ModifyDBClusterSnapshotAttribute",
    "rds:ModifyDBInstance",
    "rds:ModifyDBSnapshotAttribute",
    "redshift:ModifyCluster",
    "s3:CreateBucket",
    "s3:ListAllMyBuckets",
    "s3:ListBucket",
    "s3:PutBucketAcl",
    "s3:PutBucketLogging",
    "s3:PutBucketVersioning",
    "s3:PutBucketPolicy",
    "s3:PutBucketPublicAccessBlock",
    "s3:PutObject",
    "s3:GetObject",
    "s3:GetBucketPolicy",
    "s3:GetBucketWebsite",
    "s3:GetBucketAcl",
    "s3:GetBucketPublicAccessBlock",
    "s3:GetEncryptionConfiguration",
    "s3:DeleteBucketPolicy",
    "s3:ListBuckets",
    "s3:DeleteBucket",
    "iam:PassRole",
    "iam:DeleteLoginProfile",
    "iam:PutUserPolicy",
    "iam:RemoveRoleFromInstanceProfile",
    "iam:UpdateAccessKey",
    "iam:GetAccountPasswordPolicy",
    "iam:UpdateAccountPasswordPolicy",
    "iam:GetAccountAuthorizationDetails",
    "ecs:UpdateClusterSettings",
    "acm:UpdateCertificateOptions",
    "cloudtrail:DescribeTrails",
    "lambda:GetFunctionConfiguration",
    "lambda:GetFunctionUrlConfig",
    "lambda:GetPolicy",
    "lambda:InvokeFunction",
    "lambda:UpdateFunctionUrlConfig",
    "lambda:UpdateFunctionConfiguration",
    "lambda:GetFunction",
    "lambda:ListFunctions",
    "lambda:ListAliases",
    "lambda:GetAccountSettings",
    "lambda:ListVersionsByFunction",
    "lambda:DeleteFunctionUrlConfig",
    "lambda:CreateFunction",
    "lambda:ListLayerVersions",
    "lambda:DeleteFunction",
    "lambda:DeleteLayerVersion",
    "lambda:PublishLayerVersion",
    "elasticloadbalancing:ModifyLoadBalancerAttributes",
    "ce:GetCostAndUsage",
    "ce:GetCostForecast",
    "budgets:DescribeBudgets",
    "budgets:DescribeNotificationsForBudget",
    "logs:CreateLogGroup",
    "logs:CreateLogStream",
    "logs:DeleteLogGroup",
    "logs:DeleteLogStream",
    "logs:FilterLogEvents",
    "logs:DescribeLogGroups",
    "logs:DescribeLogStreams",
    "logs:PutRetentionPolicy",
    "logs:DeleteRetentionPolicy",
    "logs:PutLogEvents",
    "logs:PutMetricFilter",
    "logs:DeleteMetricFilter",
    "logs:DescribeMetricFilters",
    "logs:TagResource",
    "network-firewall:DescribeFirewall",
    "network-firewall:ListFirewalls",
    "network-firewall:DescribeFirewallPolicy",
    "network-firewall:CreateFirewall",
    "network-firewall:DeleteFirewall",
    "network-firewall:UpdateFirewallDeleteProtection",
    "network-firewall:UpdateFirewallDescription",
    "network-firewall:UpdateSubnetChangeProtection",
    "network-firewall:AssociateSubnets",
    "network-firewall:DisassociateSubnets",
    "network-firewall:TagResource",
    "network-firewall:ListFirewallPolicies",
    "network-firewall:CreateFirewallPolicy",
    "network-firewall:UpdateFirewallPolicy",
    "network-firewall:DeleteFirewallPolicy",
    "network-firewall:AssociateFirewallPolicy",
    "network-firewall:UpdateFirewallPolicyChangeProtection",
    "network-firewall:CreateRuleGroup",
    "network-firewall:DeleteRuleGroup",
    "network-firewall:DescribeRuleGroup",
    "network-firewall:ListRuleGroups",
    "network-firewall:UpdateRuleGroup",
    "network-firewall:DeleteResourcePolicy",
    "network-firewall:PutResourcePolicy",
    "network-firewall:DescribeResourcePolicy",
    "network-firewall:ListTagsForResource",
    "network-firewall:UntagResource",
    "network-firewall:DescribeLoggingConfiguration",
    "network-firewall:UpdateLoggingConfiguration",
]


def validate_params(aws_default_region, aws_role_arn, aws_role_session_name, aws_access_key_id, aws_secret_access_key):
    """
    Validates that the provided parameters are compatible with the appropriate authentication method.
    """
    if not aws_default_region:
        raise DemistoException("You must specify AWS default region.")

    if bool(aws_access_key_id) != bool(aws_secret_access_key):
        raise DemistoException("You must provide Access Key id and Secret key id to configure the instance with credentials.")
    if bool(aws_role_arn) != bool(aws_role_session_name):
        raise DemistoException("Role session name is required when using role ARN.")


def extract_session_from_secret(secret_key, session_token):
    """
    Extract the session token from the secret_key field.
    """
    if secret_key and "@@@" in secret_key and not session_token:
        return secret_key.split("@@@")[0], secret_key.split("@@@")[1]
    else:
        return secret_key, session_token


class AWSServices(str, Enum):
    S3 = "s3"
    IAM = "iam"
    EC2 = "ec2"
    RDS = "rds"
    EKS = "eks"
    LAMBDA = "lambda"
    CloudTrail = "cloudtrail"
    ECS = "ecs"
    ACM = "acm"
    KMS = "kms"
    ELB = "elb"
    CostExplorer = "ce"
    BUDGETS = "budgets"
    SSM = "ssm"
    Redshift = "redshift"
    CloudWatchLogs = "logs"
    NetworkFirewall = "network-firewall"
    STS = "sts"


class AWSErrorHandler:
    """
    Centralized error handling for AWS boto3 client errors.
    Provides specialized handling for permission errors and general AWS API errors.
    """

    # Permission-related error codes that should be handled specially
    PERMISSION_ERROR_CODES = [
        "AccessDenied",
        "UnauthorizedOperation",
        "Forbidden",
        "AccessDeniedException",
        "UnauthorizedOperationException",
        "InsufficientPrivilegesException",
        "NotAuthorized",
    ]

    @classmethod
    def handle_response_error(cls, response: dict, account_id: str | None = None) -> None:
        """
        Handle boto3 response errors.
        For permission errors, returns a structured error entry using return_error.
        For other errors, raises DemistoException with informative error message.
        Args:
            err (ClientError): The boto3 ClientError exception
            account_id (str, optional): AWS account ID. If not provided, will try to get from demisto.args()
        """
        # Create informative error message
        detailed_error = (
            f"AWS API Error occurred while executing: {demisto.command()} with arguments: {list(demisto.args().keys())}\n"
            f"Request Id: {response.get('ResponseMetadata',{}).get('RequestId', 'N/A')}\n"
            f"HTTP Status Code: {response.get('ResponseMetadata',{}).get('HTTPStatusCode', 'N/A')}"
        )

        return_error(detailed_error)

    @classmethod
    def handle_client_error(cls, err: ClientError, account_id: str | None = None) -> None:
        """
        Handle boto3 client errors with special handling for permission issues.
        For permission errors, returns a structured error entry using return_error.
        For other errors, raises DemistoException with informative error message.
        Args:
            err (ClientError): The boto3 ClientError exception
            account_id (str, optional): AWS account ID. If not provided, will try to get from demisto.args()
        """
        try:
            demisto.debug(f"The original error message: {err}")
            error_code = err.response.get("Error", {}).get("Code")
            error_message = err.response.get("Error", {}).get("Message")
            http_status_code = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
            demisto.debug(f"[AWSErrorHandler] Got a client error: {error_message}")
            if not error_code or not error_message or not http_status_code:
                return_error(err)
            # Check if this is a permission-related error
            if (error_code in cls.PERMISSION_ERROR_CODES) or (http_status_code in [401, 403]):
                cls._handle_permission_error(err, error_code, error_message, account_id)
            else:
                cls._handle_general_error(err, error_code, error_message)
        except Exception as e:
            demisto.debug(f"[AWSErrorHandler] Unhandled error: {str(e)}")
            return_error(err)

    @classmethod
    def _handle_permission_error(
        cls, err: ClientError, error_code: str, error_message: str, account_id: str | None = None
    ) -> None:
        """
        Handle permission-related errors by returning structured error entry.
        Args:
            err (ClientError): The boto3 ClientError exception
            error_code (str): The AWS error code
            error_message (str): The AWS error message
            account_id (str, optional): AWS account ID
        """
        # Get account_id from args if not provided
        if not account_id:
            account_id = demisto.args().get("account_id", "unknown")

        action = cls._extract_action_from_message(error_message)
        # When encountering an unauthorized error, an encoded authorization message may be returned with different
        # encoding each time. This will create different error entries for each unauthorized error and will confuse the user.
        # Therefore we will omit the actual encoded message.
        demisto.info(f"Original error message: {error_message}")
        error_entry = {
            "account_id": account_id,
            "message": cls.remove_encoded_authorization_message(error_message),
            "name": action,
        }
        demisto.debug(f"Permission error detected: {error_entry}")
        return_multiple_permissions_error([error_entry])

    @classmethod
    def remove_encoded_authorization_message(cls, message: str) -> str:
        """
        Remove encoded authorization messages from AWS error responses.
        Args:
            message (str): Original error message
        Returns:
            str: Cleaned error message without encoded authorization details
        """
        index = message.lower().find("encoded authorization failure message:")
        if index != -1:  # substring found
            return message[:index]
        else:
            return message

    @classmethod
    def _handle_general_error(cls, err: ClientError, error_code: str, error_message: str) -> None:
        """
        Handle general (non-permission) errors with informative error messages.
        Args:
            err (ClientError): The boto3 ClientError exception
            error_code (str): The AWS error code
            error_message (str): The AWS error message
        """
        # Get additional error details
        request_id = err.response.get("ResponseMetadata", {}).get("RequestId", "N/A")
        http_status = err.response.get("ResponseMetadata", {}).get("HTTPStatusCode", "N/A")

        # Create informative error message
        detailed_error = (
            f"AWS API Error occurred while executing: {demisto.command()} with arguments: {list(demisto.args().keys())}\n"
            f"Error Code: {error_code}\n"
            f"Error Message: {error_message}\n"
            f"HTTP Status Code: {http_status}\n"
            f"Request ID: {request_id}"
        )

        demisto.error(f"AWS API Error: {detailed_error}")
        return_error(detailed_error)

    @classmethod
    def _extract_action_from_message(cls, error_message: str) -> str:
        """
        Extract AWS permission name from error message using regex patterns.
        Args:
            error_message (str): The AWS error message
        Returns:
            str: The extracted permission name or 'unknown' if not found
        """
        # Sanitize input to prevent regex injection
        if not error_message or not isinstance(error_message, str):
            return "unknown"

        for action in REQUIRED_ACTIONS:
            try:
                match = re.search(action, error_message, re.IGNORECASE)
                if match and match.group(0) == action:
                    return action
            except re.error:
                pass

        return "unknown"


class AWSIntegration(CloudIntegration):
    """COOC AWS implementation of ``CloudIntegration``.

    Builds boto3 service clients for both authentication paths:

    - **Cortex Cloud platform**: short-lived CTS credentials, requests routed through ProxyDome.
    - **XSOAR / XSIAM marketplace**: access keys from the ``credentials`` integration parameter,
      optionally exchanged via STS ``AssumeRole`` when ``role_arn`` is configured.

    - **Registered commands** (``@AWSIntegration.register``): ``(client, args)``, or ``(args, client)``
      when registered with ``polling=True``.
    - **Existing commands** (``commands_mapping``): ``(client, args)``, or ``(args, client)`` when the
      ``polling_timeout`` argument is present.
    - **Multi-account**: when ``access_role_name`` and ``accounts_to_access`` are configured, the
      command runs once per account, each on its own ``AWSIntegration`` instance.
    """

    cloud_type = CloudTypes.AWS.value
    uses_proxy_env = True

    # ------------------------------------------------------------------
    # CloudIntegration implementation
    # ------------------------------------------------------------------

    def get_client(self) -> BotoClient:
        """Build a boto3 client for the service of ``self.command``."""
        return self.get_service_client(credentials=self.get_credentials(), service=self._resolve_service(self.command))

    def health_check(self, credentials: dict, account_id: str, connector_id: str) -> HealthCheckError | None:
        """Check that a client can be created for every AWS service.

        Args:
            credentials: CTS credentials for ``account_id``.
            account_id: The AWS account ID being checked.
            connector_id: The Cortex connector ID.

        Returns:
            ``None`` if all services connected, otherwise a single aggregated ``HealthCheckError``.
        """
        failed_services: list[str] = []
        try:
            for service in AWSServices:
                try:
                    self.get_service_client(
                        credentials=credentials,
                        service=service,
                        config=Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 1}),
                    )
                    demisto.info(f"[AWS Automation Health Check] Successfully created client for {service.value}")
                except Exception as service_error:
                    demisto.error(
                        f"[AWS Automation Health Check] Failed to create client for {service.value}: {str(service_error)}"
                    )
                    failed_services.append(service.value)

            if failed_services:
                error_msg = f"Failed to connect to AWS services: {', '.join(failed_services)}"
                demisto.info(f"[AWS Automation Health Check] Connectivity error: {error_msg}")
                return HealthCheckError(
                    account_id=account_id,
                    connector_id=connector_id,
                    message=error_msg,
                    error_type=ErrorType.CONNECTIVITY_ERROR,
                )

            demisto.info("[AWS Automation Health Check] All services connected successfully")
            return None

        except Exception as err:
            demisto.error(f"[AWS Automation Health Check] Unexpected error during health check: {err}")
            return HealthCheckError(
                account_id=account_id,
                connector_id=connector_id,
                message=f"Unexpected error during health check: {str(err)}",
                error_type=ErrorType.INTERNAL_ERROR,
            )

    def test_module(self) -> str:
        """Validate marketplace credentials by calling ``sts:GetCallerIdentity``.

        ``GetCallerIdentity`` requires no IAM permissions and validates the full auth chain,
        including assumed-role sessions. Building a boto3 client alone makes no network call,
        so invalid credentials would otherwise pass silently.
        """
        sts_client = self.get_service_client(
            credentials={},
            service=AWSServices.STS,
            config=Config(connect_timeout=5, read_timeout=5, retries={"max_attempts": 1}),
        )
        sts_client.get_caller_identity()
        demisto.info("[AWS] test-module: sts.GetCallerIdentity succeeded")
        return "ok"

    def handle_error(self, error: Exception) -> None:
        """Route boto3 ``ClientError``s through ``AWSErrorHandler``; any other error is handled by the base class."""
        if isinstance(error, ClientError):
            AWSErrorHandler.handle_client_error(error, self.account_id)
            return
        super().handle_error(error)

    def execute_command(self, commands_mapping: dict) -> CommandResults | list[CommandResults] | None:
        """Execute ``self.command``, fanning out across accounts when multi-account access is configured.

        When both ``access_role_name`` and ``accounts_to_access`` are set, the command runs in
        parallel for every listed account and per-account errors are returned as error entries
        without aborting the batch. Otherwise it runs once for ``self.account_id``.
        """
        # Set the STS regional endpoint mode once, on the main thread, before any parallel execution.
        if not self.connector_id and (regional := self.params.get("sts_regional_endpoint")):
            demisto.debug(f"Setting AWS_STS_REGIONAL_ENDPOINTS={regional}")
            os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = regional.lower()

        role_name = (self.params.get("access_role_name") or "").removeprefix("role/")
        accounts = argToList(self.params.get("accounts_to_access"))
        if role_name and accounts:
            return self._execute_multi_account(commands_mapping, role_name, accounts)

        return self.execute_single_account(commands_mapping)

    def execute_single_account(self, commands_mapping: dict) -> CommandResults | list[CommandResults] | None:
        """Execute ``self.command`` once for ``self.account_id`` (registered handler first, then ``commands_mapping``)."""
        return super().execute_command(commands_mapping)

    def is_polling_command(self) -> bool:
        """Existing AWS polling commands are detected by the ``polling_timeout`` argument, not by command name."""
        return self.args.get("polling_timeout") is not None

    # ------------------------------------------------------------------
    # AWS-specific helpers
    # ------------------------------------------------------------------

    def get_service_client(self, credentials: dict, service: AWSServices, config: Config | None = None) -> BotoClient:
        """Create and configure a boto3 client for ``service`` from ``self.params`` and ``self.args``.

        Args:
            credentials: CTS credentials. Empty on the marketplace path.
            service: The AWS service to build the client for.
            config: Additional botocore configuration merged on top of the base config.

        Returns:
            The configured boto3 client.
        """
        params = self.params
        region: str = self.args.get("region") or params.get("region", "") or DEFAULT_REGION
        is_platform_path: bool = bool(credentials) or bool(self.connector_id)

        aws_session = self._build_session(credentials, params, region, is_platform_path)

        read_timeout, connect_timeout = get_timeout(params.get("timeout"))
        retries_raw = params.get("retries")
        retries = min(int(retries_raw) if retries_raw is not None and retries_raw != "" else DEFAULT_MAX_RETRIES, 10)
        base_config = Config(connect_timeout=connect_timeout, read_timeout=read_timeout, retries={"max_attempts": retries})
        if is_platform_path:
            base_config = base_config.merge(
                Config(
                    proxies={"https": DEFAULT_PROXYDOME},
                    proxies_config={"proxy_ca_bundle": DEFAULT_PROXYDOME_CERTFICATE_PATH},
                )
            )
        client_config = base_config.merge(config) if config else base_config

        # Platform requests go through ProxyDome, which presents a self-signed cert. On the marketplace
        # path SSL verification is on unless the user checked "Trust any certificate (not secure)".
        verify_ssl: str | bool = (
            DEFAULT_PROXYDOME_CERTFICATE_PATH if is_platform_path else not argToBoolean(params.get("insecure", False))
        )
        endpoint_url: str | None = params.get("endpoint_url") or None

        client = aws_session.client(service.value, verify=verify_ssl, config=client_config, endpoint_url=endpoint_url)
        if is_platform_path:
            self._register_proxydome_header(client)
        return client

    @staticmethod
    def _resolve_service(command: str) -> AWSServices:
        """Map a command name (``aws-<service>-...``) to its AWS service."""
        if command in COMMAND_SERVICE_MAP:
            return AWSServices(COMMAND_SERVICE_MAP[command])
        if "network-firewall" in command:
            return AWSServices("network-firewall")
        return AWSServices(command.split("-")[1])

    @staticmethod
    def _build_session(credentials: dict, params: dict, region: str, is_platform_path: bool) -> Session:
        """Build a boto3 session from CTS credentials (platform) or configured access keys (marketplace)."""
        if is_platform_path:
            return Session(
                aws_access_key_id=credentials.get("key"),
                aws_secret_access_key=credentials.get("access_token"),
                aws_session_token=credentials.get("session_token"),
                region_name=region,
            )

        creds_param = params.get("credentials") or {}
        access_key_id: str = creds_param.get("identifier", "")
        secret_access_key: str = creds_param.get("password", "")
        if not (access_key_id and secret_access_key):
            raise DemistoException(
                "AWS credentials are not configured. Provide an Access Key and Secret Key "
                "on the integration instance, or run the integration through a Cortex Cloud connector."
            )

        if not params.get("role_arn"):
            return Session(aws_access_key_id=access_key_id, aws_secret_access_key=secret_access_key, region_name=region)

        tmp_creds = AWSIntegration._assume_role_credentials(params, access_key_id, secret_access_key, region)
        return Session(
            aws_access_key_id=tmp_creds["AccessKeyId"],
            aws_secret_access_key=tmp_creds["SecretAccessKey"],
            aws_session_token=tmp_creds["SessionToken"],
            region_name=region,
        )

    @staticmethod
    def _assume_role_credentials(params: dict, access_key_id: str, secret_access_key: str, region: str) -> dict:
        """Call STS ``AssumeRole`` with the marketplace access keys and return the temporary credentials.

        Returns:
            ``{"AccessKeyId", "SecretAccessKey", "SessionToken", ...}`` from the STS response.
        """
        role_arn: str = params.get("role_arn", "")
        role_session_name: str = params.get("role_session_name") or DEFAULT_SESSION_NAME
        session_duration = arg_to_number(params.get("session_duration"))
        sts_region: str = params.get("sts_region") or region
        sts_endpoint_url: str | None = params.get("sts_endpoint_url") or None

        sts_client = boto3.client(
            "sts",
            region_name=sts_region,
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            endpoint_url=sts_endpoint_url,
            config=Config(connect_timeout=10, read_timeout=10, retries={"max_attempts": 1}),
            verify=not argToBoolean(params.get("insecure", False)),
        )
        assume_kwargs: dict = {"RoleArn": role_arn, "RoleSessionName": role_session_name}
        if session_duration is not None:
            assume_kwargs["DurationSeconds"] = session_duration

        demisto.debug(f"[AWS] Calling sts.AssumeRole with {assume_kwargs=}")
        return sts_client.assume_role(**assume_kwargs)["Credentials"]

    @staticmethod
    def _register_proxydome_header(boto_client: BotoClient) -> None:
        """Inject the ProxyDome ``x-caller-id`` header into every request sent by ``boto_client``."""
        proxydome_token: str = get_proxydome_token()

        def _add_proxydome_header(request, **kwargs):
            request.headers["x-caller-id"] = proxydome_token

        boto_client.meta.events.register_last("before-send.*.*", _add_proxydome_header)

    def for_account(self, account_id: str, role_name: str) -> "AWSIntegration":
        """Return a new ``AWSIntegration`` for ``self.command`` in ``account_id``, assuming ``role_name`` there.

        Each instance has its own ``account_id`` and credentials cache, so parallel threads never share a token.
        """
        return type(self)(
            command=self.command,
            args=self.args | {self.account_id_arg: account_id},
            params=self.params | {"role_arn": f"arn:aws:iam::{account_id}:role/{role_name}"},
        )

    def _execute_multi_account(self, commands_mapping: dict, role_name: str, accounts: list[str]) -> list[CommandResults]:
        """Run ``self.command`` for each account in parallel, assuming ``role_name`` in every account."""
        max_workers = arg_to_number(self.params.get("max_workers")) or DEFAULT_MAX_WORKERS
        demisto.debug(f"[AWS] Multi-account fan-out: command={self.command}, {len(accounts)=}, {max_workers=}")

        def _run_for_account(account_id: str) -> list[CommandResults]:
            try:
                result = self.for_account(account_id, role_name).execute_single_account(commands_mapping)
                return self._tag_results_with_account(result, account_id)
            except Exception as e:
                demisto.error(f"[AWS] Error for account {account_id}: {e}")
                return [
                    CommandResults(
                        readable_output=f"#### Error for account `{account_id}`\n{e}",
                        entry_type=EntryType.ERROR,
                        content_format=EntryFormat.MARKDOWN,
                    )
                ]

        results: list[CommandResults] = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for account_results in executor.map(_run_for_account, accounts):
                results.extend(account_results)
        return results

    @staticmethod
    def _tag_results_with_account(result: CommandResults | list[CommandResults] | None, account_id: str) -> list[CommandResults]:
        """Prefix readable output with the account and add ``AccountId`` to dict outputs."""
        if result is None:
            return [CommandResults(readable_output=f"#### Result for account `{account_id}`:\nNo result returned.")]
        results_list = result if isinstance(result, list) else [result]
        for res in results_list:
            res.readable_output = f"#### Result for account `{account_id}`:\n{res.readable_output or ''}"
            outputs = res.outputs if isinstance(res.outputs, list) else [res.outputs]
            for output in outputs:
                if isinstance(output, dict):
                    output.setdefault("AccountId", account_id)
        return results_list


class AWSClient:
    def __init__(
        self,
        aws_default_region,
        aws_role_arn,
        aws_role_session_name,
        aws_role_session_duration,
        aws_role_policy,
        aws_access_key_id,
        aws_secret_access_key,
        verify_certificate,
        timeout,
        retries,
        aws_session_token=None,
        sts_endpoint_url=None,
        endpoint_url=None,
        sts_region=None,
    ):
        self.sts_endpoint_url = sts_endpoint_url
        self.endpoint_url = endpoint_url
        self.aws_default_region = aws_default_region
        self.aws_role_arn = aws_role_arn
        self.aws_role_session_name = aws_role_session_name
        # handle cases where aws_role_session_duration can be also empty string
        self.aws_role_session_duration = aws_role_session_duration if aws_role_session_duration else None
        self.aws_role_policy = aws_role_policy
        self.aws_access_key_id = aws_access_key_id
        self.aws_secret_access_key, self.aws_session_token = extract_session_from_secret(aws_secret_access_key, aws_session_token)
        self.verify_certificate = verify_certificate
        self.sts_region = sts_region

        sts_regional_endpoint = demisto.params().get("sts_regional_endpoint") or None
        if sts_regional_endpoint:
            demisto.debug(f"Sets the environment variable AWS_STS_REGIONAL_ENDPOINTS={sts_regional_endpoint}")
            os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = sts_regional_endpoint.lower()

        proxies = handle_proxy(proxy_param_name="proxy", checkbox_default_value=False)
        (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
        if int(retries) > 10:
            retries = 10
        self.config = Config(
            connect_timeout=connect_timeout, read_timeout=read_timeout, retries={"max_attempts": int(retries)}, proxies=proxies
        )

    def update_config(self):
        command_config = {}
        retries = demisto.getArg("retries")  # Supports retries and timeout parameters on the command execution level
        if retries is not None:
            command_config["retries"] = {"max_attempts": int(retries)}
        timeout = demisto.getArg("timeout")
        if timeout is not None:
            (read_timeout, connect_timeout) = AWSClient.get_timeout(timeout)
            command_config["read_timeout"] = read_timeout
            command_config["connect_timeout"] = connect_timeout
        if retries or timeout:
            demisto.debug(f"Merging client config settings: {command_config}")
            self.config = self.config.merge(Config(**command_config))  # type: ignore[arg-type]

    def aws_session(
        self, service, region=None, role_arn=None, role_session_name=None, role_session_duration=None, role_policy=None
    ):
        kwargs = {}
        client = None

        self.update_config()

        if role_arn and role_session_name is not None:
            kwargs.update(
                {
                    "RoleArn": role_arn,
                    "RoleSessionName": role_session_name,
                }
            )
        elif self.aws_role_arn and self.aws_role_session_name is not None:
            kwargs.update(
                {
                    "RoleArn": self.aws_role_arn,
                    "RoleSessionName": self.aws_role_session_name,
                }
            )

        if role_session_duration is not None:
            kwargs.update({"DurationSeconds": int(role_session_duration)})
        elif self.aws_role_session_duration is not None:
            kwargs.update({"DurationSeconds": int(self.aws_role_session_duration)})

        if role_policy is not None:
            kwargs.update({"Policy": role_policy})
        elif self.aws_role_policy is not None:
            kwargs.update({"Policy": self.aws_role_policy})

        demisto.debug(f"{kwargs=}")
        self.sts_endpoint_url = self.sts_endpoint_url or STS_ENDPOINTS.get(region) or STS_ENDPOINTS.get(self.aws_default_region)

        calculated_sts_region = self.sts_region
        if not calculated_sts_region:
            calculated_sts_region = region if region else self.aws_default_region
        demisto.debug(
            f"Calculated sts region: {calculated_sts_region}, {self.sts_region=}, {region=}, {self.aws_default_region=}"
        )

        if kwargs and not self.aws_access_key_id:  # login with Role ARN
            if not self.aws_access_key_id:
                sts_client = boto3.client(
                    "sts",
                    config=self.config,
                    verify=self.verify_certificate,
                    region_name=calculated_sts_region,
                    endpoint_url=self.sts_endpoint_url,
                )
                sts_response = sts_client.assume_role(**kwargs)
                client = boto3.client(
                    service_name=service,
                    region_name=region if region else self.aws_default_region,
                    aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
                    aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
                    aws_session_token=sts_response["Credentials"]["SessionToken"],
                    verify=self.verify_certificate,
                    config=self.config,
                    endpoint_url=self.endpoint_url,
                )
        elif self.aws_access_key_id and (role_arn or self.aws_role_arn):  # login with Access Key ID and Role ARN
            sts_client = boto3.client(
                service_name="sts",
                region_name=calculated_sts_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.sts_endpoint_url,
            )
            kwargs.update(
                {
                    "RoleArn": role_arn or self.aws_role_arn,
                    "RoleSessionName": role_session_name or self.aws_role_session_name,
                }
            )
            sts_response = sts_client.assume_role(**kwargs)
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=sts_response["Credentials"]["AccessKeyId"],
                aws_secret_access_key=sts_response["Credentials"]["SecretAccessKey"],
                aws_session_token=sts_response["Credentials"]["SessionToken"],
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url,
            )
        elif self.aws_session_token and not self.aws_role_arn:  # login with session token
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                aws_session_token=self.aws_session_token,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url,
            )
        elif self.aws_access_key_id and not self.aws_role_arn:  # login with access key id
            client = boto3.client(
                service_name=service,
                region_name=region if region else self.aws_default_region,
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                verify=self.verify_certificate,
                config=self.config,
                endpoint_url=self.endpoint_url,
            )
        else:  # login with default permissions, permissions pulled from the ec2 metadata
            client = boto3.client(
                service_name=service, region_name=region if region else self.aws_default_region, endpoint_url=self.endpoint_url
            )

        return client

    @staticmethod
    def get_timeout(timeout):
        if not timeout:
            timeout = "60,10"  # default values
        try:
            if isinstance(timeout, int):
                read_timeout = timeout
                connect_timeout = 10

            else:
                timeout_vals = timeout.split(",")
                read_timeout = int(timeout_vals[0])
                # the default connect timeout is 10
                connect_timeout = 10 if len(timeout_vals) == 1 else int(timeout_vals[1])

        except ValueError:
            raise DemistoException(
                "You can specify just the read timeout (for example 60) or also the connect "
                "timeout followed after a comma (for example 60,10). If a connect timeout is not "
                "specified, a default of 10 second will be used."
            )
        return read_timeout, connect_timeout
