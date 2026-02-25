import sys
from github import Github
import argparse
import urllib3
from github.Repository import Repository
from github.PullRequest import PullRequest
from utils import timestamped_print

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
print = timestamped_print

COMPONENT_TEST_APPROVED_LABEL = "component-test"
COMPONENT_TEST_PACKS = {
    "OktaOAG",
    "CyberArk_Privileged_Threat_Analytics",
    "MicrosoftGraphSecurity",
    "CiscoFirepower",
    "F5LTM",
    "FireEyeNX",
    "GitHub",
    "Imperva_WAF",
    "Kubernetes",
    "CiscoStealthwatch",
    "ManageEngine-ADManager",
    "MicrosoftDefenderforIdentity",
    "MySQLEnterprise",
    "NGINXWebServer",
    "OracleCloudInfrastructure",
    "SafeNet_Trusted_Access",
    "Salesforce",
    "Squid",
    "CheckpointFirewall",
    "IBMGuardium",
    "Absolute",
    "AdminByRequest",
    "MacOS",
    "HPEArubaClearPass",
    "AWS_ELB",
    "BitwardenPasswordManager",
    "BluecatAddressManager",
    "BrocadeSwitch",
    "Celonis",
    "CiscoASR",
    "IronPort",
    "CiscoISR",
    "CiscoNexus",
    "AMP",
    "CiscoThousandEyes",
    "CiscoSpark",
    "CitrixADC",
    "Claroty",
    "CloudflareZeroTrust",
    "Code42",
    "Darktrace",
    "Dragos_Platform",
    "ExtraHop",
    "FireEyeETP",
    "ForeScoutCounterACT",
    "FortiManager",
    "GenetecSecurityCenter",
    "GitGuardian",
    "GoogleApigee",
    "GoogleCloudSCC",
    "GoogleDrive",
    "HPESwitch",
    "InfobloxBloxOne",
    "IronscalesEventCollector",
    "IvantiConnectSecure",
    "JuniperSRX",
    "KeeperSecurity",
    "Kiteworks",
    "ManageEngine-ADAudit",
    "McAfeeDatabaseSecurity",
    "McAfeeNSM",
    "McAfeeWebGateway",
    "MicrosoftDefenderAdvancedThreatProtection",
    "MicrosoftWindowsAMSI",
    "MicrosoftAdvancedThreatAnalytics",
    "Mimecast",
    "MongoDBAtlas",
    "MicrosoftECM",
    "NetBox",
    "NetmotionVPN",
    "Netskope",
    "OneLogin",
    "Orca",
    "PrismaSaasSecurity",
    "PrismaCloud",
    "ProofpointIsolation",
    "ProofpointThreatResponse",
    "qualys",
    "RecordedFuture",
    "RunZero",
    "SecureAuthIdentityPlatform",
    "SemperisDSP",
    "Shodan",
    "Siemens_SiPass",
    "Slack",
    "SonicWallNSv",
    "SymantecBlueCoatProxySG",
    "SymantecDLP",
    "SymantecEndpointProtection",
    "SymantecCloudSecureWebGateway",
    "Tableau",
    "TaniumThreatResponse",
    "ThinkstCanary",
    "DelineaALM",
    "DelineaSS",
    "TrendMicroInterScanWebSecurity",
    "Auditd",
    "Vectra_AI",
    "WatchguardFirebox",
    "WithSecure",
    "Zoom",
    "ZscalerZPA",
    "AlibabaActionTrail",
    "MicrosoftADFS",
    "cisco-ise",
    "CyberArkEPM",
    "DigitalGuardian",
    "ApacheTomcat",
    "BeyondTrustEPM",
    "OktaAuth0",
    "AbnormalSecurity",
    "CiscoSMA",
    "Armis",
    "AtlassianConfluenceCloud",
    "AvayaAuraCommunicationManager",
    "Barracuda_Cloudgen_Firewall",
    "BarracudaEmailProtection",
    "BarracudaWAF",
    "BeyondTrust_Password_Safe",
}


def arguments_handler():
    """Validates and parses script arguments.
    Returns:
       Namespace: Parsed arguments object.
    """
    parser = argparse.ArgumentParser(description="Check if component-test-packs-approved label exists.")
    parser.add_argument("-p", "--pr_number", help="The PR number to check if the label exists.")
    parser.add_argument("-g", "--github_token", help="The GitHub token to authenticate the GitHub client.")
    parser.add_argument("-c", "--changed_files", nargs="*", help="The path of modified files")
    return parser.parse_args()


def main():
    """
    This script is checking that "docs-approved" label exists for a PR in case
    the label exists the workflow will pass, if the label is missing the workflow will fail.
    """
    org_name = "demisto"
    repo_name = "content"
    options = arguments_handler()
    pr_number = options.pr_number
    github_token = options.github_token
    changed_files = options.changed_files

    github_client: Github = Github(github_token, verify=False)
    content_repo: Repository = github_client.get_repo(f"{org_name}/{repo_name}")
    pr: PullRequest = content_repo.get_pull(int(pr_number))

    pr_label_names = [label.name for label in pr.labels]
    component_test_approved = COMPONENT_TEST_APPROVED_LABEL in pr_label_names

    watched_folders = COMPONENT_TEST_PACKS
    watched_folders = {folder.lower() for folder in watched_folders if folder}
    # Detect if watched folder changed
    folder_changed = any(file.split("/")[1].lower() in watched_folders for file in changed_files)
    # Validation logic
    if folder_changed and not component_test_approved:
        print(
            f"❌ Missing {COMPONENT_TEST_APPROVED_LABEL} label: This pack has XSIAM content that is also supported"
            f" in Component Test, please verify."
        )
        sys.exit(1)

    if not folder_changed and component_test_approved:
        print(f"❌ Label '{COMPONENT_TEST_APPROVED_LABEL}' added, but no changes found in Component Test packs")
        sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
