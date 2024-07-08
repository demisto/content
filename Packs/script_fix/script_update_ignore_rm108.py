import re
import os
import json
from pathlib import Path
from urllib.parse import urlparse
import logging

logger = logging.getLogger(__name__)
PACKS_PATH = '/Users/mmorag/dev/demisto/content/Packs'
PACKS_TO_ADD_IGNORE_LIST = [
    "SocialEngineeringDomainAnalysis",
    "Tanium",
    "GettingStartedWithXSOAR",
    "CloudIDS",
    "GCP-Enrichment-Remediation",
    "GroupIB_ThreatIntelligenceAttribution",
    "BreachNotification-US",
    "DBotTruthBombs",
    "Lansweeper",
    "DevSecOps",
    "HIPAA-BreachNotification",
    "CTF02",
    "NGFWTSAgentDeployment",
    "Whois",
    "Active_Directory_Query",
    "Core",
    "OTSecurity",
    "Use_Case_Builder",
    "XMatters",
    "MajorBreachesInvestigationandResponse",
    "AccessInvestigation",
    "EmployeeOffboarding",
    "ElasticsearchMonitoring",
    "CortexAttackSurfaceManagement",
    "VersaDirector",
    "CortexAttackSurfaceManagement",
    "CitrixADC",
    "DefaultPlaybook",
    "SpringRCEs",
    "PrismaCloudComputeReporting",
    "ExtraHop",
    "ComputerVisionEngine",
    "SailPointIdentityIQ",
    "AWS-Enrichment-Remediation",
    "BruteForce",
    "CVE_2021_40444",
    "CyrenInboxSecurity",
    "MicrosoftADFS",
    "FeedCyrenThreatInDepth",
    "ThreatIntelReports",
    "ImpossibleTraveler",
    "GDPR",
    "CofenseTriage",
    "MicrosoftWSUS",
    "Wiz",
    "PrismaCloudCompute",
    "NIST",
    "UncoverUnknownMalwareUsingSSDeep",
    "VersaDirector",
    "RiskIQDigitalFootprint",
    "MicrosoftIISWebServer",
    "CVE_2022_30190",
    "F5LTM",
    "SymantecBlueCoatProxySG",
    "IntegrationsAndIncidentsHealthCheck",
    "MITRECoA",
    "Ataya",
    "PrismaCloud",
    "Campaign",
    "Lost_Stolen_Device",
    "ShadowIT",
    "DynamicSectionReports",
    "CyberArkEPV",
    "Portnox",
    "Neosec",
    "CiscoASA",
    "Ataya",
    "Rapid7_Nexpose",
    "WindowsForensics",
    "OpenCVE",
    "Flashpoint",
    "Ransomware",
    "ShiftManagement",
    "WhisperGateCVE-2021-32648",
    "Druva",
    "McAfeeNSM",
    "MalwareInvestigationAndResponse",
    "CohesityHelios",
    "CVE_2022_26134",
    "Azure-Enrichment-Remediation",
    "ctf01",
    "PortScan",
    "DNSDB",
    "OpenCTI",
    "RubrikPolaris",
    "Neosec",
    "CortexXpanse",
    "PANWComprehensiveInvestigation",
    "PrismaSaasSecurity",
    "WatchguardFirebox",
    "Wiz",
    "EmailCommunication",
    "CVE_2021_44228",
]
PATH_IN_IGNORE = "[file:README.md]"


def edit_ignore_file(lines, pack_ignore_path):
    # Regular expression to match URLs ending with common image file extensions
    # urls_list = {"Success": [], "files not found in doc_files": []}
    
    # Modify the specific line
    for i, line in enumerate(lines):
        if line.strip() == f"{PATH_IN_IGNORE}":
            if "RM108" in lines[i + 1]:
                return True
            next_line = lines[i + 1].rstrip('\n')
            next_line_update = f'{next_line},RM108\n'
            lines[i + 1] = next_line_update
            
            try:
                with open(pack_ignore_path, 'w') as file:
                    file.writelines(lines)
            except Exception as e:
                logger.debug(e)
                return False
            return True
    
    # If the specific line doesn't exist, append it to the end of the file
    with open(pack_ignore_path, 'a') as file:
        file.write(f"\n\n{PATH_IN_IGNORE}\nignore=RM108\n")
    return True


def search_if_markdown_file_in_ignore(file_path):
    """
        Searches for image links in the given file and replace them to relative paths.
        Parameters:
            file_path (str): The path to the file containing text with image links.
        Returns:
            None
        Raises:
            OSError: If there is an error creating the folder to save images or downloading images.
    """
    if os.path.getsize(file_path) == 0:
        with open(file_path, 'a') as file:
            file.write(f"\n{PATH_IN_IGNORE}\nignore=RM108\n")
    try:
        with (open(file_path, 'r+') as file):
            file_lines = file.readlines()
        return edit_ignore_file(file_lines, file_path)
    except Exception as error:
        logger.debug(error)
    return False


def loop_over_files_and_update_ignore():
    """
    Searches for files matching a specified pattern within a directory and its subdirectories,
    then extracts image links from those files and saves the information to a JSON file.
    """
    success = []
    failed = []
    for path in PACKS_TO_ADD_IGNORE_LIST:
        if search_if_markdown_file_in_ignore(f'{PACKS_PATH}/{path}/.pack-ignore'):
            success.append(path)
        else:
            failed.append(path)
    try:
        with open('/Users/mmorag/dev/demisto/content/script_fix/successes.json', "a") as file_success:
            json.dump(success, file_success)
        with open('/Users/mmorag/dev/demisto/content/script_fix/fails.json', "a") as file_fails:
            json.dump(failed, file_fails)
        
    except Exception as e:
        logger.debug(e)
        

def main():
    try:
        loop_over_files_and_update_ignore()
    except Exception as e:
        logger.debug(e)


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
