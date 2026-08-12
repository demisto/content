# Mock CommonServerPython for testing
from typing import Any, Dict, List, Optional, Union
import json
import re
from datetime import datetime, timezone
import demistomock as demisto

# Common constants
class DBotScoreType:
    IP = "ip"
    FILE = "file"
    URL = "url"
    DOMAIN = "domain"
    CVE = "cve"
    
    # DBot Score values
    NONE = 0
    GOOD = 1
    SUSPICIOUS = 2
    BAD = 3

class DBotScoreReliability:
    A = "A - Completely reliable"
    B = "B - Usually reliable"
    C = "C - Fairly reliable"
    D = "D - Not usually reliable"
    E = "E - Unreliable"
    F = "F - Reliability cannot be judged"
    
    @staticmethod
    def is_valid_type(reliability: str) -> bool:
        return reliability in [
            DBotScoreReliability.A,
            DBotScoreReliability.B,
            DBotScoreReliability.C,
            DBotScoreReliability.D,
            DBotScoreReliability.E,
            DBotScoreReliability.F
        ]
    
    @staticmethod
    def get_dbot_score_reliability_from_str(reliability: str) -> str:
        """Convert reliability string to DBot score reliability."""
        # If it's already a valid reliability string, return it
        if DBotScoreReliability.is_valid_type(reliability):
            return reliability
        
        # Map common abbreviations to full reliability strings
        mapping = {
            'A': DBotScoreReliability.A,
            'B': DBotScoreReliability.B,
            'C': DBotScoreReliability.C,
            'D': DBotScoreReliability.D,
            'E': DBotScoreReliability.E,
            'F': DBotScoreReliability.F,
        }
        
        return mapping.get(reliability.upper(), DBotScoreReliability.C)

class DBotScore:
    """Mock DBotScore class for creating DBot score indicators."""
    # Score constants
    NONE = 0
    GOOD = 1
    SUSPICIOUS = 2
    BAD = 3
    
    def __init__(self, indicator: str, indicator_type: str, score: int, integration_name: str = "", 
                 malicious_description: str = "", reliability: str = ""):
        self.indicator = indicator
        self.indicator_type = indicator_type
        self.score = score
        self.integration_name = integration_name
        self.malicious_description = malicious_description
        self.reliability = reliability

class IP:
    """Mock IP indicator class."""
    def __init__(self, ip: str, dbot_score=None, asn: str = None, hostname: str = None, 
                 geo_country: str = None, geo_description: str = None, **kwargs):
        self.ip = ip
        self.dbot_score = dbot_score
        self.asn = asn
        self.hostname = hostname
        self.geo_country = geo_country
        self.geo_description = geo_description
        for key, value in kwargs.items():
            setattr(self, key, value)

class CVE:
    """Mock CVE indicator class."""
    def __init__(self, id: str, dbot_score=None, cvss: str = None, description: str = None,
                 published: str = None, modified: str = None, **kwargs):
        self.id = id
        self.dbot_score = dbot_score
        self.cvss = cvss
        self.description = description
        self.published = published
        self.modified = modified
        for key, value in kwargs.items():
            setattr(self, key, value)

class Common:
    DBotScore = DBotScore
    Reliability = DBotScoreReliability
    IP = IP
    CVE = CVE

class CommandResults:
    def __init__(self, outputs_prefix: str = None, outputs_key_field: str = None, 
                 outputs: Any = None, indicators: List = None, readable_output: str = None,
                 raw_response: Any = None, ignore_auto_extract: bool = False, indicator: Any = None):
        self.outputs_prefix = outputs_prefix
        self.outputs_key_field = outputs_key_field  
        self.outputs = outputs
        self.indicators = indicators or []
        if indicator:
            self.indicators.append(indicator)
        self.readable_output = readable_output
        self.raw_response = raw_response
        self.ignore_auto_extract = ignore_auto_extract
        self.indicator = indicator

def tableToMarkdown(name: str, t: Any, headers: List[str] = None, 
                   removeNull: bool = False, url_keys: List[str] = None) -> str:
    """Convert data to markdown table format."""
    if not t:
        return f"### {name}\n**No entries.**\n"
    
    if isinstance(t, dict):
        t = [t]
    elif not isinstance(t, list):
        return f"### {name}\n{str(t)}"
    
    if not t:
        return f"### {name}\n**No entries.**\n"
    
    # Get headers from first item if not provided
    if not headers and len(t) > 0:
        headers = list(t[0].keys())
    
    markdown = f"### {name}\n"
    if headers:
        markdown += "|" + "|".join(headers) + "|\n"
        markdown += "|" + "|".join(["---"] * len(headers)) + "|\n"
        
        for row in t:
            values = []
            for header in headers:
                value = row.get(header, "")
                if removeNull and not value:
                    value = ""
                # Handle None values
                if value is None:
                    value = ""
                # Format boolean values as lowercase
                elif isinstance(value, bool):
                    value = str(value).lower()
                else:
                    value = str(value)
                values.append(value)
            # Add spaces around values
            markdown += "| " + " | ".join(values) + " |\n"
    
    return markdown

def is_demisto_version_ge(version: str) -> bool:
    """Check if Demisto version is greater than or equal to specified version."""
    return True  # For testing, assume we have a recent version

def auto_detect_indicator_type(indicator: str) -> str:
    """Auto-detect the type of an indicator."""
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', indicator):
        return "IP"
    elif re.match(r'^[a-fA-F0-9]{32}$', indicator) or re.match(r'^[a-fA-F0-9]{40}$', indicator) or re.match(r'^[a-fA-F0-9]{64}$', indicator):
        return "File"
    elif re.match(r'^https?://', indicator):
        return "URL"
    elif re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', indicator):
        return "Domain"
    elif re.match(r'^CVE-\d{4}-\d+$', indicator):
        return "CVE"
    else:
        return "Unknown"

# Add other common functions as needed
def get_demisto_version() -> str:
    return "6.5.0"

def argToList(arg, separator: str = ',') -> List[str]:
    """Convert argument to list."""
    if isinstance(arg, list):
        return arg
    if isinstance(arg, str):
        return [x.strip() for x in arg.split(separator) if x.strip()]
    return []

def argToBoolean(arg) -> bool:
    """Convert argument to boolean."""
    if isinstance(arg, bool):
        return arg
    if isinstance(arg, str):
        return arg.lower() in ['true', 'yes', '1']
    return False

def date_to_timestamp(date_str: str, date_format: str = None) -> int:
    """Convert date string to timestamp."""
    try:
        if date_format:
            dt = datetime.strptime(date_str, date_format)
        else:
            dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        return int(dt.timestamp() * 1000)
    except:
        return 0

def handle_proxy(proxy_param_name: str = None, proxy_url: str = None) -> Dict[str, str]:
    """Handle proxy configuration."""
    if proxy_url:
        return {"http": proxy_url, "https": proxy_url}
    return {}

def return_error(message: str, error: Exception = None, outputs: Any = None):
    """Return error to Demisto."""
    demisto.results({
        "Type": 4,  # Error entry type
        "ContentsFormat": "text",
        "Contents": message
    })
    import sys
    sys.exit(1)

def logger(func):
    """Logger decorator for functions."""
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)
    return wrapper

def exception_handler(func):
    """Exception handler decorator for functions."""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            print(f"Exception in {func.__name__}: {e}")
            raise
    return wrapper

def remove_empty_elements(data):
    """Remove empty elements from a dict, list or nested structure."""
    if isinstance(data, dict):
        result = {}
        for k, v in data.items():
            if v is not None and v != [] and v != {}:
                cleaned_v = remove_empty_elements(v)
                # Only add if the cleaned value is not empty
                if cleaned_v is not None and cleaned_v != [] and cleaned_v != {}:
                    result[k] = cleaned_v
        return result
    elif isinstance(data, list):
        result = []
        for item in data:
            if item is not None and item != [] and item != {}:
                cleaned_item = remove_empty_elements(item)
                if cleaned_item is not None and cleaned_item != [] and cleaned_item != {}:
                    result.append(cleaned_item)
        return result
    else:
        return data

class DemistoException(Exception):
    """Exception class for Demisto/XSOAR errors."""
    pass

# Make DBotScoreType available at module level for direct imports
DBotScoreType = DBotScoreType