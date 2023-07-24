import argparse
from datetime import datetime, timedelta
import logging
import os
from typing import Tuple, Optional
import gitlab
import requests
from slack_sdk import WebClient

from Tests.Marketplace.marketplace_services import get_upload_data
from Tests.Marketplace.marketplace_constants import BucketUploadFlow
from Tests.scripts.utils.log_util import install_logging
from demisto_sdk.commands.coverage_analyze.tools import get_total_coverage

