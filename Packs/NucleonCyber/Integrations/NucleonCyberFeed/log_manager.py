"""
VERSION: 1.2.0

"""

import os
import logging 
from pathlib import Path
from logging.handlers import RotatingFileHandler
from configparser import ConfigParser


#########################
#### log file setup #####
#########################

LOGS = 'logs'               # logs directory name
LOGFILENAME = 'log.log'     # logs file name
MSG_FORMAT = '%(asctime)s %(levelname)s %(filename)s %(funcName)s: %(message)s'
DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

# get perent directory name
PERENT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(
            os.path.abspath(__file__)
        )
    )
)

# get log file name if exists
conf = ConfigParser()
conf.read( os.path.join(PERENT_DIR, 'config.ini'))
if conf.has_option('GLOBAL', 'LOG_FILE_NAME'):
    LOGFILENAME_TMP = conf.get('GLOBAL', 'LOG_FILE_NAME')
    if LOGFILENAME_TMP:
        LOGFILENAME = LOGFILENAME_TMP
    else:
        print('WARNING: could not get log file name from config.ini, option {} in section {} is empty'.format('LOG_FILE_NAME', 'GLOBAL'))
        print('using the default file name log.log')
else:
    print('WARNING: could not get log file name from config.ini, no option {} in section {}'.format('LOG_FILE_NAME', 'GLOBAL'))
    print('using the default file name log.log')


LOGS_DIRECTORY_PATH = os.path.join(PERENT_DIR, LOGS)             # create logs directory path name
LOG_FILE_PATH = os.path.join(LOGS_DIRECTORY_PATH, LOGFILENAME)   # create logs file path name

# create logs directory if not exists
Path(LOGS_DIRECTORY_PATH).mkdir(parents=True, exist_ok=True)

# set basic configurations
logging.basicConfig(
    filename=LOG_FILE_PATH, 
    format=MSG_FORMAT, 
    datefmt=DATE_FORMAT,
    level=logging.DEBUG
)

logger = logging.getLogger()

# create formater for handlers
formatter = logging.Formatter(MSG_FORMAT)

# limit log file size
rf = RotatingFileHandler(
    LOG_FILE_PATH,  
    mode='a',
    maxBytes=5*1024*1024, 
    backupCount=2, 
    encoding=None, 
    delay=0
)
rf.setLevel(logging.DEBUG)
rf.setFormatter(formatter)


# create console handler and set level to debug
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
ch.setFormatter(formatter) # add formatter to ch

# add handlars
logger.addHandler(rf)
logger.addHandler(ch)