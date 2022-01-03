#!/usr/bin/python
# -*- coding: utf-8 -*-
# -----------------------------------------
# Demisto integration for Bitglass
# -----------------------------------------

"""
(C) Copyright Bitglass Inc. 2021. All Rights Reserved.
Author: eng@bitglass.com
"""


# Demisto App (implicit) imports
try:
    LOG('') # noqa  # pylint: disable=E0601
    underdemisto = True
except Exception:
    underdemisto = False
    try:
        # Our internal mock (not from the SDK), demisto + CommonServerPython
        from mock.demisto import demisto, LOG, return_error, return_results,\
            IncidentSeverity, timestamp_to_datestring, CommandResults,\
            DemistoException    # ,tableToMarkdown    # pylint: disable=E0401
    except Exception:
        # demisto SDK test environment
        import demistomock as demisto   # type: ignore[no-redef]
        from CommonServerPython import *    # noqa: F401


# MERGE mergedimports.py

import os
import sys
import time
import copy
import re
import logging
import logging.handlers
import base64
import json
from datetime import datetime, timedelta
from threading import Thread, Condition
from contextlib import contextmanager
import optparse

# Additional, Demisto-specific
import traceback

# Demisto only
from typing import Any, Dict, Tuple, List, Optional, cast   # , Union
# import collections

from six import PY2, iteritems, string_types
from six.moves import socketserver

import requests     # noqa
from requests.auth import HTTPBasicAuth, AuthBase   # noqa


# NOTE to the customer: Extend and override as needed for troubleshooting, see the README file
# ====================================================================================================
# DEFAULT CONFIG SETTINGS, instead of files on the platforms supporting file I/O
# For now, the config is saved in the context for the sole sake of the context reset feature
# ... and for the sake of setting up the 'featureset' setting
# ----------------------------------------------------------------------------------------------------
dcontext = {
    'config.json': {
        "version": "1.0.13",
        "featureset": [{"demisto": True}],
        # "logging_level": "DEBUG"
    },
    # TODO Merge properly with the context on level of individual settings before can use it, see BitglassContextDemisto.__init__
    # NOTE Any settings from the foreign config (the usual ones, including the secret ones) will override anything added here
    # 'forward.json': {
    #     # All the defaults are hardcoded
    # }
}
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


# MERGE consts.py

GC_LOGTYPE_CLOUDAUDIT = u'cloudaudit'
GC_LOGTYPE_ACCESS = u'access'
GC_LOGTYPE_ADMIN = u'admin'
GC_LOGTYPE_CLOUDSUMMARY = u'cloudsummary'

GC_LOGTYPE_SWGWEB = u'swgweb'
GC_LOGTYPE_SWGWEBDLP = u'swgwebdlp'

GC_LOGTYPE_HEALTHPROXY = u'healthproxy'
GC_LOGTYPE_HEALTHAPI = u'healthapi'
GC_LOGTYPE_HEALTHSYSTEM = u'healthsystem'

GC_RESETTIME = u'resettime'

GC_FIELD_LOGTYPE = u'logtype'
GC_FIELD_NEXTPAGETOKEN = u'nextpagetoken'
GC_FIELD_DLPPATTERN = u'dlppattern'
GC_FIELD_EMAIL = u'email'
GC_FIELD_PATTERNS = u'patterns'
GC_FIELD_OWNER = u'owner'
GC_FIELD_TIME = u'time'

GC_FIELD_INGESTEDTIME = u'_ingestedtime'
GC_FIELD_INITIALTIME = u'_initialtime'


# Phantom

# Regex and datetime patterns
GC_DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'

# Ingestion run mode constants
GC_ALERT_USER_MATCH_KEY = 'User Alert Matches (by Asset Patterns)'

# Contains for the different artifact keys
GC_BG_USERNAME_CONTAINS = ['user name']

# Error message constants
ERR_CODE_MSG = "Error code unavailable"
ERR_MSG_UNAVAILABLE = "Error message unavailable. Please check the asset configuration and|or action parameters"
PARSE_ERR_MSG = "Unable to parse the error message. Please check the asset configuration and|or action parameters"

# Message constants
INVALID_PARAMS_ERR_MSG = "Please provide valid action parameters value"
INVALID_PARAM_ERR_MSG = "Please provide a valid action parameter value"


# MERGE __init__.py

__author__ = 'Bitglass'


class Logger(object):
    """ For redirecting logging output to proprietory platform APIs (such as QRadar).
        Default ctor is equivalent to logging not defined as the case is when on some platforms
        one needs to know the data path from the config first before can initialize logging.
        This allows for using app.logger.xyz() across the app in a portable way across platforms.
        By default the standard python 'logging' module is used whenever possible.
    """

    def debug(self, msg):   # pylint: disable=E0202
        self.log(msg, level='DEBUG')

    def info(self, msg):    # pylint: disable=E0202
        self.log(msg, level='INFO')

    def warning(self, msg):     # pylint: disable=E0202
        self.log(msg, level='WARNING')

    def error(self, msg):   # pylint: disable=E0202
        self.log(msg, level='ERROR')

    def nop(self, msg):     # pylint: disable=E0202
        pass

    def __bool__(self):
        return bool(self.conf)

    # TODO Remove Python 2 crutch
    def __nonzero__(self):
        return self.__bool__()

    def __init__(self, conf=None, log=None, set_log_level=None, nop=None):
        self.conf = conf
        self.log = log
        if nop:
            self.nop = nop  # type: ignore[assignment]
        if conf and log and set_log_level:
            if 'error' in conf.logging_level.lower():
                set_log_level('ERROR')
                self.debug = self.nop   # type: ignore[assignment]
                self.info = self.nop    # type: ignore[assignment]
                self.warning = self.nop     # type: ignore[assignment]
            elif 'warn' in conf.logging_level.lower():
                set_log_level('WARNING')
                self.debug = self.nop   # type: ignore[assignment]
                self.info = self.nop    # type: ignore[assignment]
            elif 'info' in conf.logging_level.lower():
                set_log_level('INFO')
                self.info = self.nop    # type: ignore[assignment]
        else:
            self.debug = self.nop   # type: ignore[assignment]
            self.info = self.nop    # type: ignore[assignment]
            self.warning = self.nop     # type: ignore[assignment]
            self.error = self.nop   # type: ignore[assignment]


# Can't initialize here b/c it's data path dependent (different for different platforms)
# logger = Logger()


# Uncomment for the merged module support
class App:
    Logger = Logger

    def __init__(self):
        self.logger = demisto


app = App()


# MERGE secret.py

# Only mask chars (and sep chars if multi-password - below) are sent back to the client, never the actual password
PSWD_MASK_CHAR = '*'

# All passwords should be validated to not contain this control char, in case it's used
# to concatenate multiple passwords for bulk encryption as in the 'proxies' setting
MULTI_PSWD_SEP_CHAR = '\t'


# All special proxy formatting chars are still valid (the re used makes sure of that), except the whitespace
# The re parsing already guarantees whitespace to be excluded so no additional checking is necessary
# INVALID_PSWD_CHARS = '/:@. \t'
INVALID_PSWD_CHARS = ' \t'


class Secret(object):
    """ For the sake of 'extra' security echo a dummy string back from the server.
        The dummy value of the same length will pass the form validation so there is no need to retype.
        On the way back to the server, detect it and don't override the value keeping it the same.
        Furthermore, explicitly clear the value when the session goes out.
    """

    def __get__(self, instance, _):     # _ owner
        return '' if instance.pswd is None or instance.pswd == '' else ''.join(
            MULTI_PSWD_SEP_CHAR if c == MULTI_PSWD_SEP_CHAR else PSWD_MASK_CHAR for c in instance.pswd)

    def __set__(self, instance, value):
        pswd = value if any(a() for a in [lambda: instance.pswd is None,
                                          lambda: instance.pswd == '',
                                          lambda: len(value) != len(instance.pswd),
                                          lambda: not set(value).issubset(
                                              set(PSWD_MASK_CHAR + MULTI_PSWD_SEP_CHAR)
                                          )]) else instance.pswd
        if pswd != instance.pswd:
            instance.pswd = pswd
            if instance.pswd != '':
                instance.save(instance.conf)


class Password(object):
    secret = Secret()

    def __init__(self, name, session=None):
        self.pswd = None
        self.name = name
        self.session = session

    def getUser(self):
        try:
            user = self.session['logged_in']
        except Exception:
            user = 'secret'
        return user

    def simpleHash(self, s):
        import ctypes
        v = ord(s[0]) << 7
        for c in s:
            v = ctypes.c_int32((int(1000003) * v) & 0xffffffff).value ^ ord(c)
        v = v ^ len(s)
        if v == -1:
            v = -2
        return int(v)

    def clear(self):
        self.pswd = None

    def load(self, conf):
        """ Load from the secure storage
        """
        self.conf = conf
        # Must load from scratch as the secret is per-user and should not leak
        self.clear()
        try:
            if not conf._isEnabled('qradar'):
                raise ImportError('Skip qpylib for LSS debug')

            from qpylib.encdec import Encryption, EncryptionError
            try:
                self.pswd = Encryption({'name': self.name, 'user': self.simpleHash(self.getUser())}).decrypt()
            except EncryptionError:
                pass
        except ImportError:
            # TODO Implement for LSS app
            pass

    def save(self, conf):
        """ Save to the secure storage
        """
        try:
            if not conf._isEnabled('qradar'):
                raise ImportError('Skip qpylib for LSS debug')

            from qpylib.encdec import Encryption, EncryptionError
            try:
                Encryption({'name': self.name, 'user': self.simpleHash(self.getUser())}).encrypt(self.pswd)
            except EncryptionError:
                pass
        except ImportError:
            # TODO Implement for LSS app
            pass


# MERGE env.py


# Use os.path.abspath() if ever wish running standalone on Windows
datapath = os.path.join(os.sep, 'store', '')
loggingpath = os.path.join(datapath, 'app.log')

# Additional relative path to look for for the initial configs (usually in the container)
confpath = None


def isOptDir(name):
    """ Need this to support multiple platform installations on the same instance
    """
    return os.path.join(os.sep, 'opt', name, '') in __file__


def initDataPath():
    global datapath
    global confpath

    # NOTE To the curious minds wondering about the purpose of the if/all()/any()/lambda constructs used throughout the code:
    #      It's used to satisfy conflicting flake8 requirements among different platforms while keeping the LAZY evaluation.
    #      Specifically, the W504 warning and its ilk. IMO these warnings are excercises in hair splitting and pure evil, they
    #      should have never been put in the warning category to begin with (de facto the error category for the purpose of the
    #      mandatory certification lint scans). BTW, it wouldn't be so bad if not for the confusion between flake8's 'ignore' and
    #      'extend-ignore' statements, the former being misused by some environments thus inadvertently activating the
    #      conflicting options.

    # For Splunk - read-only forward.json (just for the extra options) as the Save button saves to appsetup.conf
    # Also, the local/ folder will be empty (the contents are moved over to default/ by the addon builder)
    if all(a() for a in [lambda: 'SPLUNK_HOME' in os.environ,
                         lambda: isOptDir('splunk')]):
        datapath = os.path.join(os.environ['SPLUNK_HOME'], 'etc', 'apps', 'bitglass', 'default', '')

    # NOTE: To support upgrades properly, check the newest stuff first!

    # New QRadar >= 7.4 app
    elif all(a() for a in [lambda: os.path.isdir(os.path.join(os.sep, 'opt', 'app-root', '')),
                           lambda: isOptDir('app-root')]):
        datapath = os.path.join(os.sep, 'opt', 'app-root', 'store', '')
        confpath = '../container/conf'

        # NOTE Not needed as we have the app object exported from __init__.py as well (any object name will do in fact)
        # Have to Set up magic environment variables to keep it backwards-compatible with QRadar 7.3.x
        # os.environ['FLASK_APP'] = 'app.flaskinit:application'
        if 'FLASK_APP' not in os.environ:
            os.environ['FLASK_APP'] = 'app'

        if 'QRADAR_CONSOLE_IP' not in os.environ:
            # To prevent an exception (new QRadar behavior) when the var is not set in dev container
            os.environ['QRADAR_CONSOLE_IP'] = '127.0.0.1'

    # Standalone Bitglass app
    elif all(a() for a in [lambda: os.path.isdir(os.path.join(os.sep, 'opt', 'bitglass', 'store', '')),
                           lambda: isOptDir('bitglass')]):
        datapath = os.path.join(os.sep, 'opt', 'bitglass', 'store', '')


def UpdateDataPath(newpath):
    """ The app calls this to override for the paths that include container uuids
    """
    global datapath

    res = (datapath != newpath)
    datapath = newpath
    return res


def UpdateLoggingPath(defaultlogfolder=None):
    global loggingpath

    if all(a() for a in [lambda: 'SPLUNK_HOME' in os.environ,
                         lambda: isOptDir('splunk')]):
        loggingpath = os.path.join(os.environ['SPLUNK_HOME'], 'var', 'log', 'splunk', 'bitglass.log')
    # Can't use PHANTOM_LOG_DIR (not defined), /opt/phantom/var/log/phantom/apps is missing on the OVA too
    # (the latter uses /opt/phantom...) and would have to create bitglass/ directory in either anyways..
    # TODO Should probably read 'appid' from bitglass.json
    elif all(a() for a in [lambda: os.path.isdir(os.path.join(os.sep, 'opt', 'phantom', 'local_data', 'app_states',
                                                 '8119e222-818e-42f5-a210-1c7c9d337e81', '')),
                           lambda: isOptDir('phantom')]):
        loggingpath = os.path.join(os.sep, 'opt', 'phantom', 'local_data', 'app_states', '8119e222-818e-42f5-a210-1c7c9d337e81',
                                   'bitglass.log')
    # Deployed LSS instance
    elif all(a() for a in [lambda: os.path.isdir(os.path.join(os.sep, 'var', 'log', 'bitglass', '')),
                           lambda: isOptDir('bitglass')]):
        loggingpath = os.path.join(os.sep, 'var', 'log', 'bitglass', 'app.log')
    # New QRadar >= 7.4 app
    elif all(a() for a in [lambda: os.path.isdir(os.path.join(os.sep, 'opt', 'app-root', '')),
                           lambda: isOptDir('app-root')]):
        loggingpath = os.path.join(os.sep, 'opt', 'app-root', 'store', 'log', 'app.log')
    else:
        if defaultlogfolder:
            loggingpath = os.path.join(defaultlogfolder, 'log', 'app.log')
        else:
            loggingpath = os.path.join(datapath, 'app.log')

    # Phantom logs to /var/log/phantom/spawn.log
    # Can detect the version with 'cat /opt/phantom/etc/settings.json | grep phantom_version'
    return loggingpath


try:
    # Some platforms like Demisto run code from a string where __file__ is not defined (and file i/o is not defined either)
    initDataPath()
    UpdateLoggingPath()
except Exception:   # nosec
    # May or may not get here for such platforms
    pass    # nosec


if PY2:
    from urllib2 import HTTPError as HTTPException  # pylint: disable=E0401
else:
    from urllib.error import HTTPError as HTTPException     # noqa


# MERGE config.py

def versionTuple(v):
    return tuple(s.zfill(8) for s in v.split("."))


# Need to load json properly in PY2
def byteify(inp):
    if isinstance(inp, dict):
        # Can't use dict comprehension in 2.6 (the version on QRadar box as of 7.3)
        return dict([(byteify(key), byteify(value)) for key, value in iteritems(inp)])
        # return {byteify(key): byteify(value) for key, value in inp.items()}
    elif isinstance(inp, list):
        return [byteify(element) for element in inp]
    elif isinstance(inp, string_types):
        if PY2:
            return inp.encode('utf-8')
        else:
            return inp
    else:
        return inp


# Convert the object to dict for saving to json
def to_dict(obj):
    # Some platforms like Demisto use custom Python build which ends up putting any custom class into 'builtins'
    # HACK Work around the above limitation by a naive check for simple type names ever used in the config data (json)
    #      This assumes __class__ field holds "<class 'name'>". Assume the following builtin types:
    #      bool, int, float, str, list, dict
    # mod = obj.__class__.__module__
    # if mod not in ['builtins', '__builtin__']:
    tname = str(obj.__class__)[8:-2]
    if tname not in ['bool', 'int', 'float', 'str', 'list', 'dict']:
        # TODO Check for methods and classes to exclude them and get rid of the underscore in their names
        # Can't use dict comprehension in 2.6 (the version on QRadar box as of 7.3)
        return dict([(key, to_dict(getattr(obj, key)))
                    for key in dir(obj) if not key.startswith('_') and 'status' not in key])
        # return {key: to_dict(getattr(obj, key))
        #         for key in dir(obj) if not key.startswith('_') and 'status' not in key}

    if type(obj).__name__ == 'list':
        return [to_dict(el) for el in obj]
    else:
        return obj


# Thread operation status to report to UI
class Status:
    def __init__(self):
        self.lastRes = None
        self.lastMsg = 'In progress'
        self.lastLog = '{}'
        self.lastTime = datetime.utcnow()
        self.cntSuccess = 0
        self.cntError = 0
        self.updateCount = 0

    def ok(self):
        return self.lastMsg == 'ok'


# Need this hack because this ancient Jinja 2.7.3 version used by QRadar
# doesn't have the simple 'in' built-in test! Not even 'equalto'!!
class Feature:
    def __init__(self, name):
        setattr(self, name, True)

    def __getitem__(self, item):
        return getattr(self, item)


@contextmanager
def tempfile(filepath, mode, suffix=''):
    undersplunk = False
    if undersplunk:
        # For Splunk, the run environment is managed by Splunk so there is no need in temp files to sync writes
        # The cloud certification reports 'file operation outside of the app directory' etc. but this is mistaken
        # To be on the safe side, have the temp file code disabled since it's not needed under Splunk anyways
        yield filepath
        return

    import tempfile as tmp

    ddir = os.path.dirname(filepath)
    tf = tmp.NamedTemporaryFile(dir=ddir, mode=mode, delete=False, suffix=suffix)
    tf.file.close()     # type: ignore[attr-defined]
    yield tf.name

    try:
        os.remove(tf.name)
    except OSError as e:
        if e.errno != 2:
            raise e


@contextmanager
def open_atomic(filepath, mode, **kwargs):
    with tempfile(filepath, mode=mode) as tmppath:
        with open(tmppath, mode=mode, **kwargs) as file:
            yield file
            file.flush()
            os.fsync(file.fileno())
        if tmppath != filepath:
            os.rename(tmppath, filepath)


class Config(object):
    version = '1.0.12'
    _api_version_min = '1.0.7'
    _api_version_max = '1.1.5'
    _default = None

    _flags = dict(
        logging_level=('-l',
                       'loglevel field, defaults to WARNING, options are: CRITICAL, ERROR, WARNING, INFO, DEBUG'),
        featureset=('-f',
                    'featureset (SIEM/SOAR platform name), defaults to unknown with no file i/o available, options are: debug,'
                    'bitglass, qradar, splunk, phantom, demisto'),
    )

    def _genOptions(self):
        p = optparse.OptionParser()
        # for k, f in self._flags.items():
        for k, f in iteritems(self._flags):
            p.add_option(
                f[0],
                '--' + (k if k[0] != '_' else k[1:]),
                dest=k,
                # Default password is '' rather than default password object to keep plain comparisons working in general case
                default=getattr(self._default, k) if f[0] not in ['-a', '-k'] else '',
                help=f[1])
        return p

    def _applyOptionValue(self, name, value, current, default, secret):
        if value == current:
            return

        if value == default:
            app.logger.info('Ignored override with implicit default of config param "%s" of:\n%s' %
                            (name, str(getattr(self, name))))
            return

        app.logger.info('Overriding config param %s with:\n%s' % (name, str(value)))
        if current != default:
            app.logger.info('\t- double override of config param "%s" of:\n%s' %
                            (name, str(getattr(self, name))))
        if secret is None:
            setattr(self, name, value)
        else:
            secret.secret = value

    def _applyOptionsOnce(self, opts=None):
        # No validation is done on command line options letting it fail wherever..
        # It's not too bad as long as no corrupted data is saved
        # TODO Do validation (borrowing from UI code??).. make sure it's never saved for now
        # HACK Reuse _save method as flag
        if self._save is None:
            return ''
        self._save = None   # type: ignore[assignment]

        if opts is None:
            # Unless need to parse the remaining arguments..
            opts, args = self._genOptions().parse_args()
            if len(args) > 0:
                app.logger.warning('Ignored unknown options "%s"' % str(args))
        else:
            args = ''

        # If something bad happens, the config may be half-set but it's OK since it's never saved
        # for k, f in self._flags.items():
        for k, f in iteritems(self._flags):
            p = getattr(opts, k)
            # HACK Check for patterns in help string to additionally parse into list etc.
            if f[0] == '-f':
                if isinstance(p, str):
                    p = [{p: True}]
            elif ':]' in f[1]:
                if isinstance(p, str):
                    p = p.split(':')
                p.sort()
            elif ', seconds' in f[1]:
                if isinstance(p, str):
                    p = int(p)
            if 'password' in f[1] or 'token' in f[1]:
                s = getattr(self, k)
                v = getattr(self, k).secret
                d = getattr(self._default, k).secret
            else:
                s = None
                v = getattr(self, k)
                d = getattr(self._default, k)

            self._applyOptionValue(k, p, v, d, s)

        # TODO Only after validation
        self._calculateOptions()    # type: ignore[attr-defined]    # pylint: disable=E1101

        return args

    def _getvars(self):
        return vars(self)

    def _loadFile(self, fname):
        d = {}
        if self._context is not None:
            name = os.path.basename(fname)
            d = (json.loads(self._context[name])
                 if isinstance(self._context[name], str)
                 else self._context[name]) if name in self._context else {}
        else:
            with open(fname, 'r') as f:
                # d = json.load(f)
                d = byteify(json.load(f))

        if d:
            # for key, value in d.items():
            for key, value in iteritems(d):
                setattr(self, key, value)
                # if 'config.json' in fname:
                #     app.config[key] = value

    def _load(self, fname):
        if fname is None:
            return

        errMsg = 'Could not load last configuration %s across app sessions: %s'

        try:
            self._loadFile(fname)
        except Exception as ex:
            if confpath:
                # Initial config data is kept in a separate (container) directory
                try:
                    fname = os.path.join(os.path.dirname(fname), confpath, os.path.basename(fname))
                    self._loadFile(fname)
                except Exception as ex:
                    app.logger.info(errMsg % (fname, ex))
            else:
                app.logger.info(errMsg % (fname, ex))

    def _deepcopy(self):

        # Secrets contain the session inside to tie them to the user
        auth_token = self._auth_token   # type: ignore[has-type]    # pylint: disable=E0203
        password = self._password       # type: ignore[has-type]    # pylint: disable=E0203
        proxies_pswd = self._proxies_pswd   # type: ignore[has-type]    # pylint: disable=E0203
        self._auth_token = None
        self._password = None
        self._proxies_pswd = None

        session = self._session     # type: ignore[has-type]
        self._session = None
        cp = copy.deepcopy(self)
        self._session = session

        self._auth_token = auth_token
        self._password = password
        self._proxies_pswd = proxies_pswd
        cp._auth_token = auth_token
        cp._password = password
        cp._proxies_pswd = proxies_pswd
        return cp

    def __init__(self, fname=None, session={}, context=None):

        self._folder = datapath
        self._fname = os.path.join(self._folder, fname) if fname else None
        self._context = context
        self._isDaemon = True

        # Assume there is no file system to read from for unknown platform
        self.featureset = []

        self.logging_level = 'WARNING'

        self.updateCount = 0

        # Latest update count when any settings changed. It will be compared to the message update count.
        # When the message update count is at least this, it will be printed in color (vs. in a pop up of
        # 'In progress' status entry, because the message is stale in regards to the most recent settings)
        self.updateCountChanged = 0

        if self._default is None:
            self._default = copy.deepcopy(self)

        self._load(self._fname)

        # Read/override common config properties, read-only - never saved
        # TODO Optimize by reading only once for all config objects
        self._load(os.path.join(self._folder, 'config.json'))

        if versionTuple(self.version) >= versionTuple('1.0.13'):
            self.featureset += [{'health': True}]

        # NOTE Crashes when gets called before active request available (
        # Copy relevant session data so it's available to any page/form
        # self._session = {}
        # sessionKeys = ['logged_in']
        # for k in sessionKeys:
        #     if k in session:
        #         self._session[k] = session[k]
        self._session = session

    @contextmanager
    def _lock(conf, condition, notify=True):    # pylint: disable=E0213 # TODO Switch conf to self
        if condition is not None:
            condition.acquire()
        yield conf
        if notify:
            conf.updateCount = conf.updateCount + 1
        if condition is not None:
            if notify:
                condition.notify()
            condition.release()
        elif notify:
            conf.status['updateCount'] = conf.updateCount   # type: ignore[attr-defined]    # pylint: disable=E1101

    def _isEnabled(self, featureName):
        for f in self.featureset:
            if hasattr(f, '__dict__'):
                if featureName in f.__dict__:
                    return True
            else:
                if featureName in f:
                    return True
        return False

    def _isNoConfigStore(self):
        return self.featureset == []

    def _isForeignConfigStore(self):
        return self._isNoConfigStore() or not (self._isEnabled('qradar') or self._isEnabled('bitglass'))

    def _save(self):    # pylint: disable=E0202
        if self._fname is None:
            # Nothing to save (just config.json - read-only)
            return

        try:
            d = to_dict(self)
            # Exclude base properties (assumed read-only)
            if type(self).__name__ != 'Config':
                vs = vars(Config())
                for el in list(d.keys()):
                    if el in vs:
                        del d[el]
            # Exclude properties with default values
            for el in list(d.keys()):
                if hasattr(self._default, el) and d[el] == getattr(self._default, el):
                    del d[el]
            if len(d) > 0:
                if self._context is not None:
                    name = os.path.basename(self._fname)
                    self._context[name] = json.dumps(d, sort_keys=False)
                    self._context.save()
                else:
                    # Protect against writing from multiple sessions
                    with open_atomic(self._fname, 'w') as f:
                        json.dump(d, f, indent=2, sort_keys=False)
        except Exception as ex:
            app.logger.warning('Could not save last configuration %s across app sessions: %s' % (self._fname, ex))

    def _waitForStatus(self, secs):
        interval = 0.5
        for _ in range(int(secs / interval)):
            if self.status['updateCount'] >= self.updateCount:  # type: ignore[attr-defined]    # pylint: disable=E1101
                break
            time.sleep(interval)

    def _updateAndWaitForStatus(self, condition, rform):
        return False

    def _matchHost(self, h):
        # '^(?:(?!(?:10|127)(?:\.\d{1,3}){3})(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})(?!172\.(?:1[6-9]|2\d|3[0-1])'
        #   '(?:\.\d{1,3}){2})(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5]))'
        #   '{2}(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))\.|(?:(?:[a-z_-][a-z0-9_-]{0,62})?[a-z0-9]\.)+(?:[a-z]{2,}\.?)?)$'
        return re.match(
            r'^(?:'      # FIXED Added ^
            # IP address exclusion
            # private & local networks
            # FIXED: Commented out to allow private and local
            #   r'(?!(?:10|127)(?:\.\d{1,3}){3})'
            #   r'(?!(?:169\.254|192\.168)(?:\.\d{1,3}){2})'
            #   r'(?!172\.(?:1[6-9]|2\d|3[0-1])(?:\.\d{1,3}){2})'
            # IP address dotted notation octets
            # excludes loopback network 0.0.0.0
            # excludes reserved space >= 224.0.0.0
            # excludes network & broadcast addresses
            # (first & last IP address of each class)
            # TODO Figure out if need keeping any of those excluded
            r'(?:[1-9]\d?|1\d\d|2[01]\d|22[0-3])'
            r'(?:\.(?:1?\d{1,2}|2[0-4]\d|25[0-5])){2}'
            r'(?:\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4]))'
            r'\.|'    # FIXED original u"|", this is a trick to match 'localhost' by appending '.'
            # host & domain names, may end with dot
            r'(?:'
            r'(?:'
            # r'[a-z0-9\u00a1-\uffff]'
            # r'[a-z0-9\u00a1-\uffff_-]{0,62}'
            # FIXED original u"[a-z0-9_-]", allowing digits in the first position
            # discards all ip matching before (like disallowing 127.x.x.x)
            r'[a-z_-]'
            r'[a-z0-9_-]{0,62}'
            r')?'
            # r'[a-z0-9\u00a1-\uffff]\.'
            r'[a-z0-9]\.'
            r')+'
            # TLD identifier name, may end with dot
            # r'(?:[a-z\u00a1-\uffff]{2,}\.?)"
            r'(?:[a-z]{2,}\.?)?'     # FIXED Made it optional by appending '?' to support 'localhost'
            r')$',                   # FIXED Added $
            h + '.', re.I)           # FIXED Append '.'


startConf = Config()


def setPythonLoggingLevel(logger, conf=startConf):
    """ Set/override python logging level from the config
    """

    if startConf._isNoConfigStore():
        return 0

    numeric_level = getattr(logging, conf.logging_level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('Invalid log level: %s' % conf.logging_level)

    logger.setLevel(numeric_level)
    for hdlr in logger.handlers:
        hdlr.setLevel(numeric_level)

    # Should have it as warning so it's visible by default but.. don't want to overflow the log
    # when it's run periodically as a command..
    logger.info('~~~ LOGGING ENABLED AT LEVEL: %s ~~~' % conf.logging_level)
    return numeric_level


def setPythonLogging(logger=None, defaultlogfolder=startConf._folder):
    """ Set python logging options for a script (vs. a Flask app)
    """

    if startConf._isNoConfigStore():
        # TODO Use similar solution for Phantom (currently, all standard python logging is ignored as if sent to null device)
        # Currently, this crude solution (without levels) is for Demisto
        return app.Logger(nop=LOG)      # noqa

    filename = UpdateLoggingPath(defaultlogfolder)

    if startConf._isEnabled('qradar'):
        # Create logger wrapping qpylib API + Flask
        from app.flaskinit import log, set_log_level    # pylint: disable=E0401
        return app.Logger(startConf, log, set_log_level)

    # Grab the logger object
    addStderr = False
    if logger is None:
        # Create one instead of borrowing the Flask one. Create stderr handler instead of the Flask one
        addStderr = True
        logger = logging.getLogger('com.bitglass.lss')

    # This enables werkzeug logging
    # logging.basicConfig(filename=, level=)

    # Set default logging level from config
    numeric_level = setPythonLoggingLevel(logger)

    # Show thread and full path with INFO and up
    fmt = """%(asctime)s [%(filename)s:%(lineno)d] [%(levelname)s]\n\t%(message)s"""
    if numeric_level <= logging.INFO:
        fmt = """%(asctime)s,%(msecs)d [%(pathname)s:%(lineno)d] [%(thread)d] [%(levelname)s]\n\t%(message)s"""

    # Log to bitglass.log file
    fh = logging.FileHandler(filename=filename)
    fh.setLevel(numeric_level)

    formatter = logging.Formatter(
        fmt,
        '%Y-%m-%d %H:%M:%S'
    )
    fh.setFormatter(formatter)
    logger.addHandler(fh)

    if addStderr:
        # Log to STDERROR as well since it's run as a cli script
        sh = logging.StreamHandler(sys.stderr)
        sh.setLevel(numeric_level)

        # Stderr may be loaded into SIEMs like Splunk etc. so careful changing the format
        formatterStderr = formatter
        sh.setFormatter(formatterStderr)
        logger.addHandler(sh)
        logger.info('~~~ Running in CLI mode (Python logging set) ~~~')

    return logger


# MERGE configForward.py


try:
    from flask import session
except ImportError:
    session = {}


sources = [
    ('invalid.xyz', 'Bearer', ''),
    ('invalid.xyz', 'Basic', ''),
]

log_types = [
    GC_LOGTYPE_CLOUDAUDIT,
    GC_LOGTYPE_ACCESS,
    GC_LOGTYPE_ADMIN,
    GC_LOGTYPE_CLOUDSUMMARY,

    GC_LOGTYPE_SWGWEB,
    GC_LOGTYPE_SWGWEBDLP,

    GC_LOGTYPE_HEALTHPROXY,
    GC_LOGTYPE_HEALTHAPI,
    GC_LOGTYPE_HEALTHSYSTEM,
]


class ConfigForward(Config):

    #
    # Old flags delta for reference
    #

    # p = optparse.OptionParser("usage: %prog [options]")

    # Not implemented yet.. why need it?
    # p.add_option(
    #     "-o",
    #     "--host", dest="host", default='localhost', help='hostname or ip address for splunk host, defaults to localhost')
    # p.add_option(
    #     "-p",
    #     "--port", dest="port", type='int', default=9200, help='TCP or UDP port for splunk host, defaults to 9200')

    # ??
    # p.add_option(
    #     "-i",
    #     "--index", dest="index", default=None, help='Json file with index details, defaults to None')

    # fixed
    # p.add_option(
    #     "-v",
    #     "--version", dest="version", default='1.1.0', help='api version field, defaults to 1.1.0')
    # only json
    # p.add_option(
    #     "-d",
    #     "--dataformat", dest="dataformat", default='json', help='requested api dataformat, json or csv, defaults to json')
    # -r :port does it
    # p.add_option(
    #     "-P",
    #     "--Port", dest="Port", type='int', default=0, help='TCP or UDP port for syslog daemonized listening, defaults to 0"
    #       " - skip and exit'")
    # not used, no buffering
    # p.add_option(
    #     "-e",
    #     "--eps", dest="eps", type='int', default=500, help='events per second, if set to a value larger then 0 throttling"
    #       " will be applied, defaults to 500'")

    # Command line flags to override properties
    Config._flags.update(dict(
        customer=('-c',
                  'customer field, defaults to Bitglass'),
        api_url=('-r',
                 'url for portal access or syslog ":port" to listen on, required'),
        sink_url=('-n',
                  'send output messages over url, TCP socket, UDP syslog (default "0.0.0.0:514") or stdout'),
        log_types=('-t',
                   'logtype field "[access:][admin:][cloudaudit:][swgweb:][swgwebdlp:][healthproxy:][healthapi:]'
                   '[healthsystem:]cloudsummary"'),
        _username=('-u',
                   'user name for portal access'),
        _password=('-k',
                   'password for portal access'),
        # extra
        _auth_token=('-a',
                     'OAuth 2 token for portal access'),
        log_interval=('-d',
                      'log interval, seconds'),
        log_initial=('-i',
                     'log initial period, seconds'),
        # - TODO proxies, reset_time
    )
    )

    def __init__(self, context=None):

        self.status = {'updateCount': 0, 'last': Status()}
        for log_type in log_types:
            self.status[log_type] = Status()

        # Can't keep it here b/c of deepcopying
        # self._condition = condition

        # Load some (useful) hard-coded defaults
        source = 0
        self._auth_type = False
        self._use_proxy = False
        self.host = sources[source][0]
        self.api_ver = self._api_version_max
        self.auth_type = sources[source][1]
        self._auth_token = Password('auth_token')
        self._username = ''
        self._password = Password('password')
        self._proxies_pswd = Password('proxies_pswd')
        #
        self.log_types = [log_types[0]]
        self.log_interval = 900
        # self.api_url        = 'https://portal.us.%s/api/bitglassapi/logs/' % self.host
        self.api_url = ''
        self.proxies = None
        self.sink_url = 'localhost:514'

        h, p = self.sink_url.split(':') if ':' in self.sink_url else (self.sink_url, '514')
        self._syslogDest = (h, int(p))

        # Additional params not in the UI. Don't save for now
        self.log_initial = 30 * 24 * 3600
        self._max_request_rate = 10

        # Last log reset..
        # It's reset automatically back to the default upon use. Never persist (starts with underscore)!
        self._reset_time = ''
        # Empty the contents of lastlog files just short of deleting the files (vs. resetting the 'time' field to preserve
        # the other data for easy troubleshooting)
        self.hardreset = True
        # Used only by x_*.py modules' code where an alternative config store is used without the read-once-reset-to-default
        # functionality like Splunk
        self.reset_fence = ''

        # Additional (optional) settings, not exposed in the UI for now
        self.verify = True
        self.customer = 'Bitglass'
        self.useNextPageToken = True

        self.postTimeoutChanged = 30

        # Refresh timeout (0 - no waiting by default unless some settings changed - see the param above)
        self.postTimeoutRefresh = 0

        super(ConfigForward, self).__init__('forward.json', session, context)

        # Clobber unsupported log types by app version to allow for testing new types before releasing officially
        # if False:     # For testing
        if not self._isEnabled('health'):
            for lt in ['healthproxy', 'healthapi', 'healthsystem']:
                if lt in self.log_types:
                    self.log_types.remove(lt)

        # Provide session after the defaults have been deep-copied
        self._auth_token = Password('auth_token', session)
        self._password = Password('password', session)
        self._proxies_pswd = Password('proxies_pswd', session)

        # Cut down requests for debugging
        if self._isEnabled('debug'):
            self.log_initial = 7 * 24 * 3600

        # Load secrets (if managing secure storage)
        if all(a() for a in [lambda: not self._isEnabled('splunk'),
                             lambda: not self._isEnabled('phantom'),
                             lambda: not self._isEnabled('demisto')]):
            self._auth_token.load(self)
            self._password.load(self)
            self._proxies_pswd.load(self)

        # Sort any lists so can rely on bulk comparison
        self.log_types.sort()

    # From param dict to canonical string to load to UI, assume username never
    # contains \' and no ', ' in either the username or password
    def _printProxies(self, proxies):
        return str(proxies)\
            .replace('\': ', '\'=')\
            .replace(', ', '\n')\
            .replace("'", '')\
            .replace('"', '')\
            .replace('{', '')\
            .replace('}', '')\
            if proxies is not None else ''

    # From user multi-string to detailed dict list
    def _parseProxies(self, s):
        proxies = {}    # type: ignore[var-annotated]
        if s == '':
            return proxies

        pxs = s.replace('\r', '').split('\n')
        for p in pxs:
            # Skip all-whitespace lines
            if p.replace(' ', '') == '':
                continue

            proxy = {}
            try:
                # TODO Handle unicode data properly

                # Either = or : assignment, quotes are optional, username, password and port are optional
                #
                # 'nttps=nttps;\\user;pass a*t 127 d*t 0 d*t 0 d*t 1;9999'
                #
                # '^"?(https?|ftp)"?[ ]*(?:\=|\:)[ ]*"?(https?|socks5)\:\/\/(?:([a-zA-Z][-\w]*)(?:\:(\S*))?@)?([^\:]+)(?:\:'
                #   '([0-9]{2,5}))?"?$'
                v = re.split(
                    r'^'
                    # schema
                    r'(?:"?(https?|ftp)'
                    r'"?[ ]*(?:\=|\:)[ ]*)?"?'
                    # schema_p
                    r'(https?|socks5)\:\/\/'
                    # user + pswd (optional, must not contain ":@ )
                    r'(?:([a-zA-Z][-\w]*)(?:\:(\S*))?@)?'
                    # host
                    r'([^\:]+)'
                    # port (optional)
                    r'(?:\:([0-9]{2,5}))?"?'
                    r'$', p.strip())

                start = v[0]
                schema = v[1]
                schema_p = v[2]
                user = v[3] if v[3] is not None else ''
                pswd = v[4] if v[4] is not None else ''
                host = v[5]
                port = v[6] if v[6] is not None else ''
                end = v[7]

                if schema is None:
                    schema = 'https'

                if schema in proxies:
                    raise BaseException('Duplicate proxy entry for protocol %s' % schema)

                if start != '' or end != '':
                    raise BaseException('Bad proxy expression')

                # Validate host separately
                if not self._matchHost(host):
                    raise BaseException('Bad host name "%s" in proxy expression' % host)

                if int(port) < 0 or int(port) > 65535:
                    raise BaseException('Bad port number in proxy expression')

                proxy = {'schema_p': schema_p, 'user': user, 'pswd': pswd, 'host': host, 'port': port}
                proxies[schema] = proxy
            except Exception as ex:
                raise BaseException('Bad proxy expression %s' % str(ex))
            except BaseException as ex:
                raise ex
        return proxies

    # From user multi-string to param dict
    def _getProxies(self, s):
        proxies = {}
        proxies_pswd = ''
        pxd = self._parseProxies(s)
        # for k, p in pxd.items():
        for k, p in iteritems(pxd):
            v = '%s://%s:%s@%s:%s' % (p['schema_p'], p['user'], p['pswd'], p['host'], p['port'])
            if v[-1] == ':':
                # Empty port
                v = v[0:-1]
            if ':@' in v:
                # Empty password
                v = v.replace(':@', '@')
            if '/:' in v:
                # Empty user
                v = v.replace(':@', '@')
                v = v.replace('/:', '/')

            # Keep the passwords as a concatenated string separately for saving to the secure storage
            # NOTE The dictionary insertion order is maintained in Python 3.6 and up (no need to use OrderedDict)
            # TODO ? Fix for PY2
            proxies[k] = '%s://%s@%s:%s' % (p['schema_p'], p['user'], p['host'], p['port'])
            proxies_pswd += (MULTI_PSWD_SEP_CHAR + p['pswd'])
        return (proxies, proxies_pswd[1:]) if proxies != {} else (None, None)

    @staticmethod
    def _mergeProxiesPswd(proxies, pswds):
        if proxies is None:
            return None

        ps = pswds.split(MULTI_PSWD_SEP_CHAR)
        return dict([(k, p.replace('@', ':' + ps[i] + '@')) for i, (k, p) in enumerate(iteritems(proxies))])
        # return {k: p.replace('@', ':' + ps[i] + '@') for i, (k, p) in enumerate(proxies.items())}

    def _getMergedProxies(self, s):
        proxies, pswd = self._getProxies(s)
        return ConfigForward._mergeProxiesPswd(proxies, pswd)

    def _updateAndWaitForStatus(self, condition, rform):
        # Get the user inputs (validated already)
        auth_token = str(rform['auth_token'])
        username = str(rform['username'])
        password = str(rform['password'])
        log_interval = int(rform['log_interval'])
        api_url = str(rform['api_url'])
        proxies, proxies_pswd = self._getProxies(str(rform['proxies']))
        sink_url = str(rform['sink_url'])

        # Override only the ones modified in the UI keeping the config ones in effect (if a different set)
        if PY2:
            # Membership 'in' operator fails unless same format (unlike ==)
            logTypes = [lt.decode('utf-8') for lt in self.log_types]
        else:
            logTypes = [lt for lt in self.log_types]

        for lt in [GC_LOGTYPE_ACCESS,
                   GC_LOGTYPE_ADMIN,
                   GC_LOGTYPE_CLOUDAUDIT,
                   GC_LOGTYPE_SWGWEB,
                   GC_LOGTYPE_SWGWEBDLP,
                   GC_LOGTYPE_HEALTHPROXY,
                   GC_LOGTYPE_HEALTHAPI,
                   GC_LOGTYPE_HEALTHSYSTEM,
                   GC_RESETTIME]:
            if len(rform.getlist(lt)):
                if lt == 'resettime':
                    reset_time = 'reset'
                else:
                    if lt not in logTypes:
                        logTypes += [lt]
            else:
                if lt == 'resettime':
                    reset_time = ''
                else:
                    if lt in logTypes:
                        logTypes.remove(lt)

        logTypes.sort()
        auth_type = len(rform.getlist('auth_type'))
        use_proxy = len(rform.getlist('use_proxy'))

        app.logger.info(str('POST %s %s %s %s' % ('auth_token', ', '.join(logTypes), log_interval, api_url)))

        # Assume update is needed if first time
        isChanged = True
        if all(a() for a in [lambda: self.updateCount > 0,
                             # Don't care b/c not saved anyways
                             # and self._auth_type == True if auth_type == 'on' or auth_type == 'True' else False
                             # and self._use_proxy == True if use_proxy == 'on' or use_proxy == 'True' else False
                             #
                             # Not saved but need to check authentication to update status
                             lambda: self._auth_token.secret == auth_token,  # type: ignore[union-attr]
                             lambda: self._username == username,
                             lambda: self._password.secret == password,          # type: ignore[union-attr]
                             lambda: self._proxies_pswd.secret == proxies_pswd,  # type: ignore[union-attr]
                             #
                             lambda: self.log_types == logTypes,
                             lambda: self.log_interval == log_interval,
                             lambda: self.api_url == api_url,
                             lambda: self.proxies == proxies,
                             lambda: self.sink_url == sink_url,
                             lambda: self._reset_time == reset_time]):
            # return False
            isChanged = False

        # Update the data under thread lock
        # Do it to signal the poll thread to refresh the logs, even if no settings changed
        isSaved = False
        with self._lock(condition):
            self._auth_type = auth_type in ['on', 'True']
            self._use_proxy = (use_proxy in ['on', 'True']) and proxies is not None
            self._auth_token.secret = auth_token    # type: ignore[union-attr]
            self._username = username
            self._password.secret = password            # type: ignore[union-attr]
            self._proxies_pswd.secret = proxies_pswd    # type: ignore[union-attr]
            self.log_types = logTypes
            self.log_interval = log_interval
            self.api_url = api_url
            self.proxies = proxies
            self.sink_url = sink_url
            self._reset_time = reset_time

            self._calculateOptions()

            # Since the polling thread might update some (rare) settings for certain integrations
            # like reset_fence, do the save under the lock (otherwise it wouldn't be necessary)
            if self._isForeignConfigStore() and isChanged:
                # Actually, should never end up here since for those cases
                # the saving is done by alternative client code to alternative config store
                self._save()    # pylint: disable=E1102
                isSaved = True

        if isChanged:
            # Need to save it for printing status on refresh correctly (relative to changes in settings rather than the latest
            # refresh)
            self.updateCountChanged = self.updateCount

            # Save across sessions without blocking on I/O
            if not isSaved:
                self._save()    # pylint: disable=E1102

            # Wait for the update to come through but only if there were changes as a compromise.
            # If there are no changes the page info likely won't be up-to-date to avoid the wait,
            # refreshing multiple times would get the "latest" status eventually.
            # The wait time is a context switch + up to 5 (number of log types) API requests
            # TODO JS: The status could be updated continuously in the background AJAX-style
            self._waitForStatus(self.postTimeoutChanged)
        else:
            # Disabled by default to reduce the confusion from excessive "In progress" status and
            # to avoid the additional wait from network and data processing latency on refresh
            if self.postTimeoutRefresh > 0:
                self._waitForStatus(self.postTimeoutRefresh)

        return isChanged

    def _parseApiUrl(self, url):
        badMatch = ''
        host = None
        api_ver = None

        m = re.search(r'https\:\/\/portal\.((?:us\.)?.+)\/api\/bitglassapi(?:\/(?:logs(?:\/(?:\?cv=(\d\.\d\.\d))?)?)?)?', url)
        if m is None:
            # TODO Do not require auth_token in syslog source case
            # Allow for localhost:514 etc. source but ONLY in LSS app
            if self._isEnabled('bitglass') or self._isEnabled('debug'):
                try:
                    isSyslog = ('://' not in url and len(url.split(':')) == 2)
                    if isSyslog:
                        host, port = url.split(':')
                        if all(a() for a in [lambda: self._matchHost(host),
                                             lambda: int(port) >= 0 and int(port) <= 65535]):
                            return (badMatch, host, api_ver)
                except Exception:
                    return (badMatch, host, api_ver)

            return (badMatch, host, api_ver)

        if m.end() < len(url):
            badMatch = url[m.end():]
            return (badMatch, host, api_ver)

        h = m.group(1)
        if h is not None and self._matchHost(h):
            host = h

        v = m.group(2)
        if v is not None:
            api_ver = v

        return (badMatch, host, api_ver)

    def _calculateOptions(self):
        _, host, api_ver = self._parseApiUrl(self.api_url)

        if host is not None:
            self.host = host

        if api_ver is not None:
            self.api_ver = api_ver
        else:
            # Restore to default
            self.api_ver = self._api_version_max

        addr_host, addr_port = self.sink_url.split(':')
        if all(a() for a in [lambda: '_qradarConsoleAddress' in self.__dict__,
                             lambda: any(b() for b in [lambda: addr_host == 'localhost',
                                                       lambda: addr_host == '127.0.0.1',
                                                       lambda: all(c() for c in [lambda: '.0.0.' in addr_host,
                                                                                 lambda: addr_host[0] == '0',
                                                                                 lambda: addr_host[-1] == '0',
                                                                                 lambda: len(addr_host) == 7])])]):
            # NOTE  ^^^ Workaround for a false security scan medium error
            #       instead of: addr_host == '0.0.0.0')):
            addr_host = self._qradarConsoleAddress      # type: ignore[attr-defined]    # pylint: disable=E1101
        self._syslogDest = (addr_host, int(addr_port))


# MERGE logevent.py


# Priority <xy> is already prepended by logging.handlers.emit()
SYSLOG_HEADER = '%s bitglass :%s'
# Feb 21 11:32:34
SYSLOG_HEADER_DATEFORMAT = '%b %d %H:%M:%S'

qradar_address = None
qradar_logger = None


def pushLog(d, address, logTime=datetime.utcnow()):
    """
    Push bg log event entry in json format to QRadar's syslog input
    """
    global qradar_address
    global qradar_logger
    if address != qradar_address:
        # NOTE Having 'QRadar' for the logger name below caused message payload leaks to log files through stdout
        # Also, make sure none of other handlers are called inadvertently
        qradar_logger = logging.getLogger('com.bitglass.lss')
        qradar_logger.propagate = False

        qradar_logger.setLevel(logging.INFO)
        handler = logging.handlers.SysLogHandler(address=address)
        qradar_logger.addHandler(handler)
        qradar_address = address

    msg = json.dumps(d)
    syslogMsg = SYSLOG_HEADER % (datetime.strftime(logTime, SYSLOG_HEADER_DATEFORMAT), msg)
    qradar_logger.info(syslogMsg)   # type: ignore[union-attr]

    return msg


"""
def main():
    args = sys.argv[1:]
    host = 'localhost'
    if len(args):
        host = args[0].strip()
    if host == 'localhost':
        # from app.qpylib import qpylib
        # host = qpylib.get_console_address()
        pass

    testPayload =\
        '{"pagetitle": "", "emailsubject": "", "action": "", "emailbcc": "", "filename": "", "application":'
    '"Bitglass", "dlppattern": "", "location": "Atlanta||Georgia||GA||US", "email": "nspringer@acme-gadget.com",'
    '"details": "Logged out.", "emailcc": "", "time": "25 Feb 2020 13:44:50", "emailfrom": "", "user": "Nate Springer",'
    '"syslogheader": "<110>1 2020-02-25T13:44:50.038000Z api.bitglass.com NILVALUE NILVALUE access",'
    '"device": "Mac OS X 10.15.3", "transactionid": "b862f16858171579ea8e6001848ed1d527f0daca [25 Feb 2020 13:44:50]",'
    '"ipaddress": "v.x.y.z", "url": "/accounts/server_logout/", "request": "", "activity": "Logout", "emailsenttime": "",'
    '"useragent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_3) AppleWebKit/537.36 (KHTML, '
        'like Gecko) Chrome/80.0.3987.122 Safari/537.36",'
    '"emailto": ""}'
    print (testPayload)     # noqa

    pushLog(testPayload, (host, 514))
    pushLog(testPayload, (host, 514))


if __name__ == '__main__':
    main()
"""


# MERGE logeventdaemon.py


conf = None
lastLogFile = None


# For now, just using the token, never need to get/refresh one automatically (by using requests_oauthlib)
class OAuth2Token(AuthBase):
    def __init__(self, access_token):
        self.access_token = access_token

    def __call__(self, request):
        request.headers['Authorization'] = 'Bearer {0}'.format(
            self.access_token
        )
        return request


def ingestLogEvent(ctx, d, address, logTime):
    if ctx and ctx.ctx is not None:
        ctx.ctx.bgPushLogEvent(d, address, logTime)

    # TODO Prevent recursion sending to itself with syslog socket
    return pushLog(d, address, logTime)


def flushLogEvents(ctx):
    if ctx and ctx.ctx is not None:
        ctx.ctx.bgFlushLogEvents()


def Initialize(ctx, datapath=datapath, skipArgs=False, _logger=None, _conf=None, context=None):
    global conf
    global lastLogFile

    # Monkey patch env.datapath first with the value from the command line to read bg json configs
    updatepath = False
    if datapath:
        updatepath = UpdateDataPath(datapath)

    if not app.logger and not _logger:
        app.logger = setPythonLogging(None, datapath)

    if not datapath:
        # Put in the same directory as the logging file (the latter would be well-defined, without uuids)
        datapath = os.path.split(loggingpath)[0] + os.sep
        updatepath = UpdateDataPath(datapath)
        if updatepath:
            conf = None

    if not conf or updatepath:
        if not _conf:
            conf = ConfigForward(context)
            # Be sure to update the logging level once the config is loaded
            setPythonLoggingLevel(app.logger, conf)

            if not skipArgs or conf._isEnabled('debug'):
                # Parse and apply command line options. Always process for a local dev run ('debug'), it's compatible
                conf._applyOptionsOnce()
        else:
            conf = _conf

    # Override the configuration
    if ctx and ctx.ctx is not None:
        # Override the config settings and disable daemon mode for explicit cli context
        ctx.ctx.bgLoadConfig(conf)
        conf._isDaemon = False  # type: ignore[union-attr]
    conf._calculateOptions()    # type: ignore[union-attr]

    if not lastLogFile or updatepath:
        cnf = _conf or conf

        # For Splunk app upgrade, manually 'cp lastlog.json ../local/' before upgrading to ingest incrementally
        # This is because it was saved in default/ in the previous version 1.0.8 and default/ is yanked during upgrade
        folder = cnf._folder    # type: ignore[union-attr]
        if (os.path.sep + 'default') in cnf._folder:    # type: ignore[union-attr]
            folder = os.path.join(folder, '..', 'local', '')

        lastLogFile = LastLog(os.path.join(folder, 'lastlog'), context)

    return conf


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    kwargs = None
    callback = None

    @classmethod
    def start(cls, callback, host, port=514, poll_interval=0.5, **kwargs):
        cls.kwargs = kwargs
        cls.callback = callback
        # TODO Test exception propagation to the main thread (due to a bad host?), may need handling
        try:
            server = socketserver.UDPServer((host, port), cls)
            server.serve_forever(poll_interval=poll_interval)
        except (IOError, SystemExit):
            raise
        except KeyboardInterrupt:
            app.logger.info("Crtl+C Pressed. Shutting down.")

    def handle(self):
        # logger = self.kwargs['logger']
        data = bytes.decode(self.request[0].strip())

        # Strip the string and convert to json
        try:
            conf = self.kwargs['conf']      # type: ignore[index]
            condition = self.kwargs['condition']    # type: ignore[index]

            s = u'%s :{' % conf.customer.lower()
            start = data.find(s) + len(s) - 1
            end = data.rfind(u'}') + 1
            logData = json.loads(u'{"response":{"data":[' + data[start:end] + u']}}')

            with conf._lock(condition, notify=False):
                transferLogs(None, logTypes=None, logData=logData, **self.kwargs)   # type: ignore[misc]  # pylint: disable=E1134

        except Exception as ex:
            app.logger.warning('{0}\n - Discarded bad event message in syslog stream:\n"{1}"\n- from sender {2}'.format(
                str(ex),
                data,
                self.client_address[0])
            )
            return


TIME_FORMAT_URL = '%Y-%m-%dT%H:%M:%SZ'
TIME_FORMAT_LOG = '%d %b %Y %H:%M:%S'
TIME_FORMAT_ISO = '%Y-%m-%dT%H:%M:%S.%fZ'


def strptime(s):
    # For more reliable (but slower) datetime parsing (non-English locales etc.) use:
    # pip install python-dateutil
    # from dateutil import parser
    # parser.parse("Aug 28 1999 12:00AM")  # datetime.datetime(1999, 8, 28, 0, 0)
    # '06 Nov 2018 08:15:10'

    return datetime.strptime(s, TIME_FORMAT_LOG)


class LastLog:
    def __init__(self, fname, context=None, shared=None, logtype=''):
        self.fname = '{0}-{1}.json'.format(fname, logtype) if shared else '{0}.json'.format(fname)
        self.shared = shared
        self.log = {}
        self.logtype = logtype
        self.subLogs = {}
        self.context = context
        try:
            if self.context is not None:
                # No file system, also may be flat (the old format). That's Demisto limitation so far
                self.log = (({logtype: json.loads(context[logtype])}
                             if isinstance(context[logtype], str)
                             else {logtype: context[logtype]})
                            if logtype in context
                            else {logtype: {}}) if self.shared else dict(context)
            else:
                with open(self.fname, 'r') as f:
                    self.log = byteify(json.load(f))
                    # self.log = json.load(f)

            if self.shared is None:
                # This is a shared (old) file (or string-only context). Convert to the new format if needed
                for lt in log_types:
                    if self.get(logtype=lt) and isinstance(self.log[lt], str):
                        self.log[lt] = json.loads(self.log[lt])
        except Exception as ex:
            app.logger.info('{0}\n - Last log file {1} not found'.format(str(ex), self.fname))
            lastLog = {}
            if self.shared:
                lastLog[logtype] = self.shared.log[logtype]
            else:
                for lt in log_types:
                    lastLog[lt] = {}
            self.log = lastLog

        # Create children one per log type unless sharing the same file for all
        if self.shared is None:
            for lt in log_types:
                self.subLogs[lt] = LastLog(fname, context, self, lt)

    def dump(self):
        try:
            if self.context is not None:
                # Don't assume it has to be converted to string, maybe some platform support nested context (unlike Demisto)
                # The save() method below will take care of that and merging different log types
                self.context[self.logtype] = self.log[self.logtype]
                self.context.save()
            else:
                with open_atomic(self.fname, 'w') as f:
                    json.dump(self.log, f, indent=4, sort_keys=True)
        except Exception as ex:
            app.logger.error('Could not save last log event across app sessions: %s' % ex)

    def get(self, field=None, logtype=None):
        if logtype is None:
            logtype = self.logtype
        elif logtype in self.subLogs:
            return self.subLogs[logtype].get(field)

        if logtype not in self.log or self.log[logtype] == {}:
            return False

        if field:
            ll = self.log[logtype]
            # Handle the old format to be forward compatible across upgrade
            res = json.loads(ll) if isinstance(ll, str) else ll
            return res[field] if field in res else None

        return True

    def getHistoricLogTypeList(self):
        return [lt for lt in log_types if self.get(logtype=lt)]

    def update(self, dtime, ll, logtype=None):
        if logtype is None:
            logtype = self.logtype
        elif logtype in self.subLogs:
            return self.subLogs[logtype].update(dtime, ll)

        if ll:
            # Add extra fields for diagnostics. Should not lag event log timestamp more than by the API polling interval
            ll[GC_FIELD_INGESTEDTIME] = datetime.utcnow().strftime(TIME_FORMAT_LOG)

            # For diagnostics purposes (for some weird cases of limited SIEM license issues or deployment irregularities etc.),
            # keep the earliest (initial) timestamp of past requests starting from the most recent reset (log rewind)
            # This way we can prove that the missing data is due to some SIEM platform vagary rather than our bug
            it = self.get('_initialtime', logtype)
            if it:
                # Copy over, this never changes unless logs get rewound
                ll[GC_FIELD_INITIALTIME] = it
            else:
                # This is the first successful save
                ll[GC_FIELD_INITIALTIME] = dtime.strftime(TIME_FORMAT_LOG)

            self.log[logtype] = ll
            self.dump()
        else:
            # This is a successful request with empty (exhausted) data so use the last one but handle the (corner) case
            # of error logged inbetween (coinsiding with app relaunch) by clearing the error entries if there are any
            if self.get(logtype=logtype):
                if self.get('_failedtime', logtype):
                    del self.log[logtype]['_failedtime']
                if self.get('_errormessage', logtype):
                    del self.log[logtype]['_errormessage']

        if logtype in self.log:
            return json.dumps(self.log[logtype])
        else:
            return ''

    def updateError(self, conf, errormsg, resettime, logtype=None):
        if logtype is None:
            logtype = self.logtype
        elif logtype in self.subLogs:
            return self.subLogs[logtype].updateError(conf, errormsg, resettime)

        if not self.get(logtype=logtype):
            self.log[logtype] = {}

        # Handle the corner case of never having a successful message ever yet so add the missing time
        # field to make the recovery possible (the data reading code defaults to 'now' in such case to
        # play it safe and avoid the possible data duplication but this leads to never getting
        # good messages unless by fluke of hitting upon a very recent message). Assume the initial
        # data period just the same as the reading code does when starting up.
        # This provides for an alternative hack to reset the log type: edit the file and rename the 'time' field.
        if not self.get('time', logtype) or resettime:
            if self.get('time', logtype):
                # Backup the original 'time' field if present by renaming it first
                self.log[logtype]['_time'] = self.log[logtype]['time']
            t = datetime.utcnow() + timedelta(seconds=-1 * conf.log_initial) if not resettime else resettime
            self.log[logtype]['time'] = t.strftime(TIME_FORMAT_LOG)

        # Update with failure timestamp and message, keep last ingested success timestamp
        self.log[logtype]['_failedtime'] = datetime.utcnow().strftime(TIME_FORMAT_LOG)
        self.log[logtype]['_errormessage'] = str(errormsg)
        self.dump()

    def clobber(self, resettime=None, logtype=None):
        # Clobbering the children with empty json {} is the simplest and most robust way to go.
        # Actually deleting the file would not be enough as the old format file persist, so
        # implementing it correctly would need atomically updating more than one file which would
        # complicate the code immensely and for Splunk, even the use of temp files is a potential
        # certification problem (although bogus one IMO)
        if logtype is None:
            logtype = self.logtype
        elif logtype in self.subLogs:
            return self.subLogs[logtype].clobber(resettime)

        # Just write bare braces (without adding the log type) keeping it simpler
        # self.log[logtype] = {}
        self.log = {}

        # The softer option of rolling back the time (provided by the UI already for flexibility)
        # TODO Ignore for the simplicity sake until the UI provides the actual reset time
        # if resettime:
        #     self.log[logtype] = {}
        #     self.log[logtype]['time'] = resettime.strftime(TIME_FORMAT_LOG)

        self.dump()


def isOldLogType(lt):
    """ Different data order (specific to the storage on the server), npt format etc.
    """
    return lt in [GC_LOGTYPE_ACCESS, GC_LOGTYPE_ADMIN, GC_LOGTYPE_CLOUDAUDIT, GC_LOGTYPE_CLOUDSUMMARY,
                  # Old APIs do return health* data (a bug) and npt is in the old format anyways!
                  GC_LOGTYPE_HEALTHPROXY, GC_LOGTYPE_HEALTHAPI, GC_LOGTYPE_HEALTHSYSTEM]


def getAPIToken(logData, conf, logType):
    if not conf.useNextPageToken:
        return None

    try:
        token = logData['nextpagetoken']
        d = json.loads(base64.b64decode(token))
    except Exception as ex:
        app.logger.warning('Invalid token returned: %s %s' % (token, ex))
        return None

    if d == {}:
        # Technically, it's an invalid token but this accompanies an empty data set
        return None

    if isOldLogType(logType):
        if 'log_id' not in d:
            app.logger.warning('No "log_id" encoded in logtype "%s" returned token: %s' % (logType, token))
            return None

        if 'datetime' not in d:
            app.logger.warning('No "datetime" encoded in logtype "%s" returned token: %s' % (logType, token))
            return None
    else:
        if 'start_time' not in d:
            app.logger.warning('No "start_time" encoded in logtype "%s" returned token: %s' % (logType, token))
            return None

        if 'end_time' not in d:
            app.logger.warning('No "end_time" encoded in logtype "%s" returned token: %s' % (logType, token))
            return None

        if 'page' not in d:
            app.logger.warning('No "page" encoded in logtype "%s" returned token: %s' % (logType, token))
            return None

    return token


SKIPPED_REQUEST_ERROR = 'UNAUTHORiZED'


def RestParamsLogs(_, host, api_ver, logType, npt, dtime):
    url = ('https://portal.' + host) if host else ''
    endpoint = '/api/bitglassapi/logs'

    # Adjust the version upwards to the minimum supported version for new log types as necessary
    # Make sure it's lower before overriding to avoid downgrading the version
    if logType in [GC_LOGTYPE_SWGWEB, GC_LOGTYPE_SWGWEBDLP]:
        if versionTuple(api_ver) < versionTuple('1.1.0'):
            api_ver = '1.1.0'
    elif logType in [GC_LOGTYPE_HEALTHPROXY, GC_LOGTYPE_HEALTHAPI, GC_LOGTYPE_HEALTHSYSTEM]:
        if versionTuple(api_ver) < versionTuple('1.1.5'):
            api_ver = '1.1.5'

    if npt is None:
        urlTime = dtime.strftime(TIME_FORMAT_URL)
        dataParams = '/?cv={0}&responseformat=json&type={1}&startdate={2}'.format(api_ver, str(logType), urlTime)
    else:
        dataParams = '/?cv={0}&responseformat=json&type={1}&nextpagetoken={2}'.format(api_ver, str(logType), npt)

    return (url, endpoint, dataParams)


def RestParamsConfig(_, host, api_ver, type_, action):
    url = ('https://portal.' + host) if host else ''

    # This is a POST, version is not a proper param, unlike in logs (?? for some reason)
    endpoint = '/api/bitglassapi/config/v{0}/?type={1}&action={2}'.format(api_ver, type_, action)
    return (url, endpoint)


def restCall(_,
             url, endpoint, dataParams,
             auth_token,
             proxies=None,
             verify=True,
             username=None,
             password=None):
    if dataParams is None:
        dataParams = ''

    # BANDIT    No, this is not a 'hardcoded password'. This is a check if any password supplied by the user.
    if auth_token is None or auth_token == '':  # nosec
        auth_type = 'Basic'

        # Must have creds supplied for basic
        if any(a() for a in [lambda: username is None or username == '',
                             lambda: password is None or password == '']):    # nosec
            # BANDIT    ^^^ No, this is not a 'hardcoded password'. This is a check if any password supplied by the user.
            # Emulate an http error instead of calling with empty password (when the form initially loads)
            # to avoid counting against API count quota
            raise HTTPException(url + endpoint, 401, SKIPPED_REQUEST_ERROR, {}, None)

        if PY2:
            auth_token = base64.b64encode(username + ':' + password)
        else:
            auth_token = base64.b64encode((username + ':' + password).encode('utf-8'))
            auth_token = auth_token.decode('utf-8')
    else:
        auth_type = 'Bearer'

    # Use requests by default if available
    r = None

    # The authentication header is added below
    headers = {'Content-Type': 'application/json'}

    d = {}
    with requests.Session() as s:
        if auth_type == 'Basic':
            s.auth = HTTPBasicAuth(username, password)
        else:
            s.auth = OAuth2Token(auth_token)

        if proxies is not None and len(proxies) > 0:
            if isinstance(proxies, dict):
                s.proxies = proxies
            elif proxies[1] is None:
                # Assume a tuple, no passwords provided (or merged in already) - nothing to merge
                s.proxies = proxies[0]
            else:
                # Assume a tuple and merge in the passwords
                s.proxies = ConfigForward._mergeProxiesPswd(proxies[0], proxies[1])

        if isinstance(dataParams, dict):
            # Assume json
            r = s.post(url + endpoint, headers=headers, verify=verify, json=dataParams)
        else:
            # TODO Inject failures (including the initial failure) for testing: raise Exception('test')
            r = s.get(url + endpoint + dataParams, headers=headers, verify=verify)

        r.raise_for_status()
        d = r.json()

    return d, r


def RestCall(_, endpoint, dataParams):
    return restCall(
        _,
        'https://portal.' + conf.host,  # type: ignore[union-attr]
        endpoint,
        dataParams,
        conf._auth_token.pswd,  # type: ignore[union-attr]
        (conf.proxies, conf._proxies_pswd.pswd),    # type: ignore[union-attr]
        conf.verify,    # type: ignore[union-attr]
        conf._username,     # type: ignore[union-attr]
        conf._password.pswd     # type: ignore[union-attr]
    )


def RestCallConfig(_, endpoint, dataParams):
    """ Do basic exception handling, just what is necessary for the Bitglass API for integration into SIEM
    """
    try:
        return RestCall(_, endpoint, dataParams)
    except Exception as ex:
        msg = 'Bitglass Config API: request %s(%s) failed with %s' % (endpoint, dataParams, ex)
        # Avoid polluting the log if no valid settings have been set yet
        if SKIPPED_REQUEST_ERROR not in msg:
            app.logger.error(msg)

        return {}, ex


def processLogEvents(ctx, conf, logType, data, nextPageToken, logTime, isSyslog):
    # Cover the case of reverse chronological order (in case of not reversing it back)
    lastLog = data[0]

    # Querying API data by 'time' field (not using nextpagetoken) is broken for 1.1.0 log types
    # swgweb and swgwebdlp causing overlaps. So disable the fallback path for them (no nextpagetoken)
    # No fix planned, so this workaround is a keeper
    isOldLt = isOldLogType(logType)
    if nextPageToken is None and not isOldLt and not isSyslog:
        raise ValueError('Invalid page token for swgweb* log types is not supported')

    for d in data[::-1 if strptime(data[0]['time']) > strptime(data[-1]['time']) else 1]:
        # In some new log types like swgweb the data are sorted from recent to older
        # So let's not assume chronological order to be on the safe side..
        tm = strptime(d['time'])

        # Inject logtype field, it's needed by QRadar Event ID definition (defined in DSM editor)
        if GC_FIELD_LOGTYPE not in d:
            d[GC_FIELD_LOGTYPE] = logType

        # NOTE Use logTime if QRadar has problems with decreasing time (as in swgweb and swgwebdlp)
        ingestLogEvent(ctx, d, conf._syslogDest, tm)

        d[GC_FIELD_NEXTPAGETOKEN] = nextPageToken if nextPageToken is not None else u''

        if any(a() for a in [lambda: logTime is None,
                             lambda: tm > logTime,
                             lambda: isOldLt]):
            # ^^^ This is to avoid the possible +1 sec skipping data problem (if no npt)
            logTime = tm
            lastLog = d
            # json.dumps(d, sort_keys=False, indent=4, separators = (',', ': '))

    return logTime, lastLog


def rewindLogEvents(ctx, conf, logType):
    # Must be validated by the app if it's the actual time datetime.datetime
    # TODO Can switch to using format TIME_FORMAT_ISO for conf._reset_time here and in the UI
    dtime = datetime.utcnow() + timedelta(seconds=-1 * conf.log_initial)
    nextPageToken = None

    # Override the last log data with the new 'time' field
    if conf.hardreset:
        # This should be the default.
        # Clobber all the data in the file as the last resort! This is the important fool-proof method for
        # ultimate UI control on the cloud if some bug is suspected to hold new messages etc.
        app.logger.warning('Hard-reset for "%s" initiated due to user request. '
                           'The data will resume when new messages get available.' % logType)
        lastLogFile.clobber(dtime, logtype=logType)     # type: ignore[union-attr]
    else:
        # The soft reset mode is essential for testing by keeping the state around. It's used for auto-reset as well
        app.logger.warning('Soft-reset for "%s" initiated due to user request. '
                           'The data will resume when new messages get available.' % logType)
        lastLogFile.updateError(conf, 'Soft-reset initiated due to user request. '  # type: ignore[union-attr]
                                'Waiting for the new data becoming available starting from (see the \'time\' field below)',
                                dtime, logType)

    return nextPageToken, dtime


def drainLogEvents(ctx, conf, logType, logData=None, dtime=None, nextPageToken=None):

    status = conf.status[logType]
    r = None

    isSyslog = (logData is not None)

    if conf._reset_time and not isSyslog:
        nextPageToken, dtime = rewindLogEvents(ctx, conf, logType)

    logTime = dtime

    try:
        raiseBackendError = False
        if raiseBackendError:
            raise Exception('injectbackendfailure')

        i = 0
        drained = False
        while not drained:
            if isSyslog:
                drained = True
            else:
                if i > 0:
                    # This is a crude way to control max event rate for Splunk / QRadar etc. as required
                    # without adding another thread and a queue which is a design over-kill
                    time.sleep(1.0 / conf._max_request_rate)

                if conf.host == conf._default.host:
                    # Avoid the overhead of invalid request even if there is no traffic generated
                    raise HTTPException(conf.host, -2, SKIPPED_REQUEST_ERROR, {}, None)

                # TODO If there is a hint from API that all data is drained can save the
                # split second sleep and the extra request
                url, endpoint, dataParams = RestParamsLogs(None,
                                                           conf.host,
                                                           conf.api_ver,
                                                           logType,
                                                           nextPageToken,
                                                           logTime + timedelta(seconds=1))
                logData, r = restCall(None,
                                      url, endpoint, dataParams,
                                      conf._auth_token.pswd,
                                      (conf.proxies, conf._proxies_pswd.pswd),
                                      conf.verify,
                                      conf._username,
                                      conf._password.pswd)
                i += 1

            lastLog = None
            nextPageToken = getAPIToken(logData, conf, logType)

            data = logData['response']['data']
            if len(data) == 0:
                drained = True
            else:
                logTime, lastLog = processLogEvents(ctx, conf, logType, data, nextPageToken, logTime, isSyslog)

            status.cntSuccess = status.cntSuccess + 1
            status.lastMsg = 'ok'
            if isSyslog:
                status.lastLog = json.dumps(lastLog)
            else:
                status.lastLog = lastLogFile.update(dtime, lastLog, logType)    # type: ignore[union-attr]

            flushLogEvents(ctx)

    except Exception as ex:
        msg = 'Bitglass Log Event Polling: failed to fetch data "%s": %s' % (str(logType), ex)
        # If no valid settings have been set, avoid polluting the log
        if SKIPPED_REQUEST_ERROR not in msg:
            app.logger.error(msg)
            r = ex
            lastLogFile.updateError(conf, r, None, logType)     # type: ignore[union-attr]
            status.cntError = status.cntError + 1
            status.lastMsg = str(ex)

        status.lastLog = ''

    # NOTE  Last successful result has empty data now (drained), instead, could merge all data and return
    #       making it optional if ingestLogEvent is not set.. Without it, attaching data to result is rather useless
    status.lastRes = r
    status.lastTime = logTime
    status.updateCount = conf.updateCount

    conf.status['last'] = status

    return logTime


def transferLogs(ctx, conf, condition, logTypes=None, logData=None, dtime=None,
                 npt=None, resetFence=datetime.utcnow().isoformat()):
    myConf = conf._deepcopy()
    condition.release()

    if not logTypes:
        if myConf._reset_time:
            # Pull all the log types that have ever been pulled unless the specific log type list was provided (like in Phantom).
            # Merge with the currently specified ones
            # logTypes = log_types   # All possibly supported log types
            h = lastLogFile.getHistoricLogTypeList()    # type: ignore[union-attr]
            n = myConf.log_types
            logTypes = h + list(set(n) - set(h))   # Whatever have been tried from the last reset plus currently requested
        else:
            logTypes = myConf.log_types    # Only currently requested

    logTime = {}
    if logData is None:
        for lt in logTypes:
            logTime[lt] = drainLogEvents(ctx, myConf, lt, logData,
                                         dtime[lt] if dtime is not None else None,
                                         npt[lt] if npt is not None else None)
    else:
        # syslog source
        # Make sure nextpagetoken is disabled
        myConf.useNextPageToken = False
        lt = logData['response']['data'][0]['logtype']
        logTime[lt] = drainLogEvents(None, myConf, lt, logData=logData)

    condition.acquire()
    myConf.status['updateCount'] = conf.updateCount

    # Load the latest state for the UI and reset the read-once-reset-to-default config params
    conf.status = copy.deepcopy(myConf.status)
    if conf._reset_time:
        if conf._isForeignConfigStore():
            conf.reset_fence = resetFence
            conf._save()
        conf._reset_time = ''

    # Increment by smallest delta to avoid repeating same entries
    # TODO Using microseconds=1 causes event duplication.. what is the minimum resolution to increment??
    #       without data loss but with guaranteed no repetitions
    if logData is None:
        if conf._isDaemon:
            condition.wait(myConf.log_interval)
        for lt in logTypes:
            dtime[lt] = logTime[lt] + timedelta(seconds=1)


def getLastLogTimeAndNpt(ctx, conf, logTypes=None):
    # Have to complicate things b/c the API doesn't support combining different log types
    dtime = {}
    npt = {}    # type: ignore[var-annotated]
    now = datetime.utcnow()
    for lt in log_types:
        # = datetime.utcnow() + timedelta(days=-1)
        dtime[lt] = now + timedelta(seconds=-1 * conf.log_initial)
        npt[lt] = None

        # Adjust to avoid the overlap with a previous run, warn on a possible gap
        # The gap is caused by either: app down time or the log source being disabled in earlier app run
        # was greater than 30 days (default of 'log_initial')
        try:
            if lastLogFile.get(logtype=lt):     # type: ignore[union-attr]
                try:
                    # Could be missing due to the old file format
                    npt[lt] = lastLogFile.get('nextpagetoken', lt)  # type: ignore[union-attr]
                    if npt[lt] == '':
                        npt[lt] = None
                        app.logger.warning('Empty nextpagetoken found for log type %s (old lastlog format?)' % lt)

                except Exception as ex:
                    npt[lt] = None
                    app.logger.warning('Error "%s" retrieving nextpagetoken for log type %s' % (str(ex), lt))

                d = strptime(lastLogFile.get('time', lt))   # type: ignore[union-attr]
                if dtime[lt] <= d:
                    dtime[lt] = d
                else:
                    # Important! For a possible gap, discard nextpagetoken loaded from lastlog
                    # NOTE: This still has an extremely remote possibility of data duplication
                    #       (no messages over the gap period is a necessary condition then - unpopulated gap)
                    npt[lt] = None
                    app.logger.warning('Possible gap for log type %s from %s to %s' %
                                       (str(lt),
                                           d.strftime(TIME_FORMAT_LOG),
                                           dtime[lt].strftime(TIME_FORMAT_LOG))
                                       )
            else:
                app.logger.info('No lastlog data found for log type %s' % lt)

        except Exception as ex:
            # Bad data in lastLogFile? Treat overlap as data corruption so exclude its possibility and warn
            # Discard nextpagetoken loaded from lastlog, also see the comment just above
            npt[lt] = None

            # By just setting it to 'now' the bad data would persist without getting any new messages and
            # hence no chance to reset the data to good format unless due to a fluke of a very recent message.
            # Instead, do a soft reset
            dtime[lt] = now
            app.logger.error('Probable gap for log type %s to %s due to BAD LAST LOG DATA: %s' %
                             (str(lt),
                                 dtime[lt].strftime(TIME_FORMAT_LOG),
                                 ex)
                             )

            # Re-write the file back to the good format
            # TODO If wishing to reduce missing a lot of data in favor of some overlap,
            #      may rely on the last log file mofification time minus polling period (which one? could have changed)
            app.logger.warning('Auto-reset initiated due to bad last log data. '
                               'The data will resume when new messages get available.')
            lastLogFile.updateError(conf, 'Auto-reset initiated due to bad last log data. '     # type: ignore[union-attr]
                                    'Waiting for the new data becoming available starting from (see the \'time\' field below)',
                                    now, lt)

            # Should never end up here again unless the file gets invalidated outside the app once more

        if npt[lt] is not None:
            app.logger.info('Valid_nextpagetoken "%s" found for log type %s' % (npt[lt], lt))

    return dtime, npt


def PollLogs(ctx, conf, logTypes=None, condition=Condition(), resetFence=datetime.utcnow().isoformat()):
    """
    Pump BG log events from BG API to QRadar
    """

    pid = os.getpid()
    # tid = get_ident()
    tid = 0
    app.logger.info('================================================================')
    app.logger.info('Polling: start polling log events.. pid=%s, tid=%s' % (pid, tid))
    app.logger.info('----------------------------------------------------------------')

    isSyslog = all(a() for a in [lambda: '://' not in conf.api_url,
                                 lambda: len(conf.api_url.split(':')) == 2])

    res = None
    if isSyslog:
        host, port = conf.api_url.split(':')
        # TODO: At least verify that sink_url is different to reduce the loop possibility sending back to itself
        SyslogUDPHandler.start(transferLogs,
                               host=host,
                               port=int(port),
                               conf=conf,
                               condition=condition
                               )
    else:
        dtime, npt = getLastLogTimeAndNpt(ctx, conf, logTypes)

        with conf._lock(condition, notify=False):
            isDaemon = True
            while isDaemon:
                transferLogs(ctx, conf, condition, logTypes, None, dtime, npt, resetFence)

                # Run only once if not in the daemon mode
                isDaemon = conf._isDaemon

        res = conf.status

    app.logger.info('Polling: stop polling log events.. pid=%s, tid=%s' % (pid, tid))
    app.logger.info('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
    return res


class bitglassapi:

    Initialize = Initialize

    # TODO Implement OverrideConfig(), it will also validate all settings (the validation is to be moved from UI)

    # Low level (overriding settings params)
    restCall = restCall

    RestParamsLogs = RestParamsLogs
    RestParamsConfig = RestParamsConfig

    RestCall = RestCall
    RestCallConfig = RestCallConfig

    # Higher level calls relying on serialized data and synchronization
    PollLogs = PollLogs

    def __init__(self, ctx=None):
        if ctx is None:
            # Use default callbacks
            ctx = self

        self.ctx = ctx

    # Default callbacks command mode without explicit context (like Splunk)
    def bgPushLogEvent(self, d, address, logTime):
        # Additional processing for the script
        from app import cli     # pylint: disable=E0401
        cli.pushLog(d, address, logTime)

    def bgFlushLogEvents(self):
        from app import cli     # pylint: disable=E0401
        cli.flushLogs()

    def bgLoadConfig(self, conf):
        from app import cli     # pylint: disable=E0401
        cli.loadConfiguration(conf)


# Test flat dict context (when file i/o is not available)
# This class gets overridden in the actual platform using such context
class BitglassContext(dict):
    def __init__(self, context={}):
        # Purge the old data
        for k, v in dict(self).items():
            del self[k]
        # Load the new data
        for k, v in context.items():
            self[k] = v

    def save(self):
        # Must convert into flat dict of strings or it's not saved properly
        d = {k: v if isinstance(v, str) else json.dumps(v) for k, v in dict(self).items()}

        # This (test code) runs repeatedly in a thread instead of passing from real framework on repeated script invocation
        # The above means the Initialize() path called only once with empty dict (making it a partial scenario), unlike in Demisto
        self.__init__(d)    # type: ignore[misc]


context = None


# Uncomment for testing flat file-less context like the one used in Demisto
# This is passed to bgapi to keep the lastlog object in since there is no file i/o available
# context = BitglassContext()


def startWorkerThread(conf, isDaemon=True, bgapi=None):

    Initialize(bgapi, _logger=app.logger, _conf=conf, context=context)

    condition = Condition()
    thread = Thread(target=PollLogs, args=(bgapi, conf, None, condition))

    conf._isDaemon = isDaemon
    thread.start()
    if not isDaemon:
        thread.join()
    return condition


# ================================================================


BG_E = 'BG#error: '
BG_W = 'BG#warning: '
BG_I = 'BG#info: '
BG_D = 'BG#debug: '


# No original warning() method
def _warning(msg):
    demisto.error(BG_W + msg)


# No original info() method
def _info(msg):
    demisto.debug(BG_I + msg)


demisto.warning = _warning
demisto.info = _info


''' CONSTANTS '''

# TODO
BITGLASS_SEVERITIES = ['Low', 'Medium', 'High', 'Critical']


def convert_to_demisto_severity(severity: str) -> int:  # noqa BFSV (Bad flake setting or version - valid python syntax)
    """Maps Bitglass severity to Cortex XSOAR severity

    Converts the Bitglass alert severity level ('Low', 'Medium',
    'High', 'Critical') to Cortex XSOAR incident severity (1 to 4)
    for mapping.

    :type severity: ``str``
    :param severity: severity as returned from the Bitglass API (str)

    :return: Cortex XSOAR Severity (1 to 4)
    :rtype: ``int``
    """

    # In this case the mapping is straightforward, but more complex mappings
    # might be required in your integration, so a dedicated function is
    # recommended. This mapping should also be documented.
    return {
        'Low': IncidentSeverity.LOW,
        'Medium': IncidentSeverity.MEDIUM,
        'High': IncidentSeverity.HIGH,
        'Critical': IncidentSeverity.CRITICAL
    }[severity]


class BitglassContextDemisto(BitglassContext):
    def __init__(self, dcontext):
        context = demisto.getIntegrationContext()
        demisto.debug(BG_D + 'getIntegrationContext: {0}'.format(context))
        # Override the config values, analagous to config files. Pack the value dicts to json strings
        for k, v in dcontext.items():
            context[k] = json.dumps(v)

        # Purge the old data
        for k, v in dict(self).items():
            del self[k]
        # Load the new data
        for k, v in context.items():
            self[k] = v

    def save(self):
        # Must convert into flat dict of strings or it's not saved properly
        for k, v in dict(self).items():
            if not isinstance(v, str):
                self[k] = json.dumps(v)
        demisto.debug(BG_D + 'setIntegrationContext: {0}'.format(dict(self)))
        demisto.setIntegrationContext(dict(self))


# This is passed to bgapi to keep the lastlog object in since there is no file I/O available
context = BitglassContextDemisto(dcontext)


# TODO ?? Mocking still available/needed?
# import DemistoClientMock as demisto
# from CommonServerPython import *
# from CommonServerUserPython import *


# Disable insecure warnings
requests.packages.urllib3.disable_warnings()


''' CLIENT CLASS '''


class PatternMatch(object):
    def __init__(self, username, pattern, time, data={}, field='email'):
        self.username = username
        self.pattern = pattern
        self.time = time
        self.data = data
        self.field = field

        # Set the additional cef field
        self.data['userName'] = username
        self.data['dataPatterns'] = pattern


def bgDemistoParamsGetString(name, default=''):
    ''' Demisto 6.1 returns None instead of empty string if the optional text param is not filled
        ignoring the default param value supplied. That's probably for telling apart empty vs.
        absence of the param itself. Maybe that's a bug or for security but very much bug prone and
        against our convention for config values. No difference why it's empty whether omitted
        or missing (also, due to an earlier version as may happen) - using the default in all cases.
        This seems to have been fixed in ver 6.2
    '''
    v = demisto.params().get(name, default)
    if v:
        return v

    return default


class Client:
    def __init__(self, base_url='', verify=True, auth_token=None):
        """Arguments are similar to Demisto BaseClient but proxy flag, ok_codes and headers are not used:
            proxy: flag is ignored
            ok_codes: not used, all below-400 are success unless the data access generates an exception
            headers: additional headers not used
            auth: request().auth not used, passed in a header instead, use renamed auth_token to pass a dummy token instead

        Args:
            base_url: Same as in demisto.BaseClient. If not provided (default) then it's not a mock run so ignore the rest args
            verify: Same as in demisto.BaseClient
            auth_token: A dummy auth token (discarded by requests_mock)
        """
        self.mock_base_url = base_url
        bitglassapi(self).Initialize(None, skipArgs=True, context=context)

        if self.mock_base_url:
            # This is a coverage/unit test run. All params are default except the following ones set below
            # No actual connecttion takes place, as requests module is replaced with requests_mock feeding back
            # the test data defined in Bitglass_test.py and the test_data/*.json files
            conf.api_url = base_url     # type: ignore[union-attr]
            conf.verify = verify    # type: ignore[union-attr]
            conf.log_types = [GC_LOGTYPE_ACCESS, GC_LOGTYPE_CLOUDAUDIT]     # type: ignore[union-attr]
            conf._auth_token.pswd = auth_token  # type: ignore[union-attr]

        # Accumulate the users to add to the risky group
        self.newUsers = []
        self.newMatches = []

        # Cash the added ones to cut down on extra API calls (assuming none of the users
        # were removed from the group by another app / manually)
        self.riskyUsers = []

    def bgLoadConfig(self, conf):
        ''' Apply all parameters to internal configuration settings
        '''

        if self.mock_base_url:
            demisto.debug(BG_D + 'Configuration loading skipped due to the mock run')
            return

        # Not used in Demisto as it manages polling by itself UNLESS it's in the "Long running instance" mode
        # Convert from minutes to seconds. The magic name makes it show up in the UI as Hrs/Mins hence not using 'log_interval'
        conf.log_interval = 60 * int(demisto.params().get('incidentFetchInterval'))

        conf.api_url = demisto.params().get('api_url')

        conf.verify = not demisto.params().get('insecure')

        deleteDefaultProxy = False
        proxies = demisto.params().get('proxies')
        if proxies:
            try:
                if proxies.upper() not in ['HTTP_PROXY', 'HTTPS_PROXY', '*']:
                    deleteDefaultProxy = True
                    # TODO Accomodate the return tuple value and handle the password securily
                    conf.proxies = conf._getProxies(proxies)
            except BaseException as ex:
                demisto.debug(BG_D + 'Bad proxy param while getting configuration params {}'.format(str(ex)))

        if deleteDefaultProxy:
            for ev in ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']:
                try:
                    del os.environ[ev]
                except Exception:   # nosec
                    pass

        # These 2 are extra
        conf.filter_access = demisto.params().get('filter_access')
        conf.filter_cloudaudit = demisto.params().get('filter_cloudaudit')

        # Access and CloudAudit only, if enabled and non-empty pattern expression only
        # (the latter is to avoid accidental flooding with unnecessary high frequency data)
        conf.log_types = []
        if demisto.params().get('enable_access') and conf.filter_access != '':
            conf.log_types += [GC_LOGTYPE_ACCESS]
        if demisto.params().get('enable_cloudaudit') and conf.filter_cloudaudit != '':
            conf.log_types += [GC_LOGTYPE_CLOUDAUDIT]

        # Secret parameters
        conf._auth_token.pswd = demisto.params().get('auth_token')

        conf._username = demisto.params().get('username')
        conf._password.pswd = demisto.params().get('password')

        # Trigger complete log rewind? Have to base it on a string match since time control is not available in the UI
        reset_tag = bgDemistoParamsGetString('reset_tag', '')
        if reset_tag != conf.reset_fence:
            # Fresh reset request
            demisto.debug(BG_D + 'Log rewind pending under new reset tag: {0}'.format(reset_tag))
            conf._reset_time = 'reset'

        demisto.debug(BG_D + 'Configuration loaded')

    def bgPushLogEvent(self, d, address, logTime):
        user = None
        try:
            if d[GC_FIELD_LOGTYPE] == 'access':
                # TODO ?? Why ALL-PCI not matching with 'PCI.*' (without ^)?
                if re.fullmatch(conf.filter_access, d[GC_FIELD_DLPPATTERN]):    # type: ignore[union-attr]
                    demisto.debug(BG_D + 'access matched %s' % d[GC_FIELD_DLPPATTERN])
                    user = d[u'email']
                    pattern = d[GC_FIELD_DLPPATTERN]
                    field = 'email'
            elif d[GC_FIELD_LOGTYPE] == 'cloudaudit':
                if re.fullmatch(conf.filter_cloudaudit, d[GC_FIELD_PATTERNS]):  # type: ignore[union-attr]
                    demisto.debug(BG_D + 'cloudaudit matched %s' % d[GC_FIELD_PATTERNS])
                    user = d[u'owner']
                    pattern = d[GC_FIELD_PATTERNS]
                    field = 'owner'
        except Exception:   # nosec
            pass

        if user:
            # Add all matches properly, not just first matches for the user
            if user not in self.newUsers:
                self.newUsers.append(user)
            self.newMatches.append(PatternMatch(user, pattern, d[u'time'], d, field))

    def bgFlushLogEvents(self):
        # A new container/incidence is created in fetch_incidents
        pass

    def bgCallApi(self, type_, action, params):
        _, endpoint = bitglassapi().RestParamsConfig(None, '1', type_, action)
        resp_json, r = bitglassapi().RestCallConfig(endpoint, params)
        if not resp_json:
            raise DemistoException('Bitglass Config API Error', r)

        readable_output = f'## {resp_json}'
        return CommandResults(
            readable_output=readable_output,
            outputs_prefix=f'bg.{action}_{type_}',
            outputs_key_field='',
            outputs=resp_json
            # ### indicators?
        )

    def getIncident(self, aid):
        # NOTE: No need to retrieve the data, it's already loaded and parsed under 'labels' by default
        return aid['labels']
        # params = {
        #     'type': 'metaInfo',
        #     'incidentId': aid,
        # }
        # bc = BaseClient()
        # incident = self.http_request('GET', '/incident/get', headers={'token': self._token}, params=params)
        # return incident.get('result').get('data')


''' COMMAND FUNCTIONS '''


def test_module(client: Client) -> str:  # noqa BFSV
    """Tests API connectivity and authentication'

    Returning 'ok' indicates that the integration works like it is supposed to.
    Connection to the service is successful.
    Raises exceptions if something goes wrong.

    :type client: ``Client``
    :param Client: Bitglass API and config wrapper

    :return: 'ok' if test passed, anything else will fail the test.
    :rtype: ``str``
    """

    # Make sure to return error message for Demisto to display (other than 'ok')
    try:
        demisto.debug(BG_D + 'Testing connectivity')

        status = bitglassapi(client).PollLogs(conf, [u'cloudsummary'], resetFence=bgDemistoParamsGetString('reset_tag', ''))
        if not status['last'].ok():
            return status['last'].lastMsg

    except Exception as e:
        return 'Unexpected Error: %s' % str(e)

    return 'ok'


def fetch_incidents(client: Client,
                    max_results: int,
                    last_run: Dict[str, int],
                    first_fetch_time: Optional[int],
                    alert_status: Optional[str],
                    min_severity: str,
                    alert_type: Optional[str]

                    ) -> Tuple[Dict[str, int], List[dict]]: # noqa BFSV
    """This function retrieves new alerts every interval (default is 5 minutes).

    TODO Review
    This function has to implement the logic of making sure that incidents are
    fetched only onces and no incidents are missed. By default it's invoked by
    XSOAR every minute. It will use last_run to save the timestamp of the last
    incident it processed. If last_run is not provided, it should use the
    integration parameter first_fetch_time to determine when to start fetching
    the first time.

    :type client: ``Client``
    :param Client: Bitglass client to use

    :type max_results: ``int``
    :param max_results: Maximum numbers of incidents per fetch

    :type last_run: ``Optional[Dict[str, int]]``
    :param last_run:
        A dict with a key containing the latest incident created time we got
        from last fetch

    :type first_fetch_time: ``Optional[int]``
    :param first_fetch_time:
        If last_run is None (first time we are fetching), it contains
        the timestamp in milliseconds on when to start fetching incidents

    :type alert_status: ``Optional[str]``
    :param alert_status:
        status of the alert to search for. Options are: 'ACTIVE'
        or 'CLOSED'

    :type min_severity: ``str``
    :param min_severity:
        minimum severity of the alert to search for.
        Options are: "Low", "Medium", "High", "Critical"

    :type alert_type: ``Optional[str]``
    :param alert_type:
        type of alerts to search for. There is no list of predefined types

    :return:
        A tuple containing two elements:
            next_run (``Dict[str, int]``): Contains the timestamp that will be
                    used in ``last_run`` on the next fetch.
            incidents (``List[dict]``): List of incidents that will be created in XSOAR

    :rtype: ``Tuple[Dict[str, int], List[dict]]``
    """

    # Get the last fetch time, if exists
    # last_run is a dict with a single key, called last_fetch
    last_fetch = last_run.get('last_fetch', None)

    # Handle first fetch time
    if last_fetch is None:
        # if missing, use what provided via first_fetch_time
        last_fetch = first_fetch_time
    else:
        # otherwise use the stored last fetch
        last_fetch = int(last_fetch)

    # for type checking, making sure that latest_created_time is int
    latest_created_time = cast(int, last_fetch)

    # Initialize an empty list of incidents to return
    # Each incident is a dict with a string as a key
    incidents: List[Dict[str, Any]] = []

    # NOTE No severity query param for now, just assume Medium
    # Get the CSV list of severities from min_severity
    # severity = ','.join(BITGLASS_SEVERITIES[BITGLASS_SEVERITIES.index(min_severity):])

    reset_tag = bgDemistoParamsGetString('reset_tag', '')
    demisto.debug(BG_D + 'Start polling events under reset tag: {0}'.format(reset_tag))
    status = bitglassapi(client).PollLogs(conf, resetFence=reset_tag)
    if status['last'].ok():
        for alert in client.newMatches:
            # Demisto uses time in ms
            incident_created_time = int(strptime(alert.time).timestamp())
            incident_created_time_ms = incident_created_time * 1000

            # This simplistic approach (from HelloWorld sample) won't work correctly.
            # The time is properly synced by the lastlog object (next page token, timestamp, per-log type)
            # This synchronization object is kept in the demisto context dict
            # if last_fetch:
            #     if incident_created_time <= last_fetch:
            #         continue

            # TODO Move to bgapi (same name as in Phantom)
            # If no name is present it will throw an exception
            incident_name = '{0}: {1}'.format(alert.field.title(), alert.username)

            # INTEGRATION DEVELOPER TIP
            # The incident dict is initialized with a few mandatory fields:
            # name: the incident name
            # occurred: the time on when the incident occurred, in ISO8601 format
            # we use timestamp_to_datestring() from CommonServerPython.py to
            # handle the conversion.
            # rawJSON: everything else is packed in a string via json.dumps()
            # and is included in rawJSON. It will be used later for classification
            # and mapping inside XSOAR.
            # severity: it's not mandatory, but is recommended. It must be
            # converted to XSOAR specific severity (int 1 to 4)
            # Note that there are other fields commented out here. You can do some
            # mapping of fields (either out of the box fields, like "details" and
            # "type") or custom fields (like "helloworldid") directly here in the
            # code, or they can be handled in the classification and mapping phase.
            # In either case customers can override them. We leave the values
            # commented out here, but you can use them if you want.
            incident = {
                'name': incident_name,
                # 'details': alert['name'],
                'occurred': timestamp_to_datestring(incident_created_time_ms),
                'rawJSON': json.dumps(alert.data),
                # TODO Doesn't get set for some reason.. why? Need it to 'trigger' the Playbook automatically
                'type': 'Bitglass DLP',  # Map to a specific XSOAR incident Type
                'severity': convert_to_demisto_severity('Medium'),
                # 'CustomFields': {  # Map specific XSOAR Custom Fields
                #     'helloworldid': alert.get('alert_id'),
                #     'helloworldstatus': alert.get('alert_status'),
                #     'helloworldtype': alert.get('alert_type')
                # }
            }

            incidents.append(incident)

            # Update last run and add incident if the incident is newer than last fetch
            if incident_created_time > latest_created_time:
                latest_created_time = incident_created_time

    # Save the next_run as a dict with the last_fetch key to be stored
    next_run = {'last_fetch': latest_created_time}
    return next_run, incidents


def filter_by_dlp_pattern_command(client: Client,
                                  args: Dict[str, Any]
                                  ) -> CommandResults:  # noqa BFSV

    # Get data
    matchRe = args.get('bg_match_expression')
    aid = args.get('bg_log_event')

    # demisto.error('%s' % {}['crashme'])

    userName = '_'
    incident = client.getIncident(aid)
    if incident:
        try:
            if re.fullmatch(matchRe, incident['dataPatterns']):     # type: ignore[type-var]
                demisto.debug(BG_D + f"'dataPatterns' matched {incident['dataPatterns']}")
            else:
                # To avoid the error message, have to return non-empty set of data.
                # This will be ignored as the user name is empty
                incident['userName'] = '_'
            userName = incident['userName']
        except Exception:
            demisto.debug(BG_D + "'dataPatterns' not found")

    return CommandResults(
        readable_output=f'{matchRe} - {aid}',
        outputs_prefix='Bitglass.user_name',
        outputs_key_field='',
        # TODO Return the entire incident data as well?
        outputs=userName
    )


def create_update_group_command(client: Client,
                                args: Dict[str, Any]
                                ) -> CommandResults:    # noqa BFSV

    group_name = args.get('bg_group_name')
    new_group_name = args.get('bg_new_group_name')

    return client.bgCallApi(
        'group', 'createupdate',
        {
            'groupname': group_name,
            'newgroupname': new_group_name
        }
    )


def delete_group_command(client: Client,
                         args: Dict[str, Any]
                         ) -> CommandResults:   # noqa BFSV

    group_name = args.get('bg_group_name')

    return client.bgCallApi(
        'group', 'delete',
        {
            'groupname': group_name
        }
    )


def add_user_to_group_command(client: Client,
                              args: Dict[str, Any]
                              ) -> CommandResults:  # noqa BFSV

    group_name = args.get('bg_group_name')
    user_name = args.get('bg_user_name')

    return client.bgCallApi(
        'group', 'addmembers',
        {
            'groupname': group_name,
            'companyemail': [user_name]
        }
    )


def remove_user_from_group_command(client: Client,
                                   args: Dict[str, Any]
                                   ) -> CommandResults: # noqa BFSV

    group_name = args.get('bg_group_name')
    user_name = args.get('bg_user_name')

    return client.bgCallApi(
        'group', 'removemembers',
        {
            'groupname': group_name,
            'companyemail': [user_name]
        }
    )


def create_update_user_command(client: Client,
                               args: Dict[str, Any]
                               ) -> CommandResults: # noqa BFSV

    user_name = args.get('bg_user_name')
    first_name = args.get('bg_first_name')
    last_name = args.get('bg_last_name')
    secondary_email = args.get('bg_secondary_email')
    netbios_domain = args.get('bg_netbios_domain')
    sam_account_name = args.get('bg_sam_account_name')
    user_principal_name = args.get('bg_user_principal_name')
    object_guid = args.get('bg_object_guid')
    country_code = args.get('bg_country_code')
    mobile_number = args.get('bg_mobile_number')
    admin_role = args.get('bg_admin_role')
    group_membership = args.get('bg_group_membership')

    return client.bgCallApi(
        'user', 'createupdate',
        {
            'companyemail': user_name,
            'firstname': first_name,
            'lastname': last_name,
            'secondaryemail': secondary_email,
            'netbiosdomain': netbios_domain,
            'samaccountname': sam_account_name,
            'userprincipalname': user_principal_name,
            'objectguid': object_guid,
            'countrycode': country_code,
            'mobilenumber': mobile_number,
            'adminrole': admin_role,
            'groupmembership': group_membership
        }
    )


def deactivate_user_command(client: Client,
                            args: Dict[str, Any]
                            ) -> CommandResults:    # noqa BFSV

    user_name = args.get('bg_user_name')

    return client.bgCallApi(
        'user', 'deactivate',
        {
            'companyemail': user_name
        }
    )


def reactivate_user_command(client: Client,
                            args: Dict[str, Any]
                            ) -> CommandResults:    # noqa BFSV

    user_name = args.get('bg_user_name')

    return client.bgCallApi(
        'user', 'reactivate',
        {
            'companyemail': user_name
        }
    )


''' MAIN FUNCTION '''


def main() -> None: # noqa BFSV
    """main function, parses params and runs command functions

    :return:
    :rtype:
    """

    # TODO ?? Do we need first_fetch to expose 'initial'
    # # How much time before the first fetch to retrieve incidents
    # first_fetch_time = arg_to_datetime(
    #     arg=demisto.params().get('first_fetch', '3 days'),
    #     arg_name='First fetch time',
    #     required=True
    # )
    # first_fetch_timestamp = int(first_fetch_time.timestamp()) if first_fetch_time else None
    # # Using assert as a type guard (since first_fetch_time is always an int when required=True)
    # assert isinstance(first_fetch_timestamp, int)

    # INTEGRATION DEVELOPER TIP
    # You can use functions such as ``demisto.debug()``, ``demisto.info()``,
    # etc. to print information in the XSOAR server log. You can set the log
    # level on the server configuration
    # See: https://xsoar.pan.dev/docs/integrations/code-conventions#logging

    demisto.debug(BG_D + f'Command being called is {demisto.command()}')
    try:
        # TODO Generate token for local requests to get the pre-fetched incident data
        client = Client()

        if demisto.command() == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = test_module(client)
            return_results(result)

        elif demisto.command() == 'fetch-incidents':
            # Set and define the fetch incidents command to run after activated via integration settings.
            alert_status = demisto.params().get('alert_status', None)
            alert_type = demisto.params().get('alert_type', None)
            min_severity = demisto.params().get('min_severity', None)

            # TODO Implement max fetch count in logeventdaemon (the actual incident total will be less - only matched ones)
            # Convert the argument to an int using helper function or set to MAX_INCIDENTS_TO_FETCH
            # max_results = arg_to_number(
            #     arg=demisto.params().get('max_fetch'),
            #     arg_name='max_fetch',
            #     required=False
            # )
            # if not max_results or max_results > MAX_INCIDENTS_TO_FETCH:
            #     max_results = MAX_INCIDENTS_TO_FETCH

            max_results = 0
            first_fetch_timestamp = 0     # Give whatever available
            min_severity = 'Medium'

            next_run, incidents = fetch_incidents(
                client=client,
                max_results=max_results,
                last_run=demisto.getLastRun(),  # getLastRun() gets the last run dict
                first_fetch_time=first_fetch_timestamp,
                alert_status=alert_status,
                min_severity=min_severity,
                alert_type=alert_type
            )

            # saves next_run for the time fetch-incidents is invoked
            demisto.setLastRun(next_run)
            # fetch-incidents calls ``demisto.incidents()`` to provide the list
            # of incidents to create
            demisto.incidents(incidents)

        elif demisto.command() == 'bitglass-filter-by-dlp-pattern':
            return_results(filter_by_dlp_pattern_command(client, demisto.args()))

        elif demisto.command() == 'bitglass-create-update-group':
            return_results(create_update_group_command(client, demisto.args()))

        elif demisto.command() == 'bitglass-delete-group':
            return_results(delete_group_command(client, demisto.args()))

        elif demisto.command() == 'bitglass-add-user-to-group':
            return_results(add_user_to_group_command(client, demisto.args()))

        elif demisto.command() == 'bitglass-remove-user-from-group':
            return_results(remove_user_from_group_command(client, demisto.args()))

        elif demisto.command() == 'bitglass-create-update-user':
            return_results(create_update_user_command(client, demisto.args()))

        elif demisto.command() == 'bitglass-deactivate-user':
            return_results(deactivate_user_command(client, demisto.args()))

        elif demisto.command() == 'bitglass-reactivate-user':
            return_results(reactivate_user_command(client, demisto.args()))

    # Log exceptions and return errors
    except Exception as e:
        # demisto.debug(BG_D + 'testdebuginsystem.log') - debug() or error() - niether is printed to serever.log,
        # need to use the debug mode from CLI?

        # Print error AND the traceback
        return_error(f'Failed to execute {demisto.command()} '
                     f'command.\nError:\n{str(e)}\nTraceback:\n{str(traceback.format_exc())}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
