# -*- coding:utf-8 -*-
try:
    import simplejson as json
except ImportError:
    import json


class MethodParsingException(Exception):
    pass
