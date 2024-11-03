from CommonServerPython import *
from CommonServerUserPython import *
import time
import requests
import urllib3
import calendar
import json
import re


class EndaceVisionAPIAdapter:
    """Adapter for EndaceWebSession which allows
    a simpler interface to the private Vision API.

    Implements some of the request methods, so the interface
    in most cases should be the same.

    Ensures CSRF tokens are sent correctly in requests.
    """

    API_BASE = "/vision2/data"

    def __init__(self, endace_session):
        self.endace_session = endace_session

    def request(self, method, path, **kwargs):
        headers = {}
        if method == "POST":
            csrf_cookie = self.endace_session.requests.cookies.get("vision2_csrf_cookie")
            if csrf_cookie:
                headers = {
                    'XSRF-csrf-token': str(csrf_cookie)
                }
        try:
            r = self.endace_session.requests.request(
                method, self.endace_session.page(f"{self.API_BASE}/{path}"), headers=headers, **kwargs)
            r.raise_for_status()
        except requests.exceptions.HTTPError as err:
            return err.response.status_code
        else:
            return r

    def get(self, path, **kwargs):
        return self.request("GET", path, **kwargs)

    def post(self, path, **kwargs):
        return self.request("POST", path, **kwargs)

    def put(self, path, **kwargs):
        return self.request("PUT", path, **kwargs)

    def delete(self, path, **kwargs):
        return self.request("DELETE", path, **kwargs)


class EndaceWebSession:

    LOGIN_PAGE = "/admin/launch?script=rh&template=login"
    LOGIN_ACTION = "/admin/launch?script=rh&template=login&action=login"
    LOGOUT_PAGE = "/admin/launch?script=rh&template=logout&action=logout"

    def __init__(self, app_url=None, username=None, password=None, cert_verify=False):
        self.app_url = app_url
        self.username = username
        self.password = password
        self.requests = None
        self.verify = cert_verify

    def __enter__(self):
        self.requests = self._create_login_session()
        return self

    def __exit__(self, exception_type, exception_value, traceback):
        self.close()
        _ = exception_type
        _ = exception_value
        _ = traceback

    def close(self):
        self.logout()
        if self.requests:
            self.requests.close()
            self.requests = None

    def page(self, path="/"):
        return f"{self.app_url}{path}"

    def logout(self):
        if self.requests:
            logout = self.requests.get(self.page(self.LOGOUT_PAGE))
            if logout.status_code == 200:
                return True
            else:
                raise Exception(f"logout to {self.app_url} failed")
        else:
            return False

    def _create_login_session(self):
        """
        Creates a requests.Session object with correct cookies
        setup for an OSm session.
        """
        sess = requests.Session()
        r = sess.get(self.page(self.LOGIN_PAGE), verify=self.verify)
        if r.status_code == 200:
            csrf_token = EndaceWebSession.find_csrf_token_login(r.content)
            if csrf_token is None:
                raise Exception("Could not find CSRF token")
            # Submit login form
            login_result = sess.post(self.page(self.LOGIN_ACTION),
                                     data={
                                         "_csrf": csrf_token,
                                         "d_user_id": "user_id",
                                         "t_user_id": "string",
                                         "c_user_id": "string",
                                         "e_user_id": "true",
                                         "f_user_id": str(self.username),
                                         "f_password": str(self.password),
                                         "Login": "Login"},
                                     headers={'Content-type': 'application/x-www-form-urlencoded'}
                                     )
            if login_result.status_code == 200 and len(sess.cookies) > 0:
                return sess
            else:
                raise Exception("Login failed")
        else:
            raise Exception("Login failed")

    @staticmethod
    def find_csrf_token_login(page_content=""):
        return EndaceWebSession.fetch_csrf_token(str(page_content), r"(class=\"csrf-token\").*?\/>")

    @staticmethod
    def fetch_csrf_token(input_text, pattern):
        """
        Fetch CSRF Token from the given input html tag by applying the pattern passed
        :param input_text:
        :param pattern:
        :return:
        """

        m = re.search(pattern=pattern, string=input_text)
        if not m:
            return None

        match_input_tag = m.group(0)

        if match_input_tag:
            for replace_tag in ["value", "content"]:
                m = re.search(pattern=replace_tag + "=\".*\"", string=match_input_tag)
                if m:
                    csrf_tag = str(m.group(0))
                    csrf_tag = csrf_tag.replace(replace_tag + "=", '')
                    csrf_tag = csrf_tag.replace('"', '')
                    return csrf_tag.strip()
        return None


class EndaceVisionData:
    def __init__(self, args=None):
        self.args = args

    def build_search_data(self):
        investigation_data = {
            "type": "TrafficBreakdownNG",
            "breakdown_type": "datasource",
            "datasource_guids": ["tag:rotation-file"],
            "start_time": int(self.args['start']) * 1000,
            "end_time": int(self.args['end']) * 1000,
            "filter": self.get_filters(),
            "order_by": "bytes",
            "required_aggregates": ["bytes"],
            "order_direction": "desc",
            "other_required": True,
            "points": 10,
            "auto_pivot": True,
            "disable_uvision": False,
            "disable_mvision": False
        }
        return investigation_data

    def build_archive_data(self):
        archive_data = {
            "filename": self.args['archive_filename'],
            "deduplication": False,
            "bidirection": False,
            "datasources": self.get_datasources(),
            "timerange": self.get_timerange(),
            "filters": self.get_filters(),
            "individualSessionData": False
        }

        return archive_data

    def get_datasources(self):

        datasources = {
            "key": "tag:rotation-file",
            "datasource": {
                "id": "tag:rotation-file",
                "type": "tag",
                "name": "rotation-file",
                "probeName": "tag",
                "displayName": "tag:rotation-file",
                "status": {
                    "inUse": False,
                    "readers": [],
                    "writers": []
                },
                "vision": True,
                "mplsLevel1": 1,
                "mplsLevel2": "BOTTOM",
                "metadataTimerange": {
                    "visionObjectType": "timerange",
                    "visionObjectValue": {
                        "start": {
                            "seconds": self.args['start'],
                            "nanoseconds": 0
                        },
                        "end": {
                            "seconds": self.args['end'],
                            "nanoseconds": 0
                        }
                    }
                },
                "packetTimerange": {
                    "visionObjectType": "timerange",
                    "visionObjectValue": {
                        "start": {
                            "seconds": self.args['start'],
                            "nanoseconds": 0
                        },
                        "end": {
                            "seconds": self.args['end'],
                            "nanoseconds": 0
                        }
                    }
                },
                "datasourceIds": self.args['ids']
            },
            "missing": False
        }

        return [datasources]

    def get_timerange(self):

        timerange = {
            "visionObjectType": "timerange",
            "visionObjectValue": {
                "start": {
                    "seconds": int(self.args['start']),
                    "nanoseconds": 0
                },
                "end": {
                    "seconds": int(self.args['end']),
                    "nanoseconds": 0
                }
            }
        }
        return timerange

    def get_filters(self):

        filters = {
            "visionObjectType": "filter",
            "visionObjectValue": {
                "active": "basic",
                "basic": {
                    "visionObjectType": "basicFilter",
                    "visionObjectValue": {
                        "filters": self.get_basicfilters()
                    }
                }
            }
        }

        return filters

    def get_basicfilters(self):

        allfilterslist = []
        visionobjecttype = "basicFilterDirectionlessIp"
        for filtertype in self.args['filterby']:
            filterlist = []
            if filtertype == 0:
                visionobjecttype = "basicFilterDirectionlessIp"
                filterlist.append(self.args['ip'])
            if filtertype == 1:
                visionobjecttype = "basicFilterSourceIp"
                for sip in self.args['src_host_list']:
                    filterlist.append(sip)
            if filtertype == 2:
                visionobjecttype = "basicFilterDestinationIp"
                for dip in self.args['dest_host_list']:
                    filterlist.append(dip)
            if filtertype == 3:
                visionobjecttype = "basicFilterSourcePort"
                for sport in self.args['src_port_list']:
                    filterlist.append(sport)
            if filtertype == 4:
                visionobjecttype = "basicFilterDestinationPort"
                for dport in self.args['dest_port_list']:
                    filterlist.append(dport)
            if filtertype == 5:
                visionobjecttype = "basicFilterIpProtocol"
                filterlist.append(self.args['protocol'])
            if filtertype == 6:
                visionobjecttype = "basicFilterDirectionlessPort"
                filterlist.append(self.args['port'])
            if filtertype == 7:
                visionobjecttype = "basicFilterVlan"
                for vlan in self.args.vlan1list:
                    filterlist.append(vlan)

            visionfilter = {
                "visionObjectType": visionobjecttype,
                "visionObjectValue": {
                    "version": 1,
                    "include": True,
                    "value": filterlist
                }
            }

            allfilterslist.append(visionfilter)

        return allfilterslist


class EndaceApp:
    delta_time = 120
    wait_time = 5

    def __init__(self, *args):
        self.args = dict()

        self.applianceurl = args[0]
        self.username = args[1]
        self.password = args[2]
        self.cert_verify = args[3]
        self.hostname = args[4]

    @staticmethod
    def endace_get_input_arguments(args=None):
        timeframe_converter = {'30seconds': 30, '1minute': 60, '5minutes': 300, '10minutes': 600, '30minutes': 1800,
                               '1hour': 3600, '2hours': 7200, '5hours': 18000, '10hours': 36000, '12hours': 43200,
                               '1day': 86400, '3days': 259200, '5days': 432000, '1week': 604800}

        function_args = dict()

        #  timestamps
        function_args['start'] = args.get("start")
        if args.get("start"):
            #   converting ISO time to epoch time
            function_args['start'] = date_to_timestamp(args.get("start")) / 1000

        function_args['end'] = args.get("end")
        if args.get("end"):
            #   converting ISO time to epoch time
            function_args['end'] = date_to_timestamp(args.get("end")) / 1000

        function_args['timeframe'] = timeframe_converter.get(args.get("timeframe"))

        #   filter params
        #   args.get("directionless IP")
        function_args['ip'] = args.get("ip")
        #   args.get("directionless PORT")
        function_args['port'] = args.get("port")
        #   args.get("src_host_list")
        function_args['src_host_list'] = list(set(argToList(args.get("src_host_list"))))[:10]
        #   args.get("dest_host_list")
        function_args['dest_host_list'] = list(set(argToList(args.get("dest_host_list"))))[:10]
        #   args.get("src_port_list")
        function_args['src_port_list'] = list(set(argToList(args.get("src_port_list"))))[:10]
        #   args.get("dest_port_list")
        function_args['dest_port_list'] = list(set(argToList(args.get("dest_port_list"))))[:10]

        function_args['protocol'] = args.get("protocol")

        #   Doing a sanity check on input function arguments
        #   adding a limit to number of filter items to be passed to 10 max
        if (len(function_args['src_host_list']) + len(function_args['dest_host_list'])
                + len(function_args['src_port_list']) + len(function_args['dest_port_list'])) > 10:
            raise ValueError("Wrong number of filters items - Limit search filters to 10 items")

        if not function_args['ip'] and not function_args['src_host_list'] and not function_args['dest_host_list']:
            raise ValueError("Wrong or missing value - Src and Dest IP arguments")

        if not function_args['start'] and not function_args['end'] and not function_args['timeframe']:
            raise ValueError("Wrong arguments - StartTime, EndTime or TimeFrame is invalid ")
        elif (not function_args['start'] or not function_args['end']) and not function_args['timeframe']:
            raise ValueError("Wrong arguments - either StartTime or EndTime or Timeframe is invalid ")

        if function_args['start'] and function_args['end']:
            if function_args['start'] == function_args['end']:
                raise ValueError("Wrong arguments - value of StartTime and EndTime argument - both are same")

        #   Logical options for search time:
        #   1) start and stop time is not provided: will work like search Last n seconds, n = timeframe
        #   2) only either start or stop time is provided: Search will be either +/- of timeframe of the given time
        #   3) Both start and stop time is provided: Search using start and stop time, ignore timeframe

        if not function_args['start'] and not function_args['end']:
            function_args['end'] = int(calendar.timegm(time.gmtime()) - 10)
            function_args['start'] = (int(function_args['end']) - int(function_args['timeframe']))
        elif function_args['start'] and not function_args['end']:
            if int(function_args['start']) > (calendar.timegm(time.gmtime()) - 10):
                raise ValueError(f'Wrong argument - value of StartTime - {args.get("start")} UTC cannot be in future')
            function_args['end'] = int(function_args['start']) + int(function_args['timeframe'])
            if int(function_args['end']) > (calendar.timegm(time.gmtime()) - 10):
                raise ValueError('Wrong argument - value of EndTime - adjust '
                                 'timeframe argument such that EndTime is not in future')
        elif not function_args['start'] and function_args['end']:
            if int(function_args['end']) > (calendar.timegm(time.gmtime()) - 10):
                raise ValueError(f'Wrong argument - value of EndTime - {args.get("end")} UTC cannot be in future')
            function_args['start'] = (int(function_args['end']) - int(function_args['timeframe']))

        #   search time boundary check
        if function_args['end'] < function_args['start']:
            raise ValueError('Wrong argument - value of EndTime - cannot be before StartTime')
        if int(function_args['start']) > (calendar.timegm(time.gmtime()) - 10):
            raise ValueError(f'Wrong argument - value of StartTime - {args.get("start")} UTC cannot be in future')
        if int(function_args['end']) > (calendar.timegm(time.gmtime()) - 10):
            raise ValueError(f'Wrong argument - value of EndTime - {args.get("end")} UTC cannot be in future')

        return function_args

    @staticmethod
    def handle_error_notifications(eperror):
        error_dict = {"common.notAuthorized": "Authorization issue due to incorrect RBAC roles on EndaceProbe",
                      "duration.invalidInput": "Fix Invalid search starttime, endtime or timeframe",
                      "timestamp.invalidInput": "Fix Invalid search starttime, endtime or timeframe",
                      "query.serviceLayerError": "One of the search parameters have invalid syntax",
                      "filter.invalidFilterFormat": "One of the search parameters have invalid syntax",
                      "download.emptyDatasource": "Empty Packet Datasource, this happens when packet data has "
                                                  "rotated out but metadata is still available due to incorrect "
                                                  "datastore sizing configuration. Contact support@endace.com for "
                                                  "any technical assistance on optimal datasource sizing",
                      "FileNotFound": "File not found on EndaceProbe",
                      "SearchTimeOut": "Search query has timed out. Improve search by narrowing search filter "
                                       "items - IP addresses, Port or Timeframe. If problem persists "
                                       "contact support@endace.com to review EndaceProbe configuration",
                      }

        raise Exception(error_dict.get(eperror, f"try again. contact support@endace.com and report {eperror} "
                                                f"if problem persists"))

    #  search
    def create_search_task(self, args=None):
        """ create a search task on Endace Probe
        Args: dict
        Returns:
            Dictionary context data in response to the command execution
       """
        input_args_dict = args
        input_args_dict.update({"filterby": []})

        result = {"Task": "CreateSearchTask", "Status": "Started", "Error": "NoError", "JobID": ""}

        #   Filter order
        if input_args_dict['ip']:
            input_args_dict['filterby'].append(0)
        if input_args_dict['src_host_list']:
            input_args_dict['filterby'].append(1)
        if input_args_dict['dest_host_list']:
            input_args_dict['filterby'].append(2)
        if input_args_dict['src_port_list']:
            input_args_dict['filterby'].append(3)
        if input_args_dict['dest_port_list']:
            input_args_dict['filterby'].append(4)
        if input_args_dict['protocol']:
            input_args_dict['filterby'].append(5)
        if input_args_dict['port']:
            input_args_dict['filterby'].append(6)

        with EndaceWebSession(app_url=self.applianceurl, username=self.username, password=self.password,
                              cert_verify=self.cert_verify) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rd = api.get(path)
            if rd.status_code == 200:
                path = "queries/"
                evid = EndaceVisionData(input_args_dict)
                rp = api.post(path, json=evid.build_search_data())
                if rp.status_code == 200:
                    try:
                        response = rp.json()
                    except json.decoder.JSONDecodeError:
                        raise Exception(f"JsonDecodeError - path {path}")
                    else:
                        meta = response.get("meta", {})
                        payload = response.get("payload")
                        if meta:
                            meta_error = meta.get("error")
                            if meta_error is not None:
                                if meta_error is not False:
                                    result['Status'] = "Failed"
                                    result['Error'] = str(meta_error)
                                else:
                                    if payload is not None:
                                        result['JobID'] = payload
                                    else:
                                        result['Status'] = "Failed"
                                        result['Error'] = f"ServerError - empty payload data from {path}"
                        else:
                            result['Status'] = "Failed"
                            result['Error'] = f"ServerError - empty meta data from {path}"
                else:
                    result['Status'] = "Failed"
                    result['Error'] = f"HTTP {rp.status_code} to /{path}"
            else:
                result['Status'] = "Failed"
                result['Error'] = f"HTTP {rd.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    def get_search_status(self, args=None):
        """ get status of the search task on Endace Probe
           Args: string - Job ID
           Returns:
               Dictionary context data in response to the command execution
        """
        result = {'Task': "GetSearchStatus", "Status": "complete", "Error": "NoError", "JobProgress": '0',
                  "DataSources": [], "TotalBytes": 0, "JobID": args}

        matching_data = 0
        keys = []
        values = []
        id_to_key_dict = dict()
        app_dict = dict()

        with EndaceWebSession(app_url=self.applianceurl, username=self.username, password=self.password,
                              cert_verify=self.cert_verify) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rd = api.get(path)
            if rd.status_code == 200:
                path = "queries/" + args
                progress_status = True
                query_time = calendar.timegm(time.gmtime())
                while progress_status:
                    #  progress loop
                    #  exit when whichever occurrs before, search timeout or search progress = 100% or search returns an
                    #   unknown value
                    current_time = calendar.timegm(time.gmtime())
                    if current_time - query_time > self.delta_time:
                        progress_status = False
                        result['Status'] = "InProgress"
                        result['Error'] = "SearchTimeOut"
                    else:
                        rj = api.get(path)
                        if rj.status_code == 200:
                            #  Check metadata for no error.
                            try:
                                response = rj.json()
                            except json.decoder.JSONDecodeError:
                                raise Exception(f"JsonDecodeError - path {path}")
                            else:
                                meta = response.get("meta", {})
                                if meta:
                                    meta_error = meta.get("error")
                                    if meta_error is not None:
                                        if meta_error is not False:
                                            progress_status = False
                                            result['Status'] = "complete"
                                            result['Error'] = str(meta_error)
                                        else:
                                            #  check payload for no error
                                            payload = response.get("payload")
                                            if payload is not None:
                                                progress = payload.get("progress")
                                                if progress is not None:
                                                    result['JobProgress'] = str(progress)
                                                    #  check if the Search Job has finished.
                                                    #  if so, return a data dict back to Demisto
                                                    #  if No, Wait and loop in to run another status check,
                                                    #   until "self.delta_time" has elapsed
                                                    payload_data = payload.get("data")
                                                    if payload_data is not None:
                                                        if int(progress) == 100:
                                                            progress_status = False
                                                            for data_map_dict in payload_data:
                                                                id_to_key_dict[data_map_dict['id']] = \
                                                                    data_map_dict['name']

                                                            for top_key in payload["top_keys"]:
                                                                keys.append(id_to_key_dict[top_key])

                                                            #   Calculate Total matching MBytes
                                                            for top_value in payload["top_values"]:
                                                                matching_data = matching_data + int(top_value)
                                                                values.append(str(top_value))

                                                            result['TotalBytes'] = int(matching_data)

                                                            for index in range(len(keys)):
                                                                app_dict[keys[index]] = values[index] + ' Bytes'

                                                            result['Status'] = str(payload['state'])
                                                            result['DataSources'] = keys
                                            else:
                                                progress_status = False
                                                result['Status'] = "Failed"
                                                result['Error'] = f"ServerError - empty payload data from {path}"
                                else:
                                    progress_status = False
                                    result['Status'] = "Failed"
                                    result['Error'] = f"ServerError - empty meta data from {path}"
                        else:
                            progress_status = False
                            result['Status'] = rj.status_code
                            result['Error'] = f"ServerError - HTTP {rj.status_code} to /{path}"
                    #   wait time before next run
                    time.sleep(self.wait_time)
            else:
                result['Status'] = "Failed"
                result['Error'] = f"ServerError - HTTP {rd.status_code} to /{path}"

        if result['Status'] != 'complete':
            self.handle_error_notifications(result['Error'])
        return result

    def delete_search_task(self, args=None):
        """ delete the search task on Endace Probe
            Args: string - Job ID
            Returns:
                dict with delete status
        """
        result = {"Task": "DeleteSearchTask", "Status": "Deleted", "Error": "NoError", "JobID": args}

        with EndaceWebSession(app_url=self.applianceurl, username=self.username, password=self.password,
                              cert_verify=self.cert_verify) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rd = api.get(path)
            if rd.status_code == 200:
                path = "queries/" + args
                dr = api.delete(path)
                if dr.status_code == 200:
                    try:
                        response = dr.json()
                    except json.decoder.JSONDecodeError:
                        raise Exception(f"JsonDecodeError - path {path}")
                    else:
                        meta = response.get('meta', {})
                        if meta:
                            meta_error = meta.get("error")
                            if meta_error is not None:
                                if meta_error is not False:
                                    result['Status'] = "complete"
                                    result['Error'] = str(meta_error)
                        else:
                            result['Status'] = "Failed"
                            result['Error'] = f"ServerError - empty meta data from {path}"
            else:
                result['Status'] = "Failed"
                result['Error'] = f"ServerError - HTTP {rd.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    #  archive
    def create_archive_task(self, args=None):
        """ create an archive task on Endace Probe
        Args: dict
        Returns:
            Dictionary context data in response to the command execution
        """
        input_args_dict = args
        input_args_dict.update({"archive_filename": (args.get('archive_filename')
                                                     + '-' + str(calendar.timegm(time.gmtime())))
                                })
        input_args_dict.update({"filterby": []})
        input_args_dict.update({"ids": ""})

        result = {"Task": "CreateArchiveTask", "Status": "Started", "Error": "NoError", "JobID": "",
                  "Start": args.get('start'), "End": args.get('end'), "P2Vurl": "",
                  "FileName": args['archive_filename']}

        datasource = self.hostname + ":" + input_args_dict['archive_filename']

        start_time_in_ms = str(int(input_args_dict['start']) * 1000)
        end_time_in_ms = str(int(input_args_dict['end']) * 1000)

        p2v_url = f'{self.applianceurl}/vision2/pivotintovision/?datasources={datasource}' \
                  f'&title={result["FileName"]}&start={start_time_in_ms}&end={end_time_in_ms}' \
                  f'&tools=trafficOverTime_by_app%2Cconversations_by_ipaddress'

        #   Endace Filter order
        if input_args_dict['ip']:
            input_args_dict['filterby'].append(0)
            p2v_url = p2v_url + "&ip=" + input_args_dict['ip']
        if input_args_dict['src_host_list']:
            input_args_dict['filterby'].append(1)
            src_ip = ''
            for ip in input_args_dict['src_host_list']:
                src_ip = src_ip + "," + ip
            src_ip = src_ip[1:]
            p2v_url = p2v_url + "&sip=" + src_ip
        if input_args_dict['dest_host_list']:
            input_args_dict['filterby'].append(2)
            dest_ip = ''
            for ip in input_args_dict['dest_host_list']:
                dest_ip = dest_ip + "," + ip
            dest_ip = dest_ip[1:]
            p2v_url = p2v_url + "&dip=" + dest_ip
        if input_args_dict['src_port_list']:
            input_args_dict['filterby'].append(3)
            port = ''
            for sport in input_args_dict['src_port_list']:
                port = port + "," + sport
            port = port[1:]
            p2v_url = p2v_url + "&sport=" + port
        if input_args_dict['dest_port_list']:
            input_args_dict['filterby'].append(4)
            port = ''
            for dport in input_args_dict['dest_port_list']:
                port = port + "," + dport
            port = port[1:]
            p2v_url = p2v_url + "&dport=" + port
        if input_args_dict['protocol']:
            input_args_dict['filterby'].append(5)
        if input_args_dict['port']:
            input_args_dict['filterby'].append(6)
            p2v_url = p2v_url + "&port=" + input_args_dict['port']

        evid = EndaceVisionData(input_args_dict)
        with EndaceWebSession(app_url=self.applianceurl, username=self.username, password=self.password,
                              cert_verify=self.cert_verify) as sess:
            #  Extract list of rotationfiles datasources and exclude previously archived files
            rotfile_ids = []

            api = EndaceVisionAPIAdapter(sess)
            path = "datasources"
            rd = api.get(path)
            try:
                response = rd.json()
            except json.decoder.JSONDecodeError:
                raise Exception(f"JsonDecodeError - path {path}")
            else:
                if rd.status_code == 200:
                    payload = response.get("payload")
                    for rotfile in payload:
                        if rotfile["type"] == "rotation_file_v2":
                            rotfile_ids.append(rotfile["id"])

                    input_args_dict['ids'] = rotfile_ids

                    path = "archive/"
                    rp = api.post(path, json=evid.build_archive_data())
                    if rp.status_code == 200:
                        try:
                            response = rp.json()
                        except json.decoder.JSONDecodeError:
                            raise Exception(f"JsonDecodeError - path {path}")
                        else:
                            meta = response.get("meta", {})
                            payload = response.get("payload")
                            if meta:
                                meta_error = meta.get("error")
                                if meta_error is not None:
                                    if meta_error is not False:
                                        result['Status'] = "Failed"
                                        result['Error'] = str(meta_error)
                                    else:
                                        if payload is not None:
                                            result['JobID'] = payload
                                            result['P2Vurl'] = f'[Endace PivotToVision URL]({p2v_url})'
                                        else:
                                            result['Status'] = "Failed"
                                            result['Error'] = f"ServerError - empty payload data from {path}"
                            else:
                                result['Status'] = "Failed"
                                result['Error'] = f"ServerError - empty meta data from {path}"
                    else:
                        result['Status'] = "Failed"
                        result['Error'] = f"HTTP {rd.status_code} to /{path}"
                else:
                    result['Status'] = "Failed"
                    result['Error'] = f"HTTP {rd.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    def get_archive_status(self, args=None):
        """ get status of the archive task on Endace Probe
           Args: string - Archived File Name
           Returns:
               Dictionary context data in response to the command execution
        """
        result = {"Task": "GetArchiveStatus", "Error": "NoError", "Status": "InProgress",
                  "FileName": args['archive_filename'], "FileSize": 0}

        with EndaceWebSession(app_url=self.applianceurl, username=self.username, password=self.password,
                              cert_verify=self.cert_verify) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            progress_status = True
            query_time = calendar.timegm(time.gmtime())

            while progress_status:
                #   wait time before next run
                time.sleep(self.wait_time)
                current_time = calendar.timegm(time.gmtime())
                if current_time - query_time > self.delta_time:
                    progress_status = False
                    result['Status'] = "InProgress"

                rf = api.get(path)
                if rf.status_code == 200:
                    try:
                        response = rf.json()
                    except json.decoder.JSONDecodeError:
                        raise Exception(f"JsonDecodeError - path {path}")
                    else:
                        meta = response.get("meta", {})
                        payload = response.get("payload")
                        if meta:
                            meta_error = meta["error"]
                            if meta_error is not None:
                                if meta_error is not False:
                                    progress_status = False
                                    result['Status'] = "InProgress"
                                    result['Error'] = str(meta_error)
                                else:
                                    #   progress loop
                                    #   exit at timeout or archive finished
                                    #  archive_payload = payload
                                    for file in payload:
                                        if args['archive_filename'] == file['name']:
                                            result['FileName'] = file['name']
                                            if not file['status']['inUse']:
                                                #  archive finished
                                                progress_status = False
                                                result['FileSize'] = file['usage']
                                                result['Status'] = "Finished"
                                            else:
                                                result['Status'] = "InProgress"
                                            break

                        else:
                            progress_status = False
                            result['Status'] = "Failed"
                            result['Error'] = f"ServerError - empty meta data from {path}"
                else:
                    progress_status = False
                    result['Status'] = rf.status_code
                    result['Error'] = f"ServerError - HTTP {rf.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    def delete_archive_task(self, args=None):
        """ delete the search task on Endace Probe
            Args: string - Job ID
            Returns: dict with delete status
        """
        result = {"Task": "DeleteArchiveTask", "Error": "NoError", "Status": "Deleted", "JobID": args}

        with EndaceWebSession(app_url=self.applianceurl, username=self.username, password=self.password,
                              cert_verify=self.cert_verify) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rd = api.get(path)
            if rd.status_code == 200:
                path = "queries/" + args
                dr = api.delete(path)
                if dr.status_code == 200:
                    try:
                        response = dr.json()
                    except json.decoder.JSONDecodeError:
                        raise Exception(f"JsonDecodeError - path {path}")
                    else:
                        meta = response.get('meta', {})
                        if meta:
                            meta_error = meta.get("error")
                            if meta_error is not None:
                                if meta_error is not False:
                                    result['Status'] = "complete"
                                    result['Error'] = str(meta_error)
                        else:
                            result['Status'] = "Failed"
                            result['Error'] = f"ServerError - empty meta data from {path}"
            else:
                result['Error'] = rd.status_code
                result['Error'] = f"ServerError - HTTP {rd.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    def delete_archived_file(self, args=None):
        """ Delete archived file on Endace Probe
           Args: string - Archived File Name
           Returns:
               Dictionary context data in response to the command execution
        """
        result = {"Task": "DeleteArchivedFile", "Error": "NoError", "Status": "FileNotFound",
                  "FileName": args['archived_filename']}

        with EndaceWebSession(app_url=self.applianceurl, username=self.username, password=self.password,
                              cert_verify=self.cert_verify) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rf = api.get(path)
            if rf.status_code == 200:
                try:
                    response = rf.json()
                except json.decoder.JSONDecodeError:
                    raise Exception(f"JsonDecodeError - path {path}")
                else:
                    meta = response.get("meta", {})
                    payload = response.get("payload")
                    if meta:
                        meta_error = meta["error"]
                        if meta_error is not None:
                            if meta_error is not False:
                                result['Status'] = "FileNotFound"
                                result['Error'] = str(meta_error)
                            else:
                                #   Delete archived File
                                for file in payload:
                                    if result['FileName'] == file['name'] and len(file["id"]):
                                        #   File available to delete
                                        if file['type'] == 'archive_file':
                                            archived_file_path = f'files?_={str(calendar.timegm(time.gmtime()))}000'\
                                                                 f'&files={file["id"]}'
                                            df = api.delete(archived_file_path)
                                            try:
                                                response = df.json()
                                            except json.decoder.JSONDecodeError:
                                                raise
                                            else:
                                                meta = response.get("meta", {})
                                                if df.status_code == 200:
                                                    if meta["error"] is None:
                                                        result['Status'] = "FileNotFound"
                                                        result['Error'] = meta["error"]
                                                    else:
                                                        result['Status'] = "FileDeleted"
                                                else:
                                                    result['Error'] = f"ServerError - HTTP {rf.status_code} to /{path}"

                    else:
                        result['Status'] = "Failed"
                        result['Error'] = f"ServerError - empty meta data from {path}"
            else:
                result['Status'] = "Failed"
                result['Error'] = f"ServerError - HTTP {rf.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result

    #  download
    def download_pcap(self, args=None):
        """ download a PCAP file from EndaceProbe
            Args:
                dict - FileName and FileSize
            Returns:
                Dictionary context data in response to the command execution
        """
        result = {"Task": "DownloadPCAP", "Error": "NoError", "Status": "FileNotFound", "FileName": args['filename'],
                  "FileSize": 0, "FileType": "UnKnown", "FileURL": 'UnKnown', "FileUser": 'UnKnown'}
        with EndaceWebSession(app_url=self.applianceurl, username=self.username, password=self.password,
                              cert_verify=self.cert_verify) as sess:
            api = EndaceVisionAPIAdapter(sess)
            path = "files"
            rf = api.get(path)
            if rf.status_code == 200:
                try:
                    response = rf.json()
                except json.decoder.JSONDecodeError:
                    raise Exception(f"JsonDecodeError - path {path}")
                else:
                    meta = response.get("meta", {})
                    payload = response.get("payload")
                    if meta:
                        meta_error = meta["error"]
                        if meta_error is not None:
                            if meta_error is not False:
                                result['Status'] = "FileNotFound"
                                result['Error'] = str(meta_error)
                            else:
                                #   Download PCAP File
                                for file in payload:
                                    if result['FileName'] == file['name'] and len(file["id"]):
                                        file_numerical_part = float(re.findall(r'[\d\.]+', file['usage'])[0])

                                        if 'KB' in file['usage']:
                                            filesize = file_numerical_part * 0.001
                                        elif 'GB' in file['usage']:
                                            filesize = file_numerical_part * 1000
                                        elif 'TB' in file['usage']:
                                            filesize = file_numerical_part * 1000000
                                        else:
                                            filesize = file_numerical_part * 1

                                        if filesize <= int(args['filesizelimit']):
                                            result['FileName'] = file['name'] + ".pcap"
                                            if not file['status']['inUse']:
                                                #   File available to download
                                                pcapfile_url_path = ("files/%s/stream?format=pcap" % file["id"])
                                                d = api.get(pcapfile_url_path)
                                                if d.status_code == 200:
                                                    demisto.results(fileResult(f'{result["FileName"]}', d.content,
                                                                               file_type=entryTypes['entryInfoFile']))

                                                    result['FileURL'] = f'[Endace PCAP URL]'\
                                                                        f'({self.applianceurl}/vision2/data/'\
                                                                        f'{pcapfile_url_path})'

                                                    result['FileSize'] = file['usage']
                                                    result['Status'] = "DownloadFinished"
                                                    result['FileType'] = file['type']
                                                    result['FileUser'] = file['user']
                                                else:
                                                    result['Status'] = "FileNotFound"
                                                    result['Error'] = f"ServerError - HTTP {rf.status_code} to /{path}"
                                            else:
                                                result['Status'] = "FileInUse"
                                        else:
                                            result['Status'] = "FileExceedsSizeLimit"
                    else:
                        result['Status'] = "Failed"
                        result['Error'] = f"ServerError - empty meta data from {path}"
            else:
                result['Status'] = "Failed"
                result['Error'] = f"ServerError - HTTP {rf.status_code} to /{path}"

        if result['Status'] == 'Failed':
            self.handle_error_notifications(result['Error'])
        return result


''' COMMAND FUNCTION '''
#  Search Commands


def endace_create_search_command(app, args):
    """ create search command function
    Function Params:
        app: Endace App Client
        args:
            start time: in ISO 8601 format
            end time: in ISO 8601 format
            ip: comma separated ips to search for
            port: comma separated ports to search for
            src ips: comma separated source ips to search for. Src IPs will be OR'd
            dest ips: comma separated destination ips to search for. Destination IPs will be OR'd
            src ports: comma separated source ports to search for. Src Ports will be OR'd
            dest ports: comma separated destination ports to search for. Destination ports will be OR'd
            protocol: TCP or UDP protocol value
            search window: number in second
    Returns: The Search JOB ID.
    Raises:
        ValueError: If input argument is in wrong format.

    """
    if len(args.values()):

        function_args = app.endace_get_input_arguments(args)

        #  calling search task function of app instance
        result = app.create_search_task(function_args)

        #  create entry context to return to Demisto
        output = {'Endace.Search.Task(val.JobID == obj.JobID)': result}
        table_header = ['Task', 'JobID', 'Status', 'Error']
        readable_output = tableToMarkdown('EndaceResult', [result], headers=table_header, removeNull=False)
        raw_response = result

        return readable_output, output, raw_response
    else:
        raise ValueError("No arguments were provided to search by, at least one must be provided")


def endace_delete_search_task_command(app, args):
    """
        Delete search Job on Endace Probe
        Function Params:
        app: Endace App Client
        args: string - Search JOB id
        Returns:
            Null
        Raises:
             ValueError: If input argument is in wrong format
             exception: If delete command fails
        """

    jobid = args.get("jobid")
    if len(re.findall(r'([0-9a-fA-F]+)', jobid)) == 5:

        #   calling search status function of app instance
        result = app.delete_search_task(jobid)

        #   create entry context to return to Demisto
        output = {'Endace.Search.Delete(val.JobID == obj.JobID)': result}
        table_header = ["Task", "JobID", "Status", "Error"]
        readable_output = tableToMarkdown('EndaceResult', result, headers=table_header, removeNull=False)
        raw_response = result
        return readable_output, output, raw_response
    else:
        raise ValueError("Incorrect JOB ID provided")


def endace_get_search_status_command(app, args):
    """ Poll search task on Endace Probe by given Job ID
        Function Params:
        app: Endace App Client
        args: Search JobID
        Returns:
              Dictionary context data in response to the command execution
        Raises:
             ValueError: If input argument is in wrong format.
    """

    jobid = args.get("jobid")
    if len(re.findall(r'([0-9a-fA-F]+)', jobid)) == 5:
        #   calling search status function of app instance
        result = app.get_search_status(jobid)

        #   create entry context to return to Demisto
        output = {'Endace.Search.Response(val.JobID == obj.JobID)': result}
        table_header = ['Task', 'JobID', 'Status', 'Error', 'JobProgress', 'DataSources', 'TotalBytes']
        readable_output = tableToMarkdown('EndaceResult', result, headers=table_header, removeNull=False)
        raw_response = result

        return readable_output, output, raw_response

    else:
        raise ValueError("Wrong JOB ID provided")


#  Archive Commands


def endace_create_archive_command(app, args):
    """ create archive command function
    Function Params:
        app: Endace App Client
        args:
            start time: in ISO 8601 format
            end time: in ISO 8601 format
            ip: comma separated ips to search for
            port: comma separated ports to search for
            src ips: comma separated source ips to search for. Src IPs will be OR'd
            dest ips: comma separated destination ips to search for. Destination IPs will be OR'd
            src ports: comma separated source ports to search for. Src Ports will be OR'd
            dest ports: comma separated destination ports to search for. Destination ports will be OR'd
            protocol: TCP or UDP protocol value
            search window: number representing seconds
            archive_filename: string representing archive filename
    Returns: The Archive JOB ID.
    Raises:
        ValueError: If input argument is in wrong format.

    """
    if len(args.values()):
        #   archive file name
        if re.fullmatch(r'[\w0-9_-]+', args.get("archive_filename")) is None:
            raise ValueError("Wrong format of archive_filename. text, numbers, underscore or dash is supported")

        function_args = app.endace_get_input_arguments(args)
        function_args['archive_filename'] = args.get("archive_filename")

        #  calling archive task function of app instance
        result = app.create_archive_task(function_args)

        #  create entry context to return to Demisto
        output = {'Endace.Archive.Task(val.JobID == obj.JobID)': result}
        table_header = ['Task', 'FileName', 'P2Vurl', 'Status', 'Error', 'JobID']
        readable_output = tableToMarkdown('EndaceResult', [result], headers=table_header, removeNull=False)
        raw_response = result
        return readable_output, output, raw_response
    else:
        raise ValueError("No arguments were provided to search by, at least one Filter item, "
                         "either start/end time or timeframe is required ")


def endace_delete_archive_task_command(app, args):
    """
        Delete archive Job on Endace Probe
        Function Params:
        app: Endace App Client
        args: Archive JOB id - string
        Returns:
            Null
        Raises:
             ValueError: If input argument is in wrong format
             exception: If delete command fails
    """
    jobid = args.get("jobid")
    if re.fullmatch(r'[0-9a-zA-Z\-]+', jobid) is not None:

        #   calling delete archive task function of app instance
        result = app.delete_archive_task(jobid)

        #   create entry context to return to Demisto
        output = {'Endace.Archive.Delete(val.JobID == obj.JobID)': result}
        table_header = ["Task", "JobID", "Status", "Error"]
        readable_output = tableToMarkdown('EndaceResult', result, headers=table_header, removeNull=False)
        raw_response = result
        return readable_output, output, raw_response
    else:
        raise ValueError("Incorrect JOB ID provided")


def endace_get_archive_status_command(app, args):
    """ Poll archive task on Endace Probe by given Job ID
        Function Params:
        app: Endace App Client
        args: archive JobID - string
        Returns:
              Dictionary context data in response to the command execution
        Raises:
             ValueError: If input argument is in wrong format.
    """
    if len(args.values()):
        function_args = dict()
        #   archive file name
        if re.fullmatch(r'[\w0-9_-]+', args.get("archive_filename")) is None:
            raise ValueError("Wrong format of archive_filename. text, numbers, underscore or dash is supported")
        function_args['archive_filename'] = args.get("archive_filename")

        #  calling app instance
        result = app.get_archive_status(function_args)

        #   create entry context to return to Demisto
        output = {'Endace.Archive.Response(val.FileName == obj.FileName)': result}
        table_header = ['Task', 'FileName', 'Status', 'Error', 'FileSize']
        readable_output = tableToMarkdown('EndaceResult', result, headers=table_header, removeNull=False)
        raw_response = result
        return readable_output, output, raw_response
    else:
        raise ValueError("Archived FileName must be provided")


def endace_delete_archived_file_command(app, args):
    """ Delete archived file on Endace Probe
    Function Params:
    app: Endace App Client
    args: string , archive filename
    Returns:
        Dictionary context data in response to the command execution
    Raises:
        ValueError: If input argument is in wrong format.
    """

    if len(args.values()):
        function_arg = dict()
        #   archive file name
        function_arg['archived_filename'] = args.get("archived_filename")

        #   archive file name
        if re.fullmatch(r'[\w0-9_-]+', args.get("archived_filename")) is None:
            raise ValueError("Wrong format of archived_filename. text, numbers, underscore or dash is supported")

        #   calling archive file delete task function of app instance
        result = app.delete_archived_file(function_arg)

        #   create entry context to return to Demisto
        output = {'Endace.ArchivedFile.Delete(val.FileName == obj.FileName)': result}
        table_header = ['Task', 'FileName', 'Status', 'Error']
        readable_output = tableToMarkdown('EndaceResult', result, headers=table_header, removeNull=False)
        raw_response = result
        return readable_output, output, raw_response
    else:
        raise ValueError("Archived FileName must be provided")


#  Download Command
def endace_download_pcap_command(app, args):
    """ download pcap file function
       Function Params:
        app: Endace App Client
        args: dict of
               filename: Name of the file to download
               filesize: limit download to max filesize.
       Returns: Dictionary context data in response to the command execution
       Raises:
           ValueError: If input argument is in wrong format.
       """
    if len(args.values()):
        function_args = {"filename": args.get("filename"), "filesizelimit": args.get("filesizelimit")}

        #   Doing a sanity check on input function arguments
        try:
            int(function_args['filesizelimit'])
        except ValueError:
            raise ValueError("Filesize Limit value is incorrect, must be an integer 1  or greater")
        else:
            if int(function_args['filesizelimit']) < 1:
                raise ValueError("Filesize Limit value is incorrect, must be an integer 1  or greater")

            #   calling download PCAP function of app instance
            result = app.download_pcap(function_args)

            #   create entry context to return to Demisto

            output = {'Endace.Download.PCAP(val.FileName == obj.FileName)': result}
            table_header = ['Task', 'FileName', 'Status', 'Error', 'FileSize', 'FileType', 'FileUser', 'FileURL']
            readable_output = tableToMarkdown('EndaceResult', [result], headers=table_header, removeNull=False)
            raw_response = result
            return readable_output, output, raw_response
    else:
        raise ValueError("FileName must be provided")


#  Test Command
def endace_test_command(appurl, username, password, insecure):
    if re.match(r'https://[\w\-\.]+\.\w+', appurl) is None:
        raise ValueError('Wrong Appliance URL. Make sure URL is in format of https://<fqdn/ip[:port]>')
    with EndaceWebSession(app_url=appurl, username=username, password=password, cert_verify=insecure):
        return 'ok'


#  Main Function
def main():
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    ''' COMMANDS + REQUESTS FUNCTIONS '''
    command = demisto.command()
    applianceurl = demisto.params().get('applianceurl')
    username = demisto.params().get('credentials').get('identifier')
    password = demisto.params().get('credentials').get('password')
    insecure = not demisto.params().get('insecure', False)
    hostname = demisto.params().get('hostname')

    LOG(f'Command being called is {demisto.command()}')

    try:
        handle_proxy()
        if command == 'test-module':
            """
               Returning 'ok' indicates that the the user can login to EndaceProbe successfully with his credentials.
               Returns:
                   'ok' if test passed, anything else will fail the test
            """
            demisto.results(endace_test_command(applianceurl, username, password, insecure))
        else:
            app = EndaceApp(applianceurl, username, password, insecure, hostname)
            """ Command Modules """
            if command == "endace-create-search":
                return_outputs(*endace_create_search_command(app, demisto.args()))
            elif command == "endace-get-search-status":
                return_outputs(*endace_get_search_status_command(app, demisto.args()))
            elif command == "endace-delete-search-task":
                return_outputs(*endace_delete_search_task_command(app, demisto.args()))
            elif command == "endace-create-archive":
                return_outputs(*endace_create_archive_command(app, demisto.args()))
            elif command == "endace-get-archive-status":
                return_outputs(*endace_get_archive_status_command(app, demisto.args()))
            elif command == "endace-delete-archive-task":
                return_outputs(*endace_delete_archive_task_command(app, demisto.args()))
            elif command == "endace-delete-archived-file":
                return_outputs(*endace_delete_archived_file_command(app, demisto.args()))
            elif command == "endace-download-pcap":
                return_outputs(*endace_download_pcap_command(app, demisto.args()))

    except Exception as err:
        err_msg = f'Error in Endace integration: {err}'
        return_error(err_msg, error=err)


#   python2 uses __builtin__ python3 uses builtins
if __name__ == '__builtin__' or __name__ == 'builtins':
    main()
