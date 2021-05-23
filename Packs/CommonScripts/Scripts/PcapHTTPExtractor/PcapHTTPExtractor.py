from CommonServerPython import *
from CommonServerUserPython import *
import zlib
import pyshark
from datetime import datetime
import re
import sys
import traceback
try:
    from StringIO import StringIO  # for Python 2
except ImportError:
    from io import StringIO  # for Python 3

serr = sys.stderr
sys.stderr = StringIO()

''' GLOBAL VARIABLES '''
LIMIT = ""
START = ""
LIMIT_DATA = 0
ALLOWED_CONTENT_TYPES: tuple = ()

# Used to convert pyshark keys to Demisto's conventions
# Also used as a whitelist of relevant keys for outputs.
PYSHARK_RES_TO_DEMISTO = {

    # Request
    "http.chat": "HttpChat",
    "http.request.method": "HttpRequestMethod",
    "http.request.uri": "HttpRequestURI",
    "http.request.version": "HttpRequestVersion",
    "http.host": "HttpHost",
    "http.x_forwarded_for": "HttpXForwardedFor",
    "http.connection": "HttpConnection",
    "http.user_agent": "HttpUserAgent",
    "http.accept": "HttpAccept",
    "http.referer": "HttpReferer",
    "http.accept_encoding": "HttpAcceptEncoding",
    "http.accept_language": "HttpAcceptLanguage",
    "http.request.full_uri": "HttpRequestFullURI",
    "http.cookie": "HttpCookie",

    # Response
    "http.response.version": "HttpResponseVersion",
    "http.response.code": "HttpResponseCode",
    "http.server": "HttpServer",
    "http.date": "HttpDate",
    "http.content_type": "HttpContentType",
    "http.content_length": "HttpContentLength",
    "http.last_modified": "HttpLastModified",
    "http.cache_control": "HttpCacheControl",
    "http.file_data": "HttpFileData",
    "http.transfer_encoding": "HttpTransferEncoding",
    "http.content_encoding": "HttpContentEncoding",
}


def _file_has_extension(file_name, extensions):
    """
    Check if a file name has an extension.
    Returns true/false

    :param file_name: the file name to check against.
    :param extensions: extensions to test if exists in file_name.
    :return: True if one of the extensions is in the file_name
    """
    for ext in extensions:
        if file_name.endswith(ext):
            return True

    return False


def _find_entry_id_by_name(file_name, extensions=None):
    """
    Scan all entries and find corresponding entry id by file name
    extensions, an array used to furthur filter the entries.

    :param file_name: find by file name.
    :param extensions:  filter more by the file extension.
    :return: the found entryID
    """
    entries = demisto.executeCommand('getEntries', {})
    found_entry_id = None
    for entry in entries:
        entry_file_name = demisto.get(entry, 'File')
        is_correct_file = file_name.lower() == entry_file_name.lower()
        has_correct_extension = _file_has_extension(file_name, extensions) if extensions else True

        if is_correct_file and has_correct_extension:
            found_entry_id = entry['ID']
            break

    if not found_entry_id:
        demisto.results({"Type": entryTypes["note"],
                         "ContentsFormat": formats["markdown"],
                         "Contents": "### No file found",
                         "EntryContext": {"PcapHTTPExtractor.Flows": []}
                         })
        sys.exit(0)

    return found_entry_id


def get_entry_from_args():
    """
    Handle finding the file entry using the user supplied arguments
    return the entry or quits script entirely.

    :rtype: object containing the entry of the found file and the entry_id or error & exit
    """
    # Get the pcap file from arguments
    entry_id = None
    if 'pcapFileName' in demisto.args() \
            and 'entryID' not in demisto.args():

        PCAP_FILE = demisto.args()["pcapFileName"]
        entry_id = _find_entry_id_by_name(PCAP_FILE, [".pcap", ".cap", ".pcapng"])
    elif 'entryID' in demisto.args():
        entry_id = demisto.args()["entryID"]
    else:
        return_error('You must set pcapFileName or entryID when executing the PcapHTTPExtract script.')

    res = demisto.executeCommand('getFilePath', {'id': entry_id})

    if len(res) > 0 and res[0]['Type'] == entryTypes['error']:
        return_error(f'Failed to get the file path for entry: {entry_id}')

    return res, entry_id


def _chunker(seq, size):
    """
    Function that groups items in a sequence for easier iteration of multiple items at once.

    :param seq: the sequence (list/generator)
    :param size: the size of the group (chunk)
    :return: an iterator that outputs groups of items (chunks) from the sequence
    """
    ret = []
    for i in range(0, len(seq), size):
        chunk = seq[i: i + size]

        # Make sure the chunks are with a specified size
        padding = ["" for j in range(size - len(chunk))]
        ret.append(chunk + padding)

    return iter(ret)


def decode_gzip(str_compressed):
    """
    Decode a hex string with gz decompression

    :type str_compressed: hex string gz compressed
    :return: gz decompressed string
    """
    decoded = zlib.decompress(bytearray.fromhex(str_compressed), 47)
    return decoded


def _date_to_ISO(strdate):
    """
    Return date in ISO format, from pyshark date output

    :type strdate: string of date (pyshark's output) that is not in ISO format
    :return: an ISO formatted date
    """
    return datetime.strptime(strdate, '%a, %d %b %Y %H:%M:%S %Z').isoformat()


def get_next_matching_index(http_packets, tcp_src, tcp_dst, ip_src, ip_dst):
    for i, p in enumerate(http_packets):
        if p["TCP"].srcport == tcp_dst and \
                p["TCP"].dstport == tcp_src and \
                p["IP"].src == ip_dst and \
                p["IP"].dst == ip_src:
            return i
    return None


def fix_order(http_packets):
    """
    Re-organizes the http packets to be request-response pairs.
    Sometimes pyshark doesn't put the packets in the order they are HTTP-wise.
    So we are re-organizing them according to the tcp and ip information of the packets.
    :param http_packets:
    :return: http_packets
    """
    new_order = []

    # For each packet find the next one that matches the tcp,ip tuple.
    while len(http_packets) > 0:
        packet = http_packets[0]
        tcp_src = packet["TCP"].srcport
        tcp_dst = packet["TCP"].dstport
        ip_src = packet["IP"].src
        ip_dst = packet["IP"].dst
        new_order.append(packet)
        del http_packets[0]

        next_matching_index = get_next_matching_index(http_packets, tcp_src, tcp_dst, ip_src, ip_dst)
        if next_matching_index is None:
            new_order.append(None)
        else:
            new_order.append(http_packets[next_matching_index])
            del http_packets[next_matching_index]

    return new_order


def get_http_flows(pcap_file_path):
    """
    Return a list of HTTP requests/responses from pcap file

    :param pcap_file_path:
    :return: list of requests/response pairs.
    """
    capture_object = pyshark.FileCapture(pcap_file_path, display_filter='tcp')

    # Filter all non HTTP packets
    http_packets = [p for p in capture_object if "HTTP" in p]
    http_packets = fix_order(http_packets)

    # Construct request <> response dicts
    http_flows = []

    for req, res in _chunker(http_packets, 2):
        sanitized_req = req
        sanitized_res = res

        if req:
            req_fields = req['HTTP'].__dict__["_all_fields"].keys()

            # if the file contains only a response, the response will falsely appear in the 'req' variable
            if 'http.response' in req_fields:
                sanitized_req = None
                sanitized_res = req

        http_flows.append({
            "Request": sanitized_req,
            "Response": sanitized_res
        })
    return http_flows


def get_flow_info(http_flow):
    """
    Get the TCP, IP and Meta information of the flow.

    :param http_flow: http flow object
    :return: tcp (src,dst ports), ip (src, dst addresses)
    """
    return {
        "TcpSrcPort": http_flow["TCP"].srcport,
        "TcpDstPort": http_flow["TCP"].dstport,
        "IpSrc": http_flow["IP"].src,
        "IpDst": http_flow["IP"].dst,
        "MetaSniffTimeStamp": http_flow.sniff_timestamp,
        "ResultIndex": http_flow.frame_info.number
    }


def map_demisto_keys(pyshark_results, keys_transform_map):
    """
    Map all of the whitelisted keys from the transform map dict to the pyshark result

    :param pyshark_results: object from pyshark, use values and transform his keys
    :param keys_transform_map: map of key transformation
    :return: new dict with transformed keys.
    """
    new_keys = {}
    for k, v in pyshark_results.items():
        if k not in keys_transform_map:
            continue
        new_keys[keys_transform_map[k]] = v

    return new_keys


def create_flow_object(flow, keys_transform_map, trim_file_data_size, allowed_content_types):
    """
    Create a flow object constructed from HTTP,TCP,IP and Meta data of the flow.
    Fix the PyShark keys to enforce the Demisto standards. Trim the http data if too big.
    Strip the http data if it isn't allowed.

    :param flow: a http flow.
    :param keys_transform_map: a map of pyshark keys to Demisto standard keys.
    :param trim_file_data_size: the byte siez of max file_data_size
    :param allowed_content_types: allowed content types to display
    :return: an http flow
    """

    if flow is None:
        return {
            "Not found": "No response found"
        }

    # Get the HTTP and TCP, IP and Meta fields.
    r = flow["HTTP"].__dict__["_all_fields"]
    flow_info = get_flow_info(flow)

    # Map the keys to the conventions
    r = map_demisto_keys(r, keys_transform_map)

    # Merge the HTTP and TCP, IP fields.
    r.update(flow_info)

    # Remove the \r\n from the HttpChat
    if "HttpChat" in r:
        r["HttpChat"] = r["HttpChat"].replace("\\r\\n", "")

    # Trim a file data too big
    if "HttpFileData" in r:

        # Remove the \xef\xbf\xbd and \xa hex from the file data
        if '\\xef\\xbf\\xbd' in r["HttpFileData"]:
            r["HttpFileData"] = re.sub("(\\\\xef\\\\xbf\\\\xbd)+", "[UNICODE]", r["HttpFileData"])
        r["HttpFileData"] = r["HttpFileData"].replace("\\xa", "")

        if "HttpContentType" not in r:
            r["HttpFileData"] = "Couldn't find response content type, assuming not allowed."
        elif not r["HttpContentType"].startswith(allowed_content_types):
            r["HttpFileData"] = "[{} is not in allowedContentTypes arg/default]".format(r["HttpContentType"])
        elif len(r["HttpFileData"]) > trim_file_data_size:
            r["HttpFileData"] = r["HttpFileData"][:trim_file_data_size] + "... [TRIMMED by limitData arg]"

    # Fix ISO dates
    if "HttpDate" in r:
        r["HttpDate"] = _date_to_ISO(r["HttpDate"])
    if "HttpLastModified" in r:
        r["HttpLastModified"] = _date_to_ISO(r["HttpLastModified"])

    return r


def format_http_flows(http_flows, keys_transform_map, trim_file_data_size, allowed_content_types):
    """
    Merge the HTTP, IP and TCP fields together and create a usable object for further proceeding.

    :param http_flows:
    :param keys_transform_map:
    :return: http_flows object
    """
    formatted_http_flows = []

    for flow in http_flows:
        req = create_flow_object(flow["Request"], keys_transform_map, trim_file_data_size, allowed_content_types)
        res = create_flow_object(flow["Response"], keys_transform_map, trim_file_data_size, allowed_content_types)

        formatted_http_flows.append({
            "Request": req,
            "Response": res
        })

    return formatted_http_flows


def get_markdown_output(http_flows):
    """
           Convert a list of http flows into a markdown table

           :param http_flows: a list of http packets
           :return: a string of markdown
       """
    result_template = "---\n{req}\n{res}\n---"
    markdown_result = ""

    for i, flow in enumerate(http_flows):
        row = result_template.format(
            req=tableToMarkdown("HTTPRequest #{}".format(i + 1),
                                flow["Request"],
                                flow["Request"].keys()
                                ),
            res=tableToMarkdown("HTTPResponse #{}".format(i + 1),
                                flow["Response"],
                                flow["Response"].keys()
                                )
        )
        markdown_result += row

    return markdown_result


def main():
    try:
        ''' GLOBAL VARIABLES '''
        global LIMIT, START, LIMIT_DATA, ALLOWED_CONTENT_TYPES
        LIMIT = demisto.args().get("limit")
        START = demisto.args().get("start")
        LIMIT_DATA = int(demisto.args().get("limitData"))
        if "allowedContentTypes" not in demisto.args():
            ALLOWED_CONTENT_TYPES = ("text", "application/json", "multipart/form-data",
                                     "application/xml", "application/xhtml+xml",
                                     "application/ld+json", "application/javascript",
                                     "multipart/alternative", "application/x-www-form-urlencoded")
        else:
            ALLOWED_CONTENT_TYPES = tuple(demisto.args()["allowedContentTypes"].split(","))  # type: ignore

        # Parse the arguments
        pcap_file_path_in_container, pcap_entry_id = get_entry_from_args()
        pcap_file_path_in_container = pcap_file_path_in_container[0]['Contents']['path']

        # Work on the pcap file and return a result
        http_flows = get_http_flows(pcap_file_path_in_container)

        # Cut results according to the user args (times 2, because we are working on pairs of requests and responses).
        if START:
            http_flows = http_flows[int(START):]
        if LIMIT:
            http_flows = http_flows[:int(LIMIT)]

        # Format and get output representation of the flows
        formatted_http_flows = format_http_flows(http_flows, PYSHARK_RES_TO_DEMISTO, LIMIT_DATA, ALLOWED_CONTENT_TYPES)
        markdown_output = get_markdown_output(formatted_http_flows)
        context_output = formatted_http_flows

        # Profit, send the output
        demisto.results({"Type": entryTypes["note"],
                         "ContentsFormat": formats["markdown"],
                         "Contents": markdown_output,
                         "EntryContext": {"PcapHTTPFlows": context_output}})
    except Exception as e:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute PcapHTTPExtractor Script. Error: {str(e)}')
    finally:
        sys.stderr = serr


# python2 uses __builtin__ python3 uses builtins
if __name__ in ('__builtin__', 'builtins', '__main__'):
    main()
