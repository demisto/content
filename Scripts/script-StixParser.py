import tempfile

from stix.core import STIXPackage

from CommonServerPython import *

DATA = list()

""" HELPER FUNCTIONS """


def convert_to_json(string):
    """Will try to convert given string to json.

    Args:
        string: str of stix/json file. may be xml, then function will fail

    Returns:
        json object if succeed
        False if failed
    """
    try:
        js = json.loads(string)
        return js
    except ValueError:
        return False


def create_indicator_entry(indicator_type, value, pkg_id, ind_id, timestamp):
    """

    Args:
        indicator_type: (str) indicator type
        value: (str) indicator value
        pkg_id: package id
        ind_id: indicator id
        timestamp: timestamp

    Returns:
        dict:
            {
                "indicator_type": indicator_type,
                "value": value,
                "CustomFields": {
                    "indicatorId": ind_id,
                    "stixPackageId": pkg_id
                }
                "source" = ind_id
            }
    """
    entry = dict()
    entry["indicator_type"] = indicator_type
    entry["value"] = value
    entry["CustomFields"] = {
        "indicatorId": ind_id,
        "stixPackageId": pkg_id
    }
    entry["source"] = ind_id.split("-")[0]

    if timestamp is not None:
        entry["timestamp"] = timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    return entry


def extract_patterns(stx_obj):
    """Extracting all pattern from stix object
    function will take care of one bundle only.
    Args:
        stx_obj: json stix2 format
    """
    if "objects" in stx_obj:
        results_list = list()
        pkg_id = stx_obj.get("id")
        objects = stx_obj.get("objects")
        if isinstance(objects, list):
            for obj in objects:
                if isinstance(obj, dict) and "pattern" in obj:
                    ind_id = obj.get("id")
                    timestamp = obj.get("created")
                    pattern = obj.get("pattern")
                    if pattern:
                        indicators = demisto.executeCommand(
                            "extractIndicators", {"text": pattern}
                        )[0]["EntryContext"]

                        indicators = create_indicators(indicators)
                        for k, v in indicators:
                            if isinstance(v, list):
                                for indicator in v:
                                    result = create_indicator_entry(
                                        k, indicator, pkg_id, ind_id, timestamp
                                    )
                                    results_list.append(result)
                            else:
                                result = create_indicator_entry(
                                    k, v, pkg_id, ind_id, timestamp
                                )
                                results_list.append(result)
        return results_list
    return None


def create_indicators(indicators):
    """Converting indicators from ExtractIndicators script to Indicators format

    Args:
        indicators: (dict)


    Returns:

    """
    new_indicators = dict()
    if indicators.get("URL"):
        new_indicators["URL"] = list(set(indicators.get("URL")))

    if indicators.get("Domain"):
        new_indicators["Domain"] = list(set(indicators.get("Domain")))

    new_indicators["File"] = dict()
    if indicators.get("MD5"):
        new_indicators["File"].update(list(set(indicators.get("MD5"))))

    if indicators.get("SHA1"):
        new_indicators["File"].update(list(set(indicators.get("SHA1"))))

    if indicators.get("SHA256"):
        new_indicators["File"].update(list(set(indicators.get("SHA256"))))
    return new_indicators


def create_new_ioc(data, i, time, pkg_id, ind_id):
    data.append({})
    data[i]["CustomFields"] = {
        "indicatorId": ind_id,
        "stixPackageId": pkg_id
    }
    data[i]["source"] = ind_id.split(":")[0]
    if time is not None:
        data[i]["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def stix1_to_demisto(stix_package):
    global DATA
    i = 0
    stix_id = stix_package.id_
    if stix_package.indicators:
        for ind in stix_package.indicators:
            ind_id = ind.id_
            for obs in ind.observables:
                if hasattr(obs.object_.properties, "hashes"):
                    # File object
                    for digest in obs.object_.properties.hashes:
                        if hasattr(digest, "simple_hash_value"):
                            if isinstance(digest.simple_hash_value.value, list):
                                for hash in digest.simple_hash_value.value:
                                    create_new_ioc(
                                        DATA, i, ind.timestamp, stix_id, ind_id
                                    )
                                    DATA[i]["indicator_type"] = "File"
                                    DATA[i]["value"] = hash
                                    i += 1
                            else:
                                create_new_ioc(DATA, i, ind.timestamp, stix_id, ind_id)
                                DATA[i]["indicator_type"] = "File"
                                DATA[i][
                                    "value"
                                ] = digest.simple_hash_value.value.strip()
                                i += 1
                elif hasattr(obs.object_.properties, "category"):
                    # Address object
                    category = obs.object_.properties.category
                    if category.startswith("ip"):
                        for ip in obs.object_.properties.address_value.values:
                            create_new_ioc(DATA, i, ind.timestamp, stix_id, ind_id)
                            DATA[i]["indicator_type"] = "IP"
                            DATA[i]["value"] = ip
                            i += 1
                elif hasattr(obs.object_.properties, "type_"):
                    if obs.object_.properties.type_ == "URL":
                        # URI object
                        create_new_ioc(DATA, i, ind.timestamp, stix_id, ind_id)
                        DATA[i]["indicator_type"] = "URL"
                        DATA[i]["value"] = obs.object_.properties.value.value
                        i += 1
                    elif hasattr(obs.object_.properties.value, "values"):
                        for url in obs.object_.properties.value.values:
                            # URI object
                            create_new_ioc(DATA, i, ind.timestamp, stix_id, ind_id)
                            DATA[i]["indicator_type"] = "URL"
                            DATA[i]["value"] = url
                            i += 1


def stix2_to_demisto(stx_obj):
    """Converts stix2 json to demisto object

    Args:
        stx_obj: json object
    """
    global DATA
    results = list()
    if isinstance(stx_obj, dict):
        results = extract_patterns(stx_obj)
    elif isinstance(stx_obj, list):
        for obj in stx_obj:
            parse_obj = extract_patterns(obj)
            results.append(parse_obj)
    demisto.results(results)


# Start of script
with tempfile.NamedTemporaryFile() as temp:
    txt = demisto.args().get("iocXml").encode("utf-8")
    stx = convert_to_json(txt)
    if stx:
        stix2_to_demisto(stx)
    else:
        temp.write(txt)
        temp.flush()
        stx = STIXPackage.from_xml(temp.name)
        stix1_to_demisto(stx)

json_data = json.dumps(DATA)
demisto.results(json_data)
