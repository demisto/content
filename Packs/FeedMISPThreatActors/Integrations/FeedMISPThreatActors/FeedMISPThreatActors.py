import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

from CommonServerUserPython import *  # noqa

import urllib3
from typing import Any

# Disable insecure warnings
urllib3.disable_warnings()


''' CONSTANTS '''

SINGLE_WORD = 1
DATE_FORMAT = '%Y-%m-%dT%H:%M:%SZ'  # ISO8601 format with UTC, default in XSOAR
LOG_LINE = 'FeedMISPThreatActors -'
COUNTRIES = {
    "AF": "Afghanistan",
    "AX": "Aland Islands",
    "AL": "Albania",
    "AS": "American Samoa",
    "AD": "Andorra",
    "AO": "Angola",
    "AI": "Anguilla",
    "AQ": "Antarctica",
    "AG": "Antigua and Barbuda",
    "AR": "Argentina",
    "AM": "Armenia",
    "AW": "Aruba",
    "AU": "Australia",
    "AT": "Austria",
    "AZ": "Azerbaijan",
    "BS": "Bahamas",
    "BH": "Bahrain",
    "BD": "Bangladesh",
    "BB": "Barbados",
    "BY": "Belarus",
    "BE": "Belgium",
    "BZ": "Belize",
    "BJ": "Benin",
    "BM": "Bermuda",
    "BT": "Bhutan",
    "BO": "Bolivia, Plurinational State of",
    "BQ": "Bonaire, Sint Eustatius and Saba",
    "BA": "Bosnia and Herzegovina",
    "BW": "Botswana",
    "BV": "Bouvet Island",
    "BR": "Brazil",
    "IO": "British Indian Ocean Territory",
    "BN": "Brunei Darussalam",
    "BG": "Bulgaria",
    "BF": "Burkina Faso",
    "BI": "Burundi",
    "KH": "Cambodia",
    "CM": "Cameroon",
    "CA": "Canada",
    "CV": "Cape Verde",
    "KY": "Cayman Islands",
    "CF": "Central African Republic",
    "TD": "Chad",
    "CL": "Chile",
    "CN": "China",
    "CX": "Christmas Island",
    "CC": "Cocos (Keeling) Islands",
    "CO": "Colombia",
    "KM": "Comoros",
    "CG": "Congo",
    "CD": "Congo, The Democratic Republic of the",
    "CK": "Cook Islands",
    "CR": "Costa Rica",
    "CI": "Côte d'Ivoire",
    "HR": "Croatia",
    "CU": "Cuba",
    "CW": "Curaçao",
    "CY": "Cyprus",
    "CZ": "Czech Republic",
    "DK": "Denmark",
    "DJ": "Djibouti",
    "DM": "Dominica",
    "DO": "Dominican Republic",
    "EC": "Ecuador",
    "EG": "Egypt",
    "SV": "El Salvador",
    "GQ": "Equatorial Guinea",
    "ER": "Eritrea",
    "EE": "Estonia",
    "ET": "Ethiopia",
    "FK": "Falkland Islands (Malvinas)",
    "FO": "Faroe Islands",
    "FJ": "Fiji",
    "FI": "Finland",
    "FR": "France",
    "GF": "French Guiana",
    "PF": "French Polynesia",
    "TF": "French Southern Territories",
    "GA": "Gabon",
    "GM": "Gambia",
    "GE": "Georgia",
    "DE": "Germany",
    "GH": "Ghana",
    "GI": "Gibraltar",
    "GR": "Greece",
    "GL": "Greenland",
    "GD": "Grenada",
    "GP": "Guadeloupe",
    "GU": "Guam",
    "GT": "Guatemala",
    "GG": "Guernsey",
    "GN": "Guinea",
    "GW": "Guinea-Bissau",
    "GY": "Guyana",
    "HT": "Haiti",
    "HM": "Heard Island and McDonald Islands",
    "VA": "Holy See (Vatican City State)",
    "HN": "Honduras",
    "HK": "Hong Kong",
    "HU": "Hungary",
    "IS": "Iceland",
    "IN": "India",
    "ID": "Indonesia",
    "IR": "Iran, Islamic Republic of",
    "IQ": "Iraq",
    "IE": "Ireland",
    "IM": "Isle of Man",
    "IL": "Israel",
    "IT": "Italy",
    "JM": "Jamaica",
    "JP": "Japan",
    "JE": "Jersey",
    "JO": "Jordan",
    "KZ": "Kazakhstan",
    "KE": "Kenya",
    "KI": "Kiribati",
    "KP": "Korea, Democratic People's Republic of",
    "KR": "Korea, Republic of",
    "KW": "Kuwait",
    "KG": "Kyrgyzstan",
    "LA": "Lao People's Democratic Republic",
    "LV": "Latvia",
    "LB": "Lebanon",
    "LS": "Lesotho",
    "LR": "Liberia",
    "LY": "Libya",
    "LI": "Liechtenstein",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "MO": "Macao",
    "MK": "Macedonia, Republic of",
    "MG": "Madagascar",
    "MW": "Malawi",
    "MY": "Malaysia",
    "MV": "Maldives",
    "ML": "Mali",
    "MT": "Malta",
    "MH": "Marshall Islands",
    "MQ": "Martinique",
    "MR": "Mauritania",
    "MU": "Mauritius",
    "YT": "Mayotte",
    "MX": "Mexico",
    "FM": "Micronesia, Federated States of",
    "MD": "Moldova, Republic of",
    "MC": "Monaco",
    "MN": "Mongolia",
    "ME": "Montenegro",
    "MS": "Montserrat",
    "MA": "Morocco",
    "MZ": "Mozambique",
    "MM": "Myanmar",
    "NA": "Namibia",
    "NR": "Nauru",
    "NP": "Nepal",
    "NL": "Netherlands",
    "NC": "New Caledonia",
    "NZ": "New Zealand",
    "NI": "Nicaragua",
    "NE": "Niger",
    "NG": "Nigeria",
    "NU": "Niue",
    "NF": "Norfolk Island",
    "MP": "Northern Mariana Islands",
    "NO": "Norway",
    "OM": "Oman",
    "PK": "Pakistan",
    "PW": "Palau",
    "PS": "Palestinian Territory, Occupied",
    "PA": "Panama",
    "PG": "Papua New Guinea",
    "PY": "Paraguay",
    "PE": "Peru",
    "PH": "Philippines",
    "PN": "Pitcairn",
    "PL": "Poland",
    "PT": "Portugal",
    "PR": "Puerto Rico",
    "QA": "Qatar",
    "RE": "Réunion",
    "RO": "Romania",
    "RU": "Russian Federation",
    "RW": "Rwanda",
    "BL": "Saint Barthélemy",
    "SH": "Saint Helena, Ascension and Tristan da Cunha",
    "KN": "Saint Kitts and Nevis",
    "LC": "Saint Lucia",
    "MF": "Saint Martin (French part)",
    "PM": "Saint Pierre and Miquelon",
    "VC": "Saint Vincent and the Grenadines",
    "WS": "Samoa",
    "SM": "San Marino",
    "ST": "Sao Tome and Principe",
    "SA": "Saudi Arabia",
    "SN": "Senegal",
    "RS": "Serbia",
    "SC": "Seychelles",
    "SL": "Sierra Leone",
    "SG": "Singapore",
    "SX": "Sint Maarten (Dutch part)",
    "SK": "Slovakia",
    "SI": "Slovenia",
    "SB": "Solomon Islands",
    "SO": "Somalia",
    "ZA": "South Africa",
    "GS": "South Georgia and the South Sandwich Islands",
    "ES": "Spain",
    "LK": "Sri Lanka",
    "SD": "Sudan",
    "SR": "Suriname",
    "SS": "South Sudan",
    "SJ": "Svalbard and Jan Mayen",
    "SZ": "Swaziland",
    "SE": "Sweden",
    "CH": "Switzerland",
    "SY": "Syrian Arab Republic",
    "TW": "Taiwan, Province of China",
    "TJ": "Tajikistan",
    "TZ": "Tanzania, United Republic of",
    "TH": "Thailand",
    "TL": "Timor-Leste",
    "TG": "Togo",
    "TK": "Tokelau",
    "TO": "Tonga",
    "TT": "Trinidad and Tobago",
    "TN": "Tunisia",
    "TR": "Turkey",
    "TM": "Turkmenistan",
    "TC": "Turks and Caicos Islands",
    "TV": "Tuvalu",
    "UG": "Uganda",
    "UA": "Ukraine",
    "AE": "United Arab Emirates",
    "GB": "United Kingdom",
    "US": "United States",
    "UM": "United States Minor Outlying Islands",
    "UY": "Uruguay",
    "UZ": "Uzbekistan",
    "VU": "Vanuatu",
    "VE": "Venezuela, Bolivarian Republic of",
    "VN": "Viet Nam",
    "VG": "Virgin Islands, British",
    "VI": "Virgin Islands, U.S.",
    "WF": "Wallis and Futuna",
    "EH": "Western Sahara",
    "YE": "Yemen",
    "ZM": "Zambia",
    "ZW": "Zimbabwe",
}


''' CLIENT CLASS '''


class Client(BaseClient):
    '''
    Client to use in the Threat Vault integration. Overrides BaseClient.
    '''

    def __init__(
        self, base_url: str, verify: bool, proxy: bool, reliability: str
    ):
        super().__init__(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
        )

        self.name = 'MISPThreatActors'
        self.reliability = reliability

    def get_threat_actors_galaxy_file(self) -> dict[str, Any]:   # pragma: no cover

        demisto.debug(f"{LOG_LINE} - Trying to fetch Threat Actor Galaxy from Github")

        try:
            demisto.debug(f'{LOG_LINE} - Calling "{self._base_url}"')
            data = self._http_request(method="GET", raise_on_status=True, full_url=self._base_url)

        except Exception:
            raise

        return data

    def test_module(self) -> str:   # pragma: no cover
        '''
        Tests API connectivity and authentication
        Returning 'ok' indicates that the integration works like it is supposed to.
        Connection to the service is successful.
        Raises exceptions if something goes wrong.
        :type client: ``Client``
        :param Client: client to use
        :return: 'ok' if test passed, anything else will fail the test.
        :rtype: ``str``
        '''

        try:
            demisto.debug(f'{LOG_LINE} - Running test module.')
            self.get_threat_actors_galaxy_file()

        except DemistoException:
            raise

        return 'ok'


''' HELPER FUNCTIONS '''


def build_relationships(original_ioc: str,
                        related_iocs: list[str],
                        related_iocs_type: str,
                        relationship_name: str) -> list[dict[str, Any]]:
    '''
    Builds a list of EntityRelationship objects based on the provided original IOC and related IOCs.

    Args:
        original_ioc (str): The original IOC value.
        related_iocs (list[str]): A list of related IOC values.
        related_iocs_type (str): The type of the related IOCs.

    Returns:
        list[EntityRelationship]: A list of EntityRelationship objects.
    '''
    relationships = []

    for related_ioc in related_iocs:
        if len(related_ioc.split(" ")) >= 2:
            parsed_ioc = related_ioc.title()
        else:
            parsed_ioc = related_ioc

        relationships.append(
            EntityRelationship(
                name=relationship_name,
                entity_a=original_ioc,
                entity_a_type='Threat Actor',
                entity_b=parsed_ioc,
                entity_b_type=related_iocs_type,
            ).to_indicator()
        )

    return relationships


def parse_refs(original_ioc: str, refs: list[str]) -> list[dict[str, str]]:
    '''
    Parses the references for a given original IOC and builds the correct format to be used in the indicator Publications.

    Args:
        original_ioc (str): The value of the original threat actor.
        refs (list[str]): A list of URLs relevant to the threat actor.

    Returns:
        list[dict[str, str]]: A list of dictionaries containing the parsed references for the original IOC.
    '''

    parsed_refs = []

    for ref in refs:
        parsed_refs.append(
            {
                'title': original_ioc,
                'source': 'MISP Threat Actors Galaxy',
                'link': ref,
                'timestamp': datetime.now().strftime(DATE_FORMAT)
            }
        )

    return parsed_refs


''' COMMAND FUNCTIONS '''


def get_indicators_command(client: Client, args: dict[str, str]) -> CommandResults:
    """
    Retrieve indicators from the MISP Threat Actors Galaxy feed.

    This function fetches threat actor indicators from the MISP Threat Actors Galaxy,
    processes them according to the provided arguments, and returns the results.

    Args:
        client (Client): An instance of the Client class used to interact with the MISP Threat Actors Galaxy feed.
        args (dict[str, str]): A dictionary containing command arguments, which may include:
            - limit: The maximum number of indicators to retrieve.

    Returns:
        CommandResults: An object containing the processed indicators and associated metadata,
        formatted for display in Cortex XSOAR.
    """

    def build_results(actors: list[dict[str, Any]]) -> CommandResults:
        return CommandResults(
            outputs_prefix='FeedMISPThreatActors.ThreatActor',
            outputs_key_field='',
            outputs=actors,
            readable_output=tableToMarkdown('Threat Actors', actors, headers=['Name', 'Aliases', 'Country', 'Description']),
            raw_response=data
        )

    limit = int(args.get('limit', 10))
    data = client.get_threat_actors_galaxy_file()
    threat_actors_data = data.get('values', [])
    actors = []

    for counter, threat_actor in enumerate(threat_actors_data):
        if counter >= limit:
            break

        actor = {
            "Name": threat_actor['value'],
            "Description": threat_actor.get('description', '')
        }

        if synonyms := threat_actor["meta"].get('synonyms', []):
            actor['Aliases'] = ', '.join(synonyms)

        if origin_country := threat_actor["meta"].get('country', ''):
            full_country_name = COUNTRIES.get(origin_country, origin_country)
            actor['Country'] = full_country_name

        actors.append(actor)

    return build_results(actors)


def fetch_indicators_command(client: Client, feed_tags: str, tlp_color: str) -> tuple[str, list[dict[str, Any]]]:
    """
    Fetch threat actor indicators from the MISP Threat Actors Galaxy via Github.

    This function retrieves the latest threat actor data from the MISP Threat Actors Galaxy,
    processes it, and returns a list of indicators along with the current version.

    Args:
        client (Client): The client object used to make API requests.
        feed_tags (str): Comma-separated string of tags to be added to each indicator.
        tlp_color (str): The TLP color to be assigned to the indicators.

    Returns:
        tuple[str, list[dict[str, Any]]]: A tuple containing the current version as a string
        and a list of dictionaries representing the processed indicators.
    """
    indicators = []
    data = client.get_threat_actors_galaxy_file()

    version = data['version']
    demisto.debug(f'{LOG_LINE} - Fetched MISP threat actor galaxy version "{version}"')
    latest_version = demisto.getLastRun().get('version', 0)

    demisto.debug(f'{LOG_LINE} - Latest saved version is "{latest_version}"')

    if int(version) <= int(latest_version):
        demisto.debug(f'{LOG_LINE} Detected same or older version, No new updates - Exiting')
        return version, []

    demisto.debug(f'{LOG_LINE} - Fetched {len(data["values"])} objects.')

    for threat_actor in data['values']:
        relationships = []
        meta = threat_actor.get('meta', {})
        value = threat_actor['value']

        if len(value.split(" ")) > SINGLE_WORD:
            value = value.title()
        indicator = {
            'value': value,
            'type': 'Threat Actor',
            'fields': {
                'description': threat_actor.get('description', ''),
                'trafficlightprotocol': tlp_color,
                'tags': [tag for tag in feed_tags.split(',') + [f'MISP_ID: {(threat_actor.get("uuid"))}'] if tag]
            },
        }

        if refs := meta.get('refs', []):
            indicator['fields']['publications'] = parse_refs(threat_actor['value'], refs)

        if synonyms := meta.get('synonyms', []):
            indicator['fields']['aliases'] = synonyms
            relationships.extend(build_relationships(indicator['value'], synonyms, 'Threat Actor', 'is-also'))

        if targets := meta.get('cfr-suspected-victims', []):
            relationships.extend(build_relationships(indicator['value'], targets, 'Location', 'targets'))

        if sectors := meta.get('cfr-target-category', []):
            relationships.extend(build_relationships(indicator['value'], sectors, 'Identity', 'targets'))

        if origin_country := meta.get('country', ''):
            full_country_name = COUNTRIES.get(origin_country, origin_country)
            indicator['fields']['geocountry'] = full_country_name
            relationships.extend(build_relationships(indicator['value'], [full_country_name], 'Location', 'attributed-to'))

        if goals := meta.get('cfr-type-of-incident', ''):
            indicator['fields']['goals'] = goals

        indicator['relationships'] = relationships

        indicators.append(indicator)

    return version, indicators


''' MAIN FUNCTION '''


def main():
    params = demisto.params()

    '''PARAMS'''
    base_url = params['url']
    verify = not params.get('insecure', False)
    proxy = params.get('proxy', '')
    reliability = params.get('integrationReliability', 'B - Usually reliable')
    tlp_color = params.get('tlp_color') or 'WHITE'
    feed_tags = params.get('feedTags', '')

    if not DBotScoreReliability.is_valid_type(reliability):
        raise Exception(
            'Please provide a valid value for the Source Reliability parameter.'
        )

    try:
        command = demisto.command()
        client = Client(
            base_url=base_url,
            verify=verify,
            proxy=proxy,
            reliability=reliability,
        )

        if command == 'test-module':
            # This is the call made when pressing the integration Test button.
            result = client.test_module()
            return_results(result)

        elif command == 'fetch-indicators':
            version, res = fetch_indicators_command(
                client=client,
                feed_tags=feed_tags,
                tlp_color=tlp_color,
            )

            for iter_ in batch(res, batch_size=2000):
                demisto.debug(f'{LOG_LINE} - Processing {len(iter_)} new indicators.')
                demisto.createIndicators(iter_)

            demisto.setLastRun({'version': f'{version}'})

        elif command == "mispthreatactors-get-indicators":
            return_results(get_indicators_command(client, demisto.args()))

        else:
            raise NotImplementedError(f'Command "{command}" was not implemented.')

    except NotImplementedError:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute {command} command. The command not implemented')

    except Exception as err:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Error running integration - {err}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
