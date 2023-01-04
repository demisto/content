import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401

# country codes are in ISO-2 format
COUNTRY_CODES_TO_NAMES = {'AD': 'Andorra', 'AE': 'United Arab Emirates', 'AF': 'Afghanistan', 'AG': 'Antigua and Barbuda',
                          'AI': 'Anguilla', 'AL': 'Albania', 'AM': 'Armenia', 'AO': 'Angola', 'AQ': 'Antarctica',
                          'AR': 'Argentina', 'AS': 'American Samoa', 'AT': 'Austria', 'AU': 'Australia', 'AW': 'Aruba',
                          'AX': 'Aland Islands', 'AZ': 'Azerbaijan', 'BA': 'Bosnia and Herzegovina', 'BB': 'Barbados',
                          'BD': 'Bangladesh', 'BE': 'Belgium', 'BF': 'Burkina Faso', 'BG': 'Bulgaria', 'BH': 'Bahrain',
                          'BI': 'Burundi', 'BJ': 'Benin', 'BL': 'Saint Barthelemy', 'BM': 'Bermuda', 'BN': 'Brunei',
                          'BO': 'Bolivia', 'BQ': 'Bonaire, Saint Eustatius and Saba ', 'BR': 'Brazil', 'BS': 'Bahamas',
                          'BT': 'Bhutan', 'BV': 'Bouvet Island', 'BW': 'Botswana', 'BY': 'Belarus', 'BZ': 'Belize',
                          'CA': 'Canada', 'CC': 'Cocos Islands', 'CD': 'Democratic Republic of the Congo',
                          'CF': 'Central African Republic', 'CG': 'Republic of the Congo', 'CH': 'Switzerland',
                          'CI': 'Ivory Coast', 'CK': 'Cook Islands', 'CL': 'Chile', 'CM': 'Cameroon', 'CN': 'China',
                          'CO': 'Colombia', 'CR': 'Costa Rica', 'CU': 'Cuba', 'CV': 'Cape Verde', 'CW': 'Curacao',
                          'CX': 'Christmas Island', 'CY': 'Cyprus', 'CZ': 'Czech Republic', 'DE': 'Germany', 'DJ': 'Djibouti',
                          'DK': 'Denmark', 'DM': 'Dominica', 'DO': 'Dominican Republic', 'DZ': 'Algeria', 'EC': 'Ecuador',
                          'EE': 'Estonia', 'EG': 'Egypt', 'EH': 'Western Sahara', 'ER': 'Eritrea', 'ES': 'Spain',
                          'ET': 'Ethiopia', 'FI': 'Finland', 'FJ': 'Fiji', 'FK': 'Falkland Islands', 'FM': 'Micronesia',
                          'FO': 'Faroe Islands', 'FR': 'France', 'GA': 'Gabon', 'GB': 'United Kingdom', 'GD': 'Grenada',
                          'GE': 'Georgia', 'GF': 'French Guiana', 'GG': 'Guernsey', 'GH': 'Ghana', 'GI': 'Gibraltar',
                          'GL': 'Greenland', 'GM': 'Gambia', 'GN': 'Guinea', 'GP': 'Guadeloupe', 'GQ': 'Equatorial Guinea',
                          'GR': 'Greece', 'GS': 'South Georgia and the South Sandwich Islands', 'GT': 'Guatemala', 'GU': 'Guam',
                          'GW': 'Guinea-Bissau', 'GY': 'Guyana', 'HK': 'Hong Kong', 'HM': 'Heard Island and McDonald Islands',
                          'HN': 'Honduras', 'HR': 'Croatia', 'HT': 'Haiti', 'HU': 'Hungary', 'ID': 'Indonesia', 'IE': 'Ireland',
                          'IL': 'Israel', 'IM': 'Isle of Man', 'IN': 'India', 'IO': 'British Indian Ocean Territory',
                          'IQ': 'Iraq', 'IR': 'Iran', 'IS': 'Iceland', 'IT': 'Italy', 'JE': 'Jersey', 'JM': 'Jamaica',
                          'JO': 'Jordan', 'JP': 'Japan', 'KE': 'Kenya', 'KG': 'Kyrgyzstan', 'KH': 'Cambodia', 'KI': 'Kiribati',
                          'KM': 'Comoros', 'KN': 'Saint Kitts and Nevis', 'KP': 'North Korea', 'KR': 'South Korea',
                          'KW': 'Kuwait', 'KY': 'Cayman Islands', 'KZ': 'Kazakhstan', 'LA': 'Laos', 'LB': 'Lebanon',
                          'LC': 'Saint Lucia', 'LI': 'Liechtenstein', 'LK': 'Sri Lanka', 'LR': 'Liberia', 'LS': 'Lesotho',
                          'LT': 'Lithuania', 'LU': 'Luxembourg', 'LV': 'Latvia', 'LY': 'Libya', 'MA': 'Morocco', 'MC': 'Monaco',
                          'MD': 'Moldova', 'ME': 'Montenegro', 'MF': 'Saint Martin', 'MG': 'Madagascar', 'MH': 'Marshall Islands',
                          'MK': 'Macedonia', 'ML': 'Mali', 'MM': 'Myanmar', 'MN': 'Mongolia', 'MO': 'Macao',
                          'MP': 'Northern Mariana Islands', 'MQ': 'Martinique', 'MR': 'Mauritania', 'MS': 'Montserrat',
                          'MT': 'Malta', 'MU': 'Mauritius', 'MV': 'Maldives', 'MW': 'Malawi', 'MX': 'Mexico', 'MY': 'Malaysia',
                          'MZ': 'Mozambique', 'NA': 'Namibia', 'NC': 'New Caledonia', 'NE': 'Niger', 'NF': 'Norfolk Island',
                          'NG': 'Nigeria', 'NI': 'Nicaragua', 'NL': 'Netherlands', 'NO': 'Norway', 'NP': 'Nepal', 'NR': 'Nauru',
                          'NU': 'Niue', 'NZ': 'New Zealand', 'OM': 'Oman', 'PA': 'Panama', 'PE': 'Peru', 'PF': 'French Polynesia',
                          'PG': 'Papua New Guinea', 'PH': 'Philippines', 'PK': 'Pakistan', 'PL': 'Poland',
                          'PM': 'Saint Pierre and Miquelon', 'PN': 'Pitcairn', 'PR': 'Puerto Rico', 'PS': 'Palestinian Territory',
                          'PT': 'Portugal', 'PW': 'Palau', 'PY': 'Paraguay', 'QA': 'Qatar', 'RE': 'Reunion', 'RO': 'Romania',
                          'RS': 'Serbia', 'RU': 'Russia', 'RW': 'Rwanda', 'SA': 'Saudi Arabia', 'SB': 'Solomon Islands',
                          'SC': 'Seychelles', 'SD': 'Sudan', 'SE': 'Sweden', 'SG': 'Singapore', 'SH': 'Saint Helena',
                          'SI': 'Slovenia', 'SJ': 'Svalbard and Jan Mayen', 'SK': 'Slovakia', 'SL': 'Sierra Leone',
                          'SM': 'San Marino', 'SN': 'Senegal', 'SO': 'Somalia', 'SR': 'Suriname', 'SS': 'South Sudan',
                          'ST': 'Sao Tome and Principe', 'SV': 'El Salvador', 'SX': 'Sint Maarten', 'SY': 'Syria',
                          'SZ': 'Swaziland', 'TC': 'Turks and Caicos Islands', 'TD': 'Chad', 'TF': 'French Southern Territories',
                          'TG': 'Togo', 'TH': 'Thailand', 'TJ': 'Tajikistan', 'TK': 'Tokelau', 'TL': 'East Timor',
                          'TM': 'Turkmenistan', 'TN': 'Tunisia', 'TO': 'Tonga', 'TR': 'Turkey', 'TT': 'Trinidad and Tobago',
                          'TV': 'Tuvalu', 'TW': 'Taiwan', 'TZ': 'Tanzania', 'UA': 'Ukraine', 'UG': 'Uganda',
                          'UM': 'United States Minor Outlying Islands', 'US': 'United States', 'UY': 'Uruguay',
                          'UZ': 'Uzbekistan', 'VA': 'Vatican', 'VC': 'Saint Vincent and the Grenadines', 'VE': 'Venezuela',
                          'VG': 'British Virgin Islands', 'VI': 'U.S. Virgin Islands', 'VN': 'Vietnam', 'VU': 'Vanuatu',
                          'WF': 'Wallis and Futuna', 'WS': 'Samoa', 'XK': 'Kosovo', 'YE': 'Yemen', 'YT': 'Mayotte',
                          'ZA': 'South Africa', 'ZM': 'Zambia', 'ZW': 'Zimbabwe'}


COUNTRY_NAMES_TO_CODES = {'afghanistan': 'AF', 'aland islands': 'AX', 'albania': 'AL', 'algeria': 'DZ',
                          'american samoa': 'AS', 'andorra': 'AD', 'angola': 'AO', 'anguilla': 'AI',
                          'antarctica': 'AQ', 'antigua and barbuda': 'AG', 'argentina': 'AR', 'armenia': 'AM',
                          'aruba': 'AW', 'australia': 'AU', 'austria': 'AT', 'azerbaijan': 'AZ', 'bahamas': 'BS',
                          'bahrain': 'BH', 'bangladesh': 'BD', 'barbados': 'BB', 'belarus': 'BY', 'belgium': 'BE',
                          'belize': 'BZ', 'benin': 'BJ', 'bermuda': 'BM', 'bhutan': 'BT', 'bolivia': 'BO',
                          'bosnia and herzegovina': 'BA', 'botswana': 'BW', 'bouvet island': 'BV', 'brazil': 'BR',
                          'british indian ocean territory': 'IO', 'brunei darussalam': 'BN', 'bulgaria': 'BG',
                          'burkina faso': 'BF', 'burundi': 'BI', 'cambodia': 'KH', 'cameroon': 'CM', 'canada': 'CA',
                          'cape verde': 'CV', 'cayman islands': 'KY', 'central african republic': 'CF', 'chad': 'TD',
                          'chile': 'CL', 'china': 'CN', 'christmas island': 'CX', 'cocos (keeling) islands': 'CC',
                          'colombia': 'CO', 'comoros': 'KM', 'congo': 'CG',
                          'congo, the democratic republic of the': 'CD', 'cook islands': 'CK', 'costa rica': 'CR',
                          "cote d'ivoire": 'CI', 'croatia': 'HR', 'cuba': 'CU', 'cyprus': 'CY', 'czech republic': 'CZ',
                          'denmark': 'DK', 'djibouti': 'DJ', 'dominica': 'DM', 'dominican republic': 'DO',
                          'ecuador': 'EC', 'egypt': 'EG', 'el salvador': 'SV', 'equatorial guinea': 'GQ',
                          'eritrea': 'ER', 'estonia': 'EE', 'ethiopia': 'ET', 'falkland islands (malvinas)': 'FK',
                          'faroe islands': 'FO', 'fiji': 'FJ', 'finland': 'FI', 'france': 'FR', 'french guiana': 'GF',
                          'french polynesia': 'PF', 'french southern territories': 'TF', 'gabon': 'GA', 'gambia': 'GM',
                          'georgia': 'GE', 'germany': 'DE', 'ghana': 'GH', 'gibraltar': 'GI', 'greece': 'GR',
                          'greenland': 'GL', 'grenada': 'GD', 'guadeloupe': 'GP', 'guam': 'GU', 'guatemala': 'GT',
                          'guernsey': 'GG', 'guinea': 'GN', 'guinea-bissau': 'GW', 'guyana': 'GY', 'haiti': 'HT',
                          'heard island and mcdonald islands': 'HM', 'holy see (vatican city state)': 'VA',
                          'honduras': 'HN', 'hong kong': 'HK', 'hungary': 'HU', 'iceland': 'IS', 'india': 'IN',
                          'indonesia': 'ID', 'iran, islamic republic of': 'IR', 'iraq': 'IQ', 'ireland': 'IE',
                          'isle of man': 'IM', 'israel': 'IL', 'italy': 'IT', 'jamaica': 'JM', 'japan': 'JP',
                          'jersey': 'JE', 'jordan': 'JO', 'kazakhstan': 'KZ', 'kenya': 'KE', 'kiribati': 'KI',
                          "korea, democratic people's republic of": 'KP', 'korea, republic of': 'KR', 'kuwait': 'KW',
                          'kyrgyzstan': 'KG', "lao people's democratic republic": 'LA', 'latvia': 'LV',
                          'lebanon': 'LB', 'lesotho': 'LS', 'liberia': 'LR', 'libyan arab jamahiriya': 'LY',
                          'liechtenstein': 'LI', 'lithuania': 'LT', 'luxembourg': 'LU', 'macao': 'MO',
                          'macedonia, the former yugoslav republic of': 'MK', 'madagascar': 'MG', 'malawi': 'MW',
                          'malaysia': 'MY', 'maldives': 'MV', 'mali': 'ML', 'malta': 'MT', 'marshall islands': 'MH',
                          'martinique': 'MQ', 'mauritania': 'MR', 'mauritius': 'MU', 'mayotte': 'YT', 'mexico': 'MX',
                          'micronesia, federated states of': 'FM', 'moldova, republic of': 'MD', 'monaco': 'MC',
                          'mongolia': 'MN', 'montserrat': 'MS', 'morocco': 'MA', 'mozambique': 'MZ', 'myanmar': 'MM',
                          'namibia': 'NA', 'nauru': 'NR', 'nepal': 'NP', 'netherlands': 'NL',
                          'netherlands antilles': 'AN', 'new caledonia': 'NC', 'new zealand': 'NZ',
                          'nicaragua': 'NI', 'niger': 'NE', 'nigeria': 'NG', 'niue': 'NU', 'norfolk island': 'NF',
                          'northern mariana islands': 'MP', 'norway': 'NO', 'oman': 'OM', 'pakistan': 'PK',
                          'palau': 'PW', 'palestinian territory, occupied': 'PS', 'panama': 'PA',
                          'papua new guinea': 'PG', 'paraguay': 'PY', 'peru': 'PE', 'philippines': 'PH',
                          'pitcairn': 'PN', 'poland': 'PL', 'portugal': 'PT', 'puerto rico': 'PR', 'qatar': 'QA',
                          'reunion': 'RE', 'romania': 'RO', 'russian federation': 'RU', 'rwanda': 'RW',
                          'saint helena': 'SH', 'saint kitts and nevis': 'KN', 'saint lucia': 'LC',
                          'saint pierre and miquelon': 'PM', 'saint vincent and the grenadines': 'VC',
                          'samoa': 'WS', 'san marino': 'SM', 'sao tome and principe': 'ST', 'saudi arabia': 'SA',
                          'senegal': 'SN', 'serbia and montenegro': 'CS', 'seychelles': 'SC', 'sierra leone': 'SL',
                          'singapore': 'SG', 'slovakia': 'SK', 'slovenia': 'SI', 'solomon islands': 'SB',
                          'somalia': 'SO', 'south africa': 'ZA', 'south georgia and the south sandwich islands': 'GS',
                          'spain': 'ES', 'sri lanka': 'LK', 'sudan': 'SD', 'suriname': 'SR',
                          'svalbard and jan mayen': 'SJ', 'swaziland': 'SZ', 'sweden': 'SE',
                          'switzerland': 'CH', 'syrian arab republic': 'SY', 'taiwan, province of china': 'TW',
                          'tajikistan': 'TJ', 'tanzania, united republic of': 'TZ', 'thailand': 'TH',
                          'timor-leste': 'TL', 'togo': 'TG', 'tokelau': 'TK', 'tonga': 'TO',
                          'trinidad and tobago': 'TT', 'tunisia': 'TN', 'turkey': 'TR', 'turkmenistan': 'TM',
                          'turks and caicos islands': 'TC', 'tuvalu': 'TV', 'uganda': 'UG', 'ukraine': 'UA',
                          'united arab emirates': 'AE', 'united kingdom': 'GB', 'united states': 'US',
                          'united states minor outlying islands': 'UM', 'uruguay': 'UY', 'uzbekistan': 'UZ',
                          'vanuatu': 'VU', 'venezuela': 'VE', 'viet nam': 'VN', 'virgin islands, british': 'VG',
                          'virgin islands, u.s.': 'VI', 'wallis and futuna': 'WF', 'western sahara': 'EH',
                          'yemen': 'YE', 'zambia': 'ZM', 'zimbabwe': 'ZW'}

''' COMMAND FUNCTION '''


def convert_country_code(country_code: str) -> str:
    country_name = COUNTRY_CODES_TO_NAMES.get(country_code.upper())

    if not country_name:
        raise DemistoException('Invalid Country Code')

    return country_name


def convert_country_name(country_name: str) -> str:
    country_code = COUNTRY_NAMES_TO_CODES.get(country_name.lower())

    if not country_code:
        raise DemistoException('Invalid Country Name')

    return country_code


''' MAIN FUNCTION '''


def main():
    try:
        args = demisto.args()
        given_country_code = args.get('country_code')
        given_country_name = args.get('country_name')
        if given_country_code and given_country_name:
            raise DemistoException('Only one of country_code or country_name can be provided.')

        if given_country_code:
            country_name = convert_country_code(given_country_code)
            return_results(country_name)
        elif given_country_name:
            country_code = convert_country_name(given_country_name)
            return_results(country_code)

    except Exception as ex:
        return_error(f'Failed to execute ConvertCountryCodeCountryName. Error: {str(ex)}')


''' ENTRY POINT '''

if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
