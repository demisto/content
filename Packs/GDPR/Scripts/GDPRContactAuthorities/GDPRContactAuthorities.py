import demistomock as demisto
from CommonServerPython import *

AUTHORITY_DETAILS = {
    'Austria': {
        'Name': 'Österreichische Datenschutzbehörde',
        'Email': 'dsb@dsb.gv.at',
        'Tel': '+43 1 531 15 202525',
        'Site': 'http://www.dsb.gv.at/'
    },
    'Belgium': {
        'Name': 'Commission de la protection de la vie privée',
        'Email': 'commission@privacycommission.be',
        'Tel': '+32 2 274 48 00',
        'Site': 'http://www.privacycommission.be/'
    },
    'Bulgaria': {
        'Name': 'Commission for Personal Data Protection',
        'Email': 'kzld@cpdp.bg',
        'Tel': '+359 2 915 3580',
        'Site': 'http://www.cpdp.bg/'
    },
    'Croatia': {
        'Name': 'Croatian Personal Data Protection Agency',
        'Email': 'azop@azop.hr',
        'Tel': '+385 1 4609 000',
        'Site': 'http://www.azop.hr/'
    },
    'Cyprus': {
        'Name': 'Commissioner for Personal Data Protection',
        'Email': 'commissioner@dataprotection.gov.cy',
        'Tel': '+357 22 818 456',
        'Site': 'http://www.dataprotection.gov.cy/'
    },
    'Czech Republic': {
        'Name': 'The Office for Personal Data Protection',
        'Email': 'posta@uoou.cz',
        'Tel': '+420 234 665 111',
        'Site': 'http://www.uoou.cz/'
    },
    'Denmark': {
        'Name': 'Datatilsynet',
        'Email': 'dt@datatilsynet.dk',
        'Tel': '+45 33 1932 00',
        'Site': 'http://www.datatilsynet.dk/'
    },
    'Estonia': {
        'Name': 'Estonian Data Protection Inspectorate (Andmekaitse Inspektsioon)',
        'Email': 'info@aki.ee',
        'Tel': '+372 6274 135',
        'Site': 'http://www.aki.ee/en'
    },
    'Finland': {
        'Name': 'Office of the Data Protection Ombudsman',
        'Email': 'tietosuoja@om.fi',
        'Tel': '+358 10 3666 700',
        'Site': 'http://www.tietosuoja.fi/en/'
    },
    'France': {
        'Name': 'Commission Nationale de l’Informatique et des Libertés – CNIL',
        'Email': '',
        'Tel': '+33 1 53 73 22 22',
        'Site': 'http://www.cnil.fr/'
    },
    'Germany': {
        'Name': 'Die Bundesbeauftragte für den Datenschutz und die Informationsfreiheit',
        'Email': 'poststelle@bfdi.bund.de',
        'Tel': '+49 228 81995 0',
        'Site': 'http://www.bfdi.bund.de/'
    },
    'Greece': {
        'Name': 'Hellenic Data Protection Authority',
        'Email': 'contact@dpa.gr',
        'Tel': '+30 210 6475 600',
        'Site': 'http://www.dpa.gr/'
    },
    'Hungary': {
        'Name': 'National Authority for Data Protection and Freedom of Information',
        'Email': 'peterfalvi.attila@naih.hu',
        'Tel': '+36 1 3911 400',
        'Site': 'http://www.naih.hu/'
    },
    'Ireland': {
        'Name': 'Data Protection Commissioner',
        'Email': 'info@dataprotection.ie',
        'Tel': '+353 57 868 4800',
        'Site': 'http://www.dataprotection.ie/'
    },
    'Italy': {
        'Name': 'Garante per la protezione dei dati personali',
        'Email': 'garante@garanteprivacy.it',
        'Tel': '+39 06 69677 1',
        'Site': 'http://www.garanteprivacy.it/'
    },
    'Latvia': {
        'Name': 'Data State Inspectorate',
        'Email': 'info@dvi.gov.lv',
        'Tel': '+371 6722 3131',
        'Site': 'http://www.dvi.gov.lv/'
    },
    'Lithuania': {
        'Name': 'State Data Protection',
        'Email': 'ada@ada.lt',
        'Tel': '+ 370 5 279 14 45',
        'Site': 'http://www.ada.lt/'
    },
    'Luxembourg': {
        'Name': 'Commission Nationale pour la Protection des Données',
        'Email': 'info@cnpd.lu',
        'Tel': '+352 2610 60 1',
        'Site': 'http://www.cnpd.lu/'
    },
    'Malta': {
        'Name': 'Office of the Data Protection Commissioner',
        'Email': 'commissioner.dataprotection@gov.mt',
        'Tel': '+356 2328 7100',
        'Site': 'http://www.dataprotection.gov.mt/'
    },
    'Netherlands': {
        'Name': 'Autoriteit Persoonsgegevens',
        'Email': 'info@autoriteitpersoonsgegevens.nl',
        'Tel': '+31 70 888 8500',
        'Site': 'https://autoriteitpersoonsgegevens.nl/nl'
    },
    'Poland': {
        'Name': 'The Bureau of the Inspector General for the Protection of Personal Data – GIODO',
        'Email': 'desiwm@giodo.gov.pl',
        'Tel': '+48 22 53 10 440',
        'Site': 'http://www.giodo.gov.pl/'
    },
    'Portugal': {
        'Name': 'Comissão Nacional de Protecção de Dados – CNPD',
        'Email': 'geral@cnpd.pt',
        'Tel': '+351 21 392 84 00',
        'Site': 'http://www.cnpd.pt/'
    },
    'Romania': {
        'Name': 'The National Supervisory Authority for Personal Data Processing',
        'Email': 'anspdcp@dataprotection.ro',
        'Tel': '+40 21 252 5599',
        'Site': 'http://www.dataprotection.ro/'
    },
    'Slovakia': {
        'Name': 'Office for Personal Data Protection of the Slovak Republic',
        'Email': 'statny.dozor@pdp.gov.sk',
        'Tel': '+ 421 2 32 31 32 14',
        'Site': 'http://www.dataprotection.gov.sk/'
    },
    'Slovenia': {
        'Name': 'Information Commissioner',
        'Email': 'gp.ip@ip-rs.si',
        'Tel': '+386 1 230 9730',
        'Site': 'https://www.ip-rs.si/'
    },
    'Spain': {
        'Name': 'Agencia de Protección de Datos',
        'Email': 'internacional@agpd.es',
        'Tel': '+34 91399 6200',
        'Site': 'https://www.agpd.es/'
    },
    'Sweden': {
        'Name': 'Datainspektionen',
        'Email': 'datainspektionen@datainspektionen.se',
        'Tel': '+46 8 657 6100',
        'Site': 'http://www.datainspektionen.se/'
    },
    'United Kingdom': {
        'Name': 'The Information Commissioner’s Office',
        'Email': 'international.team@ico.org.uk',
        'Tel': '+44 1625 545 745',
        'Site': 'https://ico.org.uk'
    },
    'Iceland': {
        'Name': 'Icelandic Data Protection Agency',
        'Email': 'postur@personuvernd.is',
        'Tel': '+354 510 9600',
        'Site': ''
    },
    'Liechtenstein': {
        'Name': 'Data Protection Office',
        'Email': 'info.dss@llv.li',
        'Tel': '+423 236 6090',
        'Site': ''
    },
    'Norway': {
        'Name': 'Datatilsynet',
        'Email': 'postkasse@datatilsynet.no',
        'Tel': '+47 22 39 69 00',
        'Site': ''
    },
    'Switzerland': {
        'Name': 'Data Protection and Information Commissioner of Switzerland',
        'Email': 'contact20@edoeb.admin.ch',
        'Tel': '+41 58 462 43 95',
        'Site': ''
    }
}


country = demisto.args().get('country')

if country in AUTHORITY_DETAILS:
    headers = [
        'Name',
        'Email',
        'Tel',
        'Site',
    ]
    new_country = AUTHORITY_DETAILS.get(country)
    contents = country
    context = createContext(new_country)
    context['Country'] = country
    human_readable = tableToMarkdown(f'{country} - Supervisory Authority Information',
                                     new_country, headers=headers)
    outputs = {'GDPR.Authority(val.ID && val.ID === obj.ID)': context}
    return_outputs(readable_output=human_readable, outputs=outputs, raw_response=contents)

else:
    demisto.results('The information for this country does not exist')
