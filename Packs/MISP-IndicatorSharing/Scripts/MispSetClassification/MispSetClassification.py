import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
"""Base Script for Cortex XSOAR (aka Demisto)
This is an empty script with some basic structure according
to the code conventions.
MAKE SURE YOU REVIEW/REPLACE ALL THE COMMENTS MARKED AS "TODO"
Developer Documentation: https://xsoar.pan.dev/docs/welcome
Code Conventions: https://xsoar.pan.dev/docs/integrations/code-conventions
Linting: https://xsoar.pan.dev/docs/integrations/linting
"""

from typing import Dict, Any
import traceback

pt_enisa = [
    {
        "Classification": "Código Malicioso",
        "Type": "Sistema Infetado",
        "EnisaDescription": "System infected with malware, e.g. PC, smartphone or server infected with a rootkit. Most often this refers to a connection to a sinkholed C2 server",
        "ENISA": "Malicious Code:Infected System",
        "RSIT": "malicious-code=infected-system"

    },
    {
        "Classification": "Código Malicioso",
        "Type": "Distribuição de Malware",
        "EnisaDescription": "URI used for malware distribution, e.g. a download URL included in fake invoice malware spam or exploit-kits (on websites).",
        "ENISA": "Malicious Code:Malware Distribution",
        "RSIT": "malicious-code=malware-distribution"
    },
    {
        "Classification": "Código Malicioso",
        "Type": "Servidor C2",
        "EnisaDescription": "Command-and-control server contacted by malware on infected systems.",
        "ENISA": "Malicious Code:C2 Server",
        "RSIT": "malicious-code=c2-server"
    },
    {
        "Classification": "Código Malicioso",
        "Type": "Configuração de Malware",
        "EnisaDescription": "URI hosting a malware configuration file, e.g. web-injects for a banking trojan.",
        "ENISA": "Malicious Code:Malware Configuration",
        "RSIT": "malicious-code=malware-configuration"
    },
    {
        "Classification": "Disponibilidade",
        "Type": "Negação de Serviço",
        "EnisaDescription": "Denial of Service attack, e.g. sending specially crafted requests to a web application which causes the application to crash or slow down.",
        "ENISA": "Availability:Denial of Service",
        "RSIT": "availability=dos"

    },
    {
        "Classification": "Disponibilidade",
        "Type": "Negação de Serviço Distribuída",
        "EnisaDescription": "Distributed Denial of Service attack, e.g. SYN-Flood or UDP-based reflection/amplification attacks.",
        "ENISA": "Availability:Distributed Denial of Service",
        "RSIT": "availability=ddos"


    },
    {
        "Classification": "Disponibilidade",
        "Type": "Configuração incorreta",
        "EnisaDescription": "Software misconfiguration resulting in service availability issues, e.g. DNS server with outdated DNSSEC Root Zone KSK.",
        "ENISA": "Availability:Misconfiguration",
        "RSIT": "availability=misconfiguration"
    },
    {
        "Classification": "Disponibilidade",
        "Type": "Sabotagem",
        "EnisaDescription": "Physical sabotage, e.g cutting wires or malicious arson.",
        "ENISA": "Availability:Sabotage",
        "RSIT": "availability=sabotage"
    },
    {
        "Classification": "Disponibilidade",
        "Type": "Interrupção",
        "EnisaDescription": "An outage caused, for example, by air conditioning failure or natural disaster.",
        "ENISA": "Availability:Outage",
        "RSIT": "availability=outage"
    },
    {
        "Classification": "Recolha de Informação",
        "Type": "Scanning",
        "EnisaDescription": "Attacks that send requests to a system to discover weaknesses. This also includes testing processes to gather information on hosts, services and accounts. Examples:fingerd, DNS querying, ICMP, SMTP (EXPN, RCPT, ...), port scanning.",
        "ENISA": "Information Gathering:Scanning",
        "RSIT": "information-gathering=scanner"
    },
    {
        "Classification": "Recolha de Informação",
        "Type": "Sniffing",
        "EnisaDescription": "Observing and recording of network traffic (wiretapping).",
        "ENISA": "Information Gathering:Sniffing",
        "RSIT": "information-gathering=sniffing"
    },
    {
        "Classification": "Recolha de Informação",
        "Type": "Engenharia Social",
        "EnisaDescription": "Gathering information from a human being in a non-technical way (e.g. lies, tricks, bribes, or threats).",
        "ENISA": "Information Gathering:Social Engineering",
        "RSIT": "information-gathering=social-engineering"
    },
    {
        "Classification": "Intrusão",
        "Type": "Comprometimento de Conta Privilegiada",
        "EnisaDescription": "Compromise of a system where the attacker gained administrative privileges.",
        "ENISA": "Intrusions:Privileged Account Compromise",
        "RSIT": "intrusions=privileged-account-compromise"
    },
    {
        "Classification": "Intrusão",
        "Type": "Comprometimento de Conta Não Privilegiada",
        "EnisaDescription": "Compromise of a system using an unprivileged (user/service) account.",
        "ENISA": "Intrusions:Unprivileged Account Compromise",
        "RSIT": "intrusions=unprivileged-account-compromise"
    },
    {
        "Classification": "Intrusão",
        "Type": "Comprometimento de Aplicação",
        "EnisaDescription": "Compromise of an application by exploiting (un-)known software vulnerabilities, e.g. SQL injection.",
        "ENISA": "Intrusions:Application Compromise",
        "RSIT": "intrusions=application-compromise"
    },
    {
        "Classification": "Intrusão",
        "Type": "Comprometimento de Sistema",
        "EnisaDescription": "Compromise of a system, e.g. unauthorised logins or commands. This includes compromising attempts on honeypot systems.",
        "ENISA": "Intrusions:System Compromise",
        "RSIT": "intrusions=system"
    },
    {
        "Classification": "Intrusão",
        "Type": "Arrombamento",
        "EnisaDescription": "Physical intrusion, e.g. into corporate building or data-centre.",
        "ENISA": "Intrusions:Burglary",
        "RSIT": "intrusions=burglary"
    },
    {
        "Classification": "Tentativa de Intrusão",
        "Type": "Exploração de Vulnerabilidade",
        "EnisaDescription": "An attempt to compromise a system or to disrupt any service by exploiting vulnerabilities with a standardised identifier such as CVE name (e.g. buffer overflow, backdoor, cross site scripting, etc.)",
        "ENISA": "Intrusion Attempts:Exploitation of known Vulnerabilities",
        "RSIT": "intrusion-attempts=ids-alert"
    },
    {
        "Classification": "Tentativa de Intrusão",
        "Type": "Tentativa de Login",
        "EnisaDescription": "Multiple login attempts (Guessing / cracking of passwords, brute force). This IOC refers to a resource, which has been observed to perform brute-force attacks over a given application protocol.",
        "ENISA": "Intrusion Attempts:Login attempts",
        "RSIT": "intrusion-attempts=brute-force"
    },
    {
        "Classification": "Tentativa de Intrusão",
        "Type": "Nova assinatura de ataque",
        "EnisaDescription": "An attack using an unknown exploit.",
        "ENISA": "Intrusion Attempts:New attack signature",
        "RSIT": "intrusion-attempts=exploit"
    },
    {
        "Classification": "Segurança da Informação",
        "Type": "Acesso não autorizado",
        "EnisaDescription": "Unauthorised access to information, e.g. by abusing stolen login credentials for a system or application, intercepting traffic or gaining access to physical documents.",
        "ENISA": "Information Content Security:Unauthorised access to information",
        "RSIT": "information-content-security=unauthorised-information-access"
    },
    {
        "Classification": "Segurança da Informação",
        "Type": "Modificação não autorizada",
        "EnisaDescription": "Unauthorised modification of information, e.g. by an attacker abusing stolen login credentials for a system or application or a ransomware encrypting data. Also includes defacements.",
        "ENISA": "Information Content Security:Unauthorised modification of information",
        "RSIT": "information-content-security=unauthorised-information-modification"
    },
    {
        "Classification": "Segurança da Informação",
        "Type": "Perda de dados",
        "EnisaDescription": "Loss of data, e.g. caused by harddisk failure or physical theft.",
        "ENISA": "Information Content Security:Data Loss",
        "RSIT": "information-content-security=data-loss"
    },
    {
        "Classification": "Segurança da Informação",
        "Type": "Exfiltração de Informação",
        "EnisaDescription": "Leaked confidential information like credentials or personal data.",
        "ENISA": "Information Content Security:Leak of confidential information",
        "RSIT": "information-content-security=data-leak"
    },
    {
        "Classification": "Fraude",
        "Type": "Utilização indevida ou não autorizada de recursos",
        "EnisaDescription": "Using resources for unauthorised purposes including profit-making ventures, e.g. the use of e-mail to participate in illegal profit chain letters or pyramid schemes.",
        "ENISA": "Fraud:Unauthorised use of resources",
        "RSIT": "fraud=unauthorised-use-of-resources"
    },
    {
        "Classification": "Fraude",
        "Type": "Direitos de autor",
        "EnisaDescription": "Offering or Installing copies of unlicensed commercial software or other copyright protected materials (Warez).",
        "ENISA": "Fraud:Copyright",
        "RSIT": "fraud=copyright"
    },
    {
        "Classification": "Fraude",
        "Type": "Utilização ilegítima de nome de terceiros",
        "EnisaDescription": "Type of attack in which one entity illegitimately impersonates the identity of another in order to benefit from it.",
        "ENISA": "Fraud:Masquerade",
        "RSIT": "fraud=masquerade"
    },
    {
        "Classification": "Fraude",
        "Type": "Phishing",
        "EnisaDescription": "Masquerading as another entity in order to persuade the user to reveal private credentials. This IOC most often refers to a URL, which is used to phish user credentials.",
        "ENISA": "Fraud:Phishing",
        "RSIT": "misp-galaxy:rsit=\"Fraud:Phishing\""
    },
    {
        "Classification": "Conteúdo Abusivo",
        "Type": "Spam",
        "EnisaDescription": "Or 'Unsolicited Bulk Email', this means that the recipient has not granted verifiable permission for the message to be sent and that the message is sent as part of a larger collection of messages, all having a functionally comparable content. This IOC refers to resources, which make up a SPAM infrastructure, be it a harvesters like address verification, URLs in spam e-mails etc.",
        "ENISA": "Abusive Content:Spam",
        "RSIT": "abusive-content=spam"
    },
    {
        "Classification": "Conteúdo Abusivo",
        "Type": "Discurso Nocivo",
        "EnisaDescription": "Discretization or discrimination of somebody, e.g. cyber stalking, racism or threats against one or more individuals.",
        "ENISA": "Abusive Content:Harmful Speech",
        "RSIT": "abusive-content=harmful-speech"
    },
    {
        "Classification": "Conteúdo Abusivo",
        "Type": "Exploração sexual de menores, racismo e apologia da violência",
        "EnisaDescription": "Child Sexual Exploitation (CSE), Sexual content, glorification of violence, etc.",
        "ENISA": "Abusive Content:(Child) Sexual Exploitation/Sexual/Violent Content",
        "RSIT": "abusive-content=(child)-sexual-exploitation/sexual/violent-content"
    },
    {
        "Classification": "Vulnerabilidade",
        "Type": "Criptografia fraca",
        "EnisaDescription": "Publicly accessible services offering weak crypto, e.g. web servers susceptible to POODLE/FREAK attacks.",
        "ENISA": "Vulnerable:Weak crypto",
        "RSIT": "vulnerable=weak-crypto"
    },
    {
        "Classification": "Vulnerabilidade",
        "Type": "Amplificador DDoS",
        "EnisaDescription": "Publicly accessible services that can be abused for conducting DDoS reflection/amplification attacks, e.g. DNS open-resolvers or NTP servers with monlist enabled.",
        "ENISA": "Vulnerable:DDoS amplifier",
        "RSIT": "vulnerable=ddos-amplifier"
    },
    {
        "Classification": "Vulnerabilidade",
        "Type": "Serviços acessíveis potencialmente indesejados",
        "EnisaDescription": "Potentially unwanted publicly accessible services, e.g. Telnet, RDP or VNC.",
        "ENISA": "Vulnerable:Potentially unwanted accessible services",
        "RSIT": "vulnerable=potentially-unwanted-accessible"
    },
    {
        "Classification": "Vulnerabilidade",
        "Type": "Revelação de informação",
        "EnisaDescription": "Publicly accessible services potentially disclosing sensitive information, e.g. SNMP or Redis.",
        "ENISA": "Vulnerable:Information disclosure",
        "RSIT": "vulnerable=information-disclosure"
    },
    {
        "Classification": "Vulnerabilidade",
        "Type": "Sistema vulnerável",
        "EnisaDescription": "A system which is vulnerable to certain attacks. Example:misconfigured client proxy settings (example:WPAD), outdated operating system version, XSS vulnerabilities, etc.",
        "ENISA": "Vulnerable:Vulnerable system",
        "RSIT": "vulnerable=vulnerable-system"
    },
    {
        "Classification": "Outro",
        "Type": "Sem tipo",
        "EnisaDescription": "All incidents which don't fit in one of the given categories should be put into this class or the incident is not categorised.",
        "ENISA": "Other:Uncategorised",
        "RSIT": "other=other"
    },
    {
        "Classification": "Outro",
        "Type": "Indeterminado",
        "EnisaDescription": "The categorisation of the incident is unknown/undetermined.",
        "ENISA": "Other:Undetermined",
        "RSIT": "other=undetermined"
    },
    {
        "Classification": "Teste",
        "Type": "Teste",
        "EnisaDescription": "Meant for testing.",
        "ENISA": "Test:Test",
        "RSIT": "test=test"
    }
]


def get_value_from_list(org_type):
    if org_type == 'pt_org':
        ref_val = demisto.incident()['CustomFields'].get('cncstype')
        ref_entry = {'Key': 'Type', 'Value': ref_val}
    elif org_type == 'non_pt_org':
        ref_val = demisto.incident()['CustomFields'].get('enisacode')
        ref_entry = {'Key': 'ENISA', 'Value': ref_val}

    for enisa_value in pt_enisa:
        if enisa_value[ref_entry['Key']] == ref_entry['Value']:
            rsit_entry = enisa_value['RSIT']
            return rsit_entry


''' MAIN FUNCTION '''


def main():

    try:
        org_type = demisto.args().get('org_type')
        rsit = get_value_from_list(org_type)
        command_result = CommandResults(
            outputs_prefix='MispRSIT',
            outputs=rsit
        )
        return_results(command_result)
    except Exception as ex:
        demisto.error(traceback.format_exc())  # print the traceback
        return_error(f'Failed to execute BaseScript. Error: {str(ex)}')


''' ENTRY POINT '''


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
