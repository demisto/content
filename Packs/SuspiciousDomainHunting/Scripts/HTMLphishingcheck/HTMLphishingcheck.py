import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
import re


def check_for_phishing_indicators(html_content):
    # Check for common phishing indicators using regular expressions
    indicators = {
        "login_forms": bool(re.search(r'<input[^>]*type=["\']?password["\']?', html_content, re.IGNORECASE)),
        "suspicious_links": bool(re.search(r'href=["\'](.*?(login|signin|account).*?)["\']', html_content, re.IGNORECASE)),
        "pop-up_forms": bool(re.search(r'<input[^>]*type=["\']?text["\']?.*?name=["\'](.*?(username|email).*?)["\']?', html_content, re.IGNORECASE)),  # noqa: E501
        # Additional checks
        "meta_tags_phishing_keywords": bool(re.search(
            r'<meta[^>]*name=["\']?(keywords|description)["\']?[^>]*content=["\']?(phishing|login|password)["\']?',
            html_content, re.IGNORECASE)),
        "javascript_phishing_code": bool(re.search(r'<script[^>]*>\s*function.*?(submit|login|password).*?</script>',
                                                   html_content, re.DOTALL | re.IGNORECASE)),
        "suspicious_iframes": bool(re.search(r'<iframe[^>]*src=["\']?(https?|ftp):', html_content, re.IGNORECASE)),
        # You can add more checks for additional indicators here
        "payment_form_elements": bool(re.search(
            r'<input[^>]*type=["\']?(text|password)["\']?.*?name=["\'](.*?(credit|card|cvv|exp|security|cardNumber).*?)["\']?',
            html_content, re.IGNORECASE)),
        "suspicious_js_functions": bool(re.search(r'<script[^>]*>\s*(submit|validate|sendData).*?</script>', html_content,
                                                  re.DOTALL | re.IGNORECASE)),
        "hidden_fields": bool(re.search(
            r'<input[^>]*type=["\']?hidden["\']?.*?name=["\'](.*?(credit|card|bank|account|payment).*?)["\']?',
            html_content, re.IGNORECASE)),
        "payment_keywords": bool(re.search(r'(credit|card|debit|bank|account|payment|paypal|bitcoin|crypto)', html_content,
                                           re.IGNORECASE)),
    }

    return indicators


def check_html_for_phishing(html_content):
    phishing_indicators = check_for_phishing_indicators(html_content)

    return phishing_indicators


def format_html_response(indicators):
    html_output = "<html><head></head><body><table style='border-collapse: collapse; width: 100%; margin: 0 auto;'>"

    # Add a header row with "Validation" and "Passed/Failed" headers
    html_output += "<tr>"
    html_output += "<th style='background-color: #cce5ff; padding: 8px; text-align: center; font-weight: bold; font-size: 16px; text-decoration: underline;'>Validation</th>"  # noqa: E501
    html_output += "<th style='background-color: #cce5ff; padding: 8px; text-align: center; font-size: 16px; text-decoration: underline; '>Found</th>"  # noqa: E501
    html_output += "</tr>"

    for key, value in indicators.items():
        html_output +=      \
            f"<tr><td style='background-color: #ccc; padding: 8px; text-align: center; font-weight: bold; font-size: 16px;'>{key.replace('_', ' ').capitalize()}</td><td style='background-color: #eee; padding: 8px; text-align: center;'>{'✅'  if value else '❌' }</td></tr>"  # noqa: E501
    html_output += "</table></body></html>"
    return html_output


def main():
    try:
        demisto_context = demisto.context()
        html_content = demisto.get(demisto_context, 'HttpRequest.Response.Body')
        if not html_content:
            temp = demisto.get(demisto_context, 'HttpRequest.Response')
            html_content_root = None
            if isinstance(temp, list):
                html_content_root = temp[0]
            if not html_content_root:
                return_results("No HTML content provided.")
            else:
                html_content = html_content_root.get('Body')

        else:
            phishing_indicators = check_html_for_phishing(html_content)
            html_response = format_html_response(phishing_indicators)
            demisto.results({
                'ContentsFormat': formats['html'],
                'Type': entryTypes['note'],
                'Contents': html_response,
            })

    except Exception as e:
        return_error(f"Error: {str(e)}")


if __name__ in ('__main__', '__builtin__', 'builtins'):
    main()
