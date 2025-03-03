import ipaddress
import tldextract
import urllib.parse
from CommonServerPython import *
from re import Match


class URLError(Exception):
    pass


class URLType:
    """
    A class to represent an url and its parts
    """

    def __init__(self, raw_url: str):
        self.raw = raw_url
        self.scheme = ''
        self.user_info = ''
        self.hostname = ''
        self.port = ''
        self.path = ''
        self.query = ''
        self.fragment = ''

    def __str__(self):
        return (
            f'Scheme = {self.scheme}\nUser_info = {self.user_info}\nHostname = {self.hostname}\nPort = {self.port}\n'
            f'Path = {self.path}\nQuery = {self.query}\nFragment = {self.fragment}')


class URLCheck:
    """
    This class will build and validate a URL based on "URL Living Standard" (https://url.spec.whatwg.org)
    """
    sub_delims = ("!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "=")
    brackets = ("\"", "'", "[", "]", "{", "}", "(", ")")

    bracket_pairs = {
        '{': '}',
        '(': ')',
        '[': ']',
        '"': '"',
        '\'': '\'',
    }

    no_fetch_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

    def __init__(self, original_url: str):
        """
        Args:
            original_url: The original URL input

        Attributes:
            self.modified_url: The URL while being parsed by the formatter char by char
            self.original_url: The original URL as it was inputted
            self.url - The parsed URL and its parts (as a URLType object - see above)
            self.base: A pointer to the first char of the section being checked and validated
            self.output: The final URL output by the formatter
            self.inside_brackets = A flag to indicate the parser index is within brackets
            self.port = A flag to state that a port is found in the URL
            self.query = A flag to state that a query is found in the URL
            self.fragment = A flag to state that a fragment is found in the URL
            self.done = A flag to state that the parser is done and no more parsing is needed
        """

        self.modified_url = original_url
        self.original_url = original_url
        self.url = URLType(original_url)
        self.base = 0  # This attribute increases as the url is being parsed
        self.output = ''

        self.inside_brackets = 0
        self.opening_bracket = ''
        self.port = False
        self.query = False
        self.fragment = False
        self.done = False
        self.quoted = False

        if self.original_url:
            self.remove_leading_chars()

        else:
            raise URLError("Empty string given")

        if any(map(self.modified_url[:8].__contains__, ["//", "%3A", "%3a"])):
            # The URL seems to have a scheme indicated by presence of "//" or "%3A"
            self.scheme_check()

        host_end_position = -1
        special_chars = ("/", "?", "#")  # Any one of these states the end of the host / authority part in a URL

        for char in special_chars:
            try:
                host_end_position = self.modified_url[self.base:].index(char)
                break  # index for the end of the part found, breaking loop
            except ValueError:
                continue  # no reserved char found, URL has no path, query or fragment parts.

        try:
            if "@" in self.modified_url[:host_end_position]:
                # Checks if url has '@' sign in its authority part

                self.user_info_check()

        except ValueError:
            # No '@' in url at all
            pass

        self.host_check()

        if not self.done and self.port:
            self.port_check()

        if not self.done:
            self.path_check()

        if not self.done and self.query:
            self.query_check()

        if not self.done and self.fragment:
            self.fragment_check()

        while '%' in self.output:
            unquoted = urllib.parse.unquote(self.output)
            if unquoted != self.output:
                self.output = unquoted
            else:
                break

    def __str__(self):
        return f"{self.output}"

    def __repr__(self):
        return f"{self.output}"

    def scheme_check(self):
        """
        Parses and validates the scheme part of the URL, accepts ascii and "+", "-", "." according to standard.
        """

        index = self.base
        scheme = ''

        while self.modified_url[index].isascii() or self.modified_url[index] in ("+", "-", "."):

            char = self.modified_url[index]
            if char in self.sub_delims:
                raise URLError(f"Invalid character {char} at position {index}")

            elif char == "%" or char == ":":
                # The colon might appear as is or if the URL is quoted as "%3A"

                if char == "%":
                    # If % is present in the scheme it must be followed by "3A" to represent a colon (":")

                    if self.modified_url[index + 1:index + 3].upper() != "3A":
                        raise URLError(f"Invalid character {char} at position {index}")

                    else:
                        self.output += ":"
                        index += 3
                        self.quoted = True

                if char == ":":
                    self.output += char
                    index += 1

                if self.modified_url[index:index + 2] != "//":
                    # If URL has ascii chars and ':' with no '//' it is invalid

                    raise URLError(f"Invalid character {char} at position {index}")

                else:
                    self.url.scheme = scheme
                    self.output += self.modified_url[index:index + 2]
                    self.base = index + 2

                    if self.base == len(self.modified_url):
                        raise URLError("Only scheme provided")

                    return

            elif index == len(self.modified_url) - 1:
                # Reached end of url and no ":" found (like "foo//")

                raise URLError('Invalid scheme')

            else:
                # base is not incremented as it was incremented by 2 before
                self.output += char
                scheme += char
                index += 1

    def user_info_check(self):
        """
        Parses and validates the user_info part of the URL. Will only accept a username, password isn't allowed.
        """

        index = self.base
        user_info = ""

        if self.modified_url[index] == "@":
            raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

        else:
            while self.modified_url[index] not in ('@', '/', '?', '#', '[', ']'):
                self.output += self.modified_url[index]
                user_info += self.modified_url[index]
                index += 1

            if self.modified_url[index] == '@':
                self.output += self.modified_url[index]
                self.url.user_info = user_info
                self.base = index + 1
                return

            else:
                raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

    def host_check(self):
        """
        Parses and validates the host part of the URL. The domain must be valid, either a domain, IPv4 or an
        IPv6 with square brackets.
        """

        index = self.base
        host: Any = ''
        is_ip = False

        while index < len(self.modified_url) and self.modified_url[index] not in ('/', '?', '#'):

            if self.modified_url[index] in self.sub_delims:
                if self.modified_url[index] in self.brackets:
                    # Just a small trick to stop the parsing if a bracket is found
                    index = len(self.modified_url)
                    self.check_done(index)

                else:
                    raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

            elif self.modified_url[index] == "%" and not self.hex_check(index):
                raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

            elif self.modified_url[index] == ":" and self.inside_brackets == 0:
                # ":" are only allowed if host is ipv6 in which case inside_brackets equals True
                if index == len(self.modified_url) - 1:
                    raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

                elif index <= 4:
                    # This might be an IPv6 with no scheme
                    self.inside_brackets += 1
                    self.output = f"[{self.output}"  # Reading the bracket that was removed by the cleaner

                else:
                    self.port = True
                    self.output += self.modified_url[index]
                    index += 1
                    self.base = index
                    self.url.hostname = host
                    return  # Going back to main to handle port part

            elif self.modified_url[index] == "[":
                if self.inside_brackets == 0 and index == self.base:
                    # if index==base we're at the first char of the host in which "[" is ok
                    self.output += self.modified_url[index]
                    index += 1
                    self.inside_brackets += 1

                else:
                    raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

            elif self.modified_url[index] == "]":

                if self.inside_brackets == 0:
                    if self.check_domain(host) and all(char in self.brackets for char in self.modified_url[index:]):
                        # Domain is valid with trailing "]" and brackets, the formatter will remove the extra chars
                        self.done = True
                        return

                    else:
                        raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

                else:
                    try:
                        ip = ipaddress.ip_address(host)
                        is_ip = True

                    except ValueError:
                        raise URLError(f"Only IPv6 is allowed within square brackets, not {host}")

                    if self.inside_brackets != 0 and ip.version == 6:
                        self.output += self.modified_url[index]
                        index += 1
                        self.inside_brackets -= 1
                        break

                    raise URLError(f"Only IPv6 is allowed within square brackets, not {host}")

            else:
                self.output += self.modified_url[index]
                host += self.modified_url[index]
                index += 1

        if not is_ip:
            try:
                ip = ipaddress.ip_address(host)

                if ip.version == 6 and not self.output.endswith(']'):
                    self.output = f"{self.output}]"  # Adding a closing square bracket for IPv6

            except ValueError:
                self.check_domain(host)

        self.url.hostname = host
        self.check_done(index)

    def port_check(self):
        """
        Parses and validates the port part of the URL, accepts only digits. Index is starting after ":"
        """

        index = self.base
        port = ""

        while index < len(self.modified_url) and self.modified_url[index] not in ('/', '?', '#'):
            if self.modified_url[index].isdigit():
                self.output += self.modified_url[index]
                port += self.modified_url[index]
                index += 1

            else:
                raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

        self.url.port = port
        self.check_done(index)

    def path_check(self):
        """
        Parses and validates the path part of the URL.
        """

        index = self.base
        path = ""

        while index < len(self.modified_url) and self.modified_url[index] not in ('?', '#'):
            index, char = self.check_valid_character(index)
            path += char

        if self.check_done(index):
            self.url.path = path
            self.output += path
            return

        if self.modified_url[index] == "?":
            self.query = True

        elif self.modified_url[index] == "#":
            self.fragment = True

        self.output += path
        self.output += self.modified_url[index]
        index += 1
        self.base = index
        self.url.path = path

    def query_check(self):
        """
        Parses and validates the query part of the URL. The query starts after a "?".
        """
        index = self.base
        query = ''

        while index < len(self.modified_url) and self.modified_url[index] != '#':
            index, char = self.check_valid_character(index)
            query += char

        self.url.query = query
        self.output += query

        if self.check_done(index):
            return

        elif self.modified_url[index] == "#":
            self.output += self.modified_url[index]
            index += 1
            self.base = index
            self.fragment = True

    def fragment_check(self):
        """
        Parses and validates the fragment part of the URL, will not allow gen and sub delims unless encoded
        """

        index = self.base
        fragment = ""

        while index < len(self.modified_url):
            index, char = self.check_valid_character(index)
            fragment += char

        self.url.fragment = fragment
        self.output += fragment

    def check_valid_character(self, index: int) -> tuple[int, str]:
        """
        Checks the validity of a character passed by the main formatter

        Args:
            index: the index of the character within the URL

        Returns:
            returns the new index after incrementation and the part of the URL that was checked

        """

        part = ""
        char = self.modified_url[index]

        if char == "%":
            if not self.hex_check(index):
                raise URLError(f"Invalid character {char} at position {index}")

            else:
                part += char
                index += 1

        elif char in self.brackets:
            # char is a type of bracket or quotation mark

            if index == len(self.modified_url) - 1 and self.inside_brackets == 0:
                # Edge case of a bracket or quote at the end of the URL but not part of it
                return len(self.modified_url), part

            elif self.inside_brackets != 0 and char == self.bracket_pairs.get(self.opening_bracket, ''):
                # If the char is a closing bracket check that it matches the opening one.
                self.inside_brackets -= 1
                part += char
                index += 1

            elif char in self.bracket_pairs:
                # If the char is an opening bracket set `inside_brackets` flag to True
                self.inside_brackets += 1
                self.opening_bracket = char
                part += char
                index += 1

            else:
                # The char is a closing bracket but there was no opening one.
                return len(self.modified_url), part

        elif char == '\\':
            # Edge case of the url ending with an escape char
            return len(self.modified_url), part

        elif not char.isalnum() and not self.check_codepoint_validity(char):
            raise URLError(f"Invalid character {self.modified_url[index]} at position {index}")

        else:
            part += char
            index += 1

        return index, part

    @staticmethod
    def check_codepoint_validity(char: str) -> bool:
        """
        Checks if a character from the URL is a valid code point, see
        https://infra.spec.whatwg.org/#code-points for more information.  # disable-secrets-detection

        Args:
            char (str): A character derived from the URL

        Returns:
            bool: Is the character a valid code point.
        """
        url_code_points = ("!", "$", "&", "\"", "(", ")", "*", "+", ",", "-", ".", "/", ":", ";", "=", "?", "@",
                           "_", "~")
        unicode_code_points = {"start": "\u00A0", "end": "\U0010FFFD"}
        surrogate_characters = {"start": "\uD800", "end": "\uDFFF"}
        non_characters = {"start": "\uFDD0", "end": "\uFDEF"}

        if surrogate_characters["start"] <= char <= surrogate_characters["end"]:
            return False

        elif non_characters["start"] <= char <= non_characters["end"]:
            return False

        elif char in url_code_points:
            return True

        return unicode_code_points['start'] <= char <= unicode_code_points['end']

    def check_domain(self, host: str) -> bool:
        """
        Checks if the domain is a valid domain (has at least 1 dot and a tld >= 2)

        Args:
            host: The host string as extracted by the formatter

        Returns:
            True if the domain is valid

        Raises:
            URLError if the domain is invalid
        """

        if host.endswith("."):
            host = host.rstrip(".")

        if host.count(".") < 1:
            raise URLError(f"Invalid domain {host}")

        elif len(host.split(".")[-1]) < 2:
            raise URLError(f"Invalid tld for {host}")

        elif not self.no_fetch_extract(host).suffix:
            raise URLError(f"Invalid tld for {host}")

        else:
            return True

    def hex_check(self, index: int) -> bool:
        """
        Checks the next two chars in the url are hex digits

        Args:
            index: points to the position of the % character, used as a pointer to chars.

        Returns:
            True if %xx is a valid hexadecimal code.

        Raises:
            ValueError if the chars after % are invalid
        """

        try:
            int(self.modified_url[index + 1:index + 3], 16)
            return True

        except ValueError:
            return False

    def check_done(self, index: int) -> bool:
        """
        Checks if the validator already went over the URL and nothing is left to check.

        Args:
            index: The current index of the pointer

        Returns:
            True if the entire URL has been verified False if not.
        """

        if index == len(self.modified_url):
            # End of inputted url, no need to test further
            self.done = True
            return True

        elif self.modified_url[index] == "/":
            self.output += self.modified_url[index]
            index += 1

        self.base = index
        return False

    def remove_leading_chars(self):
        """
        Will remove all leading chars of the following ("\"", "'", "[", "]", "{", "}", "(", ")", ",")
        from the URL.
        """

        beginning = 0
        end = -1

        in_brackets = True

        while in_brackets:
            try:
                if self.bracket_pairs[self.modified_url[beginning]] == self.modified_url[end]:
                    beginning += 1
                    end -= 1

                else:
                    in_brackets = False

            except KeyError:
                in_brackets = False

        while self.modified_url[beginning] in self.brackets:
            beginning += 1

        if end == -1:
            self.modified_url = self.modified_url[beginning:]

        else:
            self.modified_url = self.modified_url[beginning:end + 1]


class URLFormatter:

    # URL Security Wrappers
    ATP_regex = re.compile('.*?[.]safelinks[.]protection[.](?:outlook|office365)[.](?:com|us)/.*?[?]url=(.*?)&', re.I)
    fireeye_regex = re.compile('.*?fireeye[.]com.*?&u=(.*)', re.I)
    proofpoint_regex = re.compile('(?i)(?:proofpoint.com/v[1-2]/(?:url\?u=)?(.+?)(?:&amp|&d|$)|'
                                  'https?(?::|%3A)//urldefense[.]\w{2,3}/v3/__(.+?)(?:__;|$))')
    trendmicro_regex = re.compile('.*?trendmicro\.com(?::443)?/wis/clicktime/.*?/?url==3d(.*?)&',  # disable-secrets-detection
                                  re.I)

    # Scheme slash fixer
    scheme_fix = re.compile("https?(:[/|\\\]*)")

    def __init__(self, original_url):
        """
        Main class for formatting a URL

        Args:
            original_url: The original URL in lower case

        Raises:
            URLError if an exception occurs
        """

        self.original_url = original_url
        self.output = ''

        url = self.correct_and_refang_url(self.original_url)
        url = self.strip_wrappers(url)
        url = self.correct_and_refang_url(url)

        try:
            self.output = URLCheck(url).output

        except URLError:
            raise

    def __repr__(self):
        return f"{self.output}"

    def __str__(self):
        return f"{self.output}"

    @staticmethod
    def strip_wrappers(url: str) -> str:
        """
        Allows for stripping of multiple safety wrappers of URLs

        Args:
            url: The original wrapped URL

        Returns:
            The URL without wrappers
        """

        wrapper = True

        while wrapper:
            # Will strip multiple wrapped URLs, wrappers are finite the loop will stop once all wrappers were removed

            if "%3A" in url[:8].upper():
                # If scheme has %3A URL is probably quoted and should be unquoted
                url = urllib.parse.unquote(url)

            if URLFormatter.fireeye_regex.match(url):
                url = URLFormatter.fireeye_regex.findall(url)[0]

            elif URLFormatter.trendmicro_regex.match(url):
                url = URLFormatter.trendmicro_regex.findall(url)[0]

            elif URLFormatter.ATP_regex.match(url):
                url = URLFormatter.ATP_regex.findall(url)[0]

            elif URLFormatter.proofpoint_regex.findall(url):
                url = URLFormatter.extract_url_proofpoint(URLFormatter.proofpoint_regex.findall(url)[0])

            else:
                wrapper = False

        return url

    @staticmethod
    def extract_url_proofpoint(url: str) -> str:
        """
        Extracts the domain from the Proofpoint wrappers using a regex

        Args:
            url: The proofpoint wrapped URL

        Returns:
            Unquoted extracted URL as a string
        """

        if url[0]:
            # Proofpoint v1 and v2
            return urllib.parse.unquote(url[0].replace("-", "%").replace("_", "/"))

        else:
            # Proofpoint v3
            return urllib.parse.unquote(url[1])

    @staticmethod
    def correct_and_refang_url(url: str) -> str:
        """
        Refangs URL and corrects its scheme

        Args:
            url: The original URL

        Returns:
            Refnaged corrected URL
        """

        schemas = re.compile("(meow|hxxp)", re.IGNORECASE)
        url = url.replace("[.]", ".")
        url = url.replace("[:]", ":")
        lower_url = url.lower()
        if lower_url.startswith(('hxxp', 'meow')):
            url = re.sub(schemas, "http", url, count=1)

        def fix_scheme(match: Match) -> str:
            return re.sub(":(\\\\|/)*", "://", match.group(0))

        return URLFormatter.scheme_fix.sub(fix_scheme, url)


def _is_valid_cidr(cidr: str) -> bool:
    """
    Will check if "url" is a valid CIDR in order to ignore it
    Args:
        cidr: the suspected input

    Returns:
        True if inout is a valid CIDR

    """
    if not cidr[-1].isdigit():  # precaution incase the regex caught an extra char by mistake
        cidr = cidr[:-1]

    try:
        ipaddress.ip_network(cidr)
        return True
    except ValueError:
        return False


def format_urls(raw_urls: list[str]) -> list[str]:
    formatted_urls: List[str] = []

    for url in raw_urls:
        formatted_url = ''

        if _is_valid_cidr(url):
            # If input is a valid CIDR formatter will ignore it to let it become a CIDR
            formatted_urls.append('')
            continue

        try:
            formatted_url = URLFormatter(url).output

        except URLError:
            demisto.debug(traceback.format_exc())

        except Exception:
            demisto.debug(traceback.format_exc())

        finally:
            formatted_urls.append(formatted_url)
    return formatted_urls
