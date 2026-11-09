"""tLab Anti-APT Feed integration for Cortex XSOAR.

Turns observables seen during sandbox analysis into Threat Intel Management
indicators.

The hard part is not fetching but precision. tLab reports observables as
``{kind, name}`` pairs where ``kind`` is often just ``VALUE``, so the value has
to be typed here. A feed that guesses badly is worse than no feed: it fills TIM
with file names typed as domains and sandbox-internal addresses typed as
infrastructure, and analysts stop trusting the source.
"""

import demistomock as demisto  # noqa: F401
from CommonServerPython import *  # noqa: F401
from CommonServerUserPython import *  # noqa: F401

from TLabAntiAPTApiModule import *  # noqa: F401,E402

import ipaddress
import re

# Vendored from https://data.iana.org/TLD/tlds-alpha-by-domain.txt (version 2026093000).
#
# The list is embedded rather than downloaded because the pack must install in
# air-gapped networks, and a separate data file would not survive the unify step
# that turns this integration into a single YAML.
#
# Without it, domain typing is unusable: "kernel32.dll" and "setup.exe" satisfy
# every naive FQDN grammar, and a feed that emits those as domains poisons TIM.
# Refresh with:
#     curl -sfL https://data.iana.org/TLD/tlds-alpha-by-domain.txt \
#       | grep -v '^#' | tr 'A-Z' 'a-z' | sort | tr '\n' ' '
_TLD_DATA = (
    "aaa aarp abb abbott abbvie abc able abogado abudhabi ac academy accenture accountant accountants aco "
    "actor ad ads adult ae aeg aero aetna af afl africa ag agakhan agency ai aig airbus airforce airtel "
    "akdn al alibaba alipay allfinanz allstate ally alsace alstom am amazon americanexpress "
    "americanfamily amex amfam amica amsterdam analytics android anquan anz ao aol apartments app apple "
    "aq aquarelle ar arab aramco archi army arpa art arte as asda asia associates at athleta attorney au "
    "auction audi audible audio auspost author auto autos aw aws ax axa az azure ba baby baidu banamex "
    "band bank bar barcelona barclaycard barclays barefoot bargains baseball basketball bauhaus bayern bb "
    "bbc bbt bbva bcg bcn bd be beats beauty beer berlin best bestbuy bet bf bg bh bharti bi bible bid "
    "bike bing bingo bio biz bj black blackfriday blockbuster blog bloomberg blue bm bms bmw bn "
    "bnpparibas bo boats boehringer bofa bom bond boo book booking bosch bostik boston bot boutique box "
    "br bradesco bridgestone broadway broker brother brussels bs bt build builders business buy buzz bv "
    "bw by bz bzh ca cab cafe cal call calvinklein cam camera camp canon capetown capital capitalone car "
    "caravan cards care career careers cars casa case cash casino cat catering catholic cba cbn cbre cc "
    "cd center ceo cern cf cfa cfd cg ch chanel channel charity chase chat cheap chintai christmas chrome "
    "church ci cipriani circle cisco citadel citi citic city ck cl claims cleaning click clinic clinique "
    "clothing cloud club clubmed cm cn co coach codes coffee college cologne com commbank community "
    "company compare computer comsec condos construction consulting contact contractors cooking cool coop "
    "corsica country coupon coupons courses cpa cr credit creditcard creditunion cricket crown crs cruise "
    "cruises cu cuisinella cv cw cx cy cymru cyou cz dad dance data date dating datsun day dclk dds de "
    "deal dealer deals degree delivery dell deloitte delta democrat dental dentist desi design dev dhl "
    "diamonds diet digital direct directory discount discover dish diy dj dk dm dnp do docs doctor dog "
    "domains dot download drive dtv dubai dupont durban dvag dvr dz earth eat ec eco edeka edu education "
    "ee eg email emerck energy engineer engineering enterprises epson equipment er ericsson erni es esq "
    "estate et eu eurovision eus events exchange expert exposed express extraspace fage fail fairwinds "
    "faith family fan fans farm farmers fashion fast fedex feedback ferrari ferrero fi fidelity fido film "
    "final finance financial fire firestone firmdale fish fishing fit fitness fj fk flickr flights flir "
    "florist flowers fly fm fo foo food football ford forex forsale forum foundation fox fr free "
    "fresenius frl frogans frontier ftr fujitsu fun fund furniture futbol fyi ga gal gallery gallo gallup "
    "game games gap garden gay gb gbiz gd gdn ge gea gent genting george gf gg ggee gh gi gift gifts "
    "gives giving gl glass gle global globo gm gmail gmbh gmo gmx gn godaddy gold goldpoint golf goodyear "
    "goog google gop got gov gp gq gr grainger graphics gratis green gripe grocery group gs gt gu gucci "
    "guge guide guitars guru gw gy hair hamburg hangout haus hbo hdfc hdfcbank health healthcare help "
    "helsinki here hermes hiphop hisamitsu hitachi hiv hk hkt hm hn hockey holdings holiday homedepot "
    "homegoods homes homesense honda horse hospital host hosting hot hotels hotmail house how hr hsbc ht "
    "hu hughes hyatt hyundai ibm icbc ice icu id ie ieee ifm ikano il im imamat imdb immo immobilien in "
    "inc industries infiniti info ing ink institute insurance insure int international intuit investments "
    "io ipiranga iq ir irish is ismaili ist istanbul it itau itv jaguar java jcb je jeep jetzt jewelry "
    "jio jll jm jmp jnj jo jobs joburg jot joy jp jpmorgan jprs juegos juniper kaufen kddi ke kerryhotels "
    "kerryproperties kfh kg kh ki kia kids kim kindle kitchen kiwi km kn koeln komatsu kosher kp kpmg kpn "
    "kr krd kred kuokgroup kw ky kyoto kz la lacaixa lamborghini lamer land landrover lanxess lasalle lat "
    "latino latrobe law lawyer lb lc lds lease leclerc lefrak legal lego lexus lgbt li lidl life "
    "lifeinsurance lifestyle lighting like lilly limited limo lincoln link live living lk llc llp loan "
    "loans locker locus lol london lotte lotto love lpl lplfinancial lr ls lt ltd ltda lu lundbeck luxe "
    "luxury lv ly ma madrid maif maison makeup man management mango map market marketing markets marriott "
    "marshalls mattel mba mc mckinsey md me med media meet melbourne meme memorial men menu merck "
    "merckmsd mg mh miami microsoft mil mini mint mit mitsubishi mk ml mlb mls mm mma mn mo mobi mobile "
    "moda moe moi mom monash money monster mormon mortgage moscow moto motorcycles mov movie mp mq mr ms "
    "msd mt mtn mtr mu museum music mv mw mx my mz na nab nagoya name navy nba nc ne nec net netbank "
    "netflix network neustar new news next nextdirect nexus nf nfl ng ngo nhk ni nico nike nikon ninja "
    "nissan nissay nl no nokia norton now nowruz nowtv np nr nra nrw ntt nu nyc nz obi observer office "
    "okinawa olayan olayangroup ollo om omega one ong onl online ooo open oracle orange org organic "
    "origins osaka otsuka ott ovh pa page panasonic paris pars partners parts party pay pccw pe pet pf "
    "pfizer pg ph pharmacy phd philips phone photo photography photos physio pics pictet pictures pid pin "
    "ping pink pioneer pizza pk pl place play playstation plumbing plus pm pn pnc pohl poker politie porn "
    "post pr praxi press prime pro prod productions prof progressive promo properties property protection "
    "pru prudential ps pt pub pw pwc py qa qpon quebec quest racing radio re read realestate realtor "
    "realty recipes red redumbrella rehab reise reisen reit reliance ren rent rentals repair report "
    "republican rest restaurant review reviews rexroth rich richardli ricoh ril rio rip ro rocks rodeo "
    "rogers room rs rsvp ru rugby ruhr run rw rwe ryukyu sa saarland safe safety sakura sale salon "
    "samsclub samsung sandvik sandvikcoromant sanofi sap sarl sas save saxo sb sbi sbs sc scb schaeffler "
    "schmidt scholarships school schule schwarz science scot sd se search seat secure security seek "
    "select sener services seven sew sex sexy sfr sg sh shangrila sharp shell shia shiksha shoes shop "
    "shopping shouji show si silk sina singles site sj sk ski skin sky skype sl sling sm smart smile sn "
    "sncf so soccer social softbank software sohu solar solutions song sony soy spa space sport spot sr "
    "srl ss st stada staples star statebank statefarm stc stcgroup stockholm storage store stream studio "
    "study style su sucks supplies supply support surf surgery suzuki sv swatch swiss sx sy sydney "
    "systems sz tab taipei talk taobao target tatamotors tatar tattoo tax taxi tc tci td tdk team tech "
    "technology tel temasek tennis teva tf tg th thd theater theatre tiaa tickets tienda tips tires tirol "
    "tj tjmaxx tjx tk tkmaxx tl tm tmall tn to today tokyo tools top toray toshiba total tours town "
    "toyota toys tr trade trading training travel travelers travelersinsurance trust trv tt tube tui "
    "tunes tushu tv tvs tw tz ua ubank ubs ug uk unicom university uno uol ups us uy uz va vacations vana "
    "vanguard vc ve vegas ventures verisign versicherung vet vg vi viajes video vig viking villas vin vip "
    "virgin visa vision viva vivo vlaanderen vn vodka volvo vote voting voto voyage vu wales walmart "
    "walter wang wanggou watch watches weather weatherchannel web webcam weber website wed wedding weibo "
    "weir wf whoswho wien wiki williamhill win windows wine winners wme woodside work works world wow ws "
    "wtc wtf xbox xerox xihuan xin xn--11b4c3d xn--1ck2e1b xn--1qqw23a xn--2scrj9c xn--30rr7y xn--3bst00m "
    "xn--3ds443g xn--3e0b707e xn--3hcrj9c xn--3pxu8k xn--42c2d9a xn--45br5cyl xn--45brj9c xn--45q11c "
    "xn--4dbrk0ce xn--4gbrim xn--54b7fta0cc xn--55qw42g xn--55qx5d xn--5su34j936bgsg xn--5tzm5g "
    "xn--6frz82g xn--6qq986b3xl xn--80adxhks xn--80ao21a xn--80aqecdr1a xn--80asehdb xn--80aswg "
    "xn--8y0a063a xn--90a3ac xn--90ae xn--90ais xn--9dbq2a xn--9et52u xn--9krt00a xn--b4w605ferd "
    "xn--bck1b9a5dre4c xn--c1avg xn--c2br7g xn--cck2b3b xn--cckwcxetd xn--cg4bki xn--clchc0ea0b2g2a9gcd "
    "xn--czr694b xn--czrs0t xn--czru2d xn--d1acj3b xn--d1alf xn--e1a4c xn--eckvdtc9d xn--efvy88h "
    "xn--fct429k xn--fhbei xn--fiq228c5hs xn--fiq64b xn--fiqs8s xn--fiqz9s xn--fjq720a xn--flw351e "
    "xn--fpcrj9c3d xn--fzc2c9e2c xn--fzys8d69uvgm xn--g2xx48c xn--gckr3f0f xn--gecrj9c xn--gk3at1e "
    "xn--h2breg3eve xn--h2brj9c xn--h2brj9c8c xn--hxt814e xn--i1b6b1a6a2e xn--imr513n xn--io0a7i "
    "xn--j1aef xn--j1amh xn--j6w193g xn--jlq480n2rg xn--jvr189m xn--kcrx77d1x4a xn--kprw13d xn--kpry57d "
    "xn--kput3i xn--l1acc xn--lgbbat1ad8j xn--mgb9awbf xn--mgba3a3ejt xn--mgba3a4f16a xn--mgba7c0bbn0a "
    "xn--mgbaam7a8h xn--mgbab2bd xn--mgbah1a3hjkrd xn--mgbai9azgqp6j xn--mgbayh7gpa xn--mgbbh1a "
    "xn--mgbbh1a71e xn--mgbc0a9azcg xn--mgbca7dzdo xn--mgbcpq6gpa1a xn--mgberp4a5d4ar xn--mgbgu82a "
    "xn--mgbi4ecexp xn--mgbpl2fh xn--mgbt3dhd xn--mgbtx2b xn--mgbx4cd0ab xn--mix891f xn--mk1bu44c "
    "xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--ngbrx xn--node xn--nqv7f xn--nqv7fs00ema xn--nyqy26a "
    "xn--o3cw4h xn--ogbpf8fl xn--otu796d xn--p1acf xn--p1ai xn--pgbs0dh xn--pssy2u xn--q7ce6a xn--q9jyb4c "
    "xn--qcka1pmc xn--qxa6a xn--qxam xn--rhqv96g xn--rovu88b xn--rvc1e0am3e xn--s9brj9c xn--ses554g "
    "xn--t60b56a xn--tckwe xn--tiq49xqyj xn--unup4y xn--vermgensberater-ctb xn--vermgensberatung-pwb "
    "xn--vhquv xn--vuq861b xn--w4r85el8fhu5dnra xn--w4rs40l xn--wgbh1c xn--wgbl6a xn--xhq521b "
    "xn--xkc2al3hye2a xn--xkc2dl3a5ee0h xn--y9a3aq xn--yfro4i67o xn--ygbi2ammx xn--zfr164b xxx xyz yachts "
    "yahoo yamaxun yandex ye yodobashi yoga yokohama you youtube yt yun za zappos zara zero zip zm zone "
    "zuerich zw"
)
TLD_SET = frozenset(_TLD_DATA.split())

# Suffixes that are simultaneously real TLDs and common file extensions. Only
# these six actually need a decision — every other extension fails the TLD check
# on its own, so listing it here would just be noise.
#
# Each choice is made for SANDBOX observable data specifically:
#   zip, cab  archives dominate; the gTLDs exist but are barely used
#   sh, py    install.sh and script.py against Saint Helena and Paraguay
#   so        lib.so against Somalia
#
# ".com" is deliberately ABSENT. It is the most common TLD in the world, and
# DOS .com executables are a historical rarity; rejecting it would silently
# drop the majority of real C2 domains.
TLD_FILE_EXTENSION_COLLISIONS = frozenset({"cab", "py", "sh", "so", "zip"})

# ThreatEvidenceCollectors truncates observable values at this length, so a
# value of exactly this size is probably cut mid-token and cannot be trusted.
MAX_VALUE_LENGTH = 300

# A sandbox VM's traffic is overwhelmingly RFC1918 plus link-local and
# multicast noise. Emitting that as threat intel is actively harmful.
DEFAULT_EXCLUDED_NETWORKS = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "0.0.0.0/8",
    "255.255.255.255/32",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]

RE_URL = re.compile(r"^[a-z][a-z0-9+.\-]*://\S+$", re.I)
RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[a-z]{2,}$", re.I)
RE_MD5 = re.compile(r"^[0-9a-f]{32}$", re.I)
RE_SHA1 = re.compile(r"^[0-9a-f]{40}$", re.I)
RE_SHA256 = re.compile(r"^[0-9a-f]{64}$", re.I)
RE_REGISTRY = re.compile(r"^HK(EY_)?(LM|CU|CR|U|CC|LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)[\\/]", re.I)
RE_DOMAIN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
RE_ATTACK = re.compile(r"^T\d{4}(\.\d{3})?$")

# Object kinds that are not indicators.
#   FILE    - file NAMES, not hashes. Emitting them as File indicators would
#             poison TIM with values nothing can ever match.
#   PROCESS - process image names such as svchost.exe.
#   SIGNATURE - antivirus signature names, which have no XSOAR indicator type.
NON_INDICATOR_KINDS = {"FILE", "PROCESS", "SIGNATURE"}

# ATT&CK techniques are a Threat Intel *object*, not a member of
# FeedIndicatorType. Using ATTACK_PATTERN_TYPE raises
# AttributeError at runtime; the type name lives under ThreatIntel.
ATTACK_PATTERN_TYPE = ThreatIntel.ObjectsNames.ATTACK_PATTERN

OUTPUT_INDICATOR = "TLabAntiAPT.Indicator"
BATCH_SIZE = 2000


# --------------------------------------------------------------------------
# Typing
# --------------------------------------------------------------------------
def type_value(value: str, excluded_networks: list, allow_private: bool = False) -> str | None:
    """Classify a free-form observable, or return None when it cannot be trusted.

    The cascade is anchored and ordered most-specific first. Anything that does
    not match cleanly is dropped: a wrong indicator costs an analyst more than
    a missing one.
    """
    candidate = (value or "").strip()
    if not candidate:
        return None
    # A value at the server's truncation limit is probably cut mid-token.
    if len(candidate) >= MAX_VALUE_LENGTH:
        return None
    # Whitespace means a sentence or a command line, not an observable — unless
    # the whole thing is a URL, which cannot contain spaces anyway.
    if any(ch.isspace() for ch in candidate) and not RE_URL.match(candidate):
        return None

    ip_type = _ip_type(candidate, excluded_networks, allow_private)
    if ip_type is not None:
        return ip_type or None

    if RE_URL.match(candidate):
        return FeedIndicatorType.URL
    if RE_EMAIL.match(candidate):
        return FeedIndicatorType.Email
    if RE_SHA256.match(candidate):
        return FeedIndicatorType.File
    if RE_SHA1.match(candidate):
        return FeedIndicatorType.File
    if RE_MD5.match(candidate):
        return FeedIndicatorType.File
    if RE_REGISTRY.match(candidate):
        return FeedIndicatorType.Registry
    if _is_domain(candidate):
        return FeedIndicatorType.Domain
    return None


def _ip_type(candidate: str, excluded_networks: list, allow_private: bool) -> str | None:
    """Return the IP indicator type, '' when the address is excluded, or None
    when the value is not an address at all."""
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if not allow_private and _is_excluded(address, excluded_networks):
        return ""
    return FeedIndicatorType.IPv6 if address.version == 6 else FeedIndicatorType.IP


def _is_excluded(address, excluded_networks: list) -> bool:
    for network in excluded_networks:
        try:
            if address in ipaddress.ip_network(network, strict=False):
                return True
        except ValueError:
            demisto.debug(f"tLab feed: ignoring malformed excluded network {network!r}")
    return False


def _is_domain(candidate: str) -> bool:
    """A hostname is a domain only if its last label is a real TLD and not a
    file extension.

    Both checks are required. Without the TLD list, "kernel32.dll" passes the
    grammar; without the collision list, "payload.zip" and "install.sh" pass too,
    because .zip and .sh are genuine TLDs.
    """
    if "\\" in candidate or not RE_DOMAIN.match(candidate):
        return False
    last_label = candidate.rsplit(".", 1)[-1].lower()
    if last_label in TLD_FILE_EXTENSION_COLLISIONS:
        return False
    return last_label in TLD_SET


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------
def sample_file_indicator(report: dict, params: dict, report_url: str = "") -> dict | None:
    """The analyzed sample itself, which anchors every relationship."""
    file_dto = report.get("file") or {}
    sha256 = file_dto.get("hashSha256")
    if not sha256:
        return None
    suspicious_from, malicious_from = _thresholds(params)
    verdict = canonical_verdict(report, suspicious_from=suspicious_from, malicious_from=malicious_from)
    score, present = score_value(report)

    fields = {
        "md5": file_dto.get("hashMd5"),
        "sha1": file_dto.get("hashSha1"),
        "sha256": sha256,
        "size": file_dto.get("size"),
        "filetype": file_dto.get("fileType"),
        "firstseenbysource": epoch_to_iso(report.get("createTime")),
        "lastseenbysource": epoch_to_iso(report.get("updateTime")),
        "tlabsamplereportid": report.get("sampleReportId"),
        "tlabverdict": verdict,
        "tlabreporturl": report_url or None,
    }
    if present:
        fields["tlabscore"] = score
    classifier = report.get("malwareClassifierResult") or {}
    if classifier.get("primaryType"):
        fields["malwarefamily"] = classifier["primaryType"]
    if report.get("uploadedFilename"):
        fields["associatedfilenames"] = [report["uploadedFilename"]]

    return {
        "value": sha256,
        "type": FeedIndicatorType.File,
        "rawJSON": {"service": "tLab Anti-APT", "sample_report_id": report.get("sampleReportId"), "verdict": verdict},
        "score": verdict_to_dbot_score(verdict),
        "fields": remove_empty_elements(fields),
    }


def extract_from_threat_indicators(
    payload: dict, params: dict, min_level: str, excluded_networks: list
) -> tuple[list, list, list]:
    """Mine observables out of the aggregated threat indicator response."""
    levels = _levels_at_or_above(min_level)
    include_filenames = param_bool(params, "include_filenames")
    allow_private = param_bool(params, "include_private_addresses")

    found: dict[tuple, dict] = {}
    signatures: list = []
    filenames: list = []

    for indicator in payload.get("indicators") or []:
        level = str(indicator.get("level") or "").upper()
        if level not in levels:
            continue
        title = indicator.get("title") or indicator.get("key") or ""
        source = indicator.get("source") or ""

        for obj in indicator.get("objects") or []:
            kind = str(obj.get("kind") or "").upper()
            name = obj.get("name") or ""
            if kind in NON_INDICATOR_KINDS:
                if kind == "SIGNATURE" and name:
                    signatures.append(name)
                elif kind == "FILE" and name and include_filenames:
                    filenames.append(name)
                continue
            indicator_type = type_value(name, excluded_networks, allow_private)
            if not indicator_type:
                continue
            key = (indicator_type, name.strip().lower())
            if key in found:
                continue
            found[key] = {
                "value": name.strip(),
                "type": indicator_type,
                "rawJSON": {
                    "service": "tLab Anti-APT",
                    "source": source,
                    "level": level,
                    "title": title,
                    "analysis_type": indicator.get("analysisType"),
                },
                "score": _level_to_score(level),
                "fields": remove_empty_elements(
                    {
                        "tlabverdict": _level_to_verdict(level),
                        "description": title or None,
                    }
                ),
            }

        for technique in indicator.get("attack") or []:
            if not RE_ATTACK.match(str(technique)):
                continue
            key = (ATTACK_PATTERN_TYPE, str(technique).lower())
            found.setdefault(
                key,
                {
                    "value": str(technique),
                    "type": ATTACK_PATTERN_TYPE,
                    "rawJSON": {"service": "tLab Anti-APT", "technique": technique},
                    "fields": {},
                },
            )

    return list(found.values()), signatures, filenames


def extract_attack_patterns(matrix: dict) -> list:
    """ATT&CK techniques from the dedicated endpoint.

    Preferred over the raw ids embedded in threat indicators, because this
    response already resolves revoked techniques and carries names and links.
    """
    out = []
    for technique in matrix.get("techniques") or []:
        technique_id = str(technique.get("id") or "")
        if not RE_ATTACK.match(technique_id):
            continue
        out.append(
            {
                "value": technique_id,
                "type": ATTACK_PATTERN_TYPE,
                "rawJSON": {"service": "tLab Anti-APT", "technique": technique},
                "score": ThreatIntel.ObjectsScore.ATTACK_PATTERN,
                "fields": remove_empty_elements(
                    {
                        "description": technique.get("description") or technique.get("name"),
                        "publications": [{"link": technique.get("url"), "title": technique.get("name")}]
                        if technique.get("url")
                        else None,
                    }
                ),
            }
        )
    return out


def build_relationships(sample_sha256: str, indicators: list, enabled: bool) -> None:
    """Attach relationships from the sample to everything seen with it.

    Relationships require server 6.2.0, so this degrades to a no-op rather than
    failing the fetch on an older instance.
    """
    if not enabled or not sample_sha256 or not supports_relationships():
        return
    for indicator in indicators:
        name = _relationship_name(indicator["type"])
        if not name:
            continue
        relationship = EntityRelationship(
            name=name,
            entity_a=sample_sha256,
            entity_a_type=FeedIndicatorType.File,
            entity_b=indicator["value"],
            entity_b_type=indicator["type"],
            source_reliability=None,
            brand="tLab Anti-APT",
        )
        indicator.setdefault("relationships", []).append(relationship.to_indicator())


def _relationship_name(indicator_type: str) -> str | None:
    if indicator_type == ATTACK_PATTERN_TYPE:
        return EntityRelationship.Relationships.USES
    if indicator_type in (FeedIndicatorType.IP, FeedIndicatorType.IPv6, FeedIndicatorType.Domain, FeedIndicatorType.URL):
        return EntityRelationship.Relationships.COMMUNICATES_WITH
    if indicator_type == FeedIndicatorType.File:
        return EntityRelationship.Relationships.DROPS
    return EntityRelationship.Relationships.RELATED_TO


def supports_relationships() -> bool:
    try:
        return is_demisto_version_ge("6.2.0")
    except Exception:  # noqa: BLE001 - older servers raise instead of returning False
        return False


def _thresholds(params: dict) -> tuple[float, float]:
    return (
        float(params.get("score_threshold_suspicious") or DEFAULT_SUSPICIOUS_FROM),
        float(params.get("score_threshold_malicious") or DEFAULT_MALICIOUS_FROM),
    )


_LEVEL_ORDER = ["INFO", "SUSPICIOUS", "MALICIOUS"]


def _levels_at_or_above(minimum: str) -> set:
    minimum = (minimum or "SUSPICIOUS").upper()
    if minimum not in _LEVEL_ORDER:
        minimum = "SUSPICIOUS"
    return set(_LEVEL_ORDER[_LEVEL_ORDER.index(minimum) :])


def _level_to_score(level: str) -> int:
    return {"MALICIOUS": Common.DBotScore.BAD, "SUSPICIOUS": Common.DBotScore.SUSPICIOUS}.get(
        level.upper(), Common.DBotScore.NONE
    )


def _level_to_verdict(level: str) -> str:
    return {"MALICIOUS": VERDICT_MALWARE, "SUSPICIOUS": VERDICT_SUSPICIOUS}.get(level.upper(), VERDICT_UNKNOWN)


# --------------------------------------------------------------------------
# Cursor
# --------------------------------------------------------------------------
# The sandbox has no "updatedSince" filter and completes analyses out of id
# order, so a single cursor cannot be correct:
#
#   an id cursor alone loses reports that finish after a higher id already did
#   an updateTime cursor alone cannot be filtered server-side
#
# So the fetch runs two passes, exactly like the Go push service. Duplicates
# between them are not a problem: TIM merges indicators by value, and feeds are
# expected to re-submit what they already sent.
def discovery_page(client: TLabClient, cursor: int, size: int, params: dict) -> dict:
    """New reports, oldest first, so the cursor can advance monotonically."""
    return client.list_sample_reports(
        page=0,
        size=size,
        sort="sampleReportId,asc",
        min_report_id=cursor,
        completeness=_completeness_filter(params),
        root_only=True,
    )


def maturation_page(client: TLabClient, lookback_hours: int, size: int, params: dict) -> dict:
    """Reports touched recently, to catch analyses that completed late."""
    since = datetime.now(timezone.utc) - timedelta(hours=max(1, lookback_hours))
    return client.list_sample_reports(
        page=0,
        size=size,
        sort="updateTime,desc",
        date_from=since.strftime(TLAB_DATE_FORMAT),
        completeness=_completeness_filter(params),
        root_only=True,
    )


def param_bool(params: dict, key: str, default: bool = False) -> bool:
    """``params.get(key) or default`` silently ignores an explicit false when
    the default is true, so the flag becomes unsettable. Read it explicitly."""
    value = params.get(key)
    if value is None or value == "":
        return default
    try:
        return argToBoolean(value)
    except ValueError:
        return default


def _completeness_filter(params: dict) -> list:
    """Only harvest analyses that are actually finished.

    A PARTIALLY_COMPLETE report still has stages running, and its observables
    are a snapshot that will change. Emitting them produces indicators whose
    verdict contradicts the finished report minutes later.
    """
    return ["COMPLETE"] if not param_bool(params, "include_partial") else ["COMPLETE", "PARTIALLY_COMPLETE"]


def next_cursor(reports: list, current: int) -> int:
    """Advance past the highest id seen; never move backwards."""
    highest = current
    for report in reports:
        report_id = arg_to_number(report.get("sampleReportId")) or 0
        highest = max(highest, report_id + 1)
    return highest


# --------------------------------------------------------------------------
# Collection
# --------------------------------------------------------------------------
def collect_from_report(client: TLabClient, report: dict, params: dict, excluded_networks: list) -> list:
    """Every indicator derived from one sample report, with relationships."""
    report_id = arg_to_number(report.get("sampleReportId"))
    if report_id is None:
        return []

    min_level = params.get("min_indicator_level") or "SUSPICIOUS"
    indicators: list = []

    sample = sample_file_indicator(report, params, _report_url(params, report_id))
    if sample:
        indicators.append(sample)

    observables: list = []
    try:
        payload = client.get_threat_indicators(report_id)
        observables, signatures, filenames = extract_from_threat_indicators(payload, params, min_level, excluded_networks)
        if sample and (signatures or filenames):
            _annotate_sample(sample, signatures, filenames)
    except Exception as exc:  # noqa: BLE001 - one bad report must not sink the fetch
        demisto.debug(f"threat_indicators failed for report {report_id}: {exc}")

    if param_bool(params, "fetch_attack_patterns"):
        try:
            observables.extend(extract_attack_patterns(client.get_attack_matrix(report_id)))
        except Exception as exc:  # noqa: BLE001
            demisto.debug(f"attack_matrix failed for report {report_id}: {exc}")

    build_relationships(
        (report.get("file") or {}).get("hashSha256") or "",
        observables,
        param_bool(params, "create_relationships", True),
    )
    indicators.extend(observables)
    return indicators


def _annotate_sample(sample: dict, signatures: list, filenames: list) -> None:
    """Signature and file names have no indicator type, so they enrich the sample."""
    if signatures:
        sample["fields"]["tlabsignatures"] = sorted(set(signatures))
    if filenames:
        existing = sample["fields"].get("associatedfilenames") or []
        sample["fields"]["associatedfilenames"] = sorted(set(existing) | set(filenames))


def _report_url(params: dict, report_id: int) -> str:
    base = (params.get("url") or "").rstrip("/")
    return f"{base}/reports/{report_id}" if base else ""


def decorate(indicators: list, params: dict) -> list:
    """Apply the feed-wide fields XSOAR expects every feed to set."""
    tags = argToList(params.get("feedTags"))
    tlp = params.get("tlp_color")
    for indicator in indicators:
        fields = indicator.setdefault("fields", {})
        if tags:
            fields["tags"] = tags
        if tlp:
            fields["trafficlightprotocol"] = tlp
    return indicators


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def fetch_indicators(client: TLabClient, params: dict, preview: bool = False) -> tuple[list, int]:
    """Both cursor passes, deduplicated by (type, value). Returns the new cursor."""
    context = demisto.getIntegrationContext() or {}
    # first_report_id is a floor: raising it takes effect on the next fetch
    # even after fetching has started, and only ever moves the cursor forward.
    floor = arg_to_number(params.get("first_report_id")) or 0
    cursor = max(arg_to_number(context.get("report_cursor")) or 0, floor)
    page_size = arg_to_number(params.get("max_reports_per_fetch")) or 50
    excluded_networks = argToList(params.get("excluded_networks")) or DEFAULT_EXCLUDED_NETWORKS

    reports: dict[int, dict] = {}
    discovery = discovery_page(client, cursor, page_size, params)
    for report in discovery.get("content") or []:
        report_id = arg_to_number(report.get("sampleReportId"))
        if report_id is not None:
            reports[report_id] = report
    advanced = next_cursor(list(reports.values()), cursor)

    lookback = arg_to_number(params.get("maturation_lookback_hours")) or 0
    if lookback and not preview:
        for report in maturation_page(client, lookback, page_size, params).get("content") or []:
            report_id = arg_to_number(report.get("sampleReportId"))
            # Only reports the discovery pass already walked past — anything
            # newer it will pick up on its own next run.
            if report_id is not None and report_id not in reports and floor <= report_id < cursor:
                reports[report_id] = report

    collected: dict[tuple, dict] = {}
    for report in sorted(reports.values(), key=lambda r: arg_to_number(r.get("sampleReportId")) or 0):
        for indicator in collect_from_report(client, report, params, excluded_networks):
            key = (indicator["type"], str(indicator["value"]).lower())
            if key in collected:
                _merge(collected[key], indicator)
            else:
                collected[key] = indicator

    return decorate(list(collected.values()), params), advanced


def _merge(existing: dict, incoming: dict) -> None:
    """Keep the worst verdict and union the relationships across reports."""
    if incoming.get("score", 0) > existing.get("score", 0):
        existing["score"] = incoming["score"]
        verdict = incoming.get("fields", {}).get("tlabverdict")
        if verdict:
            existing.setdefault("fields", {})["tlabverdict"] = verdict
    if incoming.get("relationships"):
        existing.setdefault("relationships", []).extend(incoming["relationships"])


def fetch_indicators_command(client: TLabClient, params: dict) -> None:
    indicators, cursor = fetch_indicators(client, params)
    for start in range(0, len(indicators), BATCH_SIZE):
        demisto.createIndicators(indicators[start : start + BATCH_SIZE])
    # Only after the batches are accepted, so a failure mid-way re-fetches
    # instead of silently skipping the window.
    merge_integration_context(report_cursor=cursor)
    demisto.debug(f"tLab feed: created {len(indicators)} indicators, cursor now {cursor}")


def get_indicators_command(client: TLabClient, args: dict, params: dict) -> CommandResults:
    """Manual preview. Deliberately does not create indicators or move the cursor."""
    limit = arg_to_number(args.get("limit")) or 10
    indicators, _ = fetch_indicators(client, params, preview=True)
    indicators = indicators[:limit]

    rows = [
        {
            "Value": indicator["value"],
            "Type": indicator["type"],
            "Verdict": indicator.get("fields", {}).get("tlabverdict", ""),
            "Source": indicator.get("rawJSON", {}).get("source", ""),
            "Description": indicator.get("fields", {}).get("description", ""),
        }
        for indicator in indicators
    ]
    return CommandResults(
        outputs_prefix=OUTPUT_INDICATOR,
        outputs_key_field="Value",
        outputs=indicators or None,
        raw_response=indicators,
        readable_output=tableToMarkdown(
            f"tLab Anti-APT indicators ({len(rows)})",
            rows,
            headers=["Value", "Type", "Verdict", "Source", "Description"],
            removeNull=True,
        )
        if rows
        else "No indicators found.",
    )


def reset_cursor_command() -> CommandResults:
    merge_integration_context(report_cursor=None)
    return CommandResults(readable_output="Fetch cursor reset. The next fetch starts from the configured first report id.")


def test_module_command(client: TLabClient, params: dict) -> str:
    client.list_sample_reports(page=0, size=1, sort="sampleReportId,asc")
    for network in argToList(params.get("excluded_networks")) or []:
        try:
            ipaddress.ip_network(network, strict=False)
        except ValueError:
            raise DemistoException(f"Excluded networks: '{network}' is not a valid CIDR block.") from None
    return "ok"


def build_client(params: dict) -> TLabClient:
    return TLabClient(
        base_url=params.get("url") or "",
        auth_mode=params.get("auth_mode") or AUTH_TLAB_ACCOUNT,
        credentials=params.get("credentials") or {},
        client_name=params.get("client_name") or "xsoar",
        verify=not params.get("insecure", False),
        proxy=params.get("proxy", False),
        auth_url=params.get("auth_url") or "",
    )


def main() -> None:
    params = demisto.params()
    args = demisto.args()
    command = demisto.command()

    try:
        client = build_client(params)

        if command == "test-module":
            return_results(test_module_command(client, params))
        elif command == "fetch-indicators":
            fetch_indicators_command(client, params)
        elif command == "tlab-get-indicators":
            return_results(get_indicators_command(client, args, params))
        elif command == "tlab-feed-reset-cursor":
            return_results(reset_cursor_command())
        else:
            raise NotImplementedError(f"Command {command} is not implemented.")
    except Exception as exc:  # noqa: BLE001 - XSOAR requires a single catch-all in main
        demisto.error(traceback.format_exc())
        return_error(f"Failed to execute {command}. Error: {exc}")


if __name__ in ("__main__", "__builtin__", "builtins"):
    main()
