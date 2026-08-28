import re
import json
import base64
import html
from collections import deque, defaultdict
from urllib.parse import (urljoin, urlparse, urldefrag,unquote, parse_qsl,urlencode,)

import requests
from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright



START_URL= "http://54.214.7.161/"
USERNAME= "namratha.reddy"
PASSWORD= "cb1400c9d04ce85376dd"
ALLOWED_HOST= "54.214.7.161"


PASSWORD_RE_BYTES= re.compile(rb"VISUALPING\{[0-9a-fA-F]{16}\}")
PASSWORD_RE_TEXT= re.compile(r"VISUALPING\{[0-9a-fA-F]{16}\}")
WORKED_EXAMPLE = "VISUALPING{0000deadbeef0000}"

MAX_TOTAL_URLS = 1500 #for safety, os no traps entered
MAX_PAGINATION_VALUES = 50 #to avoid infinite traps
MAX_QUERY_VARIANTS = 40
MAX_BODY_SIZE = 20 * 1024 * 1024
HTTP_TIMEOUT = 20
MAX_URLS_PER_PATH = 100 # to not let one resource type dominate crawl


visited = set()
queued = set()
queue = deque()

resources = {}
password_locations = defaultdict(list)

discovery_reasons = defaultdict(set)


query_values_seen = defaultdict(lambda: defaultdict(set)) # track query parameter values seen per endpoint

query_variants_seen = defaultdict(set) # track how many query variants were seen for each path
path_counts = defaultdict(int) # track url counts by normalized path
blocked_urls = set()
session = requests.Session()

session.auth = (USERNAME, PASSWORD)

session.headers.update({
    "User-Agent": (
        "Mozilla/5.0 "
        "(Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 "
        "(KHTML, like Gecko) "
        "Chrome/139 Safari/537.36"
    ),
    "Accept": "*/*",
})


def normalize_url(url, base=None):
    if not url:
        return None

    url= str(url).strip()

    if not url:
        return None

    lowered= url.lower()

    #not directly crawlable HTTP URLs
    if lowered.startswith((
        "javascript:",
        "mailto:",
        "tel:",
        "data:",
        "blob:",
        "about:",
        "#",
    )):
        return None

    if base:
        url = urljoin(base, url)

    url, _ = urldefrag(url)

    parsed = urlparse(url)

    if parsed.scheme not in (
        "http",
        "https",
    ):
        return None

    if not parsed.hostname:
        return None

    return url


def same_host(url):

    try:
        return (
            urlparse(url).hostname
            == ALLOWED_HOST
        )
    except Exception:
        return False


def normalized_path(url):

    try:
        path = urlparse(url).path

        if not path:
            return "/"

        return path

    except Exception:
        return ""


def query_signature(url):
    parsed = urlparse(url)
    names = sorted(
        key
        for key, _value in parse_qsl(
            parsed.query,
            keep_blank_values=True,
        )
    )

    return (
        parsed.path,
        tuple(names),
    )


#detect traps
def looks_like_pagination_parameter(name, value):
    name = name.lower()
    pagination_names = {
        "page",
        "p",
        "pg",
        "page_num",
        "page_number",
        "offset",
        "start",
        "skip",
    }

    if name in pagination_names:
        return True

    if (
        "page" in name
        or "offset" in name
        or "skip" in name
    ):
        return True

    if value.isdigit():
        return True

    return False


def should_crawl(url):
    if not same_host(url):
        return False, "external host"

    if url in visited:
        return False, "already visited"

    if url in queued:
        return False, "already queued"

    if url in blocked_urls:
        return False, "previously blocked"

    if len(visited) + len(queued) >= MAX_TOTAL_URLS:
        return False, "global URL limit"

    parsed = urlparse(url)
    path = normalized_path(url)

    if path_counts[path] >= MAX_URLS_PER_PATH:
        return False, (
            f"path limit reached for {path}"
        )

    query_items = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    if not query_items:
        return True, "normal URL"

    signature = query_signature(url)

    variant_key = urlencode(
        query_items,
        doseq=True,
    )

    variants = query_variants_seen[
        signature
    ]

    if variant_key not in variants:

        if len(variants) >= MAX_QUERY_VARIANTS:

            return False, (
                "too many query variants"
            )

        variants.add(
            variant_key
        )

    for name, value in query_items:

        if not looks_like_pagination_parameter(
            name,
            value,
        ):
            continue

        values = query_values_seen[
            signature
        ][name]

        if value in values:
            return False, "duplicate query value"

        if value.isdigit():

            number = int(value)

            if len(values) >= MAX_PAGINATION_VALUES:

                return False, (
                    f"pagination limit for "
                    f"{path}?{name}=..."
                )

            values.add(
                value
            )

            if number > 100:

                return False, (
                    f"suspiciously large "
                    f"pagination value "
                    f"{name}={number}"
                )

        else:

            values.add(value)

    return True, "allowed"

#password queue
def enqueue(
    url,
    parent=None,
    reason="discovered",
):

    normalized = normalize_url(
        url,
        parent,
    )

    if not normalized:
        return

    allowed, explanation = should_crawl(
        normalized
    )

    discovery_reasons[
        normalized
    ].add(reason)

    if not allowed:
        if explanation not in (
            "already visited",
            "already queued",
            "duplicate query value",
        ):

            print(
                f"[SKIP] {normalized}"
            )

            print(
                f"       reason: {explanation}"
            )

        blocked_urls.add(
            normalized
        )

        return

    queued.add(
        normalized
    )

    queue.append(
        normalized
    )

    path_counts[
        normalized_path(normalized)
    ] += 1

def record_password(
    password,
    url,
    method,
):

    if (
        WORKED_EXAMPLE
        and password == WORKED_EXAMPLE
    ):
        print(
            "[WORKED EXAMPLE IGNORED]",
            password,
        )
        return

    location = (
        url,
        method,
    )

    if location not in password_locations[
        password
    ]:

        password_locations[
            password
        ].append(
            location
        )

        print()
        print("=" * 80)
        print("PASSWORD FOUND")
        print("=" * 80)
        print(
            "Password:",
            password,
        )
        print(
            "URL:",
            url,
        )
        print(
            "Found in:",
            method,
        )
        print("=" * 80)
        print()


def scan_bytes(
    data,
    url,
    method,
):

    if not data:
        return

    for match in PASSWORD_RE_BYTES.finditer(
        data
    ):

        password = match.group(
            0
        ).decode(
            "ascii",
            errors="ignore",
        )

        record_password(
            password,
            url,
            method,
        )


def scan_text(
    text,
    url,
    method,
):

    if not text:
        return

    for match in PASSWORD_RE_TEXT.findall(
        text
    ):

        record_password(
            match,
            url,
            method,
        )


#decoders
def decode_common_encodings(
    text,
    url,
):

    if not text:
        return

    #html decode
    try:

        decoded = html.unescape(
            text
        )

        if decoded != text:

            scan_text(
                decoded,
                url,
                "HTML entity decoding",
            )

    except Exception:
        pass

    #url decode
    try:

        decoded = unquote(
            text
        )

        if decoded != text:

            scan_text(
                decoded,
                url,
                "URL decoding",
            )

    except Exception:
        pass

    #base 64 decode

    candidates = re.findall(
        r"(?<![A-Za-z0-9+/])"
        r"[A-Za-z0-9+/]{16,}={0,2}"
        r"(?![A-Za-z0-9+/])",
        text,
    )

    for candidate in candidates:

        try:

            decoded = base64.b64decode(
                candidate,
                validate=True,
            )

            scan_bytes(
                decoded,
                url,
                "Base64 decoding",
            )

            scan_text(
                decoded.decode(
                    "utf-8",
                    errors="ignore",
                ),
                url,
                "Base64 decoding",
            )

        except Exception:
            pass

    #hexadecimal byte strings

    hex_strings = re.findall(
        r"(?<![0-9a-fA-F])"
        r"(?:[0-9a-fA-F]{2}){8,}"
        r"(?![0-9a-fA-F])",
        text,
    )

    for candidate in hex_strings:

        try:

            decoded = bytes.fromhex(
                candidate
            )

            scan_bytes(
                decoded,
                url,
                "Hex decoding",
            )

            scan_text(
                decoded.decode(
                    "utf-8",
                    errors="ignore",
                ),
                url,
                "Hex decoding",
            )

        except Exception:
            pass

    #numeric character arrays

    arrays = re.findall(
        r"\[\s*"
        r"(?:\d+\s*,\s*){3,}"
        r"\d+\s*\]",
        text,
    )

    for array in arrays:

        try:

            numbers = re.findall(
                r"\d+",
                array,
            )

            decoded = "".join(
                chr(int(n))
                for n in numbers
                if 0 <= int(n) <= 0x10FFFF
            )

            scan_text(
                decoded,
                url,
                "Numeric character array",
            )

        except Exception:
            pass


#html extraction

URL_ATTRIBUTES = {
    "href",
    "src",
    "action",
    "formaction",
    "poster",
    "data",
    "cite",
    "background",
    "manifest",
}


def extract_html_resources(
    text,
    page_url,
):

    soup = BeautifulSoup(
        text,
        "lxml",
    )

    #search all html attributes

    for tag in soup.find_all(True):

        for attr_name, attr_value in tag.attrs.items():

            if isinstance(
                attr_value,
                list,
            ):

                attr_value = " ".join(
                    attr_value
                )

            if not isinstance(
                attr_value,
                str,
            ):
                continue

            scan_text(
                attr_value,
                page_url,
                f"HTML attribute: {attr_name}",
            )

            if attr_name.lower() in URL_ATTRIBUTES:

                enqueue(
                    attr_value,
                    page_url,
                    f"HTML {attr_name}",
                )

        #srcset

        for attribute in (
            "srcset",
            "imagesrcset",
        ):

            value = tag.get(
                attribute
            )

            if not value:
                continue

            for candidate in value.split(","):

                candidate = candidate.strip()

                if not candidate:
                    continue

                resource_url = (
                    candidate.split()[0]
                )

                enqueue(
                    resource_url,
                    page_url,
                    f"HTML {attribute}",
                )

    #meta tags

    for meta in soup.find_all(
        "meta"
    ):

        for attribute in (
            "content",
            "value",
        ):

            value = meta.get(
                attribute
            )

            if value:

                scan_text(
                    value,
                    page_url,
                    f"meta {attribute}",
                )

    #inline styles

    for tag in soup.find_all(
        style=True
    ):

        scan_css(
            tag.get(
                "style",
                "",
            ),
            page_url,
        )

    #<style>

    for style in soup.find_all(
        "style"
    ):

        scan_css(
            style.get_text(
                "",
                strip=False,
            ),
            page_url,
        )

    #inline javascript

    for script in soup.find_all(
        "script"
    ):

        src = script.get(
            "src"
        )

        if src:

            enqueue(
                src,
                page_url,
                "script src",
            )

        else:

            scan_javascript(
                script.get_text(
                    "",
                    strip=False,
                ),
                page_url,
            )


#css

def scan_css(
    text,
    page_url,
):

    if not text:
        return

    scan_text(
        text,
        page_url,
        "CSS",
    )

    decode_common_encodings(
        text,
        page_url,
    )

    #url
    urls = re.findall(
        r"url\(\s*[\"']?([^\"')]+)",
        text,
        flags=re.I,
    )

    for raw_url in urls:

        enqueue(
            raw_url,
            page_url,
            "CSS url()",
        )

    #@import
    imports = re.findall(
        r"@import\s+"
        r"(?:url\()?['\"]?"
        r"([^'\"\)\s]+)",
        text,
        flags=re.I,
    )

    for raw_url in imports:

        enqueue(
            raw_url,
            page_url,
            "CSS @import",
        )

#javascript

def scan_javascript(
    text,
    page_url,
):

    if not text:
        return

    scan_text(
        text,
        page_url,
        "JavaScript",
    )

    decode_common_encodings(
        text,
        page_url,
    )

    #fetch()

    fetches = re.findall(
        r"""
        fetch
        \s*\(
        \s*["'`]([^"'`]+)["'`]
        """,
        text,
        flags=re.I | re.X,
    )

    for raw_url in fetches:

        enqueue(
            raw_url,
            page_url,
            "JavaScript fetch()",
        )


    #xmlhttprequest.open()

    xhrs = re.findall(
        r"""
        \.open
        \s*\(
        \s*["'][^"']+["']
        \s*,\s*
        ["'`]([^"'`]+)["'`]
        """,
        text,
        flags=re.I | re.X,
    )

    for raw_url in xhrs:

        enqueue(
            raw_url,
            page_url,
            "XMLHttpRequest",
        )

    #dynamic import()

    imports = re.findall(
        r"""
        import
        \s*\(
        \s*["'`]([^"'`]+)["'`]
        """,
        text,
        flags=re.I | re.X,
    )

    for raw_url in imports:

        enqueue(
            raw_url,
            page_url,
            "JavaScript import()",
        )

    #static imports

    static_imports = re.findall(
        r"""
        import
        (?:
            .*?
            from
        )?
        \s*["'`]([^"'`]+)["'`]
        """,
        text,
        flags=re.I | re.X,
    )

    for raw_url in static_imports:

        enqueue(
            raw_url,
            page_url,
            "JavaScript import",
        )

    #websocket

    websockets = re.findall(
        r"""
        new\s+WebSocket
        \s*\(
        \s*["'`]([^"'`]+)["'`]
        """,
        text,
        flags=re.I | re.X,
    )

    for raw_url in websockets:

        enqueue(
            raw_url
            .replace(
                "ws://",
                "http://",
                1,
            )
            .replace(
                "wss://",
                "https://",
                1,
            ),
            page_url,
            "JavaScript WebSocket",
        )

    #source maps

    source_maps = re.findall(
        r"sourceMappingURL\s*=\s*([^\s*]+)",
        text,
        flags=re.I,
    )

    for raw_url in source_maps:

        enqueue(
            raw_url.strip("\"'"),
            page_url,
            "JavaScript source map",
        )

    #not enqueuing every arbitrary quoted string
    quoted_strings = re.findall(
        r"""["'`]([^"'`]{1,1000})["'`]""",
        text,
    )

    for value in quoted_strings:

        scan_text(
            value,
            page_url,
            "JavaScript string",
        )

        decode_common_encodings(
            value,
            page_url,
        )


#json

def scan_json(
    text,
    url,
):

    scan_text(
        text,
        url,
        "JSON",
    )

    try:

        value = json.loads(
            text
        )

        scan_json_value(
            value,
            url,
        )

    except Exception:
        pass


def scan_json_value(
    value,
    url,
):

    if isinstance(
        value,
        str,
    ):

        scan_text(
            value,
            url,
            "JSON value",
        )

        decode_common_encodings(
            value,
            url,
        )

    elif isinstance(
        value,
        list,
    ):

        for item in value:

            scan_json_value(
                item,
                url,
            )

    elif isinstance(
        value,
        dict,
    ):

        for key, item in value.items():

            scan_text(
                str(key),
                url,
                "JSON key",
            )

            scan_json_value(
                item,
                url,
            )

#http crawler


def crawl_http(url):

    print(
        f"[HTTP {len(visited):04d}] {url}"
    )

    try:

        response = session.get(
            url,
            timeout=HTTP_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )

    except Exception as e:

        print(
            "[HTTP ERROR]",
            url,
            e,
        )

        return

    #redirects

    for redirect in response.history:

        print(
            "[REDIRECT]",
            redirect.status_code,
            redirect.url,
        )

        try:

            body = redirect.content

            scan_bytes(
                body,
                redirect.url,
                "Redirect response",
            )

        except Exception:
            pass

        location = redirect.headers.get(
            "Location"
        )

        if location:

            enqueue(
                location,
                redirect.url,
                "HTTP redirect",
            )

    final_url = response.url

    #headers

    for name, value in response.headers.items():

        scan_text(
            value,
            final_url,
            f"HTTP header: {name}",
        )

    #link header
    link_header = response.headers.get(
        "Link"
    )

    if link_header:

        for raw_url in re.findall(
            r"<([^>]+)>",
            link_header,
        ):

            enqueue(
                raw_url,
                final_url,
                "HTTP Link header",
            )

    #body

    try:

        body = response.raw.read(
            MAX_BODY_SIZE
        )

    except Exception:

        body = b""

    resources[final_url] = {
        "status": response.status_code,
        "content_type": response.headers.get(
            "Content-Type",
            "",
        ),
        "size": len(body),
    }

    #search raw bytes
    scan_bytes(
        body,
        final_url,
        "Raw HTTP response",
    )


    #decode text

    encoding = (
        response.encoding
        or "utf-8"
    )

    try:

        text = body.decode(
            encoding,
            errors="replace",
        )

    except Exception:

        text = body.decode(
            "utf-8",
            errors="ignore",
        )

    scan_text(
        text,
        final_url,
        "Decoded HTTP response",
    )

    decode_common_encodings(
        text,
        final_url,
    )

    content_type = response.headers.get(
        "Content-Type",
        "",
    ).lower()

    lower_url = final_url.lower()

    #html

    if (
        "text/html" in content_type
        or "<html" in text.lower()
        or "<!doctype html" in text.lower()
    ):

        extract_html_resources(
            text,
            final_url,
        )

    #css

    if (
        "text/css" in content_type
        or lower_url.endswith(".css")
    ):

        scan_css(
            text,
            final_url,
        )

    #javascript

    if (
        "javascript" in content_type
        or "ecmascript" in content_type
        or lower_url.endswith(
            (
                ".js",
                ".mjs",
                ".cjs",
            )
        )
    ):

        scan_javascript(
            text,
            final_url,
        )

    #json

    if (
        "json" in content_type
        or lower_url.endswith(".json")
    ):

        scan_json(
            text,
            final_url,
        )


#playwright

def browser_crawl():

    print()
    print("=" * 80)
    print("STARTING REAL BROWSER CRAWL")
    print("=" * 80)

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=True,
        )

        context = browser.new_context(
            http_credentials={
                "username": USERNAME,
                "password": PASSWORD,
            },
            ignore_https_errors=True,
        )

        #network requests

        def on_request(request):

            url = request.url

            if not same_host(url):
                return

            print(
                "[BROWSER REQUEST]",
                request.resource_type,
                url,
            )

            #capture the resource and allow trap protected enqueue logic
            enqueue(
                url,
                reason=(
                    "Browser network request"
                ),
            )

        #network responses

        def on_response(response):

            url = response.url

            if not same_host(url):
                return

            print(
                "[BROWSER RESPONSE]",
                response.status,
                url,
            )

            try:

                body = response.body()

                scan_bytes(
                    body,
                    url,
                    "Browser network response",
                )

                text = body.decode(
                    "utf-8",
                    errors="ignore",
                )

                scan_text(
                    text,
                    url,
                    "Browser network response",
                )

                decode_common_encodings(
                    text,
                    url,
                )

                content_type = (
                    response.headers
                    .get(
                        "content-type",
                        "",
                    )
                    .lower()
                )

                if "html" in content_type:

                    extract_html_resources(
                        text,
                        url,
                    )

                elif "css" in content_type:

                    scan_css(
                        text,
                        url,
                    )

                elif (
                    "javascript" in content_type
                    or "ecmascript" in content_type
                ):

                    scan_javascript(
                        text,
                        url,
                    )

                elif "json" in content_type:

                    scan_json(
                        text,
                        url,
                    )

            except Exception as e:

                print(
                    "[BROWSER RESPONSE ERROR]",
                    e,
                )


        #websockets

        def on_websocket(ws):

            print(
                "[WEBSOCKET]",
                ws.url,
            )

            def received(message):

                print(
                    "[WEBSOCKET MESSAGE]",
                    message,
                )

                scan_text(
                    str(message),
                    ws.url,
                    "WebSocket message",
                )

                decode_common_encodings(
                    str(message),
                    ws.url,
                )

            ws.on(
                "framereceived",
                received,
            )

        context.on(
            "request",
            on_request,
        )

        context.on(
            "response",
            on_response,
        )

        context.on(
            "websocket",
            on_websocket,
        )

        #open homepage

        page = context.new_page()

        try:

            page.goto(
                START_URL,
                wait_until="networkidle",
                timeout=30000,
            )

        except Exception as e:

            print(
                "[BROWSER NAVIGATION ERROR]",
                e,
            )

        page.wait_for_timeout(
            5000
        )

        #rendered dom

        try:

            rendered_html = page.content()

            print(
                "[RENDERED DOM]",
                page.url,
            )

            scan_text(
                rendered_html,
                page.url,
                "Rendered DOM",
            )

            extract_html_resources(
                rendered_html,
                page.url,
            )

        except Exception as e:

            print(
                "[DOM ERROR]",
                e,
            )


        #iframes

        for frame in page.frames:

            try:

                frame_url = frame.url

                if not frame_url:
                    continue

                print(
                    "[FRAME]",
                    frame_url,
                )

                if same_host(frame_url):

                    enqueue(
                        frame_url,
                        reason="iframe",
                    )

                    frame_html = frame.content()

                    scan_text(
                        frame_html,
                        frame_url,
                        "Iframe DOM",
                    )

                    extract_html_resources(
                        frame_html,
                        frame_url,
                    )

            except Exception as e:

                print(
                    "[FRAME ERROR]",
                    e,
                )


        #browser storage


        try:

            storage = page.evaluate(
                """
                () => ({
                    localStorage:
                        Object.fromEntries(
                            Object.entries(
                                localStorage
                            )
                        ),

                    sessionStorage:
                        Object.fromEntries(
                            Object.entries(
                                sessionStorage
                            )
                        )
                })
                """
            )

            storage_text = json.dumps(
                storage
            )

            print(
                "[STORAGE]",
                storage_text,
            )

            scan_text(
                storage_text,
                page.url,
                "Browser storage",
            )

            decode_common_encodings(
                storage_text,
                page.url,
            )

        except Exception as e:

            print(
                "[STORAGE ERROR]",
                e,
            )


        #service workers

        try:

            registrations = page.evaluate(
                """
                async () => {
                    const regs =
                        await navigator
                            .serviceWorker
                            .getRegistrations();

                    return regs.map(
                        r => ({
                            scope: r.scope,
                            scriptURL:
                                r.active
                                    ? r.active.scriptURL
                                    : null
                        })
                    );
                }
                """
            )

            print(
                "[SERVICE WORKERS]",
                registrations,
            )

            for registration in registrations:

                script_url = registration.get(
                    "scriptURL"
                )

                if script_url:

                    enqueue(
                        script_url,
                        reason="Service worker",
                    )

        except Exception as e:

            print(
                "[SERVICE WORKER ERROR]",
                e,
            )

        page.wait_for_timeout(
            3000
        )

        browser.close()


#http queue processing

def process_queue():

    while (
        queue
        and len(visited) < MAX_TOTAL_URLS
    ):

        url = queue.popleft()

        queued.discard(
            url
        )

        if url in visited:
            continue

        visited.add(
            url
        )

        crawl_http(
            url
        )


#results

def print_results():

    print()
    print()
    print("=" * 80)
    print("FINAL RESULTS")
    print("=" * 80)

    passwords = sorted(
        password_locations.keys()
    )

    if not passwords:

        print(
            "NO PASSWORDS FOUND."
        )

    else:

        for index, password in enumerate(
            passwords,
            1,
        ):

            print()
            print(
                f"{index}. {password}"
            )

            for url, method in (
                password_locations[
                    password
                ]
            ):

                print(
                    f"    Method: {method}"
                )

                print(
                    f"    URL:    {url}"
                )

    print()
    print("-" * 80)

    print(
        "Unique passwords:",
        len(passwords),
    )

    print(
        "Visited URLs:",
        len(visited),
    )

    print(
        "Queued URLs:",
        len(queued),
    )

    print(
        "Blocked URLs:",
        len(blocked_urls),
    )

    print(
        "Resources:",
        len(resources),
    )

    print("-" * 80)

    if len(passwords) == 8:

        print(
            "SUCCESS: exactly 8 passwords found."
        )

    elif len(passwords) < 8:

        print(
            "Fewer than 8 passwords found."
        )

    else:

        print(
            "More than 8 password candidates found."
        )



def main():

    print()
    print("=" * 80)
    print("VISUALPING CRAWLER")
    print("=" * 80)
    print(
        "Target:",
        START_URL,
    )
    print(
        "Host:",
        ALLOWED_HOST,
    )
    print(
        "Authentication:",
        f"{USERNAME}:********",
    )
    print("=" * 80)

  

    enqueue(
        START_URL,
        reason="Starting page",
    )



    process_queue()

    print()
    print("=" * 80)
    print("INITIAL HTTP CRAWL COMPLETE")
    print("=" * 80)

    print(
        "Visited:",
        len(visited),
    )

    browser_crawl()


    print()
    print("=" * 80)
    print("PROCESSING BROWSER-DISCOVERED RESOURCES")
    print("=" * 80)

    process_queue()

    if queue:

        browser_crawl()

        process_queue()

    print_results()


if __name__ == "__main__":
    main()
