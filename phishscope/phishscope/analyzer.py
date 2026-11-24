"""Core analysis: parse a .eml file and return findings + a risk score.

Uses only the Python standard library. Nothing in the email is ever
opened, rendered or executed - attachments are only hashed and sniffed.
"""
import hashlib
import ipaddress
import re
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

URGENT_PHRASES = [
    "urgent", "immediately", "act now", "within 24 hours", "account suspended",
    "account will be closed", "verify your account", "confirm your identity",
    "unusual activity", "password expires", "final notice", "payment failed",
    "click here", "security alert", "limited time",
]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly"}
BRANDS = ["paypal", "microsoft", "apple", "amazon", "google", "netflix", "sbi", "hdfc", "icici", "dhl", "fedex", "linkedin"]
RISKY_EXT = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".jar", ".hta", ".lnk",
             ".iso", ".img", ".docm", ".xlsm", ".pptm", ".dll", ".msi", ".pdf"}
MAGIC = [
    (b"MZ", "Windows executable (EXE/DLL)", {".exe", ".dll", ".scr"}),
    (b"%PDF", "PDF document", {".pdf"}),
    (b"PK\x03\x04", "ZIP / Office Open XML", {".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".jar", ".apk"}),
    (b"\xd0\xcf\x11\xe0", "Legacy Office (OLE)", {".doc", ".xls", ".ppt", ".msi"}),
    (b"\x89PNG", "PNG image", {".png"}),
    (b"\xff\xd8\xff", "JPEG image", {".jpg", ".jpeg"}),
    (b"GIF8", "GIF image", {".gif"}),
    (b"Rar!", "RAR archive", {".rar"}),
    (b"7z\xbc\xaf", "7-Zip archive", {".7z"}),
]
URL_RE = re.compile(r"https?://[^\s<>\"')]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self._href, self._text = [], None, []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href") or ""
            self._text = []

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href.strip(), "".join(self._text).strip()))
            self._href = None


def _domain(addr_or_url):
    if "@" in addr_or_url and "://" not in addr_or_url:
        return addr_or_url.rsplit("@", 1)[-1].strip("> ").lower()
    host = urlparse(addr_or_url if "://" in addr_or_url else "//" + addr_or_url).hostname
    return (host or "").lower()


def _base(domain):
    """Rough registrable domain (last two labels; good enough for triage)."""
    parts = domain.split(".")
    if len(parts) >= 3 and parts[-2] in {"co", "com", "org", "net", "gov", "ac"} and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else domain


def defang(text):
    """Make a URL unclickable so it is safe to paste into a report."""
    return text.replace("http", "hxxp").replace(".", "[.]")


def _public_ips(received_headers):
    ips = []
    for h in reversed(received_headers):  # oldest hop first
        for m in IP_RE.findall(h):
            try:
                ip = ipaddress.ip_address(m)
            except ValueError:
                continue
            if ip.is_global and m not in ips:
                ips.append(m)
    return ips


def _auth_results(msg):
    blob = " ".join(str(h) for h in msg.get_all("Authentication-Results", [])).lower()
    spf_hdr = " ".join(str(h) for h in msg.get_all("Received-SPF", [])).lower()
    out = {}
    for name in ("spf", "dkim", "dmarc"):
        m = re.search(rf"\b{name}=(\w+)", blob)
        if m:
            out[name] = m.group(1)
        elif name == "spf" and spf_hdr:
            m = re.match(r"\s*(\w+)", spf_hdr)
            out[name] = m.group(1) if m else "not found"
        else:
            out[name] = "not found"
    return out


def analyze(raw: bytes, source_name="message.eml"):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    findings = []

    def add(sev, pts, title, detail):
        findings.append({"severity": sev, "points": pts, "title": title, "detail": detail})

    # ---- headers -------------------------------------------------------
    from_name, from_addr = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))
    from_dom, reply_dom, rp_dom = _domain(from_addr), _domain(reply_to), _domain(return_path)
    received = [str(h) for h in msg.get_all("Received", [])]
    origin_ips = _public_ips(received)
    auth = _auth_results(msg)

    headers = {
        "File": source_name,
        "Subject": str(msg.get("Subject", "")),
        "From": str(msg.get("From", "")),
        "Reply-To": str(msg.get("Reply-To", "")) or "-",
        "Return-Path": str(msg.get("Return-Path", "")) or "-",
        "To": str(msg.get("To", "")),
        "Date": str(msg.get("Date", "")),
        "Message-ID": str(msg.get("Message-ID", "")) or "-",
        "Originating IP(s)": ", ".join(origin_ips) or "none found",
    }

    for name, val in auth.items():
        if val in ("fail", "softfail", "permerror"):
            add("high", 20, f"{name.upper()} {val}", f"The {name.upper()} check did not pass, so the sender may be spoofed.")
        elif val in ("none", "neutral", "not found"):
            add("low", 5, f"{name.upper()} not verified", f"No usable {name.upper()} result in the headers ({val}).")

    if reply_dom and from_dom and _base(reply_dom) != _base(from_dom):
        add("high", 20, "Reply-To domain differs from From", f"Replies go to {reply_dom}, not {from_dom}.")
    if rp_dom and from_dom and _base(rp_dom) != _base(from_dom):
        add("medium", 10, "Return-Path domain differs from From", f"Bounce address uses {rp_dom}, From uses {from_dom}.")
    for brand in BRANDS:
        if brand in from_name.lower() and brand not in from_dom:
            add("high", 20, "Possible brand impersonation", f'Display name "{from_name}" mentions {brand}, but the address is @{from_dom}.')
            break
    if from_dom.startswith("xn--") or ".xn--" in from_dom:
        add("medium", 10, "Punycode sender domain", f"{from_dom} may be a look-alike (homograph) domain.")

    # ---- body & links --------------------------------------------------
    text, links = "", []
    body = msg.get_body(preferencelist=("html", "plain"))
    if body is not None:
        content = body.get_content()
        if body.get_content_type() == "text/html":
            p = _LinkParser()
            p.feed(content)
            links = p.links
            text = re.sub(r"<[^>]+>", " ", content)
        else:
            text = content
            links = [(u, "") for u in URL_RE.findall(content)]

    hits = [w for w in URGENT_PHRASES if w in (text + " " + headers["Subject"]).lower()]
    if hits:
        add("medium" if len(hits) < 3 else "high", min(5 * len(hits), 20),
            "Urgent or pressuring language", "Found: " + ", ".join(hits))

    link_rows, seen = [], set()
    for href, shown in links:
        if not href.lower().startswith(("http://", "https://")) or href in seen:
            continue
        seen.add(href)
        host = _domain(href)
        flags = []
        shown_dom = _domain(shown) if re.match(r"^(https?://)?[\w-]+(\.[\w-]+)+(/|$)", shown or "", re.I) else ""
        if shown_dom and _base(shown_dom) != _base(host):
            flags.append(f"text shows {shown_dom} but goes to {host}")
            add("high", 25, "Link text does not match destination", f'"{shown}" actually points to {defang(href)}')
        try:
            ipaddress.ip_address(host)
            flags.append("IP address as host")
            add("high", 15, "Link uses a raw IP address", defang(href))
        except ValueError:
            pass
        if host in SHORTENERS:
            flags.append("URL shortener")
            add("medium", 10, "URL shortener", defang(href))
        if host.startswith("xn--") or ".xn--" in host:
            flags.append("punycode")
            add("medium", 10, "Punycode link domain", defang(href))
        if href.lower().startswith("http://"):
            flags.append("not HTTPS")
        if "@" in urlparse(href).netloc:
            flags.append("'@' in URL")
            add("high", 15, "'@' in URL", defang(href))
        if host.count(".") >= 4:
            flags.append("many subdomains")
        link_rows.append({"url": defang(href), "text": shown, "flags": flags})

    # ---- attachments ---------------------------------------------------
    att_rows = []
    for part in msg.iter_attachments():
        data = part.get_payload(decode=True) or b""
        name = part.get_filename() or "(unnamed)"
        ext = "." + name.rsplit(".", 1)[-1].lower() if "." in name else ""
        true_type, expected = "unknown", set()
        for sig, label, exts in MAGIC:
            if data.startswith(sig):
                true_type, expected = label, exts
                break
        flags = []
        if ext in RISKY_EXT:
            flags.append("risky extension")
            add("high", 20, "Risky attachment type", f"{name} ({ext})")
            if len(name.split(".")) > 2:
                flags.append("double extension")
                add("high", 15, "Double extension", name)
        if expected and ext not in expected:
            flags.append("extension does not match content")
            add("high", 25, "Attachment extension mismatch",
                f"{name} claims {ext or 'no extension'} but the content is: {true_type}")
        att_rows.append({
            "name": name, "size": len(data), "true_type": true_type, "flags": flags,
            "sha256": hashlib.sha256(data).hexdigest(), "md5": hashlib.md5(data).hexdigest(),
        })

    score = min(sum(f["points"] for f in findings), 100)
    verdict = "Likely phishing" if score >= 50 else "Suspicious" if score >= 20 else "Low risk"
    findings.sort(key=lambda f: -f["points"])
    return {"headers": headers, "auth": auth, "findings": findings, "links": link_rows,
            "attachments": att_rows, "score": score, "verdict": verdict}
