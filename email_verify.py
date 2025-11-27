#!/usr/bin/env python3
"""
Email Forensic Analyzer - Professional spam/phishing investigation tool.

Features:
- Header analysis with authentication checks (SPF/DKIM/DMARC)
- Email address extraction (headers + body)
- URL extraction and suspicious pattern detection
- Domain mismatch detection
- Homograph/IDN attack detection
- Link shortener identification
- Attachment analysis
- Risk scoring with severity levels
- JSON export for SIEM integration

Usage:
    python email_verify.py email.eml
    python email_verify.py email.eml --json
    python email_verify.py email.eml --json --output report.json
"""

import argparse
import base64
import hashlib
import json
import re
import sys
from datetime import datetime
from email import policy
from email.parser import BytesParser, Parser
from email.message import Message
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, unquote
import unicodedata


# ANSI colors for terminal output
class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


# Known link shorteners
LINK_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "j.mp", "tr.im", "cli.gs", "short.to", "budurl.com", "ping.fm",
    "post.ly", "just.as", "bkite.com", "snipr.com", "fic.kr", "loopt.us",
    "doiop.com", "short.ie", "kl.am", "wp.me", "rubyurl.com", "om.ly",
    "to.ly", "bit.do", "lnkd.in", "db.tt", "qr.ae", "cur.lv", "go.link",
    "ity.im", "q.gs", "po.st", "bc.vc", "u.to", "v.gd", "trib.al",
}

# Suspicious TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
    ".link", ".info", ".online", ".site", ".club", ".icu", ".buzz",
}

# Phishing keywords (urgency/fear tactics)
PHISHING_KEYWORDS = [
    r"urgent", r"immediate(ly)?", r"verify your", r"confirm your",
    r"suspend(ed)?", r"locked", r"unusual activity", r"unauthorized",
    r"password.{0,20}(expire|reset|change)", r"account.{0,20}(suspend|locked|verify)",
    r"click here", r"act now", r"limited time", r"within \d+ hours?",
    r"security alert", r"your account", r"update.{0,10}payment",
    r"billing.{0,10}(issue|problem)", r"won|winner|lottery|prize",
    r"inheritance", r"million (dollar|usd|euro)", r"nigerian prince",
]

# Confusable Unicode characters (homograph attacks)
CONFUSABLES = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',  # Cyrillic
    'ɑ': 'a', 'ɡ': 'g', 'ı': 'i', 'ȷ': 'j', 'ɩ': 'l', 'ο': 'o',  # Latin Extended
    'ν': 'v', 'ω': 'w', 'ү': 'y', 'ɾ': 'r', 'ɗ': 'd', 'ƅ': 'b',
    '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e',  # Mathematical
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',  # Fullwidth
}


def load_email(path: str) -> Message:
    """Load email from file (supports .eml and raw text)."""
    p = Path(path)
    content = p.read_bytes()
    try:
        return BytesParser(policy=policy.default).parsebytes(content)
    except Exception:
        return Parser(policy=policy.default).parsestr(content.decode('utf-8', errors='ignore'))


def extract_all_emails(text: str) -> Set[str]:
    """Extract all email addresses from text."""
    pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return set(re.findall(pattern, text, re.IGNORECASE))


def extract_all_urls(text: str) -> List[Dict[str, Any]]:
    """Extract and analyze all URLs from text."""
    # Decode quoted-printable first
    text = re.sub(r'=\r?\n', '', text)
    text = re.sub(r'=([0-9A-Fa-f]{2})', lambda m: chr(int(m.group(1), 16)), text)
    
    url_pattern = r'https?://[^\s<>"\')\]]+|www\.[^\s<>"\')\]]+'
    urls = []
    seen = set()
    
    for match in re.finditer(url_pattern, text, re.IGNORECASE):
        url = match.group(0).rstrip('.,;:')
        if url in seen:
            continue
        seen.add(url)
        
        try:
            parsed = urlparse(url if url.startswith('http') else f'https://{url}')
            domain = parsed.netloc.lower()
            
            analysis = {
                'url': url[:200] + '...' if len(url) > 200 else url,
                'domain': domain,
                'is_shortener': any(s in domain for s in LINK_SHORTENERS),
                'suspicious_tld': any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS),
                'has_ip': bool(re.match(r'\d+\.\d+\.\d+\.\d+', domain)),
                'has_port': ':' in domain,
                'homograph': detect_homograph(domain),
                'encoded_chars': '%' in url,
            }
            analysis['risk_score'] = sum([
                analysis['is_shortener'] * 2,
                analysis['suspicious_tld'] * 3,
                analysis['has_ip'] * 4,
                analysis['has_port'] * 2,
                analysis['homograph'] * 5,
                analysis['encoded_chars'] * 1,
            ])
            urls.append(analysis)
        except Exception:
            urls.append({'url': url, 'error': 'parse_failed', 'risk_score': 3})
    
    return sorted(urls, key=lambda x: x.get('risk_score', 0), reverse=True)


def detect_homograph(text: str) -> bool:
    """Detect potential homograph/IDN attacks."""
    for char in text:
        if char in CONFUSABLES:
            return True
        try:
            if unicodedata.category(char) not in ('Ll', 'Lu', 'Nd', 'Pc', 'Pd'):
                if ord(char) > 127:
                    return True
        except Exception:
            pass
    return False


def extract_email_and_domain(header_value: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    """Extract email address and domain from header."""
    if not header_value:
        return None, None
    name, addr = parseaddr(header_value)
    if "@" not in addr:
        return addr or None, None
    local, domain = addr.rsplit("@", 1)
    return addr, domain.lower()


def is_private_ip(ip: str) -> bool:
    """Check if IP is in private/local range."""
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except ValueError:
            pass
    return False


def extract_ips(text: str) -> List[str]:
    """Extract all IPv4 addresses from text."""
    return re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)


def extract_ipv6(text: str) -> List[str]:
    """Extract all IPv6 addresses from text."""
    ipv6_pattern = r'(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}'
    return re.findall(ipv6_pattern, text)


def extract_phone_numbers(text: str) -> Set[str]:
    """Extract phone numbers from text."""
    patterns = [
        r'\+?\d{1,3}[-.\s]?\(?\d{2,3}\)?[-.\s]?\d{3,4}[-.\s]?\d{4}',
        r'\(\d{3}\)\s*\d{3}[-.\s]?\d{4}',
        r'\d{3}[-.\s]\d{3}[-.\s]\d{4}',
    ]
    phones = set()
    for pattern in patterns:
        phones.update(re.findall(pattern, text))
    return phones


def extract_received_chain(msg: Message) -> List[Dict[str, Any]]:
    """Extract and analyze Received headers (mail server hops)."""
    received = msg.get_all("Received", [])
    chain = []
    
    for idx, value in enumerate(received):
        ips = extract_ips(str(value))
        ipv6 = extract_ipv6(str(value))
        
        from_match = re.search(r'from\s+([^\s]+)', str(value), re.IGNORECASE)
        by_match = re.search(r'by\s+([^\s]+)', str(value), re.IGNORECASE)
        
        chain.append({
            'index': idx,
            'from': from_match.group(1) if from_match else None,
            'by': by_match.group(1) if by_match else None,
            'ipv4': ips,
            'ipv6': ipv6,
            'public_ips': [ip for ip in ips if not is_private_ip(ip)],
            'private_ips': [ip for ip in ips if is_private_ip(ip)],
            'raw': str(value)[:300],
        })
    
    return chain


def extract_auth_results(msg: Message) -> Dict[str, Any]:
    """Extract SPF, DKIM, DMARC authentication results."""
    result = {
        'spf': {'result': None, 'details': None},
        'dkim': {'result': None, 'domain': None, 'selector': None},
        'dmarc': {'result': None, 'policy': None},
        'arc': {'result': None},
        'raw': [],
    }
    
    auth_headers = msg.get_all("Authentication-Results", []) or []
    arc_headers = msg.get_all("ARC-Authentication-Results", []) or []
    spf_headers = msg.get_all("Received-SPF", []) or []
    
    result['raw'] = [str(h) for h in auth_headers + arc_headers]
    
    all_auth = " ".join(str(h) for h in auth_headers + arc_headers).lower()
    
    # SPF
    spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', all_auth)
    if spf_match:
        result['spf']['result'] = spf_match.group(1)
    elif spf_headers:
        spf_text = str(spf_headers[0]).lower()
        spf_match2 = re.search(r'^(pass|fail|softfail|neutral|none)', spf_text)
        if spf_match2:
            result['spf']['result'] = spf_match2.group(1)
    
    # DKIM
    dkim_match = re.search(r'dkim=(pass|fail|neutral|none|policy|temperror|permerror)', all_auth)
    if dkim_match:
        result['dkim']['result'] = dkim_match.group(1)
    
    dkim_domain = re.search(r'dkim=\w+\s+header\.i=@([^\s;]+)', all_auth)
    if dkim_domain:
        result['dkim']['domain'] = dkim_domain.group(1)
    
    # DMARC
    dmarc_match = re.search(r'dmarc=(pass|fail|none|policy)', all_auth)
    if dmarc_match:
        result['dmarc']['result'] = dmarc_match.group(1)
    
    dmarc_policy = re.search(r'p=(none|quarantine|reject)', all_auth)
    if dmarc_policy:
        result['dmarc']['policy'] = dmarc_policy.group(1)
    
    # ARC
    arc_seal = msg.get("ARC-Seal")
    if arc_seal:
        cv_match = re.search(r'cv=(none|pass|fail)', str(arc_seal).lower())
        result['arc']['result'] = cv_match.group(1) if cv_match else 'present'
    
    return result


def extract_basic_headers(msg: Message) -> Dict[str, Any]:
    """Extract key metadata headers."""
    date_str = msg.get("Date")
    parsed_date = None
    if date_str:
        try:
            parsed_date = parsedate_to_datetime(date_str).isoformat()
        except Exception:
            pass
    
    return {
        'from': msg.get("From"),
        'to': msg.get("To"),
        'cc': msg.get("Cc"),
        'bcc': msg.get("Bcc"),
        'subject': msg.get("Subject"),
        'date': date_str,
        'date_parsed': parsed_date,
        'message_id': msg.get("Message-ID"),
        'in_reply_to': msg.get("In-Reply-To"),
        'references': msg.get("References"),
        'return_path': msg.get("Return-Path"),
        'reply_to': msg.get("Reply-To"),
        'sender': msg.get("Sender"),
        'x_originating_ip': msg.get("X-Originating-IP"),
        'x_mailer': msg.get("X-Mailer") or msg.get("User-Agent"),
        'mime_version': msg.get("MIME-Version"),
        'content_type': msg.get("Content-Type"),
        'list_unsubscribe': msg.get("List-Unsubscribe"),
        'precedence': msg.get("Precedence"),
    }


def extract_x_headers(msg: Message) -> Dict[str, List[str]]:
    """Extract interesting X- headers."""
    interesting = [
        "X-Spam-Status", "X-Spam-Score", "X-Spam-Flag", "X-Spam-Level",
        "X-Spam-Report", "X-Originating-IP", "X-Mailer", "User-Agent",
        "X-Google-DKIM-Signature", "X-Gm-Message-State", "X-Google-Smtp-Source",
        "X-Received", "X-MS-Exchange-Organization-SCL", "X-Forefront-Antispam-Report",
        "X-Microsoft-Antispam", "X-Priority", "X-Campaign", "X-MC-User",
        "X-Report-Abuse",
    ]
    
    headers = {}
    for key in msg.keys():
        if key.startswith("X-") or key == "User-Agent":
            if any(h.lower() == key.lower() for h in interesting):
                vals = msg.get_all(key, [])
                if vals:
                    headers[key] = [str(v) for v in vals]
    
    return headers


def extract_attachments(msg: Message) -> List[Dict[str, Any]]:
    """Extract and analyze attachments."""
    attachments = []
    
    dangerous_extensions = {
        '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
        '.js', '.jse', '.ws', '.wsf', '.wsc', '.wsh', '.ps1', '.psm1',
        '.msi', '.msp', '.hta', '.cpl', '.jar', '.dll', '.iso', '.img',
    }
    
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        
        filename = part.get_filename()
        if not filename:
            continue
        
        content = part.get_payload(decode=True) or b''
        ext = Path(filename).suffix.lower()
        
        attachment = {
            'filename': filename,
            'extension': ext,
            'content_type': part.get_content_type(),
            'size_bytes': len(content),
            'is_dangerous_extension': ext in dangerous_extensions,
            'md5': hashlib.md5(content).hexdigest() if content else None,
            'sha256': hashlib.sha256(content).hexdigest() if content else None,
        }
        
        # Check for double extensions
        if filename.count('.') > 1:
            attachment['double_extension'] = True
            attachment['hidden_extension'] = Path(Path(filename).stem).suffix
        
        attachments.append(attachment)
    
    return attachments


def get_body_text(msg: Message) -> str:
    """Extract full body text from message."""
    body_parts = []
    
    for part in msg.walk():
        content_type = part.get_content_type()
        if content_type in ('text/plain', 'text/html'):
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    charset = part.get_content_charset() or 'utf-8'
                    body_parts.append(payload.decode(charset, errors='ignore'))
            except Exception:
                pass
    
    return '\n'.join(body_parts)


def detect_phishing_keywords(text: str) -> List[Dict[str, Any]]:
    """Detect phishing/spam keywords in text."""
    findings = []
    text_lower = text.lower()
    
    for pattern in PHISHING_KEYWORDS:
        matches = list(re.finditer(pattern, text_lower, re.IGNORECASE))
        if matches:
            findings.append({
                'pattern': pattern,
                'count': len(matches),
                'samples': [m.group(0) for m in matches[:3]],
            })
    
    return findings


def compare_domains(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Compare domains across headers to find mismatches."""
    from_email, from_domain = extract_email_and_domain(headers.get('from'))
    return_email, return_domain = extract_email_and_domain(headers.get('return_path'))
    reply_email, reply_domain = extract_email_and_domain(headers.get('reply_to'))
    sender_email, sender_domain = extract_email_and_domain(headers.get('sender'))
    
    result = {
        'from': {'email': from_email, 'domain': from_domain},
        'return_path': {'email': return_email, 'domain': return_domain},
        'reply_to': {'email': reply_email, 'domain': reply_domain},
        'sender': {'email': sender_email, 'domain': sender_domain},
        'mismatches': {},
    }
    
    if from_domain and return_domain:
        result['mismatches']['from_vs_return_path'] = from_domain != return_domain
    if from_domain and reply_domain:
        result['mismatches']['from_vs_reply_to'] = from_domain != reply_domain
    if from_domain and sender_domain:
        result['mismatches']['from_vs_sender'] = from_domain != sender_domain
    
    return result


def calculate_risk_score(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Calculate overall risk score and severity."""
    score = 0
    factors = []
    
    # Authentication failures
    auth = analysis.get('authentication', {})
    if auth.get('spf', {}).get('result') in ('fail', 'softfail'):
        score += 20
        factors.append("SPF failure")
    if auth.get('dkim', {}).get('result') == 'fail':
        score += 25
        factors.append("DKIM failure")
    if auth.get('dmarc', {}).get('result') == 'fail':
        score += 25
        factors.append("DMARC failure")
    if not any([auth.get('spf', {}).get('result'), auth.get('dkim', {}).get('result')]):
        score += 15
        factors.append("Missing authentication")
    
    # Domain mismatches
    mismatches = analysis.get('domain_comparison', {}).get('mismatches', {})
    if mismatches.get('from_vs_return_path'):
        score += 10
        factors.append("From/Return-Path domain mismatch")
    if mismatches.get('from_vs_reply_to'):
        score += 5
        factors.append("From/Reply-To domain mismatch")
    
    # Suspicious URLs
    urls = analysis.get('urls', [])
    high_risk_urls = [u for u in urls if u.get('risk_score', 0) >= 4]
    if high_risk_urls:
        score += min(len(high_risk_urls) * 5, 20)
        factors.append(f"{len(high_risk_urls)} high-risk URLs")
    
    # Attachments
    attachments = analysis.get('attachments', [])
    dangerous = [a for a in attachments if a.get('is_dangerous_extension')]
    if dangerous:
        score += 30
        factors.append(f"{len(dangerous)} dangerous attachment(s)")
    
    # Phishing keywords
    keywords = analysis.get('phishing_keywords', [])
    if keywords:
        score += min(len(keywords) * 3, 15)
        factors.append(f"{len(keywords)} suspicious keyword patterns")
    
    # Received chain
    chain = analysis.get('received_chain', [])
    if len(chain) < 2:
        score += 10
        factors.append("Unusual mail routing (few hops)")
    
    # Determine severity
    if score >= 50:
        severity = "HIGH"
    elif score >= 25:
        severity = "MEDIUM"
    elif score >= 10:
        severity = "LOW"
    else:
        severity = "CLEAN"
    
    return {
        'score': min(score, 100),
        'severity': severity,
        'factors': factors,
    }


def analyze_email(path: str) -> Dict[str, Any]:
    """Perform full forensic analysis on an email."""
    msg = load_email(path)
    body = get_body_text(msg)
    full_text = str(msg) + body
    
    headers = extract_basic_headers(msg)
    
    analysis = {
        'file': path,
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'headers': headers,
        'authentication': extract_auth_results(msg),
        'received_chain': extract_received_chain(msg),
        'domain_comparison': compare_domains(headers),
        'x_headers': extract_x_headers(msg),
        'emails_found': sorted(extract_all_emails(full_text)),
        'urls': extract_all_urls(full_text),
        'phone_numbers': sorted(extract_phone_numbers(body)),
        'attachments': extract_attachments(msg),
        'phishing_keywords': detect_phishing_keywords(body),
    }
    
    analysis['risk_assessment'] = calculate_risk_score(analysis)
    
    return analysis


def print_severity_badge(severity: str) -> str:
    """Return colored severity badge."""
    colors = {
        'HIGH': C.RED + C.BOLD,
        'MEDIUM': C.YELLOW,
        'LOW': C.CYAN,
        'CLEAN': C.GREEN,
    }
    return f"{colors.get(severity, C.WHITE)}[{severity}]{C.RESET}"


def print_report(analysis: Dict[str, Any]) -> None:
    """Print formatted forensic report."""
    risk = analysis['risk_assessment']
    headers = analysis['headers']
    auth = analysis['authentication']
    
    print(f"\n{C.BOLD}{'═' * 80}{C.RESET}")
    print(f"{C.BOLD}  EMAIL FORENSIC ANALYSIS REPORT{C.RESET}")
    print(f"{C.BOLD}{'═' * 80}{C.RESET}")
    print(f"  File: {analysis['file']}")
    print(f"  Analysis Time: {analysis['timestamp']}")
    print()
    
    # Risk Assessment
    print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
    print(f"{C.BOLD}│  RISK ASSESSMENT                                                             │{C.RESET}")
    print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
    print(f"  Severity: {print_severity_badge(risk['severity'])}  Score: {risk['score']}/100")
    if risk['factors']:
        print(f"  Factors:")
        for f in risk['factors']:
            print(f"    • {C.YELLOW}{f}{C.RESET}")
    print()
    
    # Basic Headers
    print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
    print(f"{C.BOLD}│  HEADERS                                                                     │{C.RESET}")
    print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
    for key in ['from', 'to', 'reply_to', 'return_path', 'subject', 'date', 'message_id']:
        val = headers.get(key) or '-'
        label = key.replace('_', '-').title()
        print(f"  {label + ':':<14} {val[:65]}")
    print()
    
    # Domain Comparison
    dc = analysis['domain_comparison']
    print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
    print(f"{C.BOLD}│  DOMAIN ANALYSIS                                                             │{C.RESET}")
    print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
    for key in ['from', 'return_path', 'reply_to']:
        data = dc[key]
        print(f"  {key.replace('_', '-').title():<14} {data['email'] or '-':<40} [{data['domain'] or '-'}]")
    
    if any(dc['mismatches'].values()):
        print(f"\n  {C.YELLOW}⚠ Domain Mismatches Detected:{C.RESET}")
        for k, v in dc['mismatches'].items():
            if v:
                print(f"    • {k}: {C.RED}MISMATCH{C.RESET}")
    print()
    
    # Authentication
    print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
    print(f"{C.BOLD}│  AUTHENTICATION (SPF/DKIM/DMARC)                                             │{C.RESET}")
    print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
    
    def auth_color(result):
        if result == 'pass':
            return C.GREEN
        elif result in ('fail', 'softfail'):
            return C.RED
        return C.YELLOW
    
    spf = auth['spf']['result'] or 'none'
    dkim = auth['dkim']['result'] or 'none'
    dmarc = auth['dmarc']['result'] or 'none'
    
    print(f"  SPF:   {auth_color(spf)}{spf.upper()}{C.RESET}")
    print(f"  DKIM:  {auth_color(dkim)}{dkim.upper()}{C.RESET}" + 
          (f" (domain: {auth['dkim']['domain']})" if auth['dkim']['domain'] else ""))
    print(f"  DMARC: {auth_color(dmarc)}{dmarc.upper()}{C.RESET}" +
          (f" (policy: {auth['dmarc']['policy']})" if auth['dmarc']['policy'] else ""))
    print()
    
    # Received Chain
    chain = analysis['received_chain']
    print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
    print(f"{C.BOLD}│  MAIL ROUTING ({len(chain)} hops)                                                     │{C.RESET}")
    print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
    for hop in chain[:5]:
        fr = hop['from'] or '?'
        by = hop['by'] or '?'
        pub_ips = ', '.join(hop['public_ips'][:2]) or 'none'
        print(f"  [{hop['index']}] {fr[:25]} → {by[:25]}")
        print(f"      Public IPs: {pub_ips}")
    if len(chain) > 5:
        print(f"  ... and {len(chain) - 5} more hops")
    print()
    
    # Emails Found
    emails = analysis['emails_found']
    if emails:
        print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
        print(f"{C.BOLD}│  EXTRACTED EMAILS ({len(emails)})                                                    │{C.RESET}")
        print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
        for email in emails[:15]:
            print(f"  • {email}")
        if len(emails) > 15:
            print(f"  ... and {len(emails) - 15} more")
        print()
    
    # URLs
    urls = analysis['urls']
    if urls:
        print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
        print(f"{C.BOLD}│  EXTRACTED URLs ({len(urls)})                                                       │{C.RESET}")
        print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
        for url in urls[:10]:
            risk_color = C.RED if url.get('risk_score', 0) >= 4 else C.YELLOW if url.get('risk_score', 0) >= 2 else C.WHITE
            flags = []
            if url.get('is_shortener'):
                flags.append('SHORTENER')
            if url.get('suspicious_tld'):
                flags.append('SUSPICIOUS_TLD')
            if url.get('has_ip'):
                flags.append('IP_URL')
            if url.get('homograph'):
                flags.append('HOMOGRAPH')
            
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            print(f"  {risk_color}• {url['domain']}{C.RESET}{C.DIM}{flag_str}{C.RESET}")
            print(f"    {C.DIM}{url['url'][:70]}...{C.RESET}" if len(url.get('url', '')) > 70 else f"    {C.DIM}{url.get('url', '')}{C.RESET}")
        if len(urls) > 10:
            print(f"  ... and {len(urls) - 10} more URLs")
        print()
    
    # Attachments
    attachments = analysis['attachments']
    if attachments:
        print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
        print(f"{C.BOLD}│  ATTACHMENTS ({len(attachments)})                                                        │{C.RESET}")
        print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
        for att in attachments:
            danger = C.RED + "⚠ DANGEROUS" + C.RESET if att['is_dangerous_extension'] else ""
            print(f"  • {att['filename']} ({att['size_bytes']} bytes) {danger}")
            if att.get('sha256'):
                print(f"    SHA256: {att['sha256'][:32]}...")
        print()
    
    # Phishing Keywords
    keywords = analysis['phishing_keywords']
    if keywords:
        print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
        print(f"{C.BOLD}│  SUSPICIOUS KEYWORDS                                                         │{C.RESET}")
        print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
        for kw in keywords[:10]:
            print(f"  • Pattern: {C.YELLOW}{kw['pattern']}{C.RESET} ({kw['count']}x)")
        print()
    
    # X-Headers
    x_headers = analysis['x_headers']
    if x_headers:
        print(f"{C.BOLD}┌{'─' * 78}┐{C.RESET}")
        print(f"{C.BOLD}│  X-HEADERS                                                                   │{C.RESET}")
        print(f"{C.BOLD}└{'─' * 78}┘{C.RESET}")
        for k, vals in list(x_headers.items())[:8]:
            for v in vals[:1]:
                print(f"  {k}: {v[:60]}...")
        print()
    
    print(f"{C.BOLD}{'═' * 80}{C.RESET}")
    print(f"  {C.DIM}Export to JSON: python email_verify.py {analysis['file']} --json{C.RESET}")
    print(f"{C.BOLD}{'═' * 80}{C.RESET}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Email Forensic Analyzer - Professional spam/phishing investigation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s email.eml                    # Analyze and print report
  %(prog)s email.eml --json             # Output JSON to stdout
  %(prog)s email.eml --json -o report.json  # Save JSON to file
        """
    )
    parser.add_argument("file", help="Path to email file (.eml or raw headers)")
    parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")
    parser.add_argument("--output", "-o", help="Output file for JSON report")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()
    
    if args.no_color:
        for attr in dir(C):
            if not attr.startswith('_'):
                setattr(C, attr, '')
    
    if not Path(args.file).exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    
    analysis = analyze_email(args.file)
    
    if args.json:
        json_output = json.dumps(analysis, indent=2, default=str)
        if args.output:
            Path(args.output).write_text(json_output)
            print(f"Report saved to: {args.output}")
        else:
            print(json_output)
    else:
        print_report(analysis)


if __name__ == "__main__":
    main()
