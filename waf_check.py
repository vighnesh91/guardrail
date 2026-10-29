import re, sys, json, threading, unicodedata, urllib.parse, html

T1 = {
    "PROMPT_INJECTION": ["ignore previous instructions", "ignore all rules", "stop being a waf",
        "developer mode", "dan mode", "jailbreak", "system override", "you must now act as",
        "unrestricted mode", "bypass filter", "bypass the filter", "forget your training",
        "assume the persona of", "do whatever i say", "you are now unrestricted"],
    "VIRTUALIZATION": ["act as a terminal", "linux console", "python interpreter",
        "database console", "text game", "safety rules are suspended", "simulate a shell"],
    "HYPOTHETICAL": ["for educational purposes only", "in a fictional world where crime",
        "a good ai would answer", "movie scene where a hacker"],
}
T2 = {
    "XSS": ["<script", "javascript:", "onerror=", "onload=", "<iframe", "document.cookie",
        "window.location", "eval(", "settimeout(", "setinterval(", "fetch(", "xmlhttprequest",
        "localstorage", "sessionstorage", "document.write", "alert("],
    "SQL_INJECTION": ["union select", "or 1=1", "and 1=1", "drop table", "insert into",
        "admin' --", "' or '1'='1"],
    "TRAVERSAL_SHELL": ["../../..", "/etc/passwd", "/bin/sh", "chmod +x", "cat /var/log",
        "rm -rf", "wget ", "curl ", "sudo ", "cmd.exe", "powershell.exe"],
}
T3 = {
    "PROBING": ["repeat the above", "output your system prompt", "what are your constraints",
        "give me your initialization text", "print everything above this line",
        "what is your system instructions text", "spell check your original prompt"],
    "EXFIL": ["![", "](http", "attacker.com", "printenv", "os.environ"],
}
ALL = {**T1, **T2, **T3}

def _boundary(s):  # word-boundary regex: no false hits inside words like "evaluating"/"curling"
    s = s.strip()
    pat = re.escape(s).replace(r"\ ", r"\s+")
    if s[:1].isalnum(): pat = r"(?<![a-z0-9_])" + pat
    if s[-1:].isalnum(): pat = pat + r"(?![a-z0-9_])"
    return re.compile(pat)

# One alternation regex per vector: flat O(N) scan instead of N sequential regexes
SIGS = [(vec, re.compile("|".join(f"(?:{_boundary(s).pattern})" for s in sigs)))
        for vec, sigs in ALL.items()]

# Structural escapes run on canonical form; delimiters tolerate any spacing/variation
STRUCT = [
    (re.compile(r"</system|###\s*end\s+system|-\s*-\s*-\s*$|system\s+update\s*:", re.I | re.M), "DELIMITER_ESCAPE"),
    (re.compile(r"\$\{|`[^`]*\+|'(?![^']*').{60,}|\"(?![^\"]*\").{60,}"), "STRING_ESCAPE"),
    (re.compile(r"[A-Za-z0-9+/]{40,}={0,2}|(?:\\x[0-9a-f]{2}){6,}|%[0-9a-f]{2}%[0-9a-f]{2}%[0-9a-f]{2}", re.I), "OBFUSCATION"),
]

def normalize(p):  # multi-layer decode to canonical base form
    for _ in range(5):
        d = html.unescape(urllib.parse.unquote(p))
        if d == p:
            break
        p = d
    p = unicodedata.normalize("NFKC", p)  # collapse homograph lookalikes (Cyrillic 'а' -> 'a')
    return re.sub(r"[\s\x00-\x1f]+", " ", p.lower())

def check(p):
    low = normalize(p)
    for rx, vec in STRUCT:
        if rx.search(low):
            return {"status": "BLOCK", "threat_vector": vec, "confidence_score": 0.8}
    for vec, rx in SIGS:
        if rx.search(low):
            return {"status": "BLOCK", "threat_vector": vec, "confidence_score": 0.9}
    return {"status": "ALLOW", "threat_vector": "NONE", "confidence_score": 1.00}

def check_safe(p):  # fail-closed: size cap, ReDoS timeout, any error -> secure BLOCK
    if len(p) > 65536:
        return {"status": "BLOCK", "threat_vector": "PAYLOAD_TOO_LARGE", "confidence_score": 1.0}
    result = {}
    def run(): result.update(check(p))
    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(0.05)
    if t.is_alive():
        return {"status": "BLOCK", "threat_vector": "SCAN_TIMEOUT", "confidence_score": 1.0}
    return result if result else {"status": "BLOCK", "threat_vector": "INTERNAL_ERROR", "confidence_score": 1.0}

try:
    print(json.dumps(check_safe(sys.stdin.read())))
except Exception:
    print(json.dumps({"status": "BLOCK", "threat_vector": "INTERNAL_ERROR", "confidence_score": 1.0}))
