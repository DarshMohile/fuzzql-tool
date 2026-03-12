#!/usr/bin/env python3

import argparse
import json
import time
from datetime import datetime, timezone
from copy import deepcopy
import requests

# ===== config =====
RATE_PER_SEC = 1
SLEEP = 1.0 / max(1, RATE_PER_SEC)
TIMEOUT = 8.0
SIZE_DIFF_THRESHOLD = 200
ERROR_KEYWORDS = (
    "syntax error", "sqlstate", "mysql", "pdoexception",
    "psql: error", "sql error", "database error", "odbc", "syntax"
)
CONFIDENCE = 0

def rate_sleep(rate_per_sec):
    time.sleep(1.0 / max(1, rate_per_sec))

def load_payloads(path):
    with open(path, "r", encoding="utf-8") as f:
        return [ln.rstrip("\n") for ln in f if ln.strip()]

def prefetch_page(session, url):
    
    try:
        session.get(url, timeout=TIMEOUT)
    except requests.RequestException:
        pass

def send_post(session, url, formdata, allow_redirects=False):
    
    try:
        r = session.post(url, data=formdata, timeout=TIMEOUT, allow_redirects=allow_redirects)
        return {
            "status": r.status_code,
            "length": len(r.text or ""),
            "body": r.text or "",
            "time": r.elapsed.total_seconds(),
            "location": r.headers.get("Location"),
            "history": [resp.status_code for resp in getattr(r, "history", [])]
        }
    except requests.RequestException:
        return None

def analyze(baseline, probe, payload):
    
    CONFIDENCE = 0
    
    issues = []
    if baseline is None or probe is None:
        return issues

    # status mismatch
    if probe["status"] != baseline["status"]:
        issues.append("status-mismatch")

    # redirect detection: 3xx status or Location header
    baseline_redirect = (baseline.get("status", 0) // 100) == 3 or bool(baseline.get("location"))
    probe_redirect = (probe.get("status", 0) // 100) == 3 or bool(probe.get("location"))
    
    if probe_redirect and not baseline_redirect:
        issues.append("redirect-on-probe")
        CONFIDENCE += 5
        
    elif probe.get("location") and baseline.get("location") and probe["location"] != baseline["location"]:
        issues.append("location-changed")
        CONFIDENCE += 5

    # response size
    if abs(probe["length"] - baseline["length"]) > SIZE_DIFF_THRESHOLD:
        issues.append("response-size-diff")
        CONFIDENCE += 1

    # error keywords
    body_lower = (probe["body"] or "").lower()
    for kw in ERROR_KEYWORDS:
        if kw in body_lower:
            issues.append("error-string")
            CONFIDENCE += 5
            break

    # reflection (payload text shows up in probe but not baseline)
    if payload and (payload in probe["body"]) and (payload not in baseline["body"]):
        issues.append("input-reflected")
        CONFIDENCE += 1

    return issues

def fuzz_login_post(url, fields_to_test, baseline_template, payloads, rate_per_sec, prefetch_url=None):
    session = requests.Session()
    findings = []

    # Optional prefetch to get cookies / tokens
    if prefetch_url:
        prefetch_page(session, prefetch_url)

    # Build baseline form: ensure all required fields exist
    baseline_form = deepcopy(baseline_template)
    
    # add defaults if missing (safe defaults)
    if "uid" not in baseline_form:
        baseline_form["uid"] = "test"
    if "passw" not in baseline_form:
        baseline_form["passw"] = "test"
    if "btnSubmit" not in baseline_form:
        baseline_form["btnSubmit"] = "Login"

    # Send baseline POST (do not follow redirects)
    print("\n>>Sending baseline POST (not following redirects)...")
    rate_sleep(rate_per_sec)
    baseline = send_post(session, url, baseline_form, allow_redirects=False)
    
    if baseline is None:
        print("ERROR: baseline request failed or endpoint unreachable.")
        return findings

    total = len(fields_to_test) * len(payloads)
    idx = 0
    
    for field in fields_to_test:
        for payload in payloads:
            idx += 1
            probe_form = deepcopy(baseline_form)
            probe_form[field] = payload

            rate_sleep(rate_per_sec)
            
            probe = send_post(session, url, probe_form, allow_redirects=False)
            issues = analyze(baseline, probe, payload)
            
            if issues:
                findings.append({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "url": url,
                    "field": field,
                    "payload": payload,
                    "issues": issues,
                    "baseline_status": baseline.get("status"),
                    "probe_status": probe.get("status") if probe else None,
                    "baseline_len": baseline.get("length"),
                    "probe_len": probe.get("length") if probe else None,
                    "baseline_location": baseline.get("location"),
                    "probe_location": probe.get("location") if probe else None
                })

            # light progress
            if idx % 10 == 0 or idx == total:
                print(f"\n>>Progress: {idx}/{total} probes")

    return findings

def main():
    parser = argparse.ArgumentParser(description="Targeted POST fuzzer (login-aware).")
    parser.add_argument("-u", "--url", required=True, help="POST action URL (e.g. https://demo.testfire.net/doLogin)")
    parser.add_argument("-T", "--template", help="JSON file with baseline form fields (uid, passw, btnSubmit,...).")
    parser.add_argument("-p", "--params", help="Comma-separated field(s) to test (e.g. uid). If omitted and template present, tests all template keys.")
    parser.add_argument("--payloads", default="payloads.txt", help="Payload file (one per line).")
    parser.add_argument("--prefetch", help="Optional page to GET before POST (e.g. login page) to obtain cookies)")
    parser.add_argument("--rate", type=int, default=RATE_PER_SEC, help="Requests per second (default 1)")
    parser.add_argument("-o", "--out", default="findings.json", help="Output JSON file")
    args = parser.parse_args()
    
    
    
    print("\n--------------------------------------------------------------------------------")
    print("███████ ██    ██ ███████ ███████  ██████  ██      ")
    print("██      ██    ██    ███     ███  ██    ██ ██      ")
    print("█████   ██    ██   ███     ███   ██    ██ ██      ")
    print("██      ██    ██  ███     ███    ██ ▄▄ ██ ██      ")
    print("██       ██████  ███████ ███████  ██████  ███████ ")
    print("                                 ▀▀               ")                                             
    print("--------------------------------------------------------------------------------\n")                                           
    
    
    

    payloads = load_payloads(args.payloads)
    if not payloads:
        print("No payloads loaded from", args.payloads)
        return

    template = {}
    if args.template:
        with open(args.template, "r", encoding="utf-8") as f:
            template = json.load(f)

    fields = []
    if args.params:
        fields = [s.strip() for s in args.params.split(",") if s.strip()]
    if not fields and template:
        fields = list(template.keys())
    if not fields:
        parser.error("Specify fields to test with -p or provide a template with keys.")

    print("SQL Injection Fuzzer to test web forms\n")
    print(f"LEGAL WARNING: Only test systems you own / have permission to test.")
    print(f"\n>>Fuzzing {args.url} on fields {fields} with {len(payloads)} payloads (rate={args.rate} rps)")

    findings = fuzz_login_post(args.url, fields, template, payloads, args.rate, prefetch_url=args.prefetch)

    with open(args.out, "w", encoding="utf-8") as fout:
        json.dump({"generated_at": datetime.now(timezone.utc).isoformat(), "findings": findings}, fout, indent=2)

    print("\n>>Done. Findings written to", args.out)
    
    if findings:
        print("\n===|SUMMARY|===")  
        
        bypass_findings = []  # collect login bypass results
        
        for f in findings:
            print(f"- field={f['field']} payload={f['payload']!r} issues={f['issues']}")
            
            # collect if bypass indicators are present
            if any(issue in f['issues'] for issue in ('redirect-on-probe', 'location-changed')):
                bypass_findings.append(f)

        # print bypass summary once
        if bypass_findings:
            print("\n>Potential Login Bypass Detected:")
            for bf in bypass_findings:
                print(f"- field={bf['field']} payload={bf['payload']!r} issues={bf['issues']}")
    else:
        print("No suspicious findings (with current payloads & heuristics)")

if __name__ == "__main__":
    main()
