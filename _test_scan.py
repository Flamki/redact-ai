import requests, json

r = requests.post('http://localhost:8000/api/v1/scan/url', json={'url':'https://flipkart.com'})
d = r.json()

print("=== RISK ===")
print(f"Score: {d['risk_score']} ({d['risk_level']})")
for f in d['risk_factors']:
    print(f"  - {f}")

print("\n=== EXPOSED PII (should be 0 now — no false positives) ===")
print(f"Count: {d['exposed_pii']['count']}")
for p in d['exposed_pii']['items']:
    print(f"  {p['type']}: {p['text']}")

print("\n=== DPDP ACT 2023 COMPLIANCE ===")
dpdp = d.get('dpdp', {})
print(f"Grade: {dpdp.get('grade')} ({dpdp.get('score')}/{dpdp.get('total_checks')})")
for k, v in dpdp.get('checks', {}).items():
    status = 'PASS' if v['passed'] else 'FAIL'
    print(f"  [{status}] {k} — {v['section']}")

print("\n=== SECURITY HEADERS ===")
c = d.get('compliance', {})
print(f"Grade: {c.get('security_header_grade')}")
for k, v in c.get('security_headers', {}).items():
    print(f"  {'[+]' if v else '[-]'} {k}")

print("\n=== COOKIES ===")
cookies = d.get('cookies', {})
print(f"Total: {cookies.get('count')}")
s = cookies.get('summary', {})
print(f"  Session: {s.get('session_cookies')}, Persistent: {s.get('persistent_cookies')}")
print(f"  HttpOnly: {s.get('httponly')}, Secure: {s.get('secure')}, SameSite: {s.get('samesite')}")
print(f"  Third-party: {s.get('third_party')}")

print("\n=== BLACKLIGHT ===")
bl = d.get('blacklight', {})
for test in ['canvas_fingerprinting', 'key_logging', 'session_recording']:
    t = bl.get(test, {})
    print(f"  {test}: {'DETECTED' if t.get('detected') else 'clean'}")
print(f"  fb_pixel: {'DETECTED' if bl.get('facebook_pixel',{}).get('detected') else 'clean'}")
print(f"  ga: {'DETECTED' if bl.get('google_analytics',{}).get('detected') else 'clean'}")
print(f"  tracking_domains: {bl.get('tracking_domains',{}).get('count')}")

print(f"\n=== ENGINE ===")
print(f"  {d.get('engine', {}).get('methodology')}")
