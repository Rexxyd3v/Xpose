"""Read-only loopback dashboard. No uploads, shell commands, or filesystem browsing."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from expose.reports.formats import STYLE, report_html
from expose.state import read_json

PAGE = '''<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Xpose dashboard</title><style>STYLE</style><main><small>XPOSE / LOCAL WORKSPACE</small><h1>Secret exposure overview</h1><p class="muted">Latest scan and up to 200 recent runs. Refresh to load new scans.</p><div id="cards" class="cards"></div><p><input id="search" aria-label="Search findings" placeholder="Search rule or file"><select id="severity" aria-label="Severity"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select><select id="status" aria-label="Status"><option value="">All statuses</option><option>new</option><option>baseline</option><option>suppressed</option></select><a href="/report">Open full report</a></p><h2>Latest findings</h2><p id="target" class="muted"></p><div class="scroll"><table><thead><tr><th>Severity</th><th>Rule / status</th><th>Location</th><th>Masked context</th></tr></thead><tbody id="findings"></tbody></table></div><h2>Recent scans</h2><div class="scroll"><table><thead><tr><th>Time</th><th>Target / mode</th><th>New</th><th>Status</th></tr></thead><tbody id="runs"></tbody></table></div><p id="error"></p></main><script>
let latest={findings:[]};function cell(row,value){const c=document.createElement('td');c.textContent=value;row.appendChild(c);return c}
function render(){const body=document.getElementById('findings');body.replaceChildren();const q=document.getElementById('search').value.toLowerCase(),sev=document.getElementById('severity').value,status=document.getElementById('status').value;for(const f of latest.findings){if(sev&&f.severity!==sev||status&&f.status!==status||!(f.file+' '+f.rule).toLowerCase().includes(q))continue;const row=document.createElement('tr');cell(row,f.severity).className=f.severity;cell(row,f.rule+' / '+f.status);cell(row,f.file+':'+f.line);cell(row,f.context);body.appendChild(row)}}
fetch('/api').then(r=>{if(!r.ok)throw Error('Could not load scans');return r.json()}).then(data=>{latest=data.latest||{findings:[]};document.getElementById('target').textContent=latest.target||'No scans yet';for(const [key,value] of Object.entries(latest.summary||{})){if(typeof value!=='number')continue;const card=document.createElement('div');card.className='card';const label=document.createElement('small');label.textContent=key.replaceAll('_',' ');const number=document.createElement('strong');number.textContent=value;card.append(label,number);document.getElementById('cards').appendChild(card)}for(const run of data.runs.slice().reverse()){const row=document.createElement('tr');cell(row,new Date(run.created_at).toLocaleString());cell(row,run.target+' / '+run.mode);cell(row,run.summary.new);cell(row,run.complete?'Complete':'Incomplete');document.getElementById('runs').appendChild(row)}render()}).catch(e=>document.getElementById('error').textContent=e.message);
for(const id of ['search','severity','status'])document.getElementById(id).addEventListener('input',render);
</script></html>'''

def serve(state_dir, port=8765, open_browser=False):
    state_dir = Path(state_dir)
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.headers.get("Host") not in {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}:
                self.send_error(403)
                return
            try:
                if self.path == "/":
                    content, kind = PAGE.replace("STYLE", STYLE), "text/html"
                elif self.path == "/api":
                    content, kind = json.dumps({"latest": read_json(state_dir / "latest.json"), "runs": read_json(state_dir / "runs.json", [])}), "application/json"
                elif self.path == "/report":
                    report = read_json(state_dir / "latest.json")
                    content, kind = report_html(report) if report else "No scans yet.", "text/html"
                else:
                    self.send_error(404)
                    return
            except (ValueError, OSError):
                self.send_error(500, "Unable to read local scan data")
                return
            data = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", kind + "; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)
        def log_message(self, *args):
            pass
    try:
        server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    except OSError as exc:
        if exc.errno in {48, 98, 10048} or getattr(exc, "winerror", None) == 10048:
            raise ValueError(f"Dashboard port {port} is already in use. Try 'xpose dashboard --port 9000 --open'.") from exc
        raise
    print(f"Xpose dashboard: http://127.0.0.1:{server.server_port}  (Ctrl+C to stop)")
    try:
        if open_browser:
            import webbrowser
            try:
                webbrowser.open(f"http://127.0.0.1:{server.server_port}")
            except OSError:
                print("Open the dashboard URL above in your browser.")
        server.serve_forever()
    finally:
        server.server_close()
