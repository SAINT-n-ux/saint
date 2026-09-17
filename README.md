# SAINT — AI Red Team Recon Copilot

An AI "buddy" for red teamers: point it at a domain, it runs real recon
tooling (subfinder → httpx → naabu), then an LLM reasons over the raw
findings like a red team lead — ranking targets by exploitability and
explaining *why*, instead of just dumping a table of open ports.

**⚠️ Only scan domains you own or have explicit written authorization to
test.**
## Setup

### 1. Python deps
```bash
cd saint
python3 -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Recon tools (Go binaries, from ProjectDiscovery)
Install Go first if you don't have it: https://go.dev/doc/install

```bash
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
```
Make sure `$(go env GOPATH)/bin` is on your `PATH` so the app can find them.
(`naabu` may need libpcap installed — `apt install libpcap-dev` on
Debian/Ubuntu, `brew install libpcap` on macOS.)

If a tool isn't installed, the app doesn't crash — that stage is just
skipped and flagged in the results (`warnings` field).

### 3. API key
```bash
export API_KEY=sk-ant-...
```
And drop it in a `.env` file in this folder (already wired up via
`python-dotenv`):
```
API_KEY=sk-ant-...
```

### 4. Run
```bash
python app.py
```
Open http://localhost:5000

## Demo mode
Check "Demo mode" in the UI to skip live scanning entirely and run the AI
analysis against cached, realistic sample data (`sample_data/demo_scan.json`).
This means your demo works even with:
- no venue wifi
- tools not installed on the demo machine
- a target that's slow/unreliable to scan live


## Project structure
```
saint/
├── app.py              # Flask routes
├── pipeline.py         # subfinder/httpx/naabu orchestration
├── llm.py              # Claude prompt + call for attack-surface reasoning
├── templates/index.html
├── sample_data/demo_scan.json   # cached fallback data
└── requirements.txt
```

## Pitch
- **Problem**: red teamers spend hours manually triaging recon output before
  they even start real testing work.
- **What SAINT does**: automates the tool chain AND adds a reasoning layer
  that prioritizes findings the way a senior red teamer would, not just by
  raw port count.
- **Why it's hard**: getting an LLM to reason usefully about security data
  (not generic "this could be a vulnerability" hedging) required a tightly
  scoped system prompt and structured output and sometimes it is blocked.
- **What's next**: nuclei integration for templated CVE checks, attack-path
  chaining across multiple hosts, auto-generated first-draft report.

