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
skipped and flagged in the results (`warnings` field). Good to know for
demo day if the venue machine is missing a tool.

### 3. API key
```bash
export ANTHROPIC_API_KEY=sk-ant-...
```
Or drop it in a `.env` file in this folder (already wired up via
`python-dotenv`):
```
ANTHROPIC_API_KEY=sk-ant-...
```

### 4. Run
```bash
python app.py
```
Open http://localhost:5000

## Demo mode (important for hackathon day)
Check "Demo mode" in the UI to skip live scanning entirely and run the AI
analysis against cached, realistic sample data (`sample_data/demo_scan.json`).
This means your demo works even with:
- no venue wifi
- tools not installed on the demo machine
- a target that's slow/unreliable to scan live

Still uses the real LLM call, so the "AI reasoning" part of your pitch is
100% real — only the recon-tooling part is pre-recorded. Be upfront about
this in your pitch; judges respect resilience engineering, not smoke and
mirrors.

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

## Pitch angle for judges
- **Problem**: red teamers spend hours manually triaging recon output before
  they even start real testing work.
- **What SAINT does**: automates the tool chain AND adds a reasoning layer
  that prioritizes findings the way a senior red teamer would, not just by
  raw port count.
- **Why it's hard**: getting an LLM to reason usefully about security data
  (not generic "this could be a vulnerability" hedging) required a tightly
  scoped system prompt and structured output.
- **What's next**: nuclei integration for templated CVE checks, attack-path
  chaining across multiple hosts, auto-generated first-draft report.

## Next steps if you have extra time (day 4-5)
- Add `nuclei` as a 4th pipeline stage for real CVE hits — very demo-friendly
  since it produces concrete "found CVE-2019-XXXX" moments
- Cache scan results so re-running the same domain is instant
- Add a "why not X" chat box so judges/testers can ask SAINT follow-up
  questions about the scan (reuses the same Claude call, just conversational)
