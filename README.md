# XScanner — Next-Generation XSS Detection Framework

```
 ██╗  ██╗███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
 ╚██╗██╔╝██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
  ╚███╔╝ ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
  ██╔██╗ ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
 ██╔╝ ██╗███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
```

> **⚠ For authorized penetration testing and security research ONLY.**
> Using this tool against systems you do not own or have explicit written
> permission to test is illegal. The authors assume no liability.

---

## What is XScanner?

XScanner is a professional-grade, modular XSS detection framework built on
Python 3.11+ async architecture. It is designed to go significantly beyond
tools like XSStrike by combining:

- Full async concurrency (`asyncio` + `aiohttp`)
- Context-aware, mutation-based payload generation
- Multi-layer response analysis (reflection + DOM + HTML position)
- Per-WAF adaptive evasion strategies
- AI-assisted payload suggestions (via Claude API)
- Headless browser XSS confirmation (Playwright)
- Blind XSS callback server (built-in)
- Clean JSON + Rich CLI reporting

---

## Architecture

```
xscanner/
├── xscanner.py              # Entry point
├── requirements.txt
│
├── cli/
│   └── interface.py         # Click CLI — all flags and option parsing
│
├── scanner/
│   ├── engine.py            # Master async orchestrator
│   ├── ai_advisor.py        # Claude API payload suggestion engine
│   ├── verifier.py          # Playwright headless XSS verification
│   └── blind_server.py      # aiohttp blind XSS callback listener
│
├── crawler/
│   └── spider.py            # Async BFS spider + injection context detector
│
├── payloads/
│   └── generator.py         # Context-aware + mutation + encoding engine
│                             # 10 context types × 8 encoding transforms
│
├── detection/
│   └── analyzer.py          # 5-layer detection:
│                             #   1. Reflection check
│                             #   2. Critical char survival
│                             #   3. HTML position (BeautifulSoup)
│                             #   4. DOM sink/source mapping
│                             #   5. Confidence scoring
│
├── waf_bypass/
│   └── detector.py          # WAF fingerprinting + 10 evasion strategies
│
├── reports/
│   └── reporter.py          # JSON report + Rich terminal table
│
├── utils/
│   ├── config.py            # Dataclasses, constants, profiles
│   ├── logger.py            # Rich-powered colorized logger
│   └── http_client.py       # Async HTTP with retry + rate limiting
│
└── tests/
    └── test_core.py         # 27 unit tests (100% passing)
```

---

## Installation

```bash
# 1. Clone / extract
cd xscanner

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. (Optional) Install Playwright for headless verification
pip install playwright
playwright install chromium

# 4. (Optional) Set API key for AI payload suggestions
export ANTHROPIC_API_KEY="your-key-here"
```

---

## Usage

### Basic scan
```bash
python xscanner.py -u "https://yoursite.com/search?q=test"
```

### Scan with deep crawl
```bash
python xscanner.py -u "https://yoursite.com" --deep --threads 5
```

### Scan multiple targets from file
```bash
python xscanner.py -l targets.txt --threads 10 -o results.json
```

### With authentication cookies
```bash
python xscanner.py -u "https://yoursite.com" \
  -c "session=abc123" \
  -c "csrf_token=xyz"
```

### With custom headers
```bash
python xscanner.py -u "https://yoursite.com" \
  -H "Authorization: Bearer token123" \
  -H "X-Custom-Header: value"
```

### Stealth mode through Burp Suite proxy
```bash
python xscanner.py -u "https://yoursite.com" \
  --profile stealth \
  --proxy http://127.0.0.1:8080 \
  --rate-limit 2.0
```

### Blind XSS with local callback server
```bash
# Start built-in callback listener on :8765
python xscanner.py -u "https://yoursite.com" --start-blind-server

# Or use your own external callback server
python xscanner.py -u "https://yoursite.com" \
  --blind-callback "https://your.server.com/xss-callback"
```

### Print full finding details
```bash
python xscanner.py -u "https://yoursite.com" --details -v
```

### Skip crawling (test only URL params)
```bash
python xscanner.py -u "https://yoursite.com/page?id=1&name=test" --no-crawl
```

---

## Scan Profiles

| Profile  | Depth | Threads | Timeout | Payloads/ctx |
|----------|-------|---------|---------|--------------|
| fast     | 1     | 20      | 5s      | 10           |
| normal   | 2     | 10      | 10s     | 30           |
| deep     | 4     | 5       | 20s     | 80           |
| stealth  | 2     | 2       | 15s     | 25           |

---

## Detection Capabilities

### XSS Types
| Type      | Detection Method                              |
|-----------|-----------------------------------------------|
| Reflected | Payload in response + HTML position analysis  |
| Stored    | POST endpoint reflection + confidence scoring |
| DOM-based | Sink/source proximity mapping in JS           |
| Blind     | Callback beacon injection                     |

### Injection Contexts
`html` · `attribute` · `javascript` · `js_string` · `js_template`
`url` · `css` · `comment` · `script_src` · `unknown`

### WAF Detection & Bypass
Fingerprints: `Cloudflare · ModSecurity · Imperva · AWS WAF · Akamai ·
Sucuri · F5 BIG-IP · Barracuda · Wordfence`

Evasion techniques:
- Case shuffling
- HTML comment injection inside keywords
- Double URL encoding
- Null byte insertion
- Tab/newline whitespace substitution
- Unicode normalization
- Partial HTML entity encoding
- Tag self-close breaking
- Event handler obfuscation via string concatenation
- Leading slash insertion

---

## Payload Engine

Each context gets its own payload library, then:

1. **Base payloads** — 15–30 hand-crafted payloads per context
2. **Mutations** — quote swapping, case flipping, whitespace insertion,
   event handler substitution (×3 per base payload)
3. **Encoding variants** — HTML entity, HTML hex, URL encode, double URL,
   base64 eval, fromCharCode, unicode escape, hex escape
4. **Polyglots** — multi-context payloads that work in ambiguous positions
5. **AI suggestions** — Claude-generated context + WAF-specific payloads
6. **Blind XSS beacons** — fetch/XHR/beacon callback templates

---

## Report Format

`xscanner_report.json`:
```json
{
  "tool": "XScanner v2.0",
  "timestamp": "2025-03-18T10:00:00Z",
  "duration_sec": 12.4,
  "targets": ["https://yoursite.com"],
  "total_findings": 3,
  "severity_summary": { "High": 2, "Medium": 1, "Low": 0, "Info": 0 },
  "findings": [
    {
      "url": "https://yoursite.com/search",
      "param": "q",
      "xss_type": "reflected",
      "context": "html",
      "severity": "High",
      "confidence": "High",
      "payload": "<script>alert(1)</script>",
      "encoding_used": "none",
      "waf_bypassed": false,
      "verified": false,
      "evidence": "...surrounding HTML context..."
    }
  ]
}
```

---

## Running Tests

```bash
python -m pytest tests/ -v
# 27 passed in ~1.3s
```

---

## Improvements Over XSStrike

| Feature                        | XSStrike   | XScanner         |
|--------------------------------|------------|------------------|
| Async HTTP engine              | ✗ sync     | ✓ aiohttp        |
| Context-aware payloads         | ✓ basic    | ✓ 10 contexts    |
| Mutation engine                | ✓          | ✓ extended       |
| DOM analysis                   | ✓ basic    | ✓ sink+source    |
| WAF per-vendor bypass          | ✓ limited  | ✓ 9 WAFs mapped  |
| Blind XSS support              | ✗          | ✓ built-in       |
| Headless browser verification  | ✗          | ✓ Playwright     |
| AI payload suggestions         | ✗          | ✓ Claude API     |
| JSON structured reporting      | ✓          | ✓ enhanced       |
| Unit test suite                | ✗          | ✓ 27 tests       |
| Rate limiting                  | ✗          | ✓ configurable   |
| Proxy support                  | ✓          | ✓                |

---

## Legal Notice

This tool is provided for **authorized security testing only**.
Always obtain explicit written permission before testing any system.
The authors are not responsible for any misuse or damage.
