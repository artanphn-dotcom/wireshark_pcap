# Wireshark-py FortiGate IPsec Analyzer

Self-hosted lightweight web app to analyze `.pcap` / `.pcapng` captures for FortiGate IPsec VPN issues.

## Planned stack

- Backend: FastAPI + `pyshark` / `tshark`
- Frontend: React + Tailwind CSS dashboard
- Security: Ephemeral uploads with timed cleanup and optional report anonymization

## Project layout

```text
Wireshark-py/
  backend/
    app/
      __init__.py
      parser.py              # Step 2 packet intelligence engine
      main.py                # Step 3 FastAPI API (implemented)
      cleanup.py             # 10-minute auto-delete scheduler (implemented)
    tests/
      test_parser.py
    requirements.txt
  frontend/
    public/
    src/
      components/
      App.tsx
      main.tsx
  docs/
    architecture.md
```

## Runtime requirements

- Python 3.11+
- Wireshark `tshark` installed and available on PATH

## Run backend

```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
```

## Run frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend expects API at `http://localhost:8000`.

## API

- `GET /health`
- `POST /api/analyze`

`/api/analyze` form fields:

- `file`: `.pcap` or `.pcapng`
- `anonymize`: `true|false` (optional, default `false`)
- `psk`: pre-shared key string (optional)

Upload files are automatically deleted 10 minutes after analysis.
# wireshark_pcap
# wireshark_pcap
