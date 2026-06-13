# Demo Script

Run from the project root after `python -m pip install -e .`.

## 1. Platform check

```powershell
portsleuth doctor
portsleuth packet demo
portsleuth packet demo --protocol udp
```

## 2. TCP banner lab

Terminal 1:

```powershell
portsleuth lab serve-tcp --port 9090 --banner "portsleuth fixture"
```

Terminal 2:

```powershell
portsleuth scan 127.0.0.1 --ports 9089-9091 --probe
portsleuth probe banner 127.0.0.1 --port 9090
```

## 3. WSGI HTTP lab

Terminal 1:

```powershell
portsleuth lab serve-wsgi --port 8080
```

Terminal 2:

```powershell
portsleuth probe http 127.0.0.1 --port 8080 --show-preview
portsleuth scan 127.0.0.1 --ports 8080 --probe --format json --output scan-report.json
portsleuth report scan-report.json --format table
```

## 4. UDP lab (optional)

Terminal 1:

```powershell
portsleuth lab serve-udp --port 5353
```

Terminal 2:

```powershell
portsleuth packet demo --protocol icmp
```

## 5. Concurrency comparison

```powershell
portsleuth benchmark 127.0.0.1 --ports 1-100
```

## 6. Authorization demo

```powershell
portsleuth scan 192.168.1.1 --ports 80
portsleuth scan 192.168.1.1 --ports 80 --authorized --reason "owned lab router"
```

## Pass criteria

- Open fixture port reports `open` with banner or HTTP/TLS probe data.
- Adjacent closed port reports `closed`, `filtered`, or `unknown` (OS-dependent).
- Unauthorized non-local scan exits with code 3.
- `doctor` reports fixture port availability for 8080 and 9090.
