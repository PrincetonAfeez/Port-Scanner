# portsleuth Schema Folder

This folder contains lightweight JSON Schema contracts for the `portsleuth` CLI.
The schemas are intentionally documentation-first and dependency-free for the
application itself. They can be used by tests, review scripts, portfolio audits,
or external tooling without changing the scanner runtime.

## Files

| File | Purpose |
| --- | --- |
| `schema-index.json` | Manifest of every schema in this folder. |
| `common-defs.schema.json` | Shared definitions for ports, states, scan options, probe results, and targets. |
| `scan-report.schema.json` | JSON emitted by `portsleuth scan --format json` and saved scan reports. |
| `port-result.schema.json` | A single scan result row from a report. |
| `http-probe-result.schema.json` | One HTTP probe object. |
| `http-probe-output.schema.json` | JSON array emitted by `portsleuth probe http --format json`. |
| `tls-probe-result.schema.json` | One TLS probe object. |
| `tls-probe-output.schema.json` | JSON array emitted by `portsleuth probe tls --format json`. |
| `banner-probe-output.schema.json` | JSON array emitted by `portsleuth probe banner --format json`. |
| `discovery-output.schema.json` | JSON array emitted by `portsleuth discover --format json`. |
| `audit-record.schema.json` | One line/object from `.portsleuth/audit.jsonl`. |
| `doctor-report.schema.json` | JSON emitted by `portsleuth doctor --format json`. |
| `benchmark-output.schema.json` | JSON array emitted by `portsleuth benchmark --format json`. |
| `config-file.schema.json` | Parsed `scan.toml` / `PORTSLEUTH_CONFIG` data. |
| `config-output.schema.json` | JSON emitted by `portsleuth config --format json`. |
| `authorization-summary.schema.json` | Standalone authorization summary object. |

## Validation Notes

- These files use JSON Schema Draft 2020-12.
- The application itself stays stdlib-only; installing a validator is optional.
- `audit-record.schema.json` validates **one JSONL line at a time**, not the whole
  `.jsonl` file as a single JSON array.
- `config-file.schema.json` validates the TOML file **after parsing** it into a
  JSON-like object. JSON Schema does not validate TOML syntax directly.
- The output schemas set `additionalProperties: false` to catch contract drift
  early during portfolio or test review.

## Example validator usage

```powershell
python -m pip install jsonschema
jsonschema -i Schema/examples/scan-report.example.json Schema/scan-report.schema.json
jsonschema -i Schema/examples/audit-record.example.json Schema/audit-record.schema.json
```

For a generated scan report:

```powershell
portsleuth scan 127.0.0.1 --ports 9089-9091 --format json --output scan-report.json
jsonschema -i scan-report.json Schema/scan-report.schema.json
```
