# kescape-be

A small Go HTTP service that triggers [Kubescape](https://kubescape.io/) cluster scans
across a cluster boundary.

You run it next to a **writable** cluster (the *runner*, e.g. a local kind cluster or a
management cluster). It creates a Kubernetes `Job` there. That Job mounts a **read-only**
kubeconfig for a **target** cluster (e.g. a customer/production cluster), runs the
Kubescape CLI against it, and prints the JSON report. The service reads the report from
the Job's pod log and serves it over HTTP.

The target cluster is never written to. The only contact is a read-only API scan.

```
        +------------------------------+          read-only API calls
        |  runner cluster (writable)   |  -------------------------------->  +-----------------------+
        |                              |                                     |  target cluster       |
        |  Job: scanner                |                                     |  (read-only identity) |
        |   - KUBECONFIG=/target/...   |                                     +-----------------------+
        |   - kubescape scan framework |
        |     --format json            |
        +------------------------------+
                    ^
                    | creates Secret + Job, reads pod logs
                    |
        +------------------------------+
        |  kescape-be (this service)   |
        |  POST /api/scans             |
        |  GET  /api/scans/{id}/results|
        +------------------------------+
```

## Contents

- [Features](#features)
- [Requirements](#requirements)
- [Build](#build)
- [Configuration](#configuration)
- [Prepare target kubeconfigs](#prepare-target-kubeconfigs)
- [Run](#run)
- [Web UI](#web-ui)
- [API reference](#api-reference)
- [Sample run](#sample-run)
- [Sample output](#sample-output)
- [How it works](#how-it-works)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Development](#development)
- [Project layout](#project-layout)

## Features

- Discovers target clusters from a directory of kubeconfig files (one drop-down entry per
  context).
- Triggers scans as native Kubernetes Jobs in a runner cluster.
- Keeps the **full** Kubescape JSON report and serves it, not just a summary.
- Simple embedded web UI with a cluster drop-down and a results link.
- No database, no agents, no storage add-on: state lives in memory and in the runner
  cluster.
- Read-only by construction: the target kubeconfig is mounted read-only into the Job and
  nothing is deployed to the target cluster.

## Requirements

- Go 1.24+ to build (developed with 1.26).
- `kubectl`-style access to a **runner** cluster where you are allowed to create `Secret`
  and `Job` objects (the `kubescape` namespace by default).
- A scanner image that contains the `kubescape` CLI. The stock
  `quay.io/kubescape/kubescape` image is distroless and ships only the server binary, so it
  cannot run a one-shot scan. Build/load a CLI image (for example
  `kubescape-scanner:local`) and make it pullable by the runner cluster.
- Kubescape releases its rego policy cache over the network. If the runner cannot reach
  GitHub, bake the cache into the image and set `KS_CACHE_DIR`.

## Build

```powershell
git clone https://github.com/loegaire/kescape-be.git
cd kescape-be
go build -o kubescape-backend.exe .
```

Or run straight from source:

```powershell
go run .
```

## Configuration

All options are command-line flags.

| Flag | Default | Description |
|---|---|---|
| `-targets-dir` | `./kubeconfigs` | Directory scanned for kubeconfig files. Each context becomes a target. |
| `-runner-kubeconfig` | `$KUBECONFIG` / `~/.kube/config` | Kubeconfig for the cluster that runs the Jobs. |
| `-runner-context` | current context | Context to use inside the runner kubeconfig. |
| `-namespace` | `kubescape` | Namespace for the scan Secrets and Jobs. |
| `-scanner-image` | `kubescape-scanner:local` | Image used by the scan Job. Must contain the `kubescape` CLI. |
| `-framework` | `NSA` | Default framework when a request omits `framework`. |
| `-job-template` | built-in | Optional path to override `deploy/scanjob-template.yaml`. |
| `-addr` | `:8080` | HTTP listen address. If the port is busy it tries the next free port and logs the one it used. |

Target cluster files are matched by name: a file is treated as a kubeconfig when its name
contains `kubeconfig` or it ends in `.yaml`, `.yml`, or `.conf`. Unreadable files are
skipped so one bad config cannot break the drop-down.

## Prepare target kubeconfigs

Create one file per target cluster, using an identity with **read-only** permissions:

```powershell
New-Item -ItemType Directory -Force .\kubeconfigs | Out-Null
Copy-Item .\path\to\prod-cluster-a.kubeconfig .\kubeconfigs\prod-cluster-a.kubeconfig
```

A multi-context kubeconfig produces one entry per context. The service stores, for each
context, a minimal kubeconfig containing only that context and the cluster/auth objects it
references.

## Run

```powershell
.\kubescape-backend.exe `
  -targets-dir .\kubeconfigs `
  -runner-kubeconfig C:\path\to\runner-kubeconfig.yaml `
  -namespace kubescape
```

Example startup output:

```
2026/10/27 04:01:06 found 1 target cluster(s) in "C:\work\kubescape-backend\kubeconfigs"
2026/10/27 04:01:06   - prod-cluster-a (https://api.example.com) from prod-cluster-a.kubeconfig
2026/10/27 04:01:06 listening on http://[::]:8085
2026/10/27 04:01:06 open http://localhost:8085 in a browser
```

Stop with `Ctrl+C`.

## Web UI

Open the printed URL (for example `http://localhost:8085`), choose a cluster, and click
**Start scan**. The page polls the status and, when the scan finishes, shows a
**View full results** link.

## API reference

Base URL: `http://localhost:<port>` (default `8080`, may fall back to the next free port).

All request and response bodies are JSON unless noted.

### `GET /api/clusters`

Lists the scannable target clusters for the drop-down. Kubeconfig bytes are never included.

```json
[
  {
    "name": "prod-cluster-a",
    "server": "https://api.example.com",
    "source": "prod-cluster-a.kubeconfig"
  }
]
```

### `POST /api/scans`

Creates the target `Secret` and the scan `Job` in the runner cluster and returns
immediately with HTTP `202 Accepted`.

Request:

```json
{ "cluster": "prod-cluster-a", "framework": "NSA" }
```

`framework` is optional; it defaults to `-framework`.

Response `202`:

```json
{
  "id": "0df030e0",
  "cluster": "prod-cluster-a",
  "framework": "NSA",
  "namespace": "kubescape",
  "jobName": "xscan-0df030e0",
  "secretName": "xscan-0df030e0-target",
  "startedAt": "2026-10-23T04:04:09.7006665Z",
  "status": "Pending"
}
```

Errors:

| Status | When |
|---|---|
| `400` | Malformed JSON body, or `cluster` is not a known target. |
| `500` | The runner cluster rejected the Secret or Job. |

### `GET /api/scans/{id}`

Returns the scan with its current status. Use this to poll.

```json
{
  "id": "0df030e0",
  "cluster": "prod-cluster-a",
  "framework": "NSA",
  "namespace": "kubescape",
  "jobName": "xscan-0df030e0",
  "secretName": "xscan-0df030e0-target",
  "startedAt": "2026-10-23T04:04:09.7006665Z",
  "status": "Succeeded",
  "report": {
    "clusterName": "prod-cluster-a",
    "score": 32.7042,
    "controls": 26,
    "failed": 16
  }
}
```

`status` is one of `Pending`, `Running`, `Succeeded`, `Failed`, `Unknown`
(`Unknown` means the Job no longer exists, e.g. after garbage collection).

Returns `404` for an unknown id.

### `GET /api/scans/{id}/results`

Returns the scan metadata plus the **full** Kubescape JSON report. Alias:
`GET /api/results/{id}`.

```json
{
  "scan": {
    "id": "0df030e0",
    "cluster": "prod-cluster-a",
    "status": "Succeeded",
    "report": { "clusterName": "prod-cluster-a", "score": 32.7042, "controls": 26, "failed": 16 }
  },
  "results": {
    "clusterName": "prod-cluster-a",
    "summaryDetails": {
      "score": 32.7042,
      "controls": {
        "C-0001": { "name": "...", "status": "failed" },
        "C-0002": { "name": "...", "status": "passed" }
      }
    }
  }
}
```

The `results` object is the report exactly as produced by `kubescape --format json`; it can
be several megabytes.

| Status | When |
|---|---|
| `200` | Report available. |
| `404` | Unknown scan id, or a finished scan produced no readable report. |
| `409` | Scan is still `Pending` or `Running`. |

### `GET /api/scans`

Returns all scans known to the process, newest first.

### `DELETE /api/scans/{id}`

Deletes the scan's `Job` and `Secret` from the runner cluster and forgets the scan.
Returns `204 No Content`, or `404` if unknown.

### `GET /healthz`

```json
{ "status": "ok" }
```

## Sample run

Two terminals. The first runs the service; the second drives it.

**Terminal 1**

```powershell
cd C:\work\kubescape-backend
.\kubescape-backend.exe `
  -targets-dir .\kubeconfigs `
  -runner-kubeconfig C:\work\kubescape-lab\cluster\kind-kubeconfig.yaml `
  -namespace kubescape
```

**Terminal 2**

```powershell
# 1. list available clusters
Invoke-RestMethod http://localhost:8085/api/clusters | Format-Table name, server

# 2. trigger a scan
$scan = Invoke-RestMethod http://localhost:8085/api/scans -Method Post `
  -ContentType application/json `
  -Body '{"cluster":"prod-cluster-a","framework":"NSA"}'
$scan.id

# 3. poll until it finishes
do {
  Start-Sleep 3
  $s = Invoke-RestMethod "http://localhost:8085/api/scans/$($scan.id)"
} while ($s.status -in 'Pending', 'Running')
$s | ConvertTo-Json -Depth 5

# 4. fetch and save the full report
$r = Invoke-RestMethod "http://localhost:8085/api/scans/$($scan.id)/results"
$r.results | ConvertTo-Json -Depth 100 | Set-Content .\scan-results.json
```

Equivalent with `curl` (bash):

```bash
curl -s localhost:8085/api/clusters
curl -s -X POST localhost:8085/api/scans \
  -H 'Content-Type: application/json' \
  -d '{"cluster":"prod-cluster-a","framework":"NSA"}'
curl -s localhost:8085/api/scans/0df030e0
curl -s localhost:8085/api/scans/0df030e0/results -o scan-results.json
```

## Sample output

Startup:

```
2026/10/27 04:01:06 found 1 target cluster(s) in "C:\work\kubescape-backend\kubeconfigs"
2026/10/27 04:01:06   - prod-cluster-a (https://api.example.com) from prod-cluster-a.kubeconfig
2026/10/27 04:01:06 listening on http://[::]:8085
2026/10/27 04:01:06 open http://localhost:8085 in a browser
```

Scan accepted (`POST /api/scans`, HTTP 202):

```json
{
  "id": "0df030e0",
  "cluster": "prod-cluster-a",
  "framework": "NSA",
  "namespace": "kubescape",
  "jobName": "xscan-0df030e0",
  "secretName": "xscan-0df030e0-target",
  "startedAt": "2026-10-23T04:04:09.7006665Z",
  "status": "Pending"
}
```

Finished status (`GET /api/scans/0df030e0`):

```json
{
  "id": "0df030e0",
  "cluster": "prod-cluster-a",
  "framework": "NSA",
  "namespace": "kubescape",
  "jobName": "xscan-0df030e0",
  "secretName": "xscan-0df030e0-target",
  "startedAt": "2026-10-23T04:04:09.7006665Z",
  "status": "Succeeded",
  "report": {
    "clusterName": "prod-cluster-a",
    "score": 32.7042,
    "controls": 26,
    "failed": 16
  }
}
```

Results (`GET /api/scans/0df030e0/results`, truncated):

```json
{
  "scan": {
    "id": "0df030e0",
    "cluster": "prod-cluster-a",
    "status": "Succeeded",
    "report": { "clusterName": "prod-cluster-a", "score": 32.7042, "controls": 26, "failed": 16 }
  },
  "results": {
    "clusterName": "prod-cluster-a",
    "summaryDetails": {
      "score": 32.7042,
      "controls": {
        "C-0001": { "name": "API server insecure port is enabled", "status": "passed" },
        "C-0002": { "name": "Applications credentials in configuration files", "status": "failed" }
      }
    },
    "resources": [ "..." ]
  }
}
```

In the reference run the full `results` document was about **2.4 MB** and reported a
compliance score of **32.70** over **26** controls, with **16** failing.

## How it works

1. On start the service reads `-targets-dir`, parses each kubeconfig, and builds a
   minimal per-context kubeconfig for every target.
2. `POST /api/scans` picks the target, generates an 8-character id, and:
   - creates `Secret xscan-<id>-target` holding the target kubeconfig under
     `kubeconfig.yaml`;
   - renders `deploy/scanjob-template.yaml` and creates `Job xscan-<id>`.
3. The Job mounts the Secret read-only at `/target`, sets
   `KUBECONFIG=/target/kubeconfig.yaml`, and runs:

   ```sh
   kubescape scan framework "$SCAN_FRAMEWORK" \
     --format json --output /tmp/report.json --scan-timeout 20m --logger error
   echo "SCAN_EXIT=$?"
   cat /tmp/report.json
   ```

4. `GET /api/scans/{id}` reads the Job status. When the Job is finished, the service reads
   the pod log, slices out the JSON object, keeps the raw bytes, and parses a small summary.
5. `GET /api/scans/{id}/results` returns the kept raw report inside an envelope.

The built-in template is embedded in the binary (`deploy/scanjob-template.yaml`) and can be
overridden with `-job-template`.

## Security notes

- Use a **read-only** kubeconfig for targets. Nothing is deployed to the target cluster.
- Never commit kubeconfigs or tokens. `.gitignore` excludes `*.kubeconfig`, `kubeconfigs/`,
  and anything containing `kubeconfig` in its name.
- The target kubeconfig is stored in a Kubernetes `Secret` in the runner cluster and mounted
  with mode `0400`. Delete the scan (`DELETE /api/scans/{id}`) or let the Job TTL
  (`ttlSecondsAfterFinished: 3600`) clean it up.
- The service has no authentication. Bind it to `127.0.0.1` (`-addr 127.0.0.1:8085`) or put
  it behind an authenticating proxy.
- Scan results can contain sensitive cluster information; treat `scan-results.json`
  accordingly.

## Limitations

- The runner must be able to pull the scanner image and reach the target API server.
- Reports are read from the pod log, so a report larger than the container log limit would
  be truncated. Observed reports are a few megabytes.
- State is in memory: restarting the service loses the scan list (the Jobs remain).
- `Failed` scans that logged no JSON return `404` from the results endpoint.
- The service scans one target per request; it does not schedule recurring scans. Use the
  Kubescape operator CronJob for that.

## Development

```powershell
go test ./...      # 34 tests
go vet ./...
go build -o kubescape-backend.exe .
```

Tests cover cluster discovery and per-context isolation, Job rendering, scan creation and
cleanup, status transitions, report parsing, results serving, and the HTTP handlers.

## Project layout

```
.
├── main.go                      # flags, wiring, HTTP server, port fallback
├── clusters.go                  # target discovery from kubeconfigs
├── render.go                    # Job template rendering
├── scan.go                      # Secret/Job creation, status, report handling
├── api.go                       # HTTP routes and handlers
├── ui.go                        # embedded web page
├── *_test.go                    # unit tests
├── deploy/
│   └── scanjob-template.yaml    # scan Job template (embedded)
├── go.mod
└── go.sum
```
