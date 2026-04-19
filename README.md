Dinahosting DNS for [`libdns`](https://github.com/libdns/libdns)
=======================

[![Go Reference](https://pkg.go.dev/badge/test.svg)](https://pkg.go.dev/github.com/libdns/dinahosting)

This package implements the [libdns interfaces](https://github.com/libdns/libdns) for the [Dinahosting API](https://es.dinahosting.com/api), allowing you to manage DNS records for your domains.

Compatible with `libdns` v1.x (the provider returns the RR-type-specific structs defined by `libdns`, such as `libdns.Address`, `libdns.TXT` and `libdns.CNAME`).

## Supported record types

This package was primarily written to be used as a [Caddy](https://github.com/caddyserver/caddy) plugin for solving ACME challenges and adding [dynamic DNS](https://github.com/mholt/caddy-dynamicdns) capabilities. The following record types are supported for writes (`AppendRecords`, `SetRecords`, `DeleteRecords`):

- `A`
- `AAAA`
- `TXT`
- `CNAME`

`GetRecords` also returns any other record types present in the zone (MX, SRV, URL, FRAME, SPF, ANAME, ...) as opaque `libdns.RR` values so callers can still enumerate them.

## Authenticating

Dinahosting does not provide API keys, so you need to use the username and password of your panel account.

## Reliability in production

The Dinahosting API is noticeably slow — a single zone-modifying request can take 10–30 seconds to return — and occasional upstream failures (HTTP 5xx, TCP resets, DNS hiccups) can surface as transient errors. To make the provider safe for automated flows such as ACME renewals, the provider:

- Uses a per-request HTTP timeout of 45 seconds by default.
- Retries up to 3 times with exponential backoff (1s, 2s, 4s) on transport-level errors (`connection refused`, `EOF`, timeouts…) and on HTTP 5xx responses.
- Does **not** retry on HTTP 200 responses that carry a business-logic error (Dinahosting's `responseCode` field): those errors are deterministic and retrying would only amplify load.
- Respects the caller's `context.Context` — if the context is cancelled during a backoff sleep, the call returns immediately with `ctx.Err()`.

Callers that need a custom transport (proxy, custom TLS, their own retry layer, tracing, etc.) can inject their own `http.Client`:

```go
p := &dinahosting.Provider{
    Username:   "YOUR_USERNAME",
    Password:   "YOUR_PASSWORD",
    HTTPClient: myCustomClient, // optional
}
```

## Testing

The test suite has two parts:

- **Unit tests** for the HTTP retry logic, which run without credentials against an in-process `httptest` server.
- **Integration tests** that talk to the real Dinahosting API. They create and delete fixture records on a zone you own, and clean up after themselves.

To enable the integration tests edit the constants at the top of `provider_test.go`:

```go
const (
    username = "YOUR_USERNAME"
    password = "YOUR_PASSWORD"
    zone     = "example.com"
)
```

Then run:

```
go test -v ./...
```

The integration tests skip themselves automatically when `password` is left at its default placeholder, so the suite is safe to run in CI without credentials. Because each API call takes several seconds, a full live run currently takes ~6 minutes.

## Example usage

```go
package main

import (
    "context"

    "github.com/libdns/libdns"
    "github.com/plorenzo/libdns-dinahosting"
)

func main() {
    p := &dinahosting.Provider{
        Username: "YOUR_USERNAME",
        Password: "YOUR_PASSWORD",
    }

    _, err := p.AppendRecords(context.Background(), "example.org.", []libdns.Record{
        libdns.TXT{
            Name: "_acme-challenge",
            Text: "123456",
        },
    })
    if err != nil {
        panic(err)
    }
}
```
