# gotinyirrdbcache

A Go implementation of [pytinyirrdbcache](https://github.com/ecix/pytinyirrdbcache) — a caching service for Internet Routing Registry Database (IRRD) data.

Fetches and caches IRRD data from multiple upstream WHOIS sources, providing a JSON HTTP API for fast lookups of AS macros, IPv4 routes, and IPv6 routes.

## Architecture

Two-process design:

- **`cmd/update`** — Background daemon that synchronises caches via NRTM telnet streams and full dump downloads. Saves state to disk and notifies the web server to reload.
- **`cmd/serve`** — HTTP server that loads cached state from disk and serves a JSON API.

## Supported Upstreams

RADB, RIPE, LEVEL3, ARIN, ALTDB (configurable via `config.json`)

## Build

```sh
go build -o bin/serve ./cmd/serve
go build -o bin/update ./cmd/update
```

## Usage

```sh
# Start the update daemon (fetches and maintains caches)
./bin/update -config config.json

# Start the HTTP server (serves cached data)
./bin/serve -config config.json
```

If no config file exists at the given path, defaults are used.

## Configuration

Create a `config.json` to override defaults:

```json
{
  "cache_data_directory": "data",
  "whois_update_interval": 60,
  "http_endpoint": "0.0.0.0:8087",
  "upstreams": {
    "RADB": {
      "name": "RADB",
      "dump_uri": "ftp://ftp.radb.net/radb/dbase/radb.db.gz",
      "serial_uri": "ftp://ftp.radb.net/radb/dbase/RADB.CURRENTSERIAL",
      "telnet_host": "whois.radb.net",
      "telnet_port": 43
    }
  }
}
```

## API Endpoints

All endpoints return JSON with `{"status": "...", "data": ...}`.

| Endpoint | Description |
|---|---|
| `GET /` | API documentation |
| `GET /cache/{cache}/macros/lookup/{key}` | Lookup macro members by name |
| `GET /cache/{cache}/macros/list` | List all macro names |
| `GET /cache/{cache}/prefixes/4/lookup/{key}` | Lookup IPv4 prefixes by ASN |
| `GET /cache/{cache}/prefixes/4/list` | List ASNs with IPv4 prefixes |
| `GET /cache/{cache}/prefixes/6/lookup/{key}` | Lookup IPv6 prefixes by ASN |
| `GET /cache/{cache}/prefixes/6/list` | List ASNs with IPv6 prefixes |
| `GET /cache/{cache}/status` | Cache serial and last update time |
| `GET /cache/{cache}/update` | Trigger cache reload from disk |
| `GET /cache/{cache}/dump` | Export entire cache as JSON |

`{cache}` can be any configured upstream name (e.g. `RADB`, `RIPE`) or `ALL` for a combined view.

## Testing

```sh
go test -v ./irrd/...
```
