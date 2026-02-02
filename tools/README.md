# Tools descriptions #

## DNS Query (dns_query_tool.py) ##

DNS Query is a tool module that performs DNS lookups and returns the output
as a JSON string. It can query common DNS record types and supports multiple
transport methods (plain DNS, DNS-over-HTTPS, DNS-over-TLS, DNS-over-QUIC). It
can also request DNSSEC data and report whether the upstream resolver marked
the response as DNSSEC-validated (via the AD flag).

### What it does ###

- Validates the requested record type against an allow-list
- Builds a DNS query (optionally with the DNSSEC DO bit enabled)
- Executes the query using the selected transport method
- Produces a JSON response containing:
  - `qname`, `qtype`
  - transport method and server/endpoint used
  - DNSSEC status (`yes`/`no`, based on the AD flag)
  - `success`, `error`
  - a flat `result` list (e.g., addresses returned in the answer section)

### How to configure ###

All configuration is done by editing constants at the top of
`dns_query_tool.py`:

- `DNS_SERVERS`: list of resolver IPs.
  - Plain DNS uses all entries (iterates until a successful response).
  - DoT/DoQ use the first entry.
  - DoH uses all entries as bootstrap IPs to avoid relying on system DNS for the
    DoH endpoint hostname.
- `TIMEOUT`: per-request timeout in seconds (applies to all transports).
- `ALLOWED_RECORD_TYPES`: allow-list of DNS record types accepted as input.
- `TRANSPORT_METHOD`: choose one of `plain`, `doh`, `dot`, `doq`.
- `ALLOW_FALLBACK_TO_PLAIN`: if enabled, DoH/DoT/DoQ failures fall back to plain
  DNS and the original errors are prepended to the final error message.
- `ENDPOINT_URL`: DoH endpoint URL (must support DNS-over-HTTPS).
- `DOT_SNI` / `DOQ_SNI`: TLS SNI / certificate hostname used for DoT/DoQ TLS
  validation.
- `USE_DNSSEC`: enables the DNSSEC DO bit in queries and reports validation
  status using the AD flag from the resolver. Use a trusted resolver when
  relying on AD.

### Requirements ###

Python packages to install:

- Base (required for all modes):
  - `dnspython`

- Additional (only if you enable DNS-over-QUIC / `doq`):
  - `aioquic` (recommended via dnspython extra)

Install commands:

```bash
python -m pip install dnspython
python -m pip install "dnspython[doq]"
