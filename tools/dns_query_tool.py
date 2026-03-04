import json
import dns.message
from helpers import (
    QueryResult,
    doh_query,
    doq_query,
    dot_query,
    plain_query,
)
from ipaddress import ip_address
from dns.message import QueryMessage
from typing import Optional, Sequence, Final, Literal

# -----------------------------------------------------------------------------
# User configuration
# -----------------------------------------------------------------------------

# List of upstream recursive DNS resolver IPs used for plain DNS and as
# bootstrap addresses for DoH. The first entry is used for DoT/DoQ.
DNS_SERVERS: Final[list[str]] = ["1.1.1.1"]

# Per-request timeout in seconds for all transports (DoH/DoT/DoQ/plain).
TIMEOUT: Final[float] = 5.0

# Allowed DNS record types for query validation (in upper case).
ALLOWED_RECORD_TYPES: Final[set[str]] = {
    "A",
    "AAAA",
    "CAA",
    "CNAME",
    "DNSKEY",
    "DS",
    "MX",
    "NAPTR",
    "NS",
    "NSEC",
    "NSEC3",
    "PTR",
    "RRSIG",
    "SOA",
    "SRV",
    "TLSA",
    "TXT",
}

# Selected transport method used to resolve queries.
TRANSPORT_METHOD: Final[Literal["doh", "dot", "doq", "plain"]] = "plain"

# DoH endpoint URL for the configured resolver (must support DNS-over-HTTPS).
ENDPOINT_URL: Final[str] = "https://cloudflare-dns.com/dns-query"

# DoT TLS SNI / certificate hostname (used for TLS certificate validation).
DOT_SNI: Final[str] = "cloudflare-dns.com"

# DoQ TLS SNI / certificate hostname (used for TLS certificate validation).
DOQ_SNI: Final[str] = "cloudflare-dns.com"

# If True, sets the DO bit (DNSSEC OK) in queries to request DNSSEC records and
# expects DNSSEC validation to be reflected by the AD flag (trusted resolver)."""
USE_DNSSEC: Final[bool] = False


# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------


def _build_response(
    *,
    qname: str = "Unknown",
    qtype: str = "Unknown",
    dns_server: str = "Unknown",
    transport_method: str = "Unknown",
    dnssec_ad: bool = False,
    success: bool = False,
    error: str = "",
    response: Optional[Sequence[str]] = None,
) -> str:
    """
    Build the public JSON response returned by the tool.

    :param qname: Queried domain name or input name provided by the caller.
    :type qname: str
    :param qtype: DNS record type used for the query.
    :type qtype: str
    :param dns_server: Resolver IP or endpoint URL used to answer the query.
    :type dns_server: str
    :param transport_method: Transport identifier used by the query.
    :type transport_method: str
    :param dnssec_ad: True when the resolver returned the AD flag.
    :type dnssec_ad: bool
    :param success: True when the query completed successfully.
    :type success: bool
    :param error: Diagnostic text returned to the caller.
    :type error: str
    :param response: Query result items serialized into the response payload.
    :type response: Optional[Sequence[str]]
    :return: JSON string with the standardized tool response structure.
    :rtype: str
    """

    result_list: list[str] = list(response) if response is not None else []

    payload: dict[str, object] = {
        "qname": qname,
        "qtype": qtype,
        "dns_server": dns_server,
        "transportMethod": transport_method,
        "dnssec": "yes" if dnssec_ad else "no",
        "success": success,
        "error": error,
        "result": result_list,
    }

    return json.dumps(payload, ensure_ascii=False)


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def tool_run(qname: str, qtype: str) -> str:
    """
    Validate tool input, execute a DNS query, and return a JSON response string.

    For PTR queries, if `qname` is an IPv4 or IPv6 address literal, it is
    automatically converted to its reverse DNS pointer form before the query
    is sent. Non-IP values are used as provided.

    :param qname: Domain name to query.
    :type qname: str
    :param qtype: DNS record type requested by the caller.
    :type qtype: str
    :return: JSON string describing the query result and diagnostics.
    :rtype: str
    """

    try:
        if not isinstance(qname, str):
            return _build_response(
                success=False, error="Qname must be a non-empty string", response=None
            )

        if not isinstance(qtype, str):
            return _build_response(
                qname=qname,
                success=False,
                error="Qtype must be a non-empty string",
                response=None,
            )

        qname = qname.strip()
        qname_len = len(qname)
        qname = qname[:-1] if qname_len > 0 and qname.endswith(".") else qname
        if qname_len < 1 or qname_len > 255:
            return _build_response(
                qname=qname,
                qtype=qtype,
                success=False,
                error="Qname must be a non-empty string with max length of 255",
                response=None,
            )

        original_qname = qname
        try:
            address = ip_address(qname)
            if address.version == 4 or address.version == 6:
                qname = address.reverse_pointer
        except ValueError:
            pass

        qtype = qtype.strip().upper()
        if not qtype:
            return _build_response(
                qname=original_qname,
                qtype=qtype,
                success=False,
                error="Qtype must be a non-empty string",
                response=None,
            )

        if qtype not in ALLOWED_RECORD_TYPES:
            allowed = ", ".join(sorted(ALLOWED_RECORD_TYPES))
            return _build_response(
                qname=original_qname,
                qtype=qtype,
                success=False,
                error=f"Incorrect qtype {qtype}. Qtype must be one of {allowed}",
                response=None,
            )

        if len(DNS_SERVERS) < 1:
            return _build_response(
                qname=original_qname,
                qtype=qtype,
                success=False,
                error="No DNS server configured",
                response=None,
            )

        query: QueryMessage = dns.message.make_query(
            qname, qtype, want_dnssec=USE_DNSSEC
        )

        if TRANSPORT_METHOD == "plain":
            query_result: QueryResult = plain_query(query, DNS_SERVERS, TIMEOUT)
            return _build_response(
                qname=original_qname,
                qtype=qtype,
                dns_server=(
                    query_result.used_endpoint
                    if query_result.used_endpoint is not None
                    else "Unknown"
                ),
                transport_method="plain",
                dnssec_ad=(
                    query_result.dnssec_ad
                    if query_result.dnssec_ad is not None
                    else False
                ),
                success=query_result.success,
                error="\n".join(
                    query_result.errors if query_result.errors is not None else []
                ),
                response=query_result.result,
            )
        elif TRANSPORT_METHOD == "doh":
            query_result: QueryResult = doh_query(
                query, DNS_SERVERS, ENDPOINT_URL, TIMEOUT
            )
            return _build_response(
                qname=original_qname,
                qtype=qtype,
                dns_server=(
                    query_result.used_endpoint
                    if query_result.used_endpoint is not None
                    else "Unknown"
                ),
                transport_method="doh",
                dnssec_ad=(
                    query_result.dnssec_ad
                    if query_result.dnssec_ad is not None
                    else False
                ),
                success=query_result.success,
                error="\n".join(
                    query_result.errors if query_result.errors is not None else []
                ),
                response=query_result.result,
            )
        elif TRANSPORT_METHOD == "dot":
            query_result: QueryResult = dot_query(
                query, DNS_SERVERS[0], DOT_SNI, TIMEOUT
            )
            return _build_response(
                qname=original_qname,
                qtype=qtype,
                dns_server=(
                    query_result.used_endpoint
                    if query_result.used_endpoint is not None
                    else "Unknown"
                ),
                transport_method="dot",
                dnssec_ad=(
                    query_result.dnssec_ad
                    if query_result.dnssec_ad is not None
                    else False
                ),
                success=query_result.success,
                error="\n".join(
                    query_result.errors if query_result.errors is not None else []
                ),
                response=query_result.result,
            )
        elif TRANSPORT_METHOD == "doq":
            query_result: QueryResult = doq_query(
                query, DNS_SERVERS[0], DOQ_SNI, TIMEOUT
            )
            return _build_response(
                qname=original_qname,
                qtype=qtype,
                dns_server=(
                    query_result.used_endpoint
                    if query_result.used_endpoint is not None
                    else "Unknown"
                ),
                transport_method="doq",
                dnssec_ad=(
                    query_result.dnssec_ad
                    if query_result.dnssec_ad is not None
                    else False
                ),
                success=query_result.success,
                error="\n".join(
                    query_result.errors if query_result.errors is not None else []
                ),
                response=query_result.result,
            )

        return _build_response(
            qname=original_qname,
            qtype=qtype,
            success=False,
            error=f"Unknown transport method: {TRANSPORT_METHOD}",
            response=None,
        )

    except Exception as ex:
        return _build_response(
            qname=qname if isinstance(qname, str) else "Unknown",
            qtype=qtype if isinstance(qtype, str) else "Unknown",
            success=False,
            error=f"Unknown exception occurred: {ex}",
            response=None,
        )


TOOL_DEFINITION = json.dumps(
    {
        "type": "function",
        "function": {
            "name": "dns_query",
            "description": (
                "Resolve DNS records for a given qname (domain or IP for PTR) and qtype.\n\n"
                "Output: a JSON string with fields:\n"
                "- qname: queried name. For PTR you can pass an IP address "
                "literal (e.g., '1.2.3.4' or '2001:4860:4860::8888') or a "
                "reverse name (e.g., '4.3.2.1.in-addr.arpa' or the "
                "corresponding '...ip6.arpa').\n"
                "- qtype: record type used (uppercase)\n"
                "- dns_server: upstream server IP (plain/dot/doq) or DoH endpoint URL\n"
                "- transportMethod: one of 'plain', 'doh', 'dot', 'doq'\n"
                "- dnssec: 'yes' if AD flag was set by resolver, otherwise 'no'\n"
                "- success: boolean, True when query succeeded\n"
                "- error: diagnostic messages. "
                "- result: list of answer items as strings (e.g., IPs for A/AAAA or domain names for PTR)\n"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "qname": {
                        "type": "string",
                        "description": "Domain name to query (e.g., 'example.com') or IP address for PTR.",
                        "minLength": 1,
                    },
                    "qtype": {
                        "type": "string",
                        "description": "DNS record type (case-insensitive).",
                        "enum": sorted(ALLOWED_RECORD_TYPES),
                    },
                },
                "required": ["qname", "qtype"],
                "additionalProperties": False,
            },
        },
    },
    ensure_ascii=False,
)
