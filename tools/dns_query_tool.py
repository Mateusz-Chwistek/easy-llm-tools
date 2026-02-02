import json

import dns.flags
import dns.rcode
import dns.query
import dns.message
import dns.exception

from dns.message import QueryMessage
from typing import Final, Literal, Optional, Sequence

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
    "A", "AAAA", "CAA", "CNAME", "DNSKEY", "DS", "MX", "NAPTR", "NS",
    "NSEC", "NSEC3", "PTR", "RRSIG", "SOA", "SRV", "TLSA", "TXT"
}

# Selected transport method used to resolve queries.
TRANSPORT_METHOD: Final[Literal["doh", "dot", "doq", "plain"]] = "plain"

# If True, any failure in DoH/DoT/DoQ attempts will fall back to plain DNS and
# the original transport errors will be prepended to the plain error field.
ALLOW_FALLBACK_TO_PLAIN: Final[bool] = False

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
    response: Optional[Sequence[str]] = None
) -> str:
    """
    Build a JSON string describing a DNS query result.

    Args:
        qname: Queried domain name (e.g., "abc.def.pl") or an IP address.
        qtype: Queried record type (e.g., "A", "AAAA").
        dns_server: Address of the server used to answer the query (IP or endpoint).
        transport_method: Transport identifier ("plain", "doh", "dot", "doq").
        dnssec_ad: Whether the upstream resolver set the AD (Authenticated Data) flag.
        success: Whether the query completed successfully.
        error: Error message (empty string if none).
        response: Result items (e.g., IP addresses). If None, an empty list is used.

    Returns:
        A JSON string with the standardized structure.
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
        "result": result_list
    }

    return json.dumps(payload, ensure_ascii=False)

def _prepend_errors_to_plain_result(plain_result: str, prefix_errors: str) -> str:
    """
    Prepend an error string to the 'error' field of a JSON response string.

    Args:
        plain_result: JSON string returned by the plain DNS path.
        prefix_errors: Error message(s) to prepend (may contain newlines).

    Returns:
        Updated JSON string with the merged error field.
    """
    if not prefix_errors:
        return plain_result

    try:
        payload = json.loads(plain_result)
        existing_error = payload.get("error", "") or ""
        payload["error"] = (
            f"{prefix_errors}\n{existing_error}" if existing_error else prefix_errors
        )
        return json.dumps(payload, ensure_ascii=False)
    except Exception:
        return plain_result

def _fallback_to_plain_or_fail(
    query: QueryMessage,
    qname: str,
    qtype: str,
    transport_method: str,
    dns_server: str,
    errors: list[str]
) -> str:
    """
    Handle fallback-to-plain behavior.

    If ALLOW_FALLBACK_TO_PLAIN is True, plain DNS is attempted and transport errors
    are prepended to the plain DNS error field. Otherwise, a failure response is
    returned for the original transport.

    Args:
        query: Prepared DNS query message.
        qname: Queried domain name.
        qtype: Queried record type.
        transport_method: Original transport method ("doh", "dot", "doq").
        dns_server: Server/endpoint used by the original transport.
        errors: Collected error messages from the original transport attempt.

    Returns:
        JSON string response.
    """
    error_text = "\n".join(errors)

    if ALLOW_FALLBACK_TO_PLAIN:
        plain_result = _plain_query(query, qname, qtype)
        return _prepend_errors_to_plain_result(plain_result, error_text)

    return _build_response(
        qname=qname,
        qtype=qtype,
        dns_server=dns_server,
        transport_method=transport_method,
        success=False,
        error=error_text,
        response=None
    )

def _extract_answer_items(response: dns.message.Message) -> list[str]:
    """
    Convert DNS answer RRsets into a flat list of string items.

    Args:
        response: DNS response message.

    Returns:
        List of answer strings, e.g., IP addresses for A/AAAA.
    """
    return [rdata.to_text() for rrset in response.answer for rdata in rrset]


# -----------------------------------------------------------------------------
# Transport implementations (internal)
# -----------------------------------------------------------------------------

def _doh_query(query: QueryMessage, qname: str, qtype: str) -> str:
    """
    Perform a DNS-over-HTTPS query using ENDPOINT_URL.

    Args:
        query: Prepared DNS query message.
        qname: Queried domain name.
        qtype: Queried record type.

    Returns:
        JSON string response.
    """
    errors: list[str] = []

    try:
        response: Optional[dns.message.Message] = None
        for server_ip in DNS_SERVERS:
            try:
                response = dns.query.https(
                    query,
                    ENDPOINT_URL,
                    timeout=TIMEOUT,
                    bootstrap_address=server_ip
                )
                break
            except Exception as ex:
                errors.append(f"Bootstrap {server_ip} failed: {ex}")

        if response is None:
            return _fallback_to_plain_or_fail(
                query=query,
                qname=qname,
                qtype=qtype,
                transport_method="doh",
                dns_server=ENDPOINT_URL,
                errors=["Failed to resolve DNS server for DoH query."]
            )

        rrc = response.rcode()
        if rrc != dns.rcode.NOERROR:
            errors.append(
                f"Query to: {ENDPOINT_URL}, failed with error code: "
                f"{dns.rcode.to_text(rrc)}"
            )
            return _fallback_to_plain_or_fail(
                query=query,
                qname=qname,
                qtype=qtype,
                transport_method="doh",
                dns_server=ENDPOINT_URL,
                errors=errors
            )

        result_items = _extract_answer_items(response)

        return _build_response(
            qname=qname,
            qtype=qtype,
            dns_server=ENDPOINT_URL,
            transport_method="doh",
            dnssec_ad=bool(response.flags & dns.flags.AD),
            success=True,
            error="\n".join(errors),
            response=result_items
        )

    except dns.exception.Timeout:
        errors.append("Timeout reached")
    except Exception as ex:
        errors.append(f"Unknown exception: {ex}")

    return _fallback_to_plain_or_fail(
        query=query,
        qname=qname,
        qtype=qtype,
        transport_method="doh",
        dns_server=ENDPOINT_URL,
        errors=errors
    )

def _dot_query(query: QueryMessage, qname: str, qtype: str) -> str:
    """
    Perform a DNS-over-TLS query to the first DNS_SERVERS entry on TCP/853.

    Args:
        query: Prepared DNS query message.
        qname: Queried domain name.
        qtype: Queried record type.

    Returns:
        JSON string response.
    """
    errors: list[str] = []
    server_ip = DNS_SERVERS[0] if DNS_SERVERS else ""

    if not server_ip:
        errors.append("No DNS servers configured")
        return _fallback_to_plain_or_fail(
            query=query,
            qname=qname,
            qtype=qtype,
            transport_method="dot",
            dns_server=server_ip,
            errors=errors
        )

    try:
        response = dns.query.tls(
            query,
            server_ip,
            timeout=TIMEOUT,
            port=853,
            server_hostname=DOT_SNI
        )

        rrc = response.rcode()
        if rrc != dns.rcode.NOERROR:
            errors.append(
                f"Query to: {server_ip}, failed with error code: "
                f"{dns.rcode.to_text(rrc)}"
            )
            return _fallback_to_plain_or_fail(
                query=query,
                qname=qname,
                qtype=qtype,
                transport_method="dot",
                dns_server=server_ip,
                errors=errors
            )

        result_items = _extract_answer_items(response)

        return _build_response(
            qname=qname,
            qtype=qtype,
            dns_server=server_ip,
            transport_method="dot",
            dnssec_ad=bool(response.flags & dns.flags.AD),
            success=True,
            error="\n".join(errors),
            response=result_items
        )

    except dns.exception.Timeout:
        errors.append("Timeout reached")
    except Exception as ex:
        errors.append(f"Unknown exception: {ex}")

    return _fallback_to_plain_or_fail(
        query=query,
        qname=qname,
        qtype=qtype,
        transport_method="dot",
        dns_server=server_ip,
        errors=errors
    )

def _doq_query(query: QueryMessage, qname: str, qtype: str) -> str:
    """
    Perform a DNS-over-QUIC query to the first DNS_SERVERS entry on UDP/853.

    Args:
        query: Prepared DNS query message.
        qname: Queried domain name.
        qtype: Queried record type.

    Returns:
        JSON string response.
    """
    errors: list[str] = []
    server_ip = DNS_SERVERS[0] if DNS_SERVERS else ""

    if not server_ip:
        errors.append("No DNS servers configured")
        return _fallback_to_plain_or_fail(
            query=query,
            qname=qname,
            qtype=qtype,
            transport_method="doq",
            dns_server=server_ip,
            errors=errors
        )

    try:
        response = dns.query.quic(
            query,
            server_ip,
            timeout=TIMEOUT,
            port=853,
            hostname=DOQ_SNI
        )

        rrc = response.rcode()
        if rrc != dns.rcode.NOERROR:
            errors.append(
                f"Query to: {server_ip}, failed with error code: "
                f"{dns.rcode.to_text(rrc)}"
            )
            return _fallback_to_plain_or_fail(
                query=query,
                qname=qname,
                qtype=qtype,
                transport_method="doq",
                dns_server=server_ip,
                errors=errors
            )

        result_items = _extract_answer_items(response)

        return _build_response(
            qname=qname,
            qtype=qtype,
            dns_server=server_ip,
            transport_method="doq",
            dnssec_ad=bool(response.flags & dns.flags.AD),
            success=True,
            error="\n".join(errors),
            response=result_items
        )

    except dns.exception.Timeout:
        errors.append("Timeout reached")
    except Exception as ex:
        errors.append(f"Unknown exception: {ex}")

    return _fallback_to_plain_or_fail(
        query=query,
        qname=qname,
        qtype=qtype,
        transport_method="doq",
        dns_server=server_ip,
        errors=errors
    )


def _plain_query(query: QueryMessage, qname: str, qtype: str) -> str:
    """
    Perform a plain DNS query (UDP with TCP fallback) to configured DNS_SERVERS.

    Args:
        query: Prepared DNS query message.
        qname: Queried domain name.
        qtype: Queried record type.

    Returns:
        JSON string response.
    """
    errors: list[str] = []

    for server_ip in DNS_SERVERS:
        try:
            response, _ = dns.query.udp_with_fallback(
                query,
                server_ip,
                timeout=TIMEOUT,
                port=53
            )

            rrc = response.rcode()
            if rrc != dns.rcode.NOERROR:
                errors.append(
                    f"Query to: {server_ip}, failed with error code: "
                    f"{dns.rcode.to_text(rrc)}"
                )
                continue

            result_items = _extract_answer_items(response)

            return _build_response(
                qname=qname,
                qtype=qtype,
                dns_server=server_ip,
                transport_method="plain",
                dnssec_ad=bool(response.flags & dns.flags.AD),
                success=True,
                error="\n".join(errors),
                response=result_items
            )

        except dns.exception.Timeout:
            errors.append("Timeout reached")
        except Exception as ex:
            errors.append(f"Unknown exception: {ex}")

    return _build_response(
        qname=qname,
        qtype=qtype,
        transport_method="plain",
        success=False,
        error="\n".join(errors),
        response=None
    )


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

def tool_run(qname: str, qtype: str) -> str:
    """
    Validate input, build a DNS query message, execute a query using TRANSPORT_METHOD,
    and return a JSON response string.

    Args:
        qname: Domain name to resolve.
        qtype: DNS record type (case-insensitive, validated against ALLOWED_RECORD_TYPES).

    Returns:
        JSON string with fields:
            - qname, qtype, dns_server, transportMethod, dnssec, success, error, result
    """
    try:
        if not isinstance(qname, str):
            return _build_response(
                success=False,
                error="Qname must be a non-empty string",
                response=None
            )

        if not isinstance(qtype, str):
            return _build_response(
                qname=qname,
                success=False,
                error="Qtype must be a non-empty string",
                response=None
            )

        qname = qname.strip()
        qtype = qtype.strip().upper()

        if not qname:
            return _build_response(
                qname=qname,
                qtype=qtype,
                success=False,
                error="Qname must be a non-empty string",
                response=None
            )

        if not qtype:
            return _build_response(
                qname=qname,
                qtype=qtype,
                success=False,
                error="Qtype must be a non-empty string",
                response=None
            )

        if qtype not in ALLOWED_RECORD_TYPES:
            allowed = ", ".join(sorted(ALLOWED_RECORD_TYPES))
            return _build_response(
                qname=qname,
                qtype=qtype,
                success=False,
                error=f"Incorrect qtype {qtype}. Qtype must be one of {allowed}",
                response=None
            )

        query: QueryMessage = dns.message.make_query(
            qname,
            qtype,
            want_dnssec=USE_DNSSEC
        )

        if TRANSPORT_METHOD == "plain":
            return _plain_query(query, qname, qtype)
        elif TRANSPORT_METHOD == "doh":
            return _doh_query(query, qname, qtype)
        elif TRANSPORT_METHOD == "dot":
            return _dot_query(query, qname, qtype)
        elif TRANSPORT_METHOD == "doq":
            return _doq_query(query, qname, qtype)

        return _build_response(
            qname=qname,
            qtype=qtype,
            success=False,
            error=f"Unknown transport method: {TRANSPORT_METHOD}",
            response=None
        )

    except Exception as ex:
        return _build_response(
            qname=qname if isinstance(qname, str) else "Unknown",
            qtype=qtype if isinstance(qtype, str) else "Unknown",
            success=False,
            error=f"Unknown exception occurred: {ex}",
            response=None
        )

TOOL_DEFINITION = json.dumps(
    {
        "type": "function",
        "function": {
            "name": "dns_query",
            "description": (
                "Resolve DNS records for a given qname (domain or IP for PTR) and qtype.\n\n"
                "Output: a JSON string with fields:\n"
                "- qname: queried name (domain or IP)\n"
                "- qtype: record type used (uppercase)\n"
                "- dns_server: upstream server IP (plain/dot/doq) or DoH endpoint URL\n"
                "- transportMethod: one of 'plain', 'doh', 'dot', 'doq'\n"
                "- dnssec: 'yes' if AD flag was set by resolver, otherwise 'no'\n"
                "- success: boolean, True when query succeeded\n"
                "- error: diagnostic messages (may be non-empty even when success=true). "
                "Examples: earlier upstream attempts failed, timeouts on some servers, "
                "or partial transport errors before a successful retry."
                "Diagnostics are concatenated with a newline separator (one issue per line, in chronological order). "
                "This can include multiple upstream attempts and/or fallback errors.\n"
                "- result: list of answer items as strings (e.g., IPs for A/AAAA)\n"
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
    ensure_ascii=False
)
