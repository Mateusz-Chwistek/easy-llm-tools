import re
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

_QNAME_ALLOWED_RE = re.compile(r"^[A-Za-z0-9.-]+\.?$")


def _validate_qname(qname: str) -> Optional[str]:
    """
    Validate a DNS query name (qname) using common hostname/FQDN rules.

    Rules enforced:
    - non-empty string after stripping
    - total length <= 255 characters
    - allowed characters: A-Z, a-z, 0-9, '-', '.', optional trailing '.'
    - no empty labels (no '..')
    - each label length: 1..63
    - labels must not start or end with '-'

    Args:
        qname: Domain name to validate (already stripped).

    Returns:
        None if valid, otherwise an error message string.
    """
    if not qname:
        return "Qname must be a non-empty string"

    if len(qname) > 255:
        return "Qname must be shorter than 256 characters"

    if not _QNAME_ALLOWED_RE.fullmatch(qname):
        return "Qname contains illegal characters (allowed: A-Z, 0-9, '-', '.')"

    qname_normalized = qname[:-1] if qname.endswith(".") else qname

    if ".." in qname_normalized:
        return "Qname contains empty label ('..' is not allowed)"

    labels = qname_normalized.split(".")
    for label in labels:
        if not (1 <= len(label) <= 63):
            return "Each DNS label must be 1..63 characters long"
        if label.startswith("-") or label.endswith("-"):
            return "DNS labels must not start or end with '-'"

    return None

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

        qname_error = _validate_qname(qname)
        if qname_error is not None:
            return _build_response(
                qname=qname,
                qtype=qtype,
                success=False,
                error=qname_error,
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

# -----------------------------------------------------------------------------
# Tests (paste at the end of this file)
# -----------------------------------------------------------------------------

import os
import sys
try:
    import pytest
except ImportError:  # allows importing this module without pytest installed
    pytest = None  # type: ignore[assignment]


if pytest is not None:
    # Set DNS_TEST_SHOW=0 to disable prints (default: show).
    _SHOW_CASES = os.getenv("DNS_TEST_SHOW", "1").strip() not in ("0", "false", "False", "no", "NO")

    def _test_parse_json(result: str) -> dict[str, Any]:
        assert isinstance(result, str), "tool_run() must return a JSON string"
        payload = json.loads(result)
        assert isinstance(payload, dict), "JSON root must be an object"

        for key in ["qname", "qtype", "dns_server", "transportMethod", "dnssec", "success", "error", "result"]:
            assert key in payload, f"Missing key: {key}"

        assert isinstance(payload["result"], list), "result must be a list"
        assert isinstance(payload["success"], bool), "success must be bool"
        assert isinstance(payload["error"], str), "error must be string"
        assert payload["dnssec"] in ("yes", "no"), "dnssec must be 'yes' or 'no'"

        return payload

    def _pretty_print_case(title: str, qname: Any, qtype: Any, payload: dict[str, Any]) -> None:
        if not _SHOW_CASES:
            return
        line = "=" * 96
        print("\n" + line)
        print(f"CASE: {title}")
        print(f"QUESTION: qname={qname!r}, qtype={qtype!r}")
        print("ANSWER:")
        print(json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True))
        print(line)

    def _call_tool_run(title: str, qname: Any, qtype: Any) -> dict[str, Any]:
        result = tool_run(qname, qtype)
        payload = _test_parse_json(result)
        _pretty_print_case(title, qname, qtype, payload)
        return payload

    def _test_make_dns_response_with_answer(
        query: dns.message.Message,
        qname: str,
        rtype: str,
        answers: list[str],
        *,
        ad: bool
    ) -> dns.message.Message:
        resp = dns.message.make_response(query)
        rrset = dns.rrset.from_text(qname, 60, "IN", rtype, *answers)
        resp.answer.append(rrset)
        if ad:
            resp.flags |= dns.flags.AD
        return resp

    @pytest.fixture()
    def _this_module():
        # Reference to this very module (the file you're pasting into)
        return sys.modules[__name__]

    @pytest.fixture(autouse=True)
    def forbid_real_network_calls(monkeypatch: pytest.MonkeyPatch):
        # Fail fast if a test forgets to mock a DNS transport call.
        def _nope(*args, **kwargs):
            raise AssertionError("Unexpected network call (mock missing)")

        monkeypatch.setattr(dns.query, "udp_with_fallback", _nope, raising=True)
        monkeypatch.setattr(dns.query, "https", _nope, raising=True)
        monkeypatch.setattr(dns.query, "tls", _nope, raising=True)
        monkeypatch.setattr(dns.query, "quic", _nope, raising=True)

    # -------------------------------------------------------------------------
    # Input validation tests
    # -------------------------------------------------------------------------

    def test_qname_must_be_string():
        payload = _call_tool_run("qname must be string", None, "A")  # type: ignore[arg-type]
        assert payload["success"] is False
        assert payload["error"] == "Qname must be a non-empty string"
        assert payload["qname"] == "Unknown"

    def test_qtype_must_be_string():
        payload = _call_tool_run("qtype must be string", "example.com", None)  # type: ignore[arg-type]
        assert payload["success"] is False
        assert payload["error"] == "Qtype must be a non-empty string"
        assert payload["qname"] == "example.com"

    def test_qname_cannot_be_empty_after_strip():
        payload = _call_tool_run("qname empty after strip", "   ", "A")
        assert payload["success"] is False
        assert payload["error"] == "Qname must be a non-empty string"
        assert payload["qname"] == ""

    def test_qtype_cannot_be_empty_after_strip():
        payload = _call_tool_run("qtype empty after strip", "example.com", "   ")
        assert payload["success"] is False
        assert payload["error"] == "Qtype must be a non-empty string"
        assert payload["qtype"] == ""

    def test_qtype_must_be_allowed_and_make_query_not_called(monkeypatch: pytest.MonkeyPatch):
        def _boom(*args, **kwargs):
            raise AssertionError("make_query() should not be called for invalid qtype")

        monkeypatch.setattr(dns.message, "make_query", _boom, raising=True)

        payload = _call_tool_run("qtype invalid (make_query must not be called)", "example.com", "BADTYPE")
        assert payload["success"] is False
        assert payload["qtype"] == "BADTYPE"
        assert payload["error"].startswith("Incorrect qtype BADTYPE. Qtype must be one of ")

    def test_qtype_is_case_insensitive_and_stripped_plain_success(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "plain", raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1"], raising=False)
        monkeypatch.setattr(_this_module, "USE_DNSSEC", False, raising=False)

        def udp_with_fallback(query, server_ip, timeout, port):
            resp = _test_make_dns_response_with_answer(query, "example.com", "A", ["93.184.216.34"], ad=False)
            return resp, False

        monkeypatch.setattr(dns.query, "udp_with_fallback", udp_with_fallback, raising=True)

        payload = _call_tool_run("qtype normalized + plain success", "  example.com  ", "  a  ")
        assert payload["success"] is True
        assert payload["qname"] == "example.com"
        assert payload["qtype"] == "A"
        assert payload["transportMethod"] == "plain"
        assert payload["dns_server"] == "1.1.1.1"
        assert payload["result"] == ["93.184.216.34"]

    # -------------------------------------------------------------------------
    # Plain transport tests
    # -------------------------------------------------------------------------

    def test_plain_success_sets_dnssec_yes_if_ad_flag(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "plain", raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["8.8.8.8"], raising=False)

        def udp_with_fallback(query, server_ip, timeout, port):
            resp = _test_make_dns_response_with_answer(query, "example.com", "A", ["1.2.3.4"], ad=True)
            return resp, False

        monkeypatch.setattr(dns.query, "udp_with_fallback", udp_with_fallback, raising=True)

        payload = _call_tool_run("plain: AD flag -> dnssec=yes", "example.com", "A")
        assert payload["success"] is True
        assert payload["dnssec"] == "yes"
        assert payload["result"] == ["1.2.3.4"]

    def test_plain_first_server_timeout_second_server_success_accumulates_error(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "plain", raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1", "8.8.8.8"], raising=False)

        calls = {"count": 0}

        def udp_with_fallback(query, server_ip, timeout, port):
            calls["count"] += 1
            if calls["count"] == 1:
                raise dns.exception.Timeout()
            resp = _test_make_dns_response_with_answer(query, "example.com", "A", ["5.6.7.8"], ad=False)
            return resp, False

        monkeypatch.setattr(dns.query, "udp_with_fallback", udp_with_fallback, raising=True)

        payload = _call_tool_run("plain: first timeout, second success", "example.com", "A")
        assert payload["success"] is True
        assert payload["dns_server"] == "8.8.8.8"
        assert "Timeout reached" in payload["error"]
        assert payload["result"] == ["5.6.7.8"]

    def test_plain_rcode_error_then_success_includes_rcode_message(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "plain", raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["9.9.9.9", "8.8.4.4"], raising=False)

        calls = {"count": 0}

        def udp_with_fallback(query, server_ip, timeout, port):
            calls["count"] += 1
            if calls["count"] == 1:
                resp = dns.message.make_response(query)
                resp.set_rcode(dns.rcode.NXDOMAIN)
                return resp, False
            resp = _test_make_dns_response_with_answer(query, "example.com", "A", ["10.0.0.1"], ad=False)
            return resp, False

        monkeypatch.setattr(dns.query, "udp_with_fallback", udp_with_fallback, raising=True)

        payload = _call_tool_run("plain: rcode fail then success", "example.com", "A")
        assert payload["success"] is True
        assert payload["dns_server"] == "8.8.4.4"
        assert "failed with error code: NXDOMAIN" in payload["error"]
        assert payload["result"] == ["10.0.0.1"]

    def test_plain_all_fail_returns_success_false_and_errors(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "plain", raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1", "8.8.8.8"], raising=False)

        def udp_with_fallback(query, server_ip, timeout, port):
            raise dns.exception.Timeout()

        monkeypatch.setattr(dns.query, "udp_with_fallback", udp_with_fallback, raising=True)

        payload = _call_tool_run("plain: all servers timeout -> fail", "example.com", "A")
        assert payload["success"] is False
        assert payload["transportMethod"] == "plain"
        assert payload["result"] == []
        assert "Timeout reached" in payload["error"]

    # -------------------------------------------------------------------------
    # DoH tests (with/without fallback)
    # -------------------------------------------------------------------------

    def test_doh_all_bootstraps_fail_returns_specific_error_without_bootstrap_details(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "doh", raising=False)
        monkeypatch.setattr(_this_module, "ALLOW_FALLBACK_TO_PLAIN", False, raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1", "8.8.8.8"], raising=False)
        monkeypatch.setattr(_this_module, "ENDPOINT_URL", "https://cloudflare-dns.com/dns-query", raising=False)

        def https_call(query, url, timeout, bootstrap_address):
            raise RuntimeError("bootstrap exploded")

        monkeypatch.setattr(dns.query, "https", https_call, raising=True)

        payload = _call_tool_run("doh: all bootstraps fail (no fallback)", "example.com", "A")
        assert payload["success"] is False
        assert payload["transportMethod"] == "doh"
        assert payload["dns_server"] == "https://cloudflare-dns.com/dns-query"
        assert payload["error"] == "Failed to resolve DNS server for DoH query."
        assert "Bootstrap" not in payload["error"]

    def test_doh_rcode_error_without_fallback(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "doh", raising=False)
        monkeypatch.setattr(_this_module, "ALLOW_FALLBACK_TO_PLAIN", False, raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1"], raising=False)
        monkeypatch.setattr(_this_module, "ENDPOINT_URL", "https://resolver.test/dns-query", raising=False)

        def https_call(query, url, timeout, bootstrap_address):
            resp = dns.message.make_response(query)
            resp.set_rcode(dns.rcode.SERVFAIL)
            return resp

        monkeypatch.setattr(dns.query, "https", https_call, raising=True)

        payload = _call_tool_run("doh: rcode error (no fallback)", "example.com", "A")
        assert payload["success"] is False
        assert payload["transportMethod"] == "doh"
        assert payload["dns_server"] == "https://resolver.test/dns-query"
        assert "failed with error code: SERVFAIL" in payload["error"]

    def test_doh_timeout_with_fallback_to_plain_success_prefixes_errors(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "doh", raising=False)
        monkeypatch.setattr(_this_module, "ALLOW_FALLBACK_TO_PLAIN", True, raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1"], raising=False)
        monkeypatch.setattr(_this_module, "ENDPOINT_URL", "https://resolver.test/dns-query", raising=False)

        def https_call(query, url, timeout, bootstrap_address):
            # In current implementation, this timeout is caught inside the bootstrap loop
            # and ends up producing: "Failed to resolve DNS server for DoH query."
            raise dns.exception.Timeout()

        def udp_with_fallback(query, server_ip, timeout, port):
            resp = _test_make_dns_response_with_answer(query, "example.com", "A", ["203.0.113.10"], ad=False)
            return resp, False

        monkeypatch.setattr(dns.query, "https", https_call, raising=True)
        monkeypatch.setattr(dns.query, "udp_with_fallback", udp_with_fallback, raising=True)

        payload = _call_tool_run("doh: timeout -> fallback to plain success", "example.com", "A")
        assert payload["transportMethod"] == "plain"
        assert payload["success"] is True
        assert payload["result"] == ["203.0.113.10"]
        assert payload["error"] == "Failed to resolve DNS server for DoH query."

    # -------------------------------------------------------------------------
    # DoT tests
    # -------------------------------------------------------------------------

    def test_dot_no_dns_servers_no_fallback_returns_failure(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "dot", raising=False)
        monkeypatch.setattr(_this_module, "ALLOW_FALLBACK_TO_PLAIN", False, raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", [], raising=False)

        payload = _call_tool_run("dot: no servers (no fallback)", "example.com", "A")
        assert payload["success"] is False
        assert payload["transportMethod"] == "dot"
        assert payload["dns_server"] == ""
        assert payload["error"] == "No DNS servers configured"

    def test_dot_no_dns_servers_with_fallback_attempts_plain_and_prefixes_error(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "dot", raising=False)
        monkeypatch.setattr(_this_module, "ALLOW_FALLBACK_TO_PLAIN", True, raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", [], raising=False)

        payload = _call_tool_run("dot: no servers -> fallback to plain (still fail)", "example.com", "A")
        assert payload["transportMethod"] == "plain"
        assert payload["success"] is False
        assert payload["error"] == "No DNS servers configured"

    def test_dot_success_sets_dnssec_yes_if_ad_flag(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "dot", raising=False)
        monkeypatch.setattr(_this_module, "ALLOW_FALLBACK_TO_PLAIN", False, raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1"], raising=False)
        monkeypatch.setattr(_this_module, "DOT_SNI", "cloudflare-dns.com", raising=False)

        def tls_call(query, server_ip, timeout, port, server_hostname):
            resp = _test_make_dns_response_with_answer(query, "example.com", "A", ["192.0.2.55"], ad=True)
            return resp

        monkeypatch.setattr(dns.query, "tls", tls_call, raising=True)

        payload = _call_tool_run("dot: success + AD flag", "example.com", "A")
        assert payload["success"] is True
        assert payload["transportMethod"] == "dot"
        assert payload["dns_server"] == "1.1.1.1"
        assert payload["dnssec"] == "yes"
        assert payload["result"] == ["192.0.2.55"]

    # -------------------------------------------------------------------------
    # DoQ tests
    # -------------------------------------------------------------------------

    def test_doq_success(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "doq", raising=False)
        monkeypatch.setattr(_this_module, "ALLOW_FALLBACK_TO_PLAIN", False, raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1"], raising=False)
        monkeypatch.setattr(_this_module, "DOQ_SNI", "cloudflare-dns.com", raising=False)

        def quic_call(query, server_ip, timeout, port, hostname):
            resp = _test_make_dns_response_with_answer(query, "example.com", "AAAA", ["2001:db8::1"], ad=False)
            return resp

        monkeypatch.setattr(dns.query, "quic", quic_call, raising=True)

        payload = _call_tool_run("doq: success", "example.com", "AAAA")
        assert payload["success"] is True
        assert payload["transportMethod"] == "doq"
        assert payload["dns_server"] == "1.1.1.1"
        assert payload["result"] == ["2001:db8::1"]
        assert payload["dnssec"] == "no"

    # -------------------------------------------------------------------------
    # Unknown transport method
    # -------------------------------------------------------------------------

    def test_unknown_transport_method_returns_error(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "weird", raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1"], raising=False)

        payload = _call_tool_run("unknown transport method", "example.com", "A")
        assert payload["success"] is False
        assert payload["error"] == "Unknown transport method: weird"

    # -------------------------------------------------------------------------
    # Exception safety in tool_run()
    # -------------------------------------------------------------------------

    def test_make_query_exception_is_caught_and_reported(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "plain", raising=False)

        def make_query_boom(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(dns.message, "make_query", make_query_boom, raising=True)

        payload = _call_tool_run("make_query throws -> tool_run catches", "example.com", "A")
        assert payload["success"] is False
        assert payload["qname"] == "example.com"
        assert payload["qtype"] == "A"
        assert "Unknown exception occurred: boom" in payload["error"]

    def test_use_dnssec_flag_is_passed_to_make_query(_this_module, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setattr(_this_module, "TRANSPORT_METHOD", "plain", raising=False)
        monkeypatch.setattr(_this_module, "DNS_SERVERS", ["1.1.1.1"], raising=False)
        monkeypatch.setattr(_this_module, "USE_DNSSEC", True, raising=False)

        original_make_query = dns.message.make_query
        observed = {"want_dnssec": None}

        def spy_make_query(qname, qtype, want_dnssec=False):
            observed["want_dnssec"] = want_dnssec
            return original_make_query(qname, qtype, want_dnssec=want_dnssec)

        def udp_with_fallback(query, server_ip, timeout, port):
            resp = _test_make_dns_response_with_answer(query, "example.com", "A", ["198.51.100.42"], ad=False)
            return resp, False

        monkeypatch.setattr(dns.message, "make_query", spy_make_query, raising=True)
        monkeypatch.setattr(dns.query, "udp_with_fallback", udp_with_fallback, raising=True)

        payload = _call_tool_run("USE_DNSSEC passed into make_query", "example.com", "A")
        assert payload["success"] is True
        assert observed["want_dnssec"] is True
        assert payload["result"] == ["198.51.100.42"]
