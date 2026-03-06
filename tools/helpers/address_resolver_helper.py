import re
import dns.message
from enum import IntEnum, auto
from ipaddress import ip_address
from dataclasses import dataclass
from typing import List, Optional, Final, Literal, Tuple
from helpers import (
    QueryResult,
    doh_query,
    doq_query,
    dot_query,
    plain_query,
)

# -----------------------------------------------------------------------------
# User configuration
# -----------------------------------------------------------------------------

# Used directly for plain DNS and as bootstrap servers for DoH.
# For DoT and DoQ, only the first server from this list is used.
DNS_SERVERS: Final[List[str]] = ["1.1.1.1"]

# Maximum time in seconds allowed for a single DNS request,
# regardless of the selected transport method.
TIMEOUT: Final[float] = 5.0

# Transport protocol used to send DNS queries.
# Supported values:
# - "plain": classic DNS over UDP/TCP
# - "doh": DNS-over-HTTPS
# - "dot": DNS-over-TLS
# - "doq": DNS-over-QUIC
TRANSPORT_METHOD: Final[Literal["doh", "dot", "doq", "plain"]] = "plain"

# DoH endpoint URL of the selected resolver.
# Must point to a server that supports DNS-over-HTTPS.
ENDPOINT_URL: Final[str] = "https://cloudflare-dns.com/dns-query"

# Server name used during the TLS handshake for DoT.
# This must match the certificate hostname presented by the resolver.
DOT_SNI: Final[str] = "cloudflare-dns.com"

# Server name used during the TLS handshake for DoQ.
# This must match the certificate hostname presented by the resolver.
DOQ_SNI: Final[str] = "cloudflare-dns.com"

# If enabled, the resolver sets the DNSSEC OK (DO) bit in outgoing queries.
# This requests DNSSEC-related records and allows a validating upstream resolver
# to return authentication status in the response.
USE_DNSSEC: Final[bool] = False

# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------

# Simple hostname-label check:
# letters, digits, and "-" only, with label length from 1 to 63 characters.
# Extra rules like "must not start or end with '-'" are checked later in code.
_HOSTNAME_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9-]{1,63}$")


@dataclass
class HostAddresses:
    """
    Store the resolved canonical hostname and associated IP addresses.

    The structure is used as the normalized result returned by address
    resolution helpers and by the public resolver entry point.

    :param address: Resolved hostname associated with the input, or None when
        no hostname could be determined.
    :type address: Optional[str]
    :param ipv4: Resolved IPv4 address associated with the input, or None when
        no IPv4 address is available.
    :type ipv4: Optional[str]
    :param ipv6: Resolved IPv6 address associated with the input, or None when
        no IPv6 address is available.
    :type ipv6: Optional[str]
    :param success: True when resolution completed successfully according to the
        module rules, otherwise False.
    :type success: bool
    """

    address: Optional[str]
    ipv4: Optional[str]
    ipv6: Optional[str]
    success: bool


class AddressType(IntEnum):
    """
    Classify the input string before attempting DNS resolution.

    The enum distinguishes between valid IPv4 literals, valid IPv6 literals,
    syntactically valid hostnames, empty input values, and unsupported or
    malformed input formats.
    """

    IPV4 = auto()
    IPV6 = auto()
    ADDRESS = auto()
    UNKNOWN = auto()
    EMPTY = auto()


def _make_query(qname: str, qtype: str):
    """
    Build a DNS query message and execute it using the configured transport.

    The function creates a dnspython query message and dispatches it to the
    transport-specific helper selected by the current configuration. Supported
    transports include plain DNS, DNS-over-HTTPS, DNS-over-TLS, and DNS-over-QUIC.

    :param qname: Query name passed to dnspython when constructing the DNS
        message.
    :type qname: str
    :param qtype: DNS record type to query, for example "A", "AAAA", or "PTR".
    :type qtype: str
    :return: Normalized query result produced by the selected transport helper.
    :rtype: QueryResult
    """

    query = dns.message.make_query(qname, qtype, want_dnssec=USE_DNSSEC)

    if TRANSPORT_METHOD == "plain":
        return plain_query(
            query=query,
            dns_servers=DNS_SERVERS,
            timeout=TIMEOUT,
        )
    elif TRANSPORT_METHOD == "doh":
        return doh_query(
            query=query,
            dns_servers=DNS_SERVERS,
            endpoint_url=ENDPOINT_URL,
            timeout=TIMEOUT,
        )
    elif TRANSPORT_METHOD == "dot":
        return dot_query(
            query=query,
            dns_server=DNS_SERVERS[0],
            dot_sni=DOT_SNI,
            timeout=TIMEOUT,
        )
    elif TRANSPORT_METHOD == "doq":
        return doq_query(
            query=query,
            dns_server=DNS_SERVERS[0],
            doq_sni=DOQ_SNI,
            timeout=TIMEOUT,
        )
    else:
        raise ValueError(f"Unsupported transport method: {TRANSPORT_METHOD}")


def _is_nxdomain(query_result: QueryResult) -> bool:
    """
    Determine whether a query result contains an NXDOMAIN diagnostic.

    The function inspects collected error messages and returns True when at
    least one message indicates that the queried name does not exist.

    :param query_result: Normalized DNS query result to inspect.
    :type query_result: QueryResult
    :return: True when the result contains an NXDOMAIN error message, otherwise
        False.
    :rtype: bool
    """

    if query_result.errors is None:
        return False

    for error in query_result.errors:
        if "NXDOMAIN" in error:
            return True

    return False


def _has_hard_dns_failure(query_result: QueryResult) -> bool:
    """
    Determine whether a query result represents a hard DNS failure.

    A result is treated as a hard failure when the query was unsuccessful and
    the failure is not explained by NXDOMAIN. This helper is used to block
    resolution bypasses caused by transport errors or other resolver failures.

    :param query_result: Normalized DNS query result to evaluate.
    :type query_result: QueryResult
    :return: True when the query failed for a reason other than NXDOMAIN,
        otherwise False.
    :rtype: bool
    """

    return not query_result.success and not _is_nxdomain(query_result)


def _get_first_result(query_result: QueryResult) -> Optional[str]:
    """
    Return the first textual answer item from a normalized query result.

    The function extracts the first entry from the flattened answer list and
    returns None when no answer items are present.

    :param query_result: Normalized DNS query result containing textual answer
        items.
    :type query_result: QueryResult
    :return: First textual answer item, or None when the result list is empty
        or missing.
    :rtype: Optional[str]
    """

    if query_result.result is None or len(query_result.result) == 0:
        return None

    return query_result.result[0]


def _normalize_dns_name(name: str) -> str:
    """
    Normalize a hostname or DNS name for internal processing.

    The function trims surrounding whitespace and removes a trailing dot so that
    fully qualified domain names can be handled consistently by later checks.

    :param name: Raw DNS name or hostname to normalize.
    :type name: str
    :return: Normalized DNS name without surrounding whitespace and without a
        trailing dot.
    :rtype: str
    """

    return name.strip().rstrip(".")


def _looks_like_ipv4_candidate(value: str) -> bool:
    """
    Check whether the input resembles an IPv4 literal candidate.

    The function performs a lightweight structural check based on dot-separated
    numeric parts. It is intentionally permissive and is used only to detect
    malformed IP literal attempts that should not be treated as hostnames.

    :param value: Input string to inspect.
    :type value: str
    :return: True when the value looks like an IPv4 literal candidate,
        otherwise False.
    :rtype: bool
    """

    parts = value.split(".")
    if len(parts) < 1:
        return False

    for part in parts:
        if part == "" or not part.isdigit():
            return False

    return True


def _looks_like_ipv6_candidate(value: str) -> bool:
    """
    Check whether the input resembles an IPv6 literal candidate.

    The function performs a lightweight structural check by detecting the
    presence of a colon character, which is not valid in hostnames handled by
    this module.

    :param value: Input string to inspect.
    :type value: str
    :return: True when the value looks like an IPv6 literal candidate,
        otherwise False.
    :rtype: bool
    """

    return ":" in value


def _is_valid_hostname(value: str) -> bool:
    """
    Validate whether the input is a syntactically acceptable hostname.

    The function normalizes the value, enforces overall hostname length limits,
    splits the name into labels, and validates each label against the allowed
    character set and boundary rules.

    :param value: Input string to validate as a hostname.
    :type value: str
    :return: True when the value is a syntactically valid hostname, otherwise
        False.
    :rtype: bool
    """

    if not isinstance(value, str):
        return False

    normalized_value = _normalize_dns_name(value)

    if normalized_value == "":
        return False

    if len(normalized_value) < 1 or len(normalized_value) > 254:
        return False

    labels = normalized_value.split(".")
    if len(labels) == 0:
        return False

    for label in labels:
        if label == "":
            return False

        if not _HOSTNAME_LABEL_PATTERN.fullmatch(label):
            return False

        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def _get_address_type(value: str) -> AddressType:
    """
    Classify the input as IPv4, IPv6, hostname, empty value, or unknown format.

    The function first attempts strict IP parsing, then rejects malformed IP-like
    inputs, and finally falls back to hostname validation. This prevents invalid
    IP literals from being misclassified as hostnames.

    :param value: Raw input value to classify.
    :type value: str
    :return: Address type derived from the input format.
    :rtype: AddressType
    """

    if not isinstance(value, str):
        return AddressType.UNKNOWN

    normalized_value = value.strip()
    if normalized_value == "":
        return AddressType.EMPTY

    try:
        return AddressType.IPV4 if ip_address(value).version == 4 else AddressType.IPV6
    except ValueError:
        pass

    # If it looks like an IP literal attempt but is invalid,
    # do not treat it as a hostname.
    if _looks_like_ipv4_candidate(normalized_value):
        return AddressType.UNKNOWN

    if _looks_like_ipv6_candidate(normalized_value):
        return AddressType.UNKNOWN

    if _is_valid_hostname(normalized_value):
        return AddressType.ADDRESS

    return AddressType.UNKNOWN


def _query_optional_first(host: str, qtype: str) -> Tuple[Optional[str], bool]:
    """
    Query a single DNS record type and return the first answer item when allowed.

    The function executes a DNS query and treats NXDOMAIN as an acceptable
    no-result state, while transport failures and other DNS errors are treated
    as hard failures.

    :param host: Hostname or reverse DNS name to query.
    :type host: str
    :param qtype: DNS record type to request, for example "A", "AAAA", or "PTR".
    :type qtype: str
    :return: A tuple containing the first answer item or None, and a boolean
        indicating whether the query outcome is acceptable for further
        processing.
    :rtype: Tuple[Optional[str], bool]
    """

    query_result: QueryResult = _make_query(host, qtype)

    if _has_hard_dns_failure(query_result):
        return None, False

    return _get_first_result(query_result), True


def _resolve_hostname(host: str) -> HostAddresses:
    """
    Resolve a hostname into its IPv4 and IPv6 addresses.

    The function validates the hostname, queries both A and AAAA records, and
    returns a normalized address structure. NXDOMAIN for one address family is
    treated as an acceptable absence of that family, while hard DNS failures
    abort the whole resolution.

    :param host: Hostname to resolve.
    :type host: str
    :return: Normalized hostname resolution result containing the original
        hostname and any resolved IP addresses.
    :rtype: HostAddresses
    """

    if not isinstance(host, str):
        return HostAddresses(None, None, None, False)

    normalized_host = _normalize_dns_name(host)

    if normalized_host == "":
        return HostAddresses(None, None, None, False)

    if len(normalized_host) < 1 or len(normalized_host) > 254:
        return HostAddresses(None, None, None, False)

    if not _is_valid_hostname(normalized_host):
        return HostAddresses(None, None, None, False)

    ipv4_value, ipv4_ok = _query_optional_first(normalized_host, "A")
    if not ipv4_ok:
        return HostAddresses(None, None, None, False)

    ipv6_value, ipv6_ok = _query_optional_first(normalized_host, "AAAA")
    if not ipv6_ok:
        return HostAddresses(None, None, None, False)

    return HostAddresses(normalized_host, ipv4_value, ipv6_value, True)


def _resolve_ipv4(ipv4: str) -> HostAddresses:
    """
    Resolve an IPv4 literal through reverse DNS and optional complementary lookup.

    The function derives the reverse pointer name, performs a PTR lookup, and
    when a hostname is obtained, optionally resolves its IPv6 address. The input
    IPv4 address is always preserved in the returned structure on successful
    processing.

    :param ipv4: IPv4 literal to resolve.
    :type ipv4: str
    :return: Normalized resolution result containing the original IPv4 address,
        an optional hostname, and an optional IPv6 address.
    :rtype: HostAddresses
    """

    try:
        reverse_name = ip_address(ipv4).reverse_pointer
    except Exception:
        return HostAddresses(None, None, None, False)

    ptr_result: QueryResult = _make_query(reverse_name, "PTR")
    if _has_hard_dns_failure(ptr_result):
        return HostAddresses(None, None, None, False)

    ptr_host = _get_first_result(ptr_result)
    if ptr_host is None:
        return HostAddresses(None, ipv4, None, True)

    normalized_host = _normalize_dns_name(ptr_host)
    if not _is_valid_hostname(normalized_host):
        return HostAddresses(None, None, None, False)

    ipv6_value, ipv6_ok = _query_optional_first(normalized_host, "AAAA")
    if not ipv6_ok:
        return HostAddresses(None, None, None, False)

    return HostAddresses(normalized_host, ipv4, ipv6_value, True)


def _resolve_ipv6(ipv6: str) -> HostAddresses:
    """
    Resolve an IPv6 literal through reverse DNS and optional complementary lookup.

    The function derives the reverse pointer name, performs a PTR lookup, and
    when a hostname is obtained, optionally resolves its IPv4 address. The input
    IPv6 address is always preserved in the returned structure on successful
    processing.

    :param ipv6: IPv6 literal to resolve.
    :type ipv6: str
    :return: Normalized resolution result containing the original IPv6 address,
        an optional hostname, and an optional IPv4 address.
    :rtype: HostAddresses
    """

    try:
        reverse_name = ip_address(ipv6).reverse_pointer
    except Exception:
        return HostAddresses(None, None, None, False)

    ptr_result: QueryResult = _make_query(reverse_name, "PTR")
    if _has_hard_dns_failure(ptr_result):
        return HostAddresses(None, None, None, False)

    ptr_host = _get_first_result(ptr_result)
    if ptr_host is None:
        return HostAddresses(None, None, ipv6, True)

    normalized_host = _normalize_dns_name(ptr_host)
    if not _is_valid_hostname(normalized_host):
        return HostAddresses(None, None, None, False)

    ipv4_value, ipv4_ok = _query_optional_first(normalized_host, "A")
    if not ipv4_ok:
        return HostAddresses(None, None, None, False)

    return HostAddresses(normalized_host, ipv4_value, ipv6, True)


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def resolve_address(host: str) -> HostAddresses:
    """
    Resolve the provided input into a normalized hostname and IP address set.

    The function classifies the input first and then dispatches it to the
    appropriate resolver path for hostnames, IPv4 literals, or IPv6 literals.
    Unsupported, malformed, or empty values result in an unsuccessful response.

    :param host: Input hostname or IP literal to resolve.
    :type host: str
    :return: Normalized resolution result containing the discovered hostname,
        IPv4 address, IPv6 address, and success flag.
    :rtype: HostAddresses
    """

    host_addr_type: AddressType = _get_address_type(host)

    if host_addr_type == AddressType.ADDRESS:
        return _resolve_hostname(host)

    elif host_addr_type == AddressType.IPV4:
        return _resolve_ipv4(host)

    elif host_addr_type == AddressType.IPV6:
        return _resolve_ipv6(host)

    else:
        return HostAddresses(None, None, None, False)
