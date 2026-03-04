import dns.flags
import dns.rcode
import dns.query
import dns.message
import dns.exception
from dns.message import QueryMessage
from typing import Optional, List
from dataclasses import dataclass

# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------


def _extract_answer_items(response: dns.message.Message) -> List[str]:
    """
    Extract textual answer items from the DNS response answer section.

    The function flattens all answer RRsets into a single list of strings using
    dnspython's textual representation for each RDATA entry.

    :param response: DNS response message returned by dnspython.
    :type response: dns.message.Message
    :return: Flat list of textual answer items.
    :rtype: List[str]
    """

    return [rdata.to_text() for rrset in response.answer for rdata in rrset]


def _validate_query_argument(query: object) -> Optional[str]:
    """
    Validate that the query argument is a dnspython message instance.

    :param query: Value passed as the DNS query object.
    :type query: object
    :return: Validation error message, or None when the value is valid.
    :rtype: Optional[str]
    """

    if not isinstance(query, dns.message.Message):
        return "Argument 'query' must be of type dns.message.Message"
    return None


def _validate_string_argument(argument_name: str, value: object) -> Optional[str]:
    """
    Validate that a named argument is a string.

    :param argument_name: Name of the validated argument.
    :type argument_name: str
    :param value: Value to validate.
    :type value: object
    :return: Validation error message, or None when the value is valid.
    :rtype: Optional[str]
    """

    if not isinstance(value, str):
        return f"Argument '{argument_name}' must be of type str"
    return None


def _validate_timeout_argument(timeout: object) -> Optional[str]:
    """
    Validate that the timeout argument is a positive numeric value.

    Boolean values are rejected explicitly because bool is a subclass of int in
    Python and should not be accepted here.

    :param timeout: Timeout value to validate.
    :type timeout: object
    :return: Validation error message, or None when the value is valid.
    :rtype: Optional[str]
    """

    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        return "Argument 'timeout' must be of type int or float"

    if timeout <= 0:
        return "Argument 'timeout' must be greater than 0"

    return None


def _validate_dns_servers_argument(dns_servers: object) -> Optional[str]:
    """
    Validate that the dns_servers argument is a list of strings.

    :param dns_servers: Resolver list to validate.
    :type dns_servers: object
    :return: Validation error message, or None when the value is valid.
    :rtype: Optional[str]
    """

    if not isinstance(dns_servers, list):
        return "Argument 'dns_servers' must be of type list[str]"

    for index, server in enumerate(dns_servers):
        if not isinstance(server, str):
            return f"Argument 'dns_servers[{index}]' must be of type str"

    return None


@dataclass
class QueryResult:
    """
    Store a normalized DNS query result returned by helper transport functions.

    :param result: Flattened DNS answer items, or None when the query failed.
    :type result: Optional[List[str]]
    :param errors: Collected diagnostic messages, or None when no diagnostics exist.
    :type errors: Optional[List[str]]
    :param used_endpoint: Resolver IP or endpoint URL used for the final attempt.
    :type used_endpoint: Optional[str]
    :param dnssec_ad: True when the resolver returned the AD flag, otherwise False or None.
    :type dnssec_ad: Optional[bool]
    :param success: True when the query completed successfully, otherwise False.
    :type success: bool
    """

    result: Optional[List[str]]
    errors: Optional[List[str]]
    used_endpoint: Optional[str]
    dnssec_ad: Optional[bool]
    success: bool


# -----------------------------------------------------------------------------
# Transport implementations
# -----------------------------------------------------------------------------


def doh_query(
    query: QueryMessage, dns_servers: List[str], endpoint_url: str, timeout: float
) -> QueryResult:
    """
    Execute a DNS-over-HTTPS query using the provided bootstrap DNS servers.

    :param query: Prepared DNS query message.
    :type query: QueryMessage
    :param dns_servers: Resolver IPs used as bootstrap addresses for the DoH endpoint.
    :type dns_servers: List[str]
    :param endpoint_url: DNS-over-HTTPS endpoint URL.
    :type endpoint_url: str
    :param timeout: Per-request timeout in seconds.
    :type timeout: float
    :return: Normalized query result containing answer items or diagnostics.
    :rtype: QueryResult
    """

    validation_errors: List[str] = []

    query_error = _validate_query_argument(query)
    if query_error is not None:
        validation_errors.append(query_error)

    dns_servers_error = _validate_dns_servers_argument(dns_servers)
    if dns_servers_error is not None:
        validation_errors.append(dns_servers_error)

    if len(dns_servers) < 1:
        validation_errors.append("No DNS servers configured")

    endpoint_url_error = _validate_string_argument("endpoint_url", endpoint_url)
    if endpoint_url_error is not None:
        validation_errors.append(endpoint_url_error)

    timeout_error = _validate_timeout_argument(timeout)
    if timeout_error is not None:
        validation_errors.append(timeout_error)

    if len(validation_errors) > 0:
        return QueryResult(None, validation_errors, None, None, False)

    errors: List[str] = []

    try:
        response: Optional[dns.message.Message] = None

        for server_ip in dns_servers:
            try:
                response = dns.query.https(
                    query,
                    endpoint_url,
                    timeout=timeout,
                    bootstrap_address=server_ip,
                )
                break
            except Exception as ex:
                errors.append(f"Bootstrap {server_ip} failed: {ex}")

        if response is None:
            if len(errors) == 0:
                errors.append("Failed to resolve DNS server for DoH query")
            return QueryResult(None, errors, None, None, False)

        rrc = response.rcode()
        if rrc != dns.rcode.NOERROR:
            errors.append(
                f"Query to: {endpoint_url}, failed with error code: {dns.rcode.to_text(rrc)}"
            )
            return QueryResult(None, errors, None, None, False)

        return QueryResult(
            _extract_answer_items(response),
            errors if len(errors) > 0 else None,
            endpoint_url,
            bool(response.flags & dns.flags.AD),
            True,
        )

    except dns.exception.Timeout:
        return QueryResult(None, ["Timeout reached"], None, None, False)
    except Exception as ex:
        return QueryResult(None, [f"Unknown exception: {ex}"], None, None, False)


def dot_query(
    query: QueryMessage, dns_server: str, dot_sni: str, timeout: float
) -> QueryResult:
    """
    Execute a DNS-over-TLS query using the provided resolver address.

    :param query: Prepared DNS query message.
    :type query: QueryMessage
    :param dns_server: Resolver IP address used for the DoT request.
    :type dns_server: str
    :param dot_sni: TLS server name used for certificate validation.
    :type dot_sni: str
    :param timeout: Per-request timeout in seconds.
    :type timeout: float
    :return: Normalized query result containing answer items or diagnostics.
    :rtype: QueryResult
    """

    validation_errors: List[str] = []

    query_error = _validate_query_argument(query)
    if query_error is not None:
        validation_errors.append(query_error)

    dns_server_error = _validate_string_argument("dns_server", dns_server)
    if dns_server_error is not None:
        validation_errors.append(dns_server_error)

    timeout_error = _validate_timeout_argument(timeout)
    if timeout_error is not None:
        validation_errors.append(timeout_error)

    dot_sni_error = _validate_string_argument("dot_sni", dot_sni)
    if dot_sni_error is not None:
        validation_errors.append(dot_sni_error)

    if len(validation_errors) > 0:
        return QueryResult(None, validation_errors, None, None, False)

    dns_server = dns_server.strip()
    if dns_server == "":
        return QueryResult(None, ["No DNS server configured"], None, None, False)

    try:
        response = dns.query.tls(
            query, dns_server, timeout=timeout, port=853, server_hostname=dot_sni
        )

        rrc = response.rcode()
        if rrc != dns.rcode.NOERROR:
            return QueryResult(
                None,
                [
                    f"Query to: {dns_server}, failed with error code: {dns.rcode.to_text(rrc)}"
                ],
                None,
                None,
                False,
            )

        return QueryResult(
            _extract_answer_items(response),
            None,
            dns_server,
            bool(response.flags & dns.flags.AD),
            True,
        )

    except dns.exception.Timeout:
        return QueryResult(None, ["Timeout reached"], None, None, False)
    except Exception as ex:
        return QueryResult(None, [f"Unknown exception: {ex}"], None, None, False)


def doq_query(
    query: QueryMessage, dns_server: str, doq_sni: str, timeout: float
) -> QueryResult:
    """
    Execute a DNS-over-QUIC query using the provided resolver address.

    :param query: Prepared DNS query message.
    :type query: QueryMessage
    :param dns_server: Resolver IP address used for the DoQ request.
    :type dns_server: str
    :param doq_sni: Hostname metadata used by the QUIC transport layer.
    :type doq_sni: str
    :param timeout: Per-request timeout in seconds.
    :type timeout: float
    :return: Normalized query result containing answer items or diagnostics.
    :rtype: QueryResult
    """

    validation_errors: List[str] = []

    query_error = _validate_query_argument(query)
    if query_error is not None:
        validation_errors.append(query_error)

    dns_server_error = _validate_string_argument("dns_server", dns_server)
    if dns_server_error is not None:
        validation_errors.append(dns_server_error)

    timeout_error = _validate_timeout_argument(timeout)
    if timeout_error is not None:
        validation_errors.append(timeout_error)

    doq_sni_error = _validate_string_argument("doq_sni", doq_sni)
    if doq_sni_error is not None:
        validation_errors.append(doq_sni_error)

    if len(validation_errors) > 0:
        return QueryResult(None, validation_errors, None, None, False)

    dns_server = dns_server.strip()
    if dns_server == "":
        return QueryResult(None, ["No DNS server configured"], None, None, False)

    try:
        response = dns.query.quic(
            query, dns_server, timeout=timeout, port=853, hostname=doq_sni
        )

        rrc = response.rcode()
        if rrc != dns.rcode.NOERROR:
            return QueryResult(
                None,
                [
                    f"Query to: {dns_server}, failed with error code: {dns.rcode.to_text(rrc)}"
                ],
                None,
                None,
                False,
            )

        return QueryResult(
            _extract_answer_items(response),
            None,
            dns_server,
            bool(response.flags & dns.flags.AD),
            True,
        )

    except dns.exception.Timeout:
        return QueryResult(None, ["Timeout reached"], None, None, False)
    except Exception as ex:
        return QueryResult(None, [f"Unknown exception: {ex}"], None, None, False)


def plain_query(
    query: QueryMessage, dns_servers: List[str], timeout: float
) -> QueryResult:
    """
    Execute a plain DNS query using UDP with automatic TCP fallback.

    :param query: Prepared DNS query message.
    :type query: QueryMessage
    :param dns_servers: Ordered list of resolver IPs to try.
    :type dns_servers: List[str]
    :param timeout: Per-request timeout in seconds.
    :type timeout: float
    :return: Normalized query result containing answer items or diagnostics.
    :rtype: QueryResult
    """

    validation_errors: List[str] = []

    query_error = _validate_query_argument(query)
    if query_error is not None:
        validation_errors.append(query_error)

    dns_servers_error = _validate_dns_servers_argument(dns_servers)
    if dns_servers_error is not None:
        validation_errors.append(dns_servers_error)

    timeout_error = _validate_timeout_argument(timeout)
    if timeout_error is not None:
        validation_errors.append(timeout_error)

    if len(validation_errors) > 0:
        return QueryResult(None, validation_errors, None, None, False)

    errors: List[str] = []

    if len(dns_servers) < 1:
        return QueryResult(None, ["No DNS servers configured"], None, None, False)

    for server_ip in dns_servers:
        try:
            response, _ = dns.query.udp_with_fallback(
                query, server_ip, timeout=timeout, port=53
            )

            rrc = response.rcode()
            if rrc != dns.rcode.NOERROR:
                errors.append(
                    f"Query to: {server_ip}, failed with error code: {dns.rcode.to_text(rrc)}"
                )
                continue

            return QueryResult(
                _extract_answer_items(response),
                errors if len(errors) > 0 else None,
                server_ip,
                bool(response.flags & dns.flags.AD),
                True,
            )

        except dns.exception.Timeout:
            errors.append("Timeout reached")
        except Exception as ex:
            errors.append(f"Unknown exception: {ex}")

    return QueryResult(None, errors if len(errors) > 0 else None, None, None, False)
