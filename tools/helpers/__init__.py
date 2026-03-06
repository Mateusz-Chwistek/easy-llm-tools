from .dns_helper import QueryResult, doh_query, doq_query, dot_query, plain_query
from .address_resolver_helper import resolve_address, HostAddresses
from .example_ssh_gate import ssh_gate

__all__ = [
    "QueryResult",
    "doh_query",
    "doq_query",
    "dot_query",
    "plain_query",
    "resolve_address",
    "HostAddresses",
    "ssh_gate",
]
