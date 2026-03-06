import string
import secrets
from typing import List, Optional


def ssh_gate(
    host: str, host_os: Optional[str], host_shell: Optional[str], commands: List[str]
) -> bool:
    """
    Example acceptance-gate implementation used by the ssh_client tool.

    This function is intended as a template only. The user should provide their
    own implementation (for the ssh_client tool) with the exact same name and
    signature:

        def ssh_gate(
            host: str,
            host_os: Optional[str],
            host_shell: Optional[str],
            commands: List[str],
        ) -> bool

    The ssh_client tool imports `ssh_gate` and calls it before executing any
    commands on the requested host. To use your own gate, replace the import
    in the ssh_client tool so it points to your implementation. The rest of
    the module can be organized as needed, as long as it exports `ssh_gate`.

    The `commands` list is intentionally mutable: your implementation may
    inspect and modify it in place (for example, remove, rewrite, or append
    commands) before returning.

    :param host: Hostname or IP address requested for the SSH connection.
    :type host: str
    :param host_os: Detected or declared operating system of the target host,
        or None if unavailable.
    :type host_os: Optional[str]
    :param host_shell: Shell that will be used on the target host,
        or None to use the system default shell.
    :type host_shell: Optional[str]
    :param commands: Mutable list of requested commands; may be modified in place.
    :type commands: List[str]
    :return: True to approve execution, False to reject it.
    :rtype: bool
    """

    banner = "-" * 13 + " SSH GATE " + "-" * 13

    print()
    print(banner)
    print(f"Host: {host}")
    print(f"Operating system: {host_os}")
    print(f"Used shell: {host_shell if host_shell is not None else "system default"}")
    print("\nCommands:")
    for command in commands:
        print(f"  - {command!r}")
    print(banner)
    print()

    pass_phrase = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(8)
    )

    if (
        input(
            f"Rewrite the following: {pass_phrase}, to accept (leave blank to disallow): "
        ).strip()
        == pass_phrase
    ):
        return True

    return False
