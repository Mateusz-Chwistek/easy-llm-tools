import re
import json
import shlex
import base64
import paramiko
from typing import List, Optional, Final, Tuple
from dataclasses import asdict, dataclass
from helpers import resolve_address, HostAddresses
from paramiko.ssh_exception import (
    AuthenticationException,
    BadHostKeyException,
    NoValidConnectionsError,
    SSHException,
)

# -----------------------------------------------------------------------------
# User configuration
# -----------------------------------------------------------------------------

# NOTE: Replace `ssh_gate` with your own implementation (same signature/behavior),
# compatible with the `ssh_gate` definition shown in `helpers/example_ssh_gate.py`.
from helpers import ssh_gate

# List of allowed remote targets in the format:
# (host/address, target OS, default shell).
#
# Supported host values:
# - IPv4
# - IPv6
# - hostname/address
#
# NOTE: DNS configuration for this tool is defined in `helpers/address_resolver_helper.py`.
#
# Supported target OS values:
# - "Windows"
# - "Linux"
# - any other OS name (treated as "Other"; using the concrete OS name is encouraged as it may help the model)
#
# Supported default shell values:
# - for Windows: "powershell", "cmd"
# - for Linux: any shell that supports the `-lc` parameter, e.g. "bash", "sh", "zsh"
# - if `None` is provided, or if the target OS is "Other", the system default shell is used
#
# Example:
# [("192.168.0.1", "Windows", "powershell")]
ALLOWED_HOSTS: Final[List[Tuple[str, str, str]]] = []

# SSH port used for the remote connection.
PORT: Final[int] = 22

# Username used to authenticate on the remote host.
USERNAME: Final[str] = "llm-agent"

# Maximum time in seconds allowed for establishing the SSH connection.
CONNECT_TIMEOUT: Final[float] = 5.0

# Maximum time in seconds allowed for a single remote command execution.
EXECUTE_TIMEOUT: Final[float] = 30.0

# Maximum number of characters returned from a single command's stdout
MAX_STDOUT_LENGTH: Final[int] = 512

# Maximum number of characters returned from a single command's stderr
MAX_STDERR_LENGTH: Final[int] = 512

# Whether to compress repeated whitespace in command output before returning it.
#
# This reduces token usage and is especially useful for whitespace-heavy output
# such as `dir` or `ls`.
#
# Warning:
# Compression does not preserve exact formatting. Repeated spaces, tabs, and
# blank lines may be collapsed, which can cause the model to misinterpret the
# real file or command output layout and make incorrect follow-up changes.
COMPRESS_OUTPUT: Final[bool] = True

# -----------------------------------------------------------------------------
# Internal helpers
# -----------------------------------------------------------------------------


@dataclass
class CommandResult:
    """
    Store the execution result of a single remote command.

    :param command: Command that was executed or marked as aborted.
    :type command: str
    :param exit_code: Process exit code, or -1 if execution failed or was aborted.
    :type exit_code: int
    :param stdout: Captured standard output.
    :type stdout: str
    :param stderr: Captured standard error.
    :type stderr: str
    """

    command: str
    exit_code: int
    stdout: str
    stderr: str


def _build_response(
    error: Optional[str] = None,
    command_results: Optional[List[CommandResult]] = None,
) -> str:
    """
    Build the final JSON response returned by the tool.

    The response contains a top-level error field and a list of command result
    objects serialized from the internal CommandResult dataclass instances.

    :param error: Error message describing the overall failure, if any.
    :type error: Optional[str]
    :param command_results: Collection of per-command execution results.
    :type command_results: Optional[List[CommandResult]]
    :return: JSON string containing the tool response payload.
    :rtype: str
    """

    payload = {
        "error": error,
        "command_results": [asdict(result) for result in (command_results or [])],
    }
    return json.dumps(payload, ensure_ascii=False)


def _wrap_with_timeout_posix(command: str, shell: Optional[str], seconds: float) -> str:
    """
    Wrap a POSIX command with the `timeout` utility.

    The generated command runs the original payload through the selected shell
    in non-interactive mode and terminates it if it exceeds the configured
    number of seconds.

    :param command: Original command to execute remotely.
    :type command: str
    :param shell: POSIX shell binary name, for example `bash` or `sh`.
    :type shell: Optional[str]
    :param seconds: Maximum execution time in seconds.
    :type seconds: float
    :return: Command string wrapped with POSIX timeout handling.
    :rtype: str
    """

    timeout_seconds = max(1, int(seconds))
    quoted_command = shlex.quote(command)
    selected_shell = (shell or "sh").strip().lower()
    return f"timeout -k 2s {timeout_seconds}s {selected_shell} -lc {quoted_command}"


def _wrap_with_timeout_windows_cmd(
    command: str, shell: Optional[str], seconds: float
) -> str:
    """
    Wrap a Windows command in a PowerShell timeout supervisor.

    The wrapper starts the requested shell process (`powershell.exe` or `cmd.exe`),
    waits for completion up to the configured timeout, and forcefully terminates
    the process tree if the timeout is exceeded.

    For PowerShell child processes, the original command is executed inside
    a try/catch block that converts PowerShell error records into plain stderr text.

    :param command: Original command to execute remotely.
    :type command: str
    :param shell: Preferred Windows shell, usually `powershell` or `cmd`.
    :type shell: Optional[str]
    :param seconds: Maximum execution time in seconds.
    :type seconds: float
    :return: PowerShell command string that enforces the timeout.
    :rtype: str
    """

    timeout_seconds = max(1, int(seconds))
    normalized_shell = (shell or "cmd").strip().lower()

    if normalized_shell not in {"powershell", "powershell.exe", "pwsh", "pwsh.exe"}:
        normalized_shell = "cmd"
    else:
        normalized_shell = "powershell"

    if normalized_shell == "powershell":
        # Convert PowerShell-native errors to plain text on stderr.
        inner_powershell_script = (
            "$ProgressPreference='SilentlyContinue'; "
            "$ErrorActionPreference='Stop'; "
            "$ErrorView='NormalView'; "
            "$OutputEncoding = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "try { " + command + " } catch { "
            "$message = $_.Exception.Message; "
            "$fullyQualifiedErrorId = $_.FullyQualifiedErrorId; "
            "$categoryInfo = $_.CategoryInfo.ToString(); "
            "if ($message) { [Console]::Error.WriteLine($message) }; "
            "if ($position) { [Console]::Error.WriteLine($position) }; "
            "if ($fullyQualifiedErrorId) { [Console]::Error.WriteLine('FullyQualifiedErrorId: ' + $fullyQualifiedErrorId) }; "
            "if ($categoryInfo) { [Console]::Error.WriteLine('CategoryInfo: ' + $categoryInfo) }; "
            "exit 1 "
            "}"
        )

        encoded_command = base64.b64encode(
            inner_powershell_script.encode("utf-16le")
        ).decode("ascii")

        process_filename = "powershell.exe"
        process_arguments_expression = (
            '"-NoLogo -NoProfile -NonInteractive -OutputFormat Text -EncodedCommand " '
            "+ $encodedCommand"
        )
    else:
        encoded_command = base64.b64encode(command.encode("utf-16le")).decode("ascii")

        process_filename = "cmd.exe"
        process_arguments_expression = (
            '"/c " + [System.Text.Encoding]::Unicode.GetString('
            "[System.Convert]::FromBase64String($encodedCommand))"
        )

    ps_script = rf"""
$timeoutMs = {timeout_seconds} * 1000
$encodedCommand = "{encoded_command}"

[Console]::InputEncoding = [System.Text.Encoding]::UTF8
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = "{process_filename}"
$psi.Arguments = {process_arguments_expression}
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true

$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
[void]$p.Start()

$stdoutTask = $p.StandardOutput.ReadToEndAsync()
$stderrTask = $p.StandardError.ReadToEndAsync()

if (-not $p.WaitForExit($timeoutMs)) {{
    try {{ taskkill /PID $p.Id /T /F | Out-Null }} catch {{}}
    [Console]::Error.WriteLine("Command timed out after {timeout_seconds}s")
    exit 124
}}

$stdoutTask.Wait()
$stderrTask.Wait()

$out = $stdoutTask.Result
$err = $stderrTask.Result

if ($out) {{ [Console]::Out.Write($out) }}
if ($err) {{ [Console]::Error.Write($err) }}

exit $p.ExitCode
""".strip()

    encoded_wrapper = base64.b64encode(ps_script.encode("utf-16le")).decode("ascii")
    return (
        "powershell.exe "
        "-NoLogo -NoProfile -NonInteractive -OutputFormat Text "
        f"-EncodedCommand {encoded_wrapper}"
    )


def _wrap_with_timeout(
    command: str,
    shell: Optional[str],
    seconds: float,
    platform: Optional[str] = "Linux",
) -> str:
    """
    Select the appropriate timeout wrapper for the target platform.

    Linux hosts use a POSIX `timeout` wrapper, Windows hosts use a PowerShell-
    based supervisor, and unknown platforms fall back to returning the original
    command unchanged.

    :param command: Original command to execute remotely.
    :type command: str
    :param shell: Shell name used on the target system.
    :type shell: Optional[str]
    :param seconds: Maximum execution time in seconds.
    :type seconds: float
    :param platform: Target operating system name.
    :type platform: Optional[str]
    :return: Command wrapped with platform-specific timeout handling.
    :rtype: str
    """

    platform = platform.lower().strip() if platform is not None else "linux"
    if platform == "windows":
        return _wrap_with_timeout_windows_cmd(command, shell, seconds)
    elif platform == "linux":
        return _wrap_with_timeout_posix(command, shell, seconds)

    return command


def _extract_plain_text_from_clixml(stderr_text: str) -> str:
    """
    Remove PowerShell CLIXML/progress noise and keep plain stderr text.

    :param stderr_text: Raw stderr text.
    :type stderr_text: str
    :return: Cleaned stderr text.
    :rtype: str
    """

    if not stderr_text or not isinstance(stderr_text, str):
        return ""

    cleaned_text = stderr_text

    # Remove the common CLIXML preamble marker.
    cleaned_text = cleaned_text.replace("#< CLIXML\r\n", "")
    cleaned_text = cleaned_text.replace("#< CLIXML\n", "")
    cleaned_text = cleaned_text.replace("#< CLIXML", "")

    # If PowerShell appended XML progress payload after readable text,
    # drop everything from the first <Objs occurrence to the end.
    cleaned_text = re.sub(r"<Objs\b.*", "", cleaned_text, flags=re.DOTALL)

    # Remove common noisy progress message if it leaked as plain text.
    cleaned_text = cleaned_text.replace("Preparing modules for first use.", "")

    # Normalize blank lines.
    cleaned_text = re.sub(r"\r?\n{3,}", "\n\n", cleaned_text)

    return cleaned_text.strip()


def _compress_whitespace_blocks(text: str) -> str:
    """
    Collapse repeated spaces, tabs, and newlines while preserving their type.

    :param text: Input text to normalize.
    :type text: str
    :return: Text with repeated whitespace collapsed.
    :rtype: str
    """

    if not isinstance(text, str):
        return "No text provided"

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r" {3,}", "  ", text)
    text = re.sub(r"\t{2,}", "\t", text)
    text = re.sub(r"\n{2,}", "\n", text)
    text = re.sub(r"[ \t]+\n", "\n", text)
    return text.strip()


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------


def tool_run(
    host: str, commands: List[str] | str, continue_on_fail: bool = False
) -> str:
    """
    Validate input, connect to an allowed SSH host, execute remote commands,
    and return a JSON response string.

    The function first validates the SSH key path, host value, command list, and
    continue_on_fail flag. It then resolves the provided host and allows the
    connection only if the resolved address matches one of the configured
    ALLOWED_HOSTS entries.

    Commands are executed in order on the remote host. If a command fails and
    continue_on_fail is set to False, the remaining commands are not executed
    and are instead returned as aborted entries with exit_code = -1.

    :param host: Hostname or IP address of the remote machine.
    :type host: str
    :param commands: Single command string or a list of command strings.
    :type commands: List[str] | str
    :param continue_on_fail: Whether execution should continue after a failed command.
    :type continue_on_fail: bool
    :return: JSON string describing the overall status and per-command results.
    :rtype: str
    """

    results: List[CommandResult] = []

    # Validate host type and content.
    if not isinstance(host, str):
        return _build_response(
            error="Host must be a string.",
            command_results=results,
        )

    host = host.strip()
    if len(host) < 1 or len(host) > 255:
        return _build_response(
            error="Host must have a length between 1 and 255 characters.",
            command_results=results,
        )

    # Normalize commands input.
    normalized_commands: List[str]
    if isinstance(commands, str):
        normalized_commands = [commands]
    elif isinstance(commands, list) and all(
        isinstance(command, str) for command in commands
    ):
        normalized_commands = commands
    else:
        return _build_response(
            error="Commands must be a string or a list of strings.",
            command_results=results,
        )

    if len(normalized_commands) == 0:
        return _build_response(
            error="Commands list cannot be empty.",
            command_results=results,
        )

    for index, command in enumerate(normalized_commands):
        normalized_commands[index] = command.strip()

    if any(len(command) == 0 for command in normalized_commands):
        return _build_response(
            error="Commands cannot contain empty values.",
            command_results=results,
        )

    # Validate continue_on_fail type.
    if not isinstance(continue_on_fail, bool):
        return _build_response(
            error="continue_on_fail must be a boolean.",
            command_results=results,
        )

    # Resolve and validate target host.
    resolved_addresses: HostAddresses = resolve_address(host)
    if resolved_addresses.success is not True:
        return _build_response(
            error=f"Failed to resolve host: {host}",
            command_results=results,
        )

    resolved_host: Optional[str] = None
    resolved_host_os: Optional[str] = None
    resolved_shell: Optional[str] = None
    for allowed_host, allowed_os, allowed_shell in ALLOWED_HOSTS:
        if allowed_host in [
            resolved_addresses.ipv4,
            resolved_addresses.ipv6,
            resolved_addresses.address,
        ]:
            resolved_host, resolved_host_os, resolved_shell = (
                allowed_host,
                allowed_os.lower().strip(),
                allowed_shell.lower().strip(),
            )
            break

    if resolved_host is None:
        return _build_response(
            error=f"Host {host} is not an allowed host.",
            command_results=results,
        )

    original_commands = normalized_commands.copy()
    try:
        if not ssh_gate(
            resolved_host, resolved_host_os, resolved_shell, normalized_commands
        ):
            return _build_response(
                error="Command aborted by acceptance gate.",
                command_results=results,
            )
    except Exception:
        return _build_response(
            error="Command aborted by acceptance gate error.",
            command_results=results,
        )

    remaining = normalized_commands.copy()
    aborted_by_gate: List[str] = []

    for cmd in original_commands:
        try:
            idx = remaining.index(cmd)  # find one matching occurrence
            remaining.pop(idx)  # consume it
        except ValueError:
            aborted_by_gate.append(cmd)

    # Record commands removed by the gate
    for cmd in aborted_by_gate:
        results.append(
            CommandResult(
                command=cmd,
                exit_code=-1,
                stdout="",
                stderr="Command aborted by acceptance gate.",
            )
        )

    try:
        with paramiko.SSHClient() as client:
            client.load_system_host_keys()
            client.set_missing_host_key_policy(paramiko.RejectPolicy())

            client.connect(
                hostname=resolved_host,
                port=PORT,
                username=USERNAME,
                timeout=CONNECT_TIMEOUT,
                look_for_keys=False,
                allow_agent=True,
            )

            for index, command in enumerate(normalized_commands):
                try:
                    wrapped_command = _wrap_with_timeout(
                        command, resolved_shell, EXECUTE_TIMEOUT, resolved_host_os
                    )
                    stdin, stdout, stderr = client.exec_command(
                        wrapped_command,
                        timeout=EXECUTE_TIMEOUT + 2,  # Add delay margin
                    )
                    stdin.close()

                    exit_code = stdout.channel.recv_exit_status()
                    stdout_text = stdout.read().decode("utf-8", errors="replace")
                    stderr_text = stderr.read().decode("utf-8", errors="replace")

                    if resolved_host_os == "windows":
                        stderr_text = _extract_plain_text_from_clixml(stderr_text)

                    stdout_text = (
                        _compress_whitespace_blocks(stdout_text)
                        if COMPRESS_OUTPUT
                        else stdout_text
                    )
                    stderr_text = (
                        _compress_whitespace_blocks(stderr_text)
                        if COMPRESS_OUTPUT
                        else stderr_text
                    )

                    results.append(
                        CommandResult(
                            command=command,
                            exit_code=exit_code,
                            stdout=stdout_text[: max(0, MAX_STDOUT_LENGTH)],
                            stderr=stderr_text[: max(0, MAX_STDERR_LENGTH)],
                        )
                    )

                    # Stop after the first failed command if continue_on_fail is disabled.
                    if exit_code != 0 and continue_on_fail is False:
                        for aborted_command in normalized_commands[index + 1 :]:
                            results.append(
                                CommandResult(
                                    command=aborted_command,
                                    exit_code=-1,
                                    stdout="",
                                    stderr="Aborted by continue_on_fail = false.",
                                )
                            )
                        break

                except Exception as exc:
                    results.append(
                        CommandResult(
                            command=command,
                            exit_code=-1,
                            stdout="",
                            stderr=f"Command execution failed: {str(exc)}",
                        )
                    )

                    if continue_on_fail is False:
                        for aborted_command in normalized_commands[index + 1 :]:
                            results.append(
                                CommandResult(
                                    command=aborted_command,
                                    exit_code=-1,
                                    stdout="",
                                    stderr="Aborted by continue_on_fail = false.",
                                )
                            )
                        break

            return _build_response(
                error=None,
                command_results=results,
            )

    except AuthenticationException:
        return _build_response(
            error="SSH authentication failed.",
            command_results=results,
        )
    except BadHostKeyException:
        return _build_response(
            error="SSH host key verification failed.",
            command_results=results,
        )
    except NoValidConnectionsError:
        return _build_response(
            error=f"Could not connect to {resolved_host}:{PORT}.",
            command_results=results,
        )
    except SSHException as exc:
        return _build_response(
            error=f"Generic SSH error occurred: {str(exc)}",
            command_results=results,
        )
    except Exception as exc:
        return _build_response(
            error=f"Unexpected error occurred: {str(exc)}",
            command_results=results,
        )


TOOL_DEFINITION = json.dumps(
    {
        "type": "function",
        "function": {
            "name": "ssh_client",
            "description": (
                "Runs non-interactive shell commands on a remote machine over SSH using agent-managed key authentication.\n"
                "Commands are executed remotely as the configured user (no implicit sudo).\n"
                "Each command is executed in a fresh, non-interactive shell session that typically starts in the user's home/profile directory.\n"
                "State does not persist between commands (e.g., `cd` in one command does not affect the next).\n"
                "If you need a different working directory, combine it into the same command (e.g., `cd /path && ...`).\n"
                "If a request is rejected by the acceptance gate, it is not an execution error; it means the user declined the action.\n"
                "The acceptance gate may also remove commands from the execution pipeline before execution.\n"
                f"Allowed hosts are (format: host/address, OS, shell): {ALLOWED_HOSTS}"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "host": {
                        "type": "string",
                        "description": "Hostname or IP address of the remote machine.",
                        "minLength": 1,
                        "maxLength": 255,
                    },
                    "commands": {
                        "description": (
                            "Remote shell command, or an ordered list of remote shell commands.\n"
                            "Provide raw commands only; the appropriate shell is applied automatically.\n"
                            "Do not prefix commands with `powershell`, `cmd /c`, `bash -lc`, or similar wrappers."
                        ),
                        "oneOf": [
                            {
                                "type": "string",
                                "minLength": 1,
                            },
                            {
                                "type": "array",
                                "items": {
                                    "type": "string",
                                    "minLength": 1,
                                },
                                "minItems": 1,
                            },
                        ],
                    },
                    "continue_on_fail": {
                        "type": "boolean",
                        "description": (
                            "Whether execution continues with the next item in the `commands` list after a command returns a non-zero exit code.\n"
                            "This only affects sequential execution of list entries and does not apply to control flow within a single command string."
                        ),
                        "default": False,
                    },
                },
                "required": ["host", "commands"],
                "additionalProperties": False,
            },
        },
    },
    ensure_ascii=False,
)
