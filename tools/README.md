# Tools descriptions #

## Tool list ##

- [**SSH Client**](#ssh-client-ssh_client_toolpy)
  **SSH Client** executes **non-interactive** shell commands on remote machines
  over SSH and returns the results as a JSON string. It is intended for
  controlled, allow-listed access and should be used with a **SSH acceptance
  gate**.

- [**DNS Query Tool**](#dns-query-dns_query_toolpy)
  **DNS Query Tool** performs DNS lookups for selected record types and returns
  the output as a JSON string. It supports multiple transport methods and can
  also request **DNSSEC-related** data.

## SSH Client (ssh_client_tool.py) ##

**SSH Client** is a tool module that executes **non-interactive** shell
commands on a remote machine over SSH and returns the output as a JSON string.
It uses the **system SSH agent** for authentication, expects working
**key-based access** for the configured remote user, and resolves hostnames
through `address_resolver_helper.py` before enforcing the allow-list.

### What it does ###

- Validates the input fields:
  - `host`
  - `commands`
  - `continue_on_fail`
- Resolves the requested host using `address_resolver_helper.py`
- Allows the connection only if the resolved hostname/IP matches one of the
  configured `ALLOWED_HOSTS` entries
- Passes the command list through `ssh_gate(...)` before execution
- Connects over SSH using the configured user and the **system SSH agent**
- Verifies remote host keys against the **system known-hosts database**
- Executes commands in order and returns per-command results containing:
  - `command`
  - `exit_code`
  - `stdout`
  - `stderr`
- Applies per-command execution time limits
- Optionally stops execution after the first failed command
- Optionally compresses whitespace in command output to reduce token usage
- Truncates stdout/stderr to configured maximum lengths

### Important behavior ###

> ⚠ **IMPORTANT:** This tool is **non-interactive**. The model cannot answer
> SSH prompts, password prompts, MFA challenges, sudo prompts, confirmation
> prompts, or any other interactive shell questions.

Commands are executed as the configured remote user only. The tool does not add
implicit privilege escalation.

### How to configure ###

All configuration is done by editing constants at the top of
`ssh_client_tool.py`:

- `ALLOWED_HOSTS`: list of allowed remote targets in the format
  `(host/address, target OS, default shell)`.
  - Supported host values:
    - IPv4
    - IPv6
    - hostname/address
  - Hostnames are resolved before allow-list matching.
  - The configured OS and shell are used to choose the command wrapper and
    timeout behavior.
- `PORT`: SSH port used for the remote connection.
- `USERNAME`: remote account name used for authentication.
- `CONNECT_TIMEOUT`: maximum time allowed to establish the SSH connection.
- `EXECUTE_TIMEOUT`: maximum time allowed for a single command.
- `MAX_STDOUT_LENGTH` / `MAX_STDERR_LENGTH`: maximum returned output size per
  command.
- `COMPRESS_OUTPUT`: whether repeated whitespace is compressed before returning
  command output.

### SSH authentication requirements ###

This tool uses the **system SSH agent** and expects **key-based
authentication** to be already configured and working. It does **not** use
passwords and it does **not** scan for private keys on disk.

Using the SSH agent is recommended for **security reasons**: it avoids passing
passwords in **plain text** and avoids exposing raw credentials directly to the
model.

Before using the tool, make sure that:

- the required private key is already loaded into the **system SSH agent**
- the remote SSH server accepts that key for the configured `USERNAME`
- the remote account already exists
- the remote host key is already present in the **system known-hosts database**

Because **host key verification** is enforced, connections to unknown hosts are
rejected until their host keys are trusted by the local system.

### DNS configuration for allow-list resolution ###

This tool uses `address_resolver_helper.py` to resolve hostnames and IP
addresses before checking the allow-list. Because of that, **DNS configuration**
for SSH allow-list behavior must be adjusted in
`address_resolver_helper.py`, not in `ssh_client_tool.py`.

In particular, review and configure:

- `DNS_SERVERS`
- `TIMEOUT`
- `TRANSPORT_METHOD`
- `ENDPOINT_URL`
- `DOT_SNI`
- `DOQ_SNI`
- `USE_DNSSEC`

This is especially important when allowed hosts use **internal DNS names**,
**split-horizon DNS**, **reverse DNS**, or **custom recursive resolvers**.

### SSH acceptance gate ###

This tool is designed to work with a user-provided `ssh_gate(...)`
implementation. The provided `example_ssh_gate.py` is only a **template**
showing the required function signature and expected behavior.

The gate is called **before** any SSH command is executed and may:

- approve execution
- reject execution
- modify the command list in place before execution

> ⚠ **SECURITY WARNING:** Using a custom gate is strongly recommended.
> Exposing raw SSH command execution directly to a model is dangerous and makes
> prompt-injection abuse much easier.

Because the tool workflow is **non-interactive**, the production gate should
also be designed for **non-interactive** use. The example gate is best treated
as an interface example, not as a production-ready approval mechanism.

For production usage, replace the example gate with your own implementation that
matches your environment and security requirements.

### Requirements ###

Python packages to install:

- Base (required):
  - `paramiko`
  - `dnspython`

- Additional (only if you enable DNS-over-QUIC in
  `address_resolver_helper.py`):
  - `aioquic` (recommended via dnspython extra)

Install commands:

```bash
python -m pip install paramiko dnspython
python -m pip install "dnspython[doq]"
```


## DNS Query (dns_query_tool.py) ##

**DNS Query** is a tool module that performs **DNS lookups** and returns the
output as a **JSON string**. It supports multiple **DNS transport methods**,
validates record types against an allow-list, and can optionally request
**DNSSEC-related** data.

### What it does ###

- Validates the input fields:
  - `qname`
  - `qtype`
- Validates the requested record type against `ALLOWED_RECORD_TYPES`
- Normalizes the requested record type to upper case
- Automatically converts **IP literals** to **reverse-pointer form** for `PTR`
  queries
- Builds a DNS query using **dnspython**
- Executes the query using the configured **transport method**
- Returns a **JSON response** containing:
  - `qname`
  - `qtype`
  - `dns_server`
  - `transportMethod`
  - `dnssec`
  - `success`
  - `error`
  - `result`

### Important behavior ###

> ⚠ **IMPORTANT:** This tool uses only the **transport method** configured in
> `dns_query_tool.py`. It does **not** dynamically switch between `plain`,
> `doh`, `dot`, and `doq` at runtime unless you change the configuration.

For `PTR` queries, the tool accepts either:

- an **IP address literal**, such as `1.2.3.4` or `2001:4860:4860::8888`
- an already prepared **reverse DNS name**, such as
  `4.3.2.1.in-addr.arpa`

When **`USE_DNSSEC`** is enabled, the tool sets the **DO bit** in the query and
reports **DNSSEC** status based on the resolver's **AD flag**. This means
**DNSSEC** status depends on the upstream resolver and should only be trusted
if that resolver is trusted.

### How to configure ###

All configuration is done by editing constants at the top of
`dns_query_tool.py`:

- `DNS_SERVERS`: list of resolver IPs.
  - **Plain DNS** uses all entries and tries them in order until a query
    succeeds.
  - **DoT** and **DoQ** use the first configured server only.
  - **DoH** uses the configured IPs as bootstrap addresses for the HTTPS
    endpoint.
- `TIMEOUT`: per-request timeout in seconds for all supported transports.
- `ALLOWED_RECORD_TYPES`: allow-list of accepted DNS record types.
- `TRANSPORT_METHOD`: selected transport method, one of:
  - `plain`
  - `doh`
  - `dot`
  - `doq`
- `ENDPOINT_URL`: **DNS-over-HTTPS** endpoint URL.
- `DOT_SNI`: **TLS server name** used for **DNS-over-TLS** certificate
  validation.
- `DOQ_SNI`: **TLS server name** used for **DNS-over-QUIC** certificate
  validation.
- `USE_DNSSEC`: enables the **DNSSEC DO bit** in outgoing queries.

### Response format ###

The tool returns a **JSON string** with the following fields:

- `qname`: queried domain name or original input name
- `qtype`: record type used for the query
- `dns_server`: resolver IP or endpoint URL used for the query
- `transportMethod`: one of `plain`, `doh`, `dot`, `doq`
- `dnssec`: `yes` if the resolver returned the **AD flag**, otherwise `no`
- `success`: `true` when the query completed successfully
- `error`: diagnostic message text
- `result`: flat list of answer items returned from the DNS response

### Requirements ###

Python packages to install:

- Base (**required**):
  - `dnspython`

- Additional (**only if you enable DNS-over-QUIC / `doq`**):
  - `aioquic` (**recommended** via dnspython extra)

Install commands:

```bash
python -m pip install dnspython
python -m pip install "dnspython[doq]"
```
