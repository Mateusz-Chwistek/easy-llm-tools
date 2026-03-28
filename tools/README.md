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

- [**Private Vault**](#private-vault-private_vault_toolpy)
  **Private Vault** gives the model **read-only** access to user-encrypted
  notes stored in a local SQLite database with two-layer AES-256-GCM
  encryption. Access is gated by a session key with a configurable secrecy
  level that is enforced both logically and cryptographically.

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


## Private Vault (private_vault_tool.py) ##

**Private Vault** is a tool module that gives the model **read-only** access to
user-managed encrypted notes. It runs a local **HTTPS server** (started
automatically on first import) backed by **SQLite** and **two-layer
AES-256-GCM** encryption (per-level key + per-user key). The model
authenticates with a **session key** that the user generates through the web UI,
scoped to a maximum **secrecy level**.

### What it does ###

- Starts the vault HTTPS server in a background daemon thread (if not already
  running)
- Accepts two actions:
  - `list`: returns all entries at or below the session key's secrecy level
    (id, title, tags, created/modified dates, secrecy level)
  - `read`: decrypts and returns the full content of a single entry by id
- Validates the session key on every call; returns an error with the unlock
  URL if the key is missing, invalid, or expired
- Enforces secrecy level checks: the model cannot list or read entries above
  the session key's level, even by guessing entry IDs
- Returns all results as JSON strings

### Important behavior ###

> **Session keys are short-lived.** By default they expire after 30 minutes.
> When a user generates a new session key via /unlock, the previous one is
> invalidated immediately.

> **Encryption keys exist only in memory.** Restarting the server process
> invalidates all active keys. Users must log in and unlock again.

> **The tool is read-only.** The model cannot create, edit, or delete entries.
> All write operations happen through the web UI only.

> **Startup is protected by a file lock.** When multiple processes try to start
> the vault simultaneously, only one proceeds; the others wait until the server
> is ready.

> **Registration is locked by default.** The first registered user becomes the
> admin and registration locks automatically. The admin can toggle registration
> open or closed via the "Reg: Locked/Open" button in the navbar.

### How to set up ###

1. Create a `.env` file in the `tools/` directory (see `.env.example`):
   ```
   VAULT_SECRET=your-strong-secret-here
   FLASK_SECRET=your-flask-session-secret-here
   VAULT_LEVEL_SECRET_0=your-level-0-secret
   VAULT_LEVEL_SECRET_1=your-level-1-secret
   VAULT_LEVEL_SECRET_2=your-level-2-secret
   VAULT_LEVEL_SECRET_3=your-level-3-secret
   ```
   All six secrets must be present and non-empty. Each should be a unique,
   strong random value. For MCP server deployment, name the file `mcp.env`
   instead. The Dockerfile copies `tools/mcp.env` to `/app/tools/.env`
   automatically.

2. On first startup the server generates a self-signed TLS certificate in
   `permanent/vault/certs/`. This certificate is reused on subsequent runs.

3. Open `https://localhost:8000` in a browser:
   - Register the first user account (this user becomes the **admin** and
     registration is **locked automatically**)
   - Log in
   - Create entries with titles, content, tags, and secrecy levels
   - Go to `/unlock`, re-enter your password, and select a secrecy level to
     generate a session key for the model

### How to configure ###

Configuration is split across several files. Each file has its constants at
the top with inline comments.

**`helpers/vault_service.py`** -- server and TLS settings:

- `VAULT_PORT`: HTTPS port (default: `8000`)
- `VAULT_HOST`: bind address (default: `127.0.0.1`). For MCP server
  deployment inside a Docker container, change this to `0.0.0.0`.
  Do not bind to `0.0.0.0` on bare metal -- the built-in server is
  not hardened for direct network exposure
- `CERT_VALIDITY_DAYS`: certificate validity period (default: `365`)

**`helpers/private_vault/key_vault.py`** -- encryption and key expiration:

- `SCRYPT_N` / `SCRYPT_R` / `SCRYPT_P`: scrypt cost parameters for key
  derivation
- `KEY_LENGTH`: derived AES key length in bytes (default: `32`)
- `MASTER_KEY_EXPIRATION_MINUTES`: web UI session key lifetime (default: `120`)
- `SESSION_KEY_EXPIRATION_MINUTES`: model session key lifetime (default: `30`)
- `NONCE_LENGTH`: AES-GCM nonce length in bytes (default: `12`)
- `ENV_PATH`: path to the `.env` file containing `VAULT_SECRET`, `FLASK_SECRET`,
  and `VAULT_LEVEL_SECRET_0..3`

**`helpers/private_vault/routes/auth.py`** -- password policy:

- `PASSWORD_MIN_LENGTH` / `PASSWORD_MAX_LENGTH`: allowed password length range
- `PASSWORD_REQUIRE_UPPERCASE` / `PASSWORD_REQUIRE_LOWERCASE`: letter requirements
- `PASSWORD_REQUIRE_DIGIT`: digit requirement
- `PASSWORD_REQUIRE_SPECIAL`: special character requirement
- `PASSWORD_SPECIAL_CHARS`: regex character class for allowed special characters

**`helpers/private_vault/routes/vault.py`** -- entry encryption options:

- `ENCRYPT_TITLES`: whether to encrypt entry titles before storing (default:
  `True`)
- `ENCRYPT_META`: whether to encrypt entry metadata before storing (default:
  `True`)

**`private_vault_tool.py`** -- tool settings:

- `UNLOCK_URL`: URL shown to the model when no valid session key is provided

### Secrecy levels ###

Each entry and each session key has a secrecy level. The model can only access
entries at or below the session key's level:

- `0` -- unclassified
- `1` -- confidential
- `2` -- secret
- `3` -- top secret

Secrecy levels are enforced both logically (access-control checks) and
cryptographically: each level has its own encryption key derived from a
dedicated secret. A session key for level 2 only receives level keys 0, 1,
and 2 -- it cannot decrypt level 3 data even if the access check is bypassed.

### Response format ###

The tool returns a JSON string with the following fields:

- `action`: the action that was performed (`list` or `read`)
- `success`: `true` when the action completed successfully
- `error`: diagnostic message (empty on success)
- `data`: action-specific payload
  - For `list`: array of entry objects (id, title, tags, dates, secrecy level)
  - For `read`: single entry object (id, title, content, tags, dates, secrecy
    level)

### Requirements ###

Python packages to install:

- `flask`
- `flask-login`
- `flask-sqlalchemy`
- `flask-wtf`
- `flask-limiter`
- `python-dotenv`
- `cryptography`

Install command:

```bash
python -m pip install flask flask-login flask-sqlalchemy flask-wtf flask-limiter python-dotenv cryptography
```
