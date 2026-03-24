# easy-llm-tools #

**Version:** 0.2.0\
**License:** MIT

## Overview ## 

`easy-llm-tools` provides a simple, automated way to manage *“tools”* for **LLM workflows**. It scans a directory for tool modules, loads each tool’s JSON definition and runner function, and exposes them through a single registry. You can quickly fetch tool definitions for prompts and execute tools by name with consistent logging and error handling.

## MCP Server ##

`easy-llm-tools` includes a Docker-based MCP server that exposes tool modules over the Model Context Protocol. It uses `easy-llm-tools` internally to discover and load tools, then registers each one with the MCP server.

### Setup ###

> ℹ **INFO:** Run commands from easy-llm-tools directory.

#### 1. Build the Docker image ####

```bash
docker build -t easy-llm-tools-mcp .
```

#### 2. Run the container ####

```bash
docker run -d --name easy-llm-tools-mcp easy-llm-tools-mcp
```

### Environment variables ###
> ℹ **INFO:** Variables configure the server **inside** the container only. Docker-level settings (port publishing, network config) must match accordingly:
> - `MCP_TRANSPORT` - If set to an unrecognized value, the server silently falls back to `"stdio"`.
> - `HOST` - Must match the container's bind address. Use `"0.0.0.0"` (or leave empty) to accept connections from outside the container.
> - `PORT` - The container-internal port. You must publish the same port with `-p` in `docker run` (e.g. `-p 9000:9000`).
> - `LOG_PATH` - Path inside the container. To persist logs, mount the parent directory as a volume (see [Persistent logging](#persistent-logging-)).

All environment variables are optional. Defaults are shown below.

- `MCP_TRANSPORT` - Transport protocol. `"stdio"` (default) or `"streamable-http"`.
- `HOST` - Bind address for the streamable-http transport. Default: `"0.0.0.0"`.
- `PORT` - Bind port for the streamable-http transport. Default: `9000`.
- `LOG_PATH` - Path to the server log file inside the container. Default: `"/var/log/easy_llm_tools_mcp/server.log"`.

Example with streamable-http:

```bash
docker run -d -p 9000:9000 \
    -e MCP_TRANSPORT=streamable-http \
    -e PORT=9000 \
    --name easy-llm-tools-mcp \
    easy-llm-tools-mcp
```

### Persistent logging ###

By default logs are written to `/var/log/easy_llm_tools_mcp/` inside the container and lost when the container is removed. To persist them, mount a Docker volume:

```bash
docker run -d -p 9000:9000 \
    -e MCP_TRANSPORT=streamable-http \
    -v easy-llm-tools-logs:/var/log/easy_llm_tools_mcp \
    --name easy-llm-tools-mcp \
    easy-llm-tools-mcp
```

### Claude Code integration ###

Add the following to your `settings.json` (user or project level) to register the MCP server with Claude Code:

```json
{
  "mcpServers": {
    "easy-llm-tools": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "easy-llm-tools-mcp"]
    }
  }
}
```

> ℹ **INFO:** The `stdio` transport requires `-i` (interactive) so Docker keeps stdin open for the MCP protocol. Do not use `-d` (detached) or `-t` (tty) here.

Example with a custom log path and persistent logging volume:

```json
{
  "mcpServers": {
    "easy-llm-tools": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "LOG_PATH=/var/log/mcp/server.log",
        "-v", "easy-llm-tools-logs:/var/log/mcp",
        "easy-llm-tools-mcp"
      ]
    }
  }
}
```

### Adding tools ###

> ⚠ **WARNING:** The `ssh_client` tool is not recommended for use with the MCP server. It relies on a command approval hook (`approve_command`) that expects a local interactive gate, which does not translate well to a containerized MCP environment.

The server discovers tool modules from `/app/tools` inside the container. Only files matching the pattern `mcp_*_tool.py` are loaded (prefix `mcp_`, suffix `_tool`).

To add a new tool:

1. Create a tool module following the naming convention (e.g. `mcp_my_tool_tool.py`).
2. Place it in the `tools/` directory. The `Dockerfile` copies all `mcp_*_tool.py` files automatically.
3. If the tool has Python dependencies, add them to `tools/mcp_requirements.txt` - they are installed during the Docker build.
4. If the tool uses helper modules, place them in `tools/helpers/` - that directory is also copied into the image. Helpers requirements should also be placed inside `tools/mcp_requirements.txt`.
5. Rebuild the image.

> The tool file must define `TOOL_DEFINITION` (JSON string) and a `tool_run` function, same as any other `easy-llm-tools` tool. See the [Defining tools](#defining-tools-) section below for details.

### MCP server dependencies ###

The MCP server has its own requirements file at `src/easy_llm_tools_mcp/requirements.txt`, separate from tool-specific dependencies in `tools/requirements.txt`.

### Selecting tools ###

Tool selection is controlled by the filename pattern. The server uses `prefix="mcp_"` and `suffix="_tool"`, so only files named `mcp_<name>_tool.py` are picked up. Files without the `mcp_` prefix (e.g. `dns_query_tool.py`) are ignored.

This lets you keep MCP-specific and non-MCP tool modules in the same `tools/` directory without conflicts.

## Library ##

### Features ###

- Scans a base directory (with optional depth limit) to discover tool modules by filename pattern (`prefix*suffix.py`).
- Loads tool modules and registers them under a tool name derived from the filename.
- Extracts and exposes `TOOL_DEFINITION` (JSON string) for prompt/tool registry usage.
- Executes tools by name via the loaded `tool_run` runner.
- Optional JSON validation for `TOOL_DEFINITION`.
- Optional “LLM/token-friendly” prettifying of tool definitions (compact arrays + small indentation).
- Skips oversized files (>1MB) to avoid accidental/non-tool modules.
- Configurable verbosity/logging (`VerboseLevel`) with optional thread lock and output target.
- Consistent error handling via `no_throw` mode (raise vs suppress).

### Installation ###

Clone the repository and install it with pip:

```bash
git clone https://github.com/Mateusz-Chwistek/easy-llm-tools.git
cd easy-llm-tools
```

#### Windows ####
```bash
python -m pip install .
```

#### Linux ####
```bash
python3 -m pip install .
```

Import example:

```python
from easy_llm_tools import LlmTools, VerboseSettings, VerboseLevel
```

### Defining tools ###
> ℹ **INFO:** To avoid side effects at import time, put test code under if `__name__ == "__main__":`

Tools are defined inside Python files.

#### File requirements ####

##### File naming #####
> ℹ **INFO:** By default `LlmTools` expects names with `_tool` suffix. This behavior can be changed using `suffix` parameter.

> ℹ **INFO:** If `prefix=None` or `suffix=None`, they are treated like empty strings.

> ⚠ **WARNING:** The filename must contain a non-empty "main" part between prefix and suffix.
> A name like `_tool.py` (with empty middle part) is rejected.

File must be a **Python** file.
**File name** should consist of 3 parts where **prefix** and **suffix** may be empty.

Name structure should look like: `prefix_main_suffix.py`

###### Examples ######
- **simple name**: calc.py
- **with prefix**: myproject-calc.py
- **with suffix**: calc_tool.py
- **with both**: myproject-calc_tool.py  

Its **main** name part *(name without prefix/suffix and extension)* must correspond to name defined inside `TOOL_DEFINITION`.

> ℹ **INFO:** The tool registry key is derived from the filename: it removes the configured `prefix` and `suffix` from the filename stem.
>
> **Example:** `prefix="myproject-"`, `suffix="_tool"`, file `myproject-calc_tool.py` -> tool name `calc`.

> ⚠ **WARNING:** `run_tool()` looks up tools by that derived name. The library does not enforce that `"function.name"` inside `TOOL_DEFINITION` matches the derived name - it’s a user contract. If they differ, the model may call a name that is not registered and you’ll get "`<name>` is not a registered tool".

###### Example ######
**Name**: myproject-calc_tool.py\
**Settings**: prefix="", suffix="_tool"
**Tool definition**: 
```json
    {
        "type": "function",
        "function": {
            "name": "myproject-calc", <- this must match the main name part
            [...]
```

##### File content #####
Each file should contain exactly one tool, and must define `tool_run` **function**, and `TOOL_DEFINITION` **JSON string**.\
You may use other functions inside the file.
> ⚠ **WARNING:** Be aware that all code inside files will be executed while gathering tools.

> ℹ **INFO:** Tools are executed as `tool_run(**arguments_dict)`.
>
> This means your `tool_run` should accept keyword arguments matching the JSON schema.
>
> If you want to ignore extra fields, add a `**kwargs` parameter.

###### Example tool_run definition (`example_tool.py`) ######

```Python
def _normalize_whitespace(text: str) -> str:
    """Helper function used by the tool."""
    return " ".join(text.split()).strip()


def repeat_text(text: str, times: int = 1) -> str:
    """Tool task logic."""
    cleaned = _normalize_whitespace(text)

    try:
        n = int(times)
    except Exception:
        n = 1

    n = max(1, min(n, 10))
    return " | ".join([cleaned] * n)


def tool_run(text: str, times: int = 1) -> str:
    """
    Tool entry point.
    """
    return repeat_text(text=text, times=times)
```

###### Example TOOL_DEFINITION ######

```Python
TOOL_DEFINITION = json.dumps(
    {
        "type": "function",
        "function": {
            "name": "example",  # tool name used by the model
            "description": "Normalize whitespace in text and repeat it N times (1-10).",
            "parameters": {
                "type": "object",
                "properties": {
                    "text": {"type": "string", "description": "Text to process."},
                    "times": {
                        "type": "integer",
                        "description": "Repetitions (1-10).",
                        "minimum": 1,
                        "maximum": 10,
                    },
                },
                "required": ["text"],
            },
        },
    },
    ensure_ascii=False,
)
```

### Usage ###

#### Verbosity levels ####
Verbosity levels are used to change what messages will be displayed.

There are four verbosity levels:
- **NONE**: No messages are displayed
- **LOW**: Only basic messages
- **MID**: Basic messages with some diagnostics
- **HIGH**: All messages are displayed

Verbosity levels are defined in `VerboseLevel` enum and might be accessed by `VerboseLevel.LEVEL` e.g. `VerboseLevel.LOW`.

#### Verbosity settings ####
Verbosity settings are used to define library outputs.

You can define them using `VerboseSettings` class.

`VerboseSettings` takes those arguments:

- **verbose_level** *(VerboseLevel)*: *positional*, **default**: `VerboseLevel.NONE` - Defines verbosity level for all outputs.
- **no_throw** *(bool)*: *keyword-only*, **default**: `False` - If `True`, suppress errors (return early / defaults instead of raising).
- **output** *(TextIO)*: *keyword-only*, **default**: `sys.stdout` - Output stream used by verbose printing (must provide `write(str)`).
- **lock** *(Optional[LockType])*: *keyword-only*, **default**: `None` - Optional lock to avoid interleaved output when printing from multiple threads.

#### LlmTools ####

##### Creating instance #####
> ⚠ **WARNING:** Creating instance runs `scan_tools` automatically, please be aware that it will execute code inside imported tools.

You can manage and run tools using the `LlmTools` class.

`LlmTools` takes those arguments:

* **base_dir** *(str | Path)*: *positional*, **required** - Base directory where tool files are searched (e.g. `./tools`).
* **verbose_settings** *(Optional[VerboseSettings])*: *positional*, **default**: `None` - Verbose configuration. If `None` (or invalid), a default `VerboseSettings()` instance is used.
* **max_depth** *(int)*: *keyword-only*, **default**: `0` - Maximum directory depth to traverse from `base_dir`. `0` means only `base_dir`, `1` includes direct subfolders, etc.
* **prefix** *(Optional[str])*: *keyword-only*, **default**: `None` - Optional filename prefix filter used when discovering tool files.
* **suffix** *(Optional[str])*: *keyword-only*, **default**: `"_tool"` - Optional filename suffix filter used when discovering tool files (before `.py`).
* **prettify** *(bool)*: *keyword-only*, **default**: `True` - Prettifies `TOOL_DEFINITION` JSON strings (LLM/token-friendly formatting). When enabled, it also validates JSON.
* **validate** *(bool)*: *keyword-only*, **default**: `False` - Validates `TOOL_DEFINITION` as JSON (keeps it as string). Ignored when `prettify=True`.
* **use_toon** *(bool)*: *keyword-only*, **default**: `False` - Reserved for future TOON format support (currently not implemented).

###### Example ######
```Python
from easy_llm_tools import *

# 1) Configure verbosity (HIGH = detailed logs)
verbose = VerboseSettings(verbose_level=VerboseLevel.HIGH)

# 2) Create the tool registry (scan only "./tools", depth=0)
tools = LlmTools(
    base_dir="./tools",
    verbose_settings=verbose,
    max_depth=0
)
```

##### Rescanning tools #####
> ℹ **INFO:** Tool scanning is run automatically when creating instance.

> ⚠ **WARNING:** Overwrite is determined by the derived tool name 
*(the filename stem after removing `prefix`/`suffix`, i.e. the “main part”)*,
not by `"function.name"` inside `TOOL_DEFINITION`.
If two tools share the same derived name, the later found tool will overwrite the earlier one.


You can rescan tools by calling the `scan_tools()` **method (no arguments)**.

###### Example ######

```Python
tools.scan_tools()
```

##### Tool definitions #####
To allow **LLMs** to use tools, you must pass tool definitions to the system prompt. 
To get **tool definitions** from gathered tools You **must** use the **zero-args function** `get_tool_definitions`.

This function returns a dictionary: `{"<tool_name>": "<tool_definition>"}`

###### Example ######

```Python
tool_defs = tools.get_tool_definitions()

# Extract tools definitions from dict
tools_for_model = [json.loads(def_str) for def_str in tool_defs.values()]
```

##### Running tools #####

`run_tool` executes a registered tool either from an LLM tool-call payload (**recommended**) or from explicit fallback arguments.

If `no_throw=False` (default), invalid inputs, missing tools, argument mismatches, or runtime failures will raise an exception.
If `no_throw=True`, errors are suppressed and the function returns `None`.

It supports common tool-call JSON formats:

* Tool name under **`"name"`** or **`"function_name"`**
* Arguments under **`"arguments"`** or **`"parameters"`**

  * Arguments may be a JSON object **or** a JSON-encoded string.

> ℹ **INFO:** `run_tool` accepts the tool call as a JSON string **or** as an already-parsed Python `dict`.

###### Expected JSON payload examples ######

```json
{"name":"test","arguments":{"text":"Hello     world","times":3}}
```

```json
{"function_name":"test","parameters":{"text":"Hello     world","times":3}}
```

Single-item list wrapper (also supported):

```json
[{"name":"test","arguments":{"text":"Hello     world","times":3}}]
```

###### Example Dict ######

```python
tool_call = {
  "name": "test",
  "arguments": {"text": "  Hello     from     Qwen    ", "times": 3}
}
```

result = tools.run_tool(tool_call)
print(result)

###### Example ######

```python
# Example tool-call payload (usually produced by the model)
tool_call = '{"name":"test","arguments":{"text":"Hello     world","times":3}}'

result = tools.run_tool(tool_call)
print(result)
```

###### Fallback example (manual call, no model output) ######
> ℹ **INFO:** If your **LLM** doesn't return any of the supported formats 
you may manually parse tool call and pass appropriate parameters manually.

```python
result = tools.run_tool(
    tool_call=None,
    tool_name="test",
    tool_args={"text": "Hello     world", "times": 3},
)

print(result)
```

## Contributing ##

Feel free to fork this project and make pull requests if you find bugs or have ideas for new features.

### License ##

This project is licensed under the MIT License. See the LICENSE file for details.