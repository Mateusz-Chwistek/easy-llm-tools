import os
import sys
import json
import traceback
from pathlib import Path
from threading import Lock
from io import TextIOWrapper
from mcp.server.fastmcp import FastMCP
from typing import Any, Callable, Dict, Literal
from easy_llm_tools import VerboseLevel, VerboseSettings, LlmTools

TransportType = Literal["stdio", "streamable-http"]
AVAILABLE_TRANSPORTS: tuple[TransportType, ...] = ("streamable-http", "stdio")
DEFAULT_TRANSPORT: TransportType = "stdio"

if __name__ == "__main__":
    # Thread-safe log file shared by the easy-llm-tools verbose output.
    log_lock: Lock = Lock()
    permanent_dir: Path = Path(__file__).resolve().parent / "permanent"
    log_path: Path = permanent_dir / "logs" / "server.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_file: TextIOWrapper = open(log_path, "a")

    try:
        verbose_settings: VerboseSettings = VerboseSettings(
            VerboseLevel.HIGH,
            no_throw=False,
            output=log_file,
            lock=log_lock,
        )

        # Discover and load tool modules from /app/tools.
        # Only files matching the pattern mcp_*_tool.py are picked up.
        llm_tools: LlmTools = LlmTools(
            base_dir="/app/tools",
            verbose_settings=verbose_settings,
            max_depth=0,
            prefix="mcp_",
            suffix="_tool",
            prettify=True,
            validate=True,
            use_toon=False,
        )

        mcp: FastMCP = FastMCP(
            "easy-llm-tools-mcp",
            host=os.getenv("HOST", "0.0.0.0"),
            port=int(os.getenv("PORT", 9000)),
        )

        # Register each discovered tool with the MCP server.
        # The tool name and description come from the TOOL_DEFINITION JSON inside
        # each tool module; the runner is the module's tool_run function.
        for tool_name, meta in llm_tools.tools.items():
            definition: Dict[str, Any] = json.loads(meta["description"])
            func_def: Dict[str, Any] = definition["function"]
            runner: Callable[..., Any] = meta["runner"]

            mcp.add_tool(
                fn=runner,
                name=func_def["name"],
                description=func_def["description"],
            )

        # Fall back to the default transport if the env var is not recognized.
        transport_env: str = os.getenv("MCP_TRANSPORT", DEFAULT_TRANSPORT)
        transport: TransportType = (
            transport_env if transport_env in AVAILABLE_TRANSPORTS else DEFAULT_TRANSPORT
        )

        mcp.run(transport=transport)
    except Exception as error:
        log_file.write(
            f"\nMCP Server Error: {type(error).__name__}: {error}\n"
            f"{traceback.format_exc()}\n"
        )
        log_file.flush()
        sys.exit(1)
    finally:
        log_file.close()
