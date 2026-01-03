import json
from pathlib import Path
from typing import Optional, Dict, Any
from .verbose_settings import VerboseSettings
from ._utils import return_or_raise
from ._tools_finder import find_tools_json

class LlmTools:
    """
    Tool registry for LLM-oriented "tools" discovered from Python files on disk.

    The scanner loads tool modules and builds a registry in `self.tools` with the shape:
        {
            "<tool_name>": {
                "description": "<TOOL_DEFINITION JSON string>",
                "runner": <callable tool_run>
            }
        }

    Notes:
        - Tool discovery imports modules from files, which executes top-level code in those modules.
    """
    def __init__(
        self,
        base_dir: str | Path,
        verbose_settings: Optional[VerboseSettings] = None,
        *,
        max_depth: int = 0,
        prefix: Optional[str] = None,
        suffix: Optional[str] = "_tool",
        prettify: bool = True,
        validate: bool = False,
        use_toon: bool = False
    ) -> None:
        """
        Create a tool registry and immediately scan for tools.

        :param base_dir: Base directory to scan for tool files.
        :type base_dir: str | Path
        
        :param verbose_settings: Verbose configuration controlling logging and error behavior.
            If None (or invalid), a default VerboseSettings() is used.
        :type verbose_settings: Optional[VerboseSettings]
        
        :param max_depth: Maximum directory depth to traverse from base_dir.
            Depth=0 means only base_dir. Depth=1 includes direct subdirectories, etc.
        :type max_depth: int
        
        :param prefix: Optional filename prefix used for filtering tool files.
        :type prefix: Optional[str]
        
        :param suffix: Optional filename suffix used for filtering tool files (default "_tool").
        :type suffix: Optional[str]
        
        :param prettify: If True, prettify TOOL_DEFINITION JSON string (LLM/token-friendly formatting).
            When enabled, `validate` is ignored.
        :type prettify: bool
        
        :param validate: If True, validate TOOL_DEFINITION as JSON (keeps it as string). Ignored when prettify=True.
        :type validate: bool
        
        :param use_toon: Reserved for future TOON support (currently not implemented).
        :type use_toon: bool
        
        :raises NotImplementedError: If use_toon=True.
        """
        
        # Store settings; if caller doesn't provide VerboseSettings, fall back to a default instance.
        self.verbose_settings: VerboseSettings = verbose_settings if isinstance(verbose_settings, VerboseSettings) else VerboseSettings()
        self.base_dir: str | Path = base_dir
        self.max_depth: int  = max_depth
        self.prefix: Optional[str] = prefix
        self.suffix: Optional[str] = suffix
        self.prettify: bool = prettify
        self.validate: bool = validate
        
        # Future format switch (TOON support planned).
        self.use_toon: bool = use_toon
        
        # Initial tool discovery happens on construction for convenience.
        self.scan_tools()
        
    def scan_tools(self) -> None:
        """
        Scan the filesystem for tool files and populate `self.tools`.

        :raises NotImplementedError: If `use_toon=True`.
        :raises Exception: Propagates exceptions depending on `verbose_settings.no_throw`
            behavior inside the underlying scanner.
        """
        
        if not self.use_toon:
            self.tools = find_tools_json(
                self.base_dir,
                self.verbose_settings,
                max_depth=self.max_depth,
                prefix=self.prefix,
                suffix=self.suffix,
                prettify=self.prettify,
                validate=self.validate
            )
        else:
            # Placeholder for future TOON-based tool definitions.
            raise NotImplementedError("TOON format is not implemented yet")
        
    def get_tool_definitions(self) -> Dict[str, str]:
        """
        Return tool definitions (descriptions) keyed by tool name.

        :return: Mapping {tool_name: TOOL_DEFINITION_string}.
        :rtype: Dict[str, str]
        
        :raises RuntimeError: If tools were not scanned yet (missing `self.tools`).
        """
        
        # Ensure tools were scanned before trying to access them.
        if not hasattr(self, "tools"):
            raise RuntimeError(
                "`self` has no attribute `tools`. \
                    Create a `LlmTools` instance first, or run `scan_tools()`"
            )
        
        # Return only the tool descriptions (TOOL_DEFINITION strings) keyed by tool name.
        return {
            name: str(meta.get("description", ""))
            for name, meta in self.tools.items()
        }
        
    def run_tool(
        self,
        tool_call: Optional[str | Dict] = None,
        *,
        tool_name: Optional[str] = None,
        tool_args: Optional[Dict[str, Any]] = None
    ) -> Optional[Any]:
        """
        Execute a registered tool using either a tool-call payload (preferred) or explicit fallback arguments.

        The primary input is `tool_call`, which can be:
            - str: JSON text produced by an LLM (e.g., {"name": "...", "arguments": {...}})
            - dict: already-parsed payload with the same structure

        Supported payload fields:
            - Tool name: "name" or "function_name"
            - Tool args: "parameters" or "arguments"
                - args may be a dict OR a JSON-encoded string that will be decoded

        Fallback behavior:
            - If `tool_call` is None or cannot be parsed into (name, args),
            this method falls back to `tool_name` + `tool_args` (if provided).

        :param tool_call: Tool-call payload as JSON string or dict. Can also be a single-item list (see notes in code).
        :type tool_call: Optional[str | Dict]
        
        :param tool_name: Fallback tool name if `tool_call` is missing/invalid.
        :type tool_name: Optional[str]
        
        :param tool_args: Fallback tool arguments if `tool_call` is missing/invalid.
        :type tool_args: Optional[Dict[str, Any]]
        
        :return: Whatever the tool runner returns. If `no_throw` is enabled, returns None on failure.
        :rtype: Optional[Any]
        
        :raises RuntimeError: If tools were not scanned yet (missing `self.tools`) or `verbose_settings` is missing.
        :raises TypeError: For invalid argument types (when no_throw is False).
        :raises ValueError: For unknown tool-call format / missing tool / missing fallback name (when no_throw is False).
        :raises RuntimeError: If runner is missing/non-callable or execution fails (when no_throw is False).
        """

        # Ensure tools were scanned before trying to run anything.
        if not hasattr(self, "tools"):
            raise RuntimeError(
                "`self` has no attribute `tools`. "
                "Create a `LlmTools` instance first, or run `scan_tools()`"
            )

        # VerboseSettings is required for consistent error-handling behavior.
        if not hasattr(self, "verbose_settings"):
            raise RuntimeError(
                "`self` has no attribute `verbose_settings`. "
                "Create a `LlmTools` instance first."
            )

        # no_throw controls whether we return None on errors or raise exceptions.
        no_throw = self.verbose_settings.no_throw if self.verbose_settings is not None else False

        parsed_name: Optional[str] = None
        parsed_args: Optional[Dict[str, Any]] = None

        # --- Primary path: parse tool_call JSON ---
        if tool_call is not None:
            is_str: bool = isinstance(tool_call, str)
            if not is_str and not isinstance(tool_call, dict):
                return return_or_raise(
                    no_throw,
                    return_value=None,
                    exception_factory=lambda: TypeError("`tool_call` must be of type str, dict or None"),
                )

            # If tool_call is a JSON string, decode it. If it's already a dict, use it as-is.
            if is_str:
                try:
                    payload = json.loads(tool_call)
                except Exception:
                    payload = None
            else:
                payload = tool_call

            # Some tool-call outputs wrap the payload in a single-item list.
            # Accept: [{"name": "...", "arguments": {...}}] as equivalent to {"name": "...", ...}.
            if isinstance(payload, list):
                if len(payload) == 1 and isinstance(payload[0], dict):
                    payload = payload[0]
                else:
                    payload = None

            if isinstance(payload, dict):
                # Name: try "name" first, then "function_name"
                candidate_name = payload.get("name", None)
                if candidate_name is None:
                    candidate_name = payload.get("function_name", None)

                # Args: try "parameters" first, then "arguments"
                candidate_args = payload.get("parameters", None)
                if candidate_args is None:
                    candidate_args = payload.get("arguments", None)

                # Missing args means "no arguments"
                if candidate_args is None:
                    candidate_args = {}

                # Sometimes args are embedded as a JSON-encoded string; decode it if needed.
                if isinstance(candidate_args, str):
                    try:
                        candidate_args = json.loads(candidate_args)
                    except Exception:
                        candidate_args = None

                # Accept only if we got a non-empty name and args as a dict.
                if isinstance(candidate_name, str) and candidate_name.strip() and isinstance(candidate_args, dict):
                    parsed_name = candidate_name
                    parsed_args = candidate_args

        # --- Fallback path: explicit tool_name/tool_args ---
        if parsed_name is None:
            # If tool_call is missing/invalid, require explicit fallback name.
            if tool_name is None:
                return return_or_raise(
                    no_throw,
                    return_value=None,
                    exception_factory=lambda: ValueError(
                        "Unknown tool-call format or missing `tool_call`; "
                        "fallback `tool_name` must be provided"
                    ),
                )

            if not isinstance(tool_name, str) or not tool_name.strip():
                return return_or_raise(
                    no_throw,
                    return_value=None,
                    exception_factory=lambda: TypeError("`tool_name` must be a non-empty str"),
                )

            # Missing args means "no arguments"
            if tool_args is None:
                tool_args = {}

            if not isinstance(tool_args, dict):
                return return_or_raise(
                    no_throw,
                    return_value=None,
                    exception_factory=lambda: TypeError("`tool_args` must be a dict or None"),
                )

            parsed_name = tool_name
            parsed_args = tool_args

        # At this point, parsed_name and parsed_args are set
        tool_name_final: str = parsed_name
        tool_args_final: Dict[str, Any] = parsed_args if parsed_args is not None else {}

        # Ensure the requested tool exists in the registry.
        if tool_name_final not in self.tools:
            return return_or_raise(
                no_throw,
                return_value=None,
                exception_factory=lambda: ValueError(f"`{tool_name_final}` is not a registered tool"),
            )

        meta: Dict[str, Any] = self.tools.get(tool_name_final, {})
        runner = meta.get("runner", None)

        # Runner must be callable; otherwise the tool entry is malformed.
        if not callable(runner):
            return return_or_raise(
                no_throw,
                return_value=None,
                exception_factory=lambda: RuntimeError(f"Registered tool `{tool_name_final}` has no callable `runner`"),
            )

        # Execute tool; when no_throw is enabled, swallow runtime errors and return None.
        try:
            return runner(**tool_args_final)

        except Exception as ex:
            if no_throw:
                return None

            raise RuntimeError(
                f"Tool `{tool_name_final}` execution failed. Exception ({type(ex).__name__}): {ex}"
            )