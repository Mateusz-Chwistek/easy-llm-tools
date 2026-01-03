from pathlib import Path
from importlib import util
from ._utils import return_or_raise, print_verbose
from ._json_utils import prettify_json, is_valid_json
from .verbose_settings import VerboseLevel, VerboseSettings
from typing import Optional, Callable, Dict, Any

# Upper bound for a "tool" Python file. Anything above this is likely a mistake (or not a tool module).
_MAX_TOOL_FILE_SIZE_BYTES = 1_048_576  # 1MB

def find_tools_json(
    base_dir: str | Path,
    verbose_settings: VerboseSettings,
    *,
    max_depth: int = 0,
    prefix: Optional[str] = None,
    suffix: Optional[str] = "_tool",
    prettify: bool = True,
    validate: bool = False,
) -> Dict[str, Dict[str, Callable]]:
    """
    Discover and load tool modules from a directory tree.

    A file is considered a tool candidate if it matches:
        prefix + <anything> + suffix + ".py"

    For each loaded tool, this function extracts only:
        - TOOL_DEFINITION (str; expected to be JSON string)
        - tool_run (callable)

    :param base_dir: Base directory to scan (string path or pathlib.Path).
    :type base_dir: str | Path
    
    :param verbose_settings: Verbose configuration controlling logging and error behavior (no_throw, output, lock).
    :type verbose_settings: VerboseSettings

    :param max_depth: Maximum directory depth to traverse from base_dir.
        Depth=0 means "only base_dir". Depth=1 includes direct subdirectories, etc.
    :type max_depth: int

    :param prefix: Optional filename prefix used for filtering.
        The tool name is derived by removing this prefix from the filename stem.
    :type prefix: Optional[str]

    :param suffix: Optional filename suffix used for filtering (default "_tool").
        The tool name is derived by removing this suffix from the filename stem.
    :type suffix: Optional[str]

    :param prettify: If True, prettify TOOL_DEFINITION string (LLM/token-friendly formatting).
        When enabled, `validate` is ignored (prettify implies validation).
    :type prettify: bool

    :param validate: If True, validate TOOL_DEFINITION as JSON (keeps it as string).
        Ignored when `prettify=True`.
    :type validate: bool

    :return: Mapping of tool_name -> {"description": <TOOL_DEFINITION str>, "runner": <tool_run callable>}.
    :rtype: Dict[str, Dict[str, Callable]]

    :raises TypeError: For invalid argument types (when no_throw is False).
    :raises ValueError: For invalid argument values (when no_throw is False).
    :raises FileNotFoundError: If base_dir does not exist or is not a directory (when no_throw is False).

    Notes:
        - Importing a module executes its top-level code. Any statements at module scope will run during discovery.
        - Tool name is derived from the filename stem with prefix/suffix removed to match the tool identity
          expected by TOOL_DEFINITION.
        - If two different files produce the same tool name, the later one overwrites the earlier entry.
          This is intentional; a warning is logged, but discovery continues.
    """
    
    if not isinstance(verbose_settings, VerboseSettings):
        raise TypeError("`verbose_settings` must be a `VerboseSettings` instance")

    # ---- Validate input ----
    if not isinstance(base_dir, str) and not isinstance(base_dir, Path):
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: TypeError(
                "`base_dir` must be a non-empty str or `Path` instance"
            ),
        )
    
    if not isinstance(max_depth, int):
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: TypeError("`max_depth` must be of type int"),
        )
        
    if max_depth < 0:
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: ValueError("`max_depth` value must be >= 0"),
        )

    if prefix is not None and not isinstance(prefix, str):
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: TypeError("`prefix` must be a of type str or None"),
        )
    
    if prefix is None:
        prefix = ""
    
    if suffix is not None and not isinstance(suffix, str):
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: TypeError("`suffix` must be a of type str or None"),
        )
    
    if suffix is None:
        suffix = ""
        
    if not isinstance(prettify, bool):
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: TypeError("`prettify` must be a of type bool"),
        )
    
    if not isinstance(validate, bool):
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: TypeError("`validate` must be a of type bool"),
        )
    
    if prettify:
        validate = False
    
    base_path = Path(base_dir)
    try:
        base_path = base_path.expanduser().resolve()
    except Exception as ex:
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: RuntimeError(
                f"Failed to resolve base path. Exception ({type(ex).__name__}): {ex}"
            ),
        )

    if not base_path.is_dir():
        return return_or_raise(
            no_throw=verbose_settings.no_throw,
            return_value={},
            exception_factory=lambda: FileNotFoundError(
                f"Base directory does not exist or is not a directory: {base_path}"
            ),
        )

    # ---- Scan + load ----
    tools: Dict[str, Dict[str, Any]] = {}

    dirs_visited = 0
    files_seen = 0
    name_matched = 0
    skipped_too_big = 0
    skipped_import_error = 0
    skipped_missing_fields = 0
    skipped_invalid_description = 0
    accepted = 0

    # Iterative traversal
    stack: list[tuple[Path, int]] = [(base_path, 0)]

    while stack:
        current_dir, depth = stack.pop()
        dirs_visited += 1

        print_verbose(
            VerboseLevel.HIGH,
            f"Traversing dir (depth={depth}): {current_dir}",
            verbose_settings
        )

        try:
            entries = list(current_dir.iterdir())
        except Exception as ex:
            print_verbose(
                VerboseLevel.LOW,
                f"Cannot list directory '{current_dir}'. Exception ({type(ex).__name__}): {ex}",
                verbose_settings,
            )
            if not verbose_settings.no_throw:
                raise
            
            continue

        for entry in entries:
            # Directories (always traverse, depth-limited if max_depth is set)
            if entry.is_dir():
                if entry.is_symlink():
                    print_verbose(
                        VerboseLevel.HIGH,
                        f"Skipping symlinked directory: {entry}",
                        verbose_settings
                    )
                    continue

                if depth >= max_depth:
                    print_verbose(
                        VerboseLevel.HIGH,
                        f"Max depth reached; skipping directory: {entry}",
                        verbose_settings
                    )
                    continue

                stack.append((entry, depth + 1))
                continue

            # Files only
            if not entry.is_file():
                continue

            files_seen += 1

            # Only *.py
            if entry.suffix != ".py":
                continue
            
            # Name filter: prefix + <anything> + suffix
            stem = entry.stem
            if not (stem.startswith(prefix) and stem.endswith(suffix)):
                continue

            # Must have something between prefix and suffix
            if len(stem) <= (len(prefix) + len(suffix)):
                print_verbose(
                    VerboseLevel.HIGH,
                    f"Rejected by name (no middle part): {entry.name}",
                    verbose_settings
                )
                continue

            name_matched += 1

            # Size guard
            try:
                size = entry.stat().st_size
            except Exception as ex:
                print_verbose(
                    VerboseLevel.HIGH,
                    f"Cannot stat file '{entry}'. Exception ({type(ex).__name__}): {ex}",
                    verbose_settings,
                )
                
                if not verbose_settings.no_throw:
                    raise
                
                continue

            if size > _MAX_TOOL_FILE_SIZE_BYTES:
                skipped_too_big += 1
                print_verbose(
                    VerboseLevel.LOW,
                    f"Skipping file >1MB: {entry.name} ({size} bytes)",
                    verbose_settings
                )
                continue

            # Load module (executes top-level code)
            module_name = stem[len(prefix):]
            if suffix:
                module_name = module_name[:-len(suffix)]

            try:
                spec = util.spec_from_file_location(module_name, entry)
                if spec is None or spec.loader is None:
                    raise ImportError("Failed to create import spec/loader")

                module = util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception as ex:
                skipped_import_error += 1
                print_verbose(
                    VerboseLevel.LOW,
                    f"Import failed for '{entry.name}': {type(ex).__name__}: {ex}",
                    verbose_settings,
                )
                if not verbose_settings.no_throw:
                    raise
                
                continue

            # Extract only what we need
            try:
                runner = getattr(module, "tool_run", None)
                description_obj = getattr(module, "TOOL_DEFINITION", None)

                if not callable(runner):
                    raise AttributeError("Missing or non-callable `tool_run`")

                if not isinstance(description_obj, str):
                    raise TypeError("`TOOL_DEFINITION` must be a JSON string (type str)")

                description: str = str(description_obj)

                # Validate/prettify description JSON
                if validate or prettify:
                    result, _, error_message = is_valid_json(description, verbose_settings.no_throw)
                    if not result:
                        raise ValueError(error_message or "`TOOL_DEFINITION` is not valid JSON")
                
                if prettify:
                    description = prettify_json(description, verbose_settings)

            except Exception as ex:
                skipped_missing_fields += 1
                if isinstance(ex, ValueError) and "JSON" in str(ex):
                    skipped_invalid_description += 1

                print_verbose(
                    VerboseLevel.LOW,
                    f"Skipping '{entry.name}'. Exception ({type(ex).__name__}): {ex}",
                    verbose_settings,
                )
                if not verbose_settings.no_throw:
                    raise
                continue
            
            if module_name in tools.keys():
                print_verbose(
                    VerboseLevel.LOW,
                    f"Overwriting '{module_name}' tool",
                    verbose_settings,
                )
                
            # Accept tool
            tools[module_name] = {
                "description": description,
                "runner": runner,
            }
            accepted += 1
            
            print_verbose(
                VerboseLevel.MID,
                f"Loaded tool: {module_name}, from file: {entry.name}",
                verbose_settings
            )

    # MID summary with names
    tool_names = ", ".join(sorted(tools.keys())) if tools else "No tools found"
    print_verbose(
        VerboseLevel.MID,
        f"Loaded tools ({accepted}): {tool_names}",
        verbose_settings
    )

    # LOW final status
    print_verbose(
        VerboseLevel.LOW,
        (
            f"Tool scan finished. base='{base_path}'. "
            f"dirs={dirs_visited}, files={files_seen}, name_matched={name_matched}, "
            f"accepted={accepted}, skipped_too_big={skipped_too_big}, "
            f"skipped_import_error={skipped_import_error}, \
                skipped_missing_fields={skipped_missing_fields}, "
            f"skipped_invalid_description={skipped_invalid_description}"
        ),
        verbose_settings,
    )

    return tools
    