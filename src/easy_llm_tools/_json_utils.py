import json
import uuid
from ._utils import return_or_raise, print_verbose
from typing import Optional, Any, Dict, List
from .verbose_settings import VerboseSettings, VerboseLevel

def is_valid_json(
    json_str: str,
    no_throw: bool = False
) -> tuple[bool, Optional[Any], Optional[str]]:
    """
    Validate and parse a JSON string.

    :param json_str: Input string to be parsed as JSON.
    :type json_str: str
    
    :param no_throw: If True, suppress errors and return (False, None, error_message) instead of raising.
    :type no_throw: bool
    
    :return: Tuple (is_valid, parsed_value, error_message).
        - On success: (True, parsed_value, None)
        - On failure with no_throw=True: (False, None, "Exception (Type): message")
        - On invalid input type with no_throw=True: (False, None, "<reason>")
    :rtype: tuple[bool, Optional[Any], Optional[str]]
    
    :raises TypeError: If `json_str` is not a str (when no_throw is False).
    :raises json.JSONDecodeError: If `json_str` is invalid JSON (when no_throw is False).
    :raises Exception: Re-raises any unexpected exception from `json.loads` (when no_throw is False).
    """

    # Validate input type early to avoid passing non-strings into json.loads().
    if not isinstance(json_str, str):
        # Use the shared helper to either raise a TypeError or return a default tuple.
        return return_or_raise(
            no_throw,
            return_value=(False, None, "`json_str` must be of type str"),
            exception_factory=lambda: TypeError("`json_str` must be of type str")
        )

    try:
        # json.loads returns a Python object (dict/list/str/int/float/bool/None) on success.
        return True, json.loads(json_str), None
    except Exception as ex:
        # On parse failure (or any other json.loads error), either return a default result or re-raise.
        if no_throw:
            # Include exception type name to make debugging easier without a stack trace.
            return False, None, f"Exception ({type(ex).__name__}): {ex}"
        raise

    
def prettify_json(json_text: str, verbose_settings: VerboseSettings) -> str:
    """
    Pretty-format a JSON string for improved readability (especially for LLM prompts).

    :param json_text: Raw JSON text to format.
    :type json_text: str
    
    :param verbose_settings: Shared verbose settings (controls error handling + optional logging).
    :type verbose_settings: VerboseSettings
    
    :return: Prettified JSON string. If input is invalid and errors are suppressed, returns the original input.
    :rtype: str
    
    :raises TypeError: If `verbose_settings` is not a VerboseSettings instance.
    :raises TypeError: If `json_text` is not a str (when no_throw is False).
    :raises RuntimeError: If `json_text` is not valid JSON (when no_throw is False).

    Notes:
        Optimized for fewer LLM tokens while remaining "pretty": small indentation, compact arrays,
        and reduced unnecessary whitespace (via `separators`).
        This uses a placeholder round-trip to keep arrays compact while still pretty-printing objects.
    """
    # Settings object must be validated upfront because we read `no_throw` and use it for control flow.
    if not isinstance(verbose_settings, VerboseSettings):
        raise TypeError("`verbose_settings` must be a `VerboseSettings` instance")

    # Input must be text; on suppressed errors we simply return the original value unchanged.
    if not isinstance(json_text, str):
        return return_or_raise(
            verbose_settings.no_throw,
            return_value=json_text,
            exception_factory=lambda: TypeError("`json_text` must be of type str")
        )

    # Validate and parse input JSON; returns (ok, parsed_obj, error_message).
    result, valid_json, error_message = is_valid_json(json_text, verbose_settings.no_throw)

    if not result:
        # Optionally log a user-friendly error message before returning/raising.
        if error_message is not None:
            print_verbose(VerboseLevel.LOW, error_message, verbose_settings)

        # Either raise (no_throw=False) or return the original JSON text (no_throw=True).
        return return_or_raise(
            verbose_settings.no_throw,
            return_value=json_text,
            exception_factory=lambda: RuntimeError("`json_text` is not a valid json")
        )

    # Stores mapping: placeholder token -> compact one-line JSON array string
    placeholders: Dict[str, str] = {}

    # Generate a placeholder that is extremely unlikely to collide with user content
    def generate_unique_token() -> str:
        # Keep token ASCII-safe to avoid escaping in json.dumps output
        while True:
            token = f"__JSON_LIST_PLACEHOLDER_{uuid.uuid4().hex}__"
            if token not in json_text and token not in placeholders:
                return token

    # Convert any Python list into a compact single-line JSON representation (no spaces after commas).
    def list_to_single_line_json(value: List[Any]) -> str:
        return json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"), 
        )

    # Walk the object and replace every list with a placeholder string
    def replace_lists_with_placeholders(value: Any) -> Any:
        if isinstance(value, list):
            # Replace the list with a unique token and remember how to reconstruct it later.
            token = generate_unique_token()
            placeholders[token] = list_to_single_line_json(value)
            return token

        if isinstance(value, dict):
            # Recursively process JSON objects (dicts) and preserve structure.
            return {key: replace_lists_with_placeholders(val) for key, val in value.items()}

        # Scalars (str/int/float/bool/None) pass through unchanged.
        return value

    # Transform the parsed object so that lists become placeholder tokens.
    transformed_obj = replace_lists_with_placeholders(valid_json)

    # Pretty-print the transformed JSON (indentation applies to objects; lists are currently tokens).
    pretty_text = json.dumps(
        transformed_obj,
        indent=1,              # smaller indent to reduce tokens
        ensure_ascii=False,
        separators=(",", ": "), # reduce whitespace globally (token-friendly)
    )

    # Replace quoted placeholders with the one-line list JSON
    # We replace the JSON string literal: "__TOKEN__" -> [ ... ]
    for token, one_line_list_json in placeholders.items():
        pretty_text = pretty_text.replace(f"\"{token}\"", one_line_list_json)

    return pretty_text
