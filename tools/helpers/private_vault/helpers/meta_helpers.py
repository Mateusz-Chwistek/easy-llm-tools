from datetime import datetime
from typing import Final, Optional, Dict, Any, List

# Separates items within a section (tags from each other, created from updated).
ITEM_SEPARATOR: Final[str] = "\x1e"

# Separates user section (tags) from system section (dates).
SECTION_SEPARATOR: Final[str] = "\x1f"

# Characters forbidden in user-provided tag values.
RESERVED_CHARS: Final[str] = ITEM_SEPARATOR + SECTION_SEPARATOR


def build_meta(tags: List[str], now: datetime) -> str:
    """
    Build a meta string from user tags and current timestamp.

    Format: ``tag1\\x1Etag2\\x1F2026-03-26T14:30:00\\x1E2026-03-26T14:30:00``

    :param tags: User-assigned tags (may be empty).
    :type tags: list[str]

    :param now: Timestamp used for both created_at and modified_at.
    :type now: datetime

    :return: Encoded meta string.
    :rtype: str
    """

    user_section: str = ITEM_SEPARATOR.join(tags)
    timestamp: str = now.isoformat()
    system_section: str = ITEM_SEPARATOR.join([timestamp, timestamp])
    return SECTION_SEPARATOR.join([user_section, system_section])


def update_meta(meta: str, tags: Optional[List[str]], now: datetime) -> str:
    """
    Update an existing meta string with new tags and/or a new modified_at timestamp.

    :param meta: Existing meta string from the database.
    :type meta: str

    :param tags: New tags to replace existing ones, or None to keep current tags.
    :type tags: Optional[list[str]]

    :param now: Timestamp for modified_at.
    :type now: datetime

    :return: Updated meta string.
    :rtype: str
    """

    parsed: Dict[str, Any] = parse_meta(meta)

    if tags is not None:
        user_section = ITEM_SEPARATOR.join(tags)
    else:
        user_section = ITEM_SEPARATOR.join(parsed["tags"])

    system_section = ITEM_SEPARATOR.join([parsed["created_at"], now.isoformat()])
    return SECTION_SEPARATOR.join([user_section, system_section])


def parse_meta(meta: str) -> Dict[str, Any]:
    """
    Parse a meta string into its components.

    :param meta: Encoded meta string from the database.
    :type meta: str

    :return: Dict with ``tags`` (list[str]), ``created_at`` (str), ``modified_at`` (str).
    :rtype: dict[str, Any]
    """

    sections: List[str] = meta.split(SECTION_SEPARATOR)
    user_section: str = sections[0]
    system_section: str = sections[1]

    tags: List[str] = [t for t in user_section.split(ITEM_SEPARATOR) if t]
    system_parts: List[str] = system_section.split(ITEM_SEPARATOR)

    return {
        "tags": tags,
        "created_at": system_parts[0],
        "modified_at": system_parts[1],
    }


def validate_tags(tags: List[Any]) -> Optional[str]:
    """
    Validate a list of tags. Returns an error message or None if valid.

    :param tags: Raw tag values from the request.
    :type tags: list[Any]

    :return: Error message, or None if all tags are valid.
    :rtype: Optional[str]
    """

    for tag in tags:
        if not isinstance(tag, str):
            return "Each tag must be a string"

        tag = tag.strip()
        if len(tag) < 1:
            return "Tags must not be empty"

        if any(char in tag for char in RESERVED_CHARS):
            return "Tags must not contain reserved separator characters"

    return None
