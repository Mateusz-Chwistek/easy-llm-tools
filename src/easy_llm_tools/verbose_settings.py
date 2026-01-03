from sys import stdout
from _thread import LockType
from enum import IntEnum, auto
from typing import Optional, TextIO

class VerboseLevel(IntEnum):
    """
    Verbosity level for program output.

    **Levels**
    - **NONE**: no messages are printed
    - **LOW**: only the most important messages
    - **MID**: standard amount of messages (more details)
    - **HIGH**: maximum verbosity (the most detailed output)

    **Rule:** the higher the level, the more messages the program emits.
    """
    NONE = 0
    LOW = auto()
    MID = auto()
    HIGH = auto()
    
    def includes(self, message_level: "VerboseLevel") -> bool:
        """
        Check whether this verbosity level includes (covers) the given message level.

        Example:
            - MID includes LOW and MID
            - HIGH includes LOW, MID, and HIGH
            - LOW includes only LOW
            - NONE includes nothing

        :param message_level: The verbosity level required by a message.
        :type message_level: VerboseLevel
        :return: True if messages at `message_level` should be shown for the current verbosity level.
        :rtype: bool
        """
        return self >= message_level
    
class VerboseSettings:
    """
    Shared configuration for verbose printing/logging.

    Notes:
        - Inputs are validated in __init__, so downstream functions can safely run with validate=False
          for better performance.
    """

    def __init__(
        self,
        verbose_level: VerboseLevel = VerboseLevel.NONE,
        *,
        no_throw: bool = False,
        output: TextIO = stdout,
        lock: Optional[LockType] = None,
    ) -> None:
        """
        Create a validated settings object used by verbose printing helpers.

        :param verbose_level: Current verbosity level selected by the user.
        :type verbose_level: VerboseLevel
        
        :param no_throw: If True, helper functions should suppress their own validation errors
                         (when validation is enabled elsewhere).
        :type no_throw: bool
        
        :param output: Output stream (e.g., sys.stdout, open file). Must provide `write(str)`.
        :type output: TextIO
        
        :param lock: Optional lock to prevent interleaved output when used from multiple threads.
        :type lock: Optional[LockType]
        
        :raises TypeError: If any argument has an invalid type or `output` does not provide `write(str)`.
        """
        # Validate verbosity enum type to ensure comparisons and includes() work correctly.
        if not isinstance(verbose_level, VerboseLevel):
            raise TypeError("`verbose_level` must be a `VerboseLevel` instance")

        # Strict bool check to avoid truthy/falsey surprises (e.g., 1, "yes").
        if not isinstance(no_throw, bool):
            raise TypeError("`no_throw` must be of type bool")

        # Runtime-safe output validation (TextIO typing cannot be used with isinstance()).
        if not hasattr(output, "write") or not callable(getattr(output, "write")):
            raise TypeError("`output` must provide a callable `write(str)` method")

        # Lock is optional; when provided, it must be a threading.Lock-compatible instance.
        if lock is not None and not isinstance(lock, LockType):
            raise TypeError("`lock` must be of type LockType or None")

        # Store validated configuration.
        self.verbose_level = verbose_level
        self.no_throw = no_throw
        self.output = output
        self.lock = lock

        # Downstream helpers can skip validation because this object is already validated.
        self.validate = False


        