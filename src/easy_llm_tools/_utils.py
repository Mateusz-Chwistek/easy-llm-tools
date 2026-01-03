import sys
from _thread import LockType
from .verbose_settings import VerboseLevel, VerboseSettings
from typing import Optional, Callable, TypeVar, TextIO

T = TypeVar("T")
def return_or_raise(
    no_throw: bool = True,
    *,
    exception_factory: Optional[Callable[[], BaseException]] = None,
    return_value: Optional[T] = None
) -> Optional[T]:
    """
    Return `return_value` when `no_throw` is True, otherwise raise an exception produced by `exception_factory`.

    :param no_throw: If True, suppress errors and return `return_value`.
    :type no_throw: bool

    :param exception_factory: Zero-argument callable returning an exception instance to raise.\n
                             Expected shape: ``lambda: SomeException("message")``
    :type exception_factory: Optional[Callable[[], BaseException]]

    :param return_value: Default value returned when `no_throw` is True.
    :type return_value: Optional[T]

    :return: `return_value` if `no_throw` is True, otherwise this function does not return.
    :rtype: Optional[T]

    :raises TypeError: If `no_throw` is not bool or `exception_factory` returns a non-exception object.
    :raises ValueError: If `no_throw` is False and `exception_factory` is not provided.
    :raises BaseException: Whatever exception instance `exception_factory` returns.

    :remarks: `exception_factory` enables lazy exception creation (the exception is built only if it will be raised).
    """
    
    if not isinstance(no_throw, bool):
        raise TypeError("`no_throw` must be of type bool")
    
    if no_throw:
        return return_value    
    
    if exception_factory is None:    
        raise ValueError(
            "`exception_factory` must be provided, when `no_throw` is False"
        )
    
    ex = exception_factory()
    if not isinstance(ex,  BaseException):
        raise TypeError("`exception_factory` didn't return `BaseException` instance")
    
    raise ex

def print_verbose(
    required_verbose_level: VerboseLevel,
    message: str = "",
    verbose_settings: Optional[VerboseSettings] = None,
    *,
    current_verbose_level: VerboseLevel = VerboseLevel.NONE,
    no_throw: bool = False,
    output: TextIO = sys.stdout,
    lock: Optional[LockType] = None,
    validate: bool = True
) -> None:
    """
    Print a message only when `current_verbose_level` includes `required_verbose_level`.

    :param required_verbose_level: Required verbosity level for this message.
    :type required_verbose_level: VerboseLevel
    
    :param message: Message to print.
    :type message: str
    
    :param verbose_settings: Optional settings object. When provided, it overrides:
        `current_verbose_level`, `no_throw`, `output`, `lock`, and `validate`.
    :type verbose_settings: Optional[VerboseSettings]
    
    :param current_verbose_level: Current user verbosity level.
    :type current_verbose_level: VerboseLevel
    
    :param no_throw: If True, suppress validation errors (returns early instead of raising).
    :type no_throw: bool
    
    :param output: Output stream (e.g., sys.stdout, file handle). Must provide `write(str)`.
    :type output: TextIO
    
    :param lock: Optional lock to avoid interleaving prints across threads.
    :type lock: Optional[threading.Lock]
    
    :param validate: If True, validate input types/values (slower but safer).\n
        Typically ~2x slower than `validate=False`.
    :type validate: bool
    
    :return: None
    :rtype: None
    
    :raises TypeError: For invalid argument types (when no_throw is False).
    :raises ValueError: For invalid argument values (when no_throw is False).
    """
    
    # If settings are provided, treat them as the source of truth and override individual parameters.
    # This reduces per-call argument noise and allows centralized validation in VerboseSettings.
    if verbose_settings is not None:
        if isinstance(verbose_settings, VerboseSettings):
            # Override individual arguments with values from the validated settings container.
            current_verbose_level = verbose_settings.verbose_level
            no_throw = verbose_settings.no_throw
            output = verbose_settings.output
            lock = verbose_settings.lock
            validate = verbose_settings.validate
        else:
            return return_or_raise(
                no_throw=no_throw,
                exception_factory=lambda: TypeError(
                    "`verbose_settings` must be a `VerboseSettings` instance or None"
                ),
            )
    
    # Optional validation block. Can be disabled for hot paths.
    if validate:
        if not isinstance(required_verbose_level, VerboseLevel):
            return return_or_raise(
                no_throw=no_throw,
                exception_factory=lambda: TypeError(
                    "`required_verbose_level` must be a `VerboseLevel` instance"
                ),
            )

        if not isinstance(current_verbose_level, VerboseLevel):
            return return_or_raise(
                no_throw=no_throw,
                exception_factory=lambda: TypeError(
                    "`current_verbose_level` must be a `VerboseLevel` instance"
                ),
            )

        if not isinstance(message, str):
            return return_or_raise(
                no_throw=no_throw,
                exception_factory=lambda: TypeError("`message` must be of type `str`"),
            )

        message = message.strip()
        if len(message) < 1:
            return return_or_raise(
                no_throw=no_throw,
                exception_factory=lambda: ValueError("`message` must be provided"),
            )

        if not hasattr(output, "write") or not callable(getattr(output, "write")):
            return return_or_raise(
                no_throw=no_throw,
                exception_factory=lambda: TypeError(
                    "`output` must provide a callable `write(str)` method"
                ),
            )

    # Fast early exit: when verbosity is NONE, we never print anything.
    if current_verbose_level == VerboseLevel.NONE:
        return

    # Print only when the current verbosity "covers" the required message level.
    if current_verbose_level.includes(required_verbose_level): 
        if lock is None or not isinstance(lock, LockType):
            print(message, file=output)
            return
        
        with lock:
            print(message, file=output)
