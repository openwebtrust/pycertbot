
from inspect import currentframe, getframeinfo

# Export the DEBUG function
__all__ = ["OWT_debug_print"]


def OWT_debug_print(msg: str) -> None:
    """
    Print debug messages with the current file and line number.
    """
    frame = currentframe()
    func = frame.f_back.f_code.co_name
    filename = getframeinfo(frame.f_back).filename
    lineno =  frame.f_back.f_lineno
    
    print(f"[{filename}:{lineno}][{func}()] DEBUG: {msg}")
    return