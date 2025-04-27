
from inspect import currentframe, getframeinfo

# Export the DEBUG function
__all__ = ["OWT_log_msg"]


def OWT_log_msg(msg: str, is_error : bool = False, is_debug : bool = False, raise_exception : bool = False) -> None:
    """
    Print debug messages with the current file and line number.
    """
    frame = currentframe()
    func = frame.f_back.f_code.co_name
    filename = getframeinfo(frame.f_back).filename
    lineno =  frame.f_back.f_lineno
    
    log_msg_prefix = f"[{filename}:{lineno}][{func}()]"
    log_msg_body = f"{msg}"
        
    if is_error:
        log_msg = f"{log_msg_prefix} ERROR: {log_msg_body}"
    else:
        # Print the message
        if raise_exception:
            log_msg = f"{log_msg_prefix} EXCEPTION: {log_msg_body}"
        elif is_debug:
            log_msg = f"{log_msg_prefix} DEBUG: {log_msg_body}"
        else:
            log_msg = f"{log_msg_prefix} INFO: {log_msg_body}"
    
    # Logs the message
    print(log_msg)
    
    # Raise an exception if requested
    if raise_exception:
        raise Exception(msg)
