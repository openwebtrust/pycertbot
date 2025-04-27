# API Message Class

class ApiReplyMessage:
    """General Structure for API Return Messages"""
    def __init__(self, code: int = 0, message: str = '', data: any = None, is_error: bool = False):
        """Initializes the API Reply Message Object

        Args:
            code (int, optional): The return code. Defaults to 0.
            message (str, optional): The return message. Defaults to ''.
            data (any, optional): The return data. Defaults to None.
            is_error (bool, optional): The return error flag. Defaults to False.
        """      
        self.code = code
        self.message = message
        self.data = data
        self.is_error = is_error
        
    def __init__(self, jsonDict: dict = {}):
        """Initializes the API Reply Message Object from a JSON Dictionary

        Args:
            jsonDict (dict, optional): The returned JSON data from the server. Defaults to {}.
        """
        if not jsonDict:
            self.code = 0
            self.message = ''
            self.data = None
            self.is_error = False
        else:
            self.code = jsonDict.get('code') or 0
            self.message = jsonDict.get('message') or ''
            self.data = jsonDict.get('data') or None
            self.is_error = jsonDict.get('is_error') or False

    def __str__(self):
        return f"AppReplyMessage: {self.code} - {self.message} - {self.data} - {self.is_error}"
    
    # Lets write a setter and getter for the code
    @property
    def code(self):
        return self.__code
    
    @code.setter
    def code(self, value):
        self.__code = value
    
    # Lets write a setter and getter for the message
    @property
    def message(self):
        return self._message
    
    @message.setter
    def message(self, value):
        self._message = value
        
    # Lets write a setter and getter for the data
    @property
    def data(self):
        return self._data
    
    @data.setter
    def data(self, value):
        self._data = value
        
    # Lets write a setter and getter for the is_error
    @property
    def is_error(self):
        return self._is_error
    
    @is_error.setter
    def is_error(self, value):
        self._is_error = value
        
    # Lets write a method to convert the object to a dictionary
    def to_dict(self):
        return {
            "code": self.code,
            "message": self.message,
            "data": self.data,
            "is_error": self.is_error
        }

# Exports the factory function
__all__ = [
    'ApiReplyMessage',
]
