class GlobalStrings:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(GlobalStrings, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.RESOURCE_PID = "resource_pid"



global_strings = GlobalStrings()