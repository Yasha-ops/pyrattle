
class FileNotPresent(Exception):
    def __init__(self, message="No file was provided"):
        self.message = message
        super().__init__(self.message)

class ScanFailed(Exception):
    def __init__(self, message= "Scan failed"):
        self.message = message
        super().__init__(self.message)

class ScanParsingFailed(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class BadArgument(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)