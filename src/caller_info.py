class CallerInfo:
    def __init__(self, clazz: str, method: str, fyle: str, linenum: int):
        self.clazz: str = clazz
        self.method: str = method
        self.fyle: str = fyle
        self.linenum: int = linenum

    def __repr__(self):
        from pprint import pformat
        return pformat(vars(self), indent=4, width=1)
