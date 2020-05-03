import typing as t

from src.caller_info import CallerInfo
from src.util import get_rand_word


class RecordedInvocation:
    def __init__(self, caller_info: t.Any, method_sig: t.Any,
                 args: t.Any, retval: t.Any, call_count: int):
        self.did_annotate: bool = False
        self.id: str = get_rand_word(8)
        self.caller_info = CallerInfo(
            str(caller_info['class']),
            str(caller_info['method']),
            str(caller_info['file']),
            int(caller_info['line']))
        self.method_sig: str = str(method_sig)
        self.args: t.List[t.Any] = list(args.values())
        self.retval: str = str(retval)
        self.call_count: int = call_count

    def __repr__(self):
        from pprint import pformat
        return pformat(vars(self), indent=6, width=1)

    def describe(self) -> str:
        """
        Describe this invocation in the form of: `func(arg1, arg2, ...) = retval`
        """
        s = 'func('
        for i, arg in enumerate(self.args):
            if i >= 1:
                s += ', '
            s += str(arg)
        s += ') = {}'.format(self.retval)

        return s
