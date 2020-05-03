import logging
import re
import typing as t

from src.error import Error

INVOKE_TYPE = {
    "unknown": -1,
    "static": 0,
    "direct": 1,
    "virtual": 2,
    "super": 3,
    "interface": 4,
}


class SmaliInvocation:
    def __init__(self):
        self.method_sig: str = ''
        self.type: int = INVOKE_TYPE['unknown']
        self.params_str: str = ''
        self.annotations: t.List[str] = []
        self.raw_line = ''

    def parse(self, line: str) -> t.Optional[Error]:
        self.raw_line: str = line.rstrip()
        matches = re.match(r'^.*(invoke-.* ?) {(.*?)}, (.*)$', self.raw_line)

        if not matches:
            return Error("Couldn't process line: {}".format(self.raw_line))

        if len(matches.groups()) != 3:
            return Error(
                "Incorrect number of groups while parsing SmaliInvocation: {}: {}".format(
                    self.raw_line, matches.groups()))

        # e.g: invoke-interface
        type_str = matches.group(1).strip()
        # e.g: p1, v1,
        self.params_str = matches.group(2).strip()
        # e.g: Ljava/lang/System;->currentTimeMillis()J
        self.method_sig = matches.group(3).strip()

        if type_str == 'invoke-static':
            self.type = INVOKE_TYPE['static']
        elif type_str == 'invoke-direct':
            self.type = INVOKE_TYPE['direct']
        elif type_str == 'invoke-virtual':
            self.type = INVOKE_TYPE['virtual']
        elif type_str == 'invoke-interface':
            self.type = INVOKE_TYPE['interface']
        elif type_str == 'invoke-super':
            self.type = INVOKE_TYPE['super']

        return None

    def write(self, fd: t.IO[t.Any]):
        logging.debug('Writing invocation [%s]', self.method_sig)
        for a in self.annotations:
            fd.write('>>> DECRYPTICON:: {}\n'.format(a))

        fd.write(self.raw_line)
        fd.write('\n')

    def add_annotation(self, msg: str):
        self.annotations.append(msg)
