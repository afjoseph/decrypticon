import logging
import typing as t

from src.error import Error
from src.smali_invocation import SmaliInvocation


class SmaliLine:
    def __init__(self, num: int):
        self.num: int = num
        self.block: t.List[t.Union[str, SmaliInvocation]] = []

    def parse(self, block: t.List[str]) -> t.Optional[Error]:
        for line in block:
            if 'invoke-' in line:
                smali_inv = SmaliInvocation()
                err = smali_inv.parse(line)
                if err:
                    return err

                self.block.append(smali_inv)
            else:
                self.block.append(line)

        return None

    def write(self, fd: t.IO[t.Any]):
        logging.debug('Writing line [%d]', self.num)
        fd.write('.line {}\n'.format(self.num))

        for line in self.block:
            if isinstance(line, SmaliInvocation):
                line.write(fd)
                continue

            fd.write(line)
            fd.write('\n')
