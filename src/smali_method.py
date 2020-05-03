import collections
import logging
import typing as t

from src.error import Error
from src.smali_line import SmaliLine


class SmaliMethod:
    def __init__(self, clazz_name: str, header: str):
        self.lines: t.OrderedDict[int,
                                  SmaliLine] = collections.OrderedDict()
        self.clazz_name: str = clazz_name
        self.header: str = header
        self.sig: str = header.split()[-1].strip()
        self.name: str = ''
        self.locals_count: int = 0
        self.is_relined: bool = False
        self.block: t.List[str] = []

        if '<init>' in header:
            self.name = '<init>'
        elif '<clinit>' in header:
            self.name = '<clinit>'
        else:
            self.name = self.sig.split('(')[0].strip()

    def __assemble_line(self,
                        block_idx: int,
                        block: t.List[str]
                        ) -> t.Tuple[int, int, t.List[str]]:
        """
        Collect all lines beginning with '.line' and ending with the next '.line' directive
        """
        collected_lines: t.List[str] = []

        linenum = int(block[block_idx].strip().split()[1])
        block_idx += 1  # Skip .line
        i = 0

        for i in range(block_idx, len(block)):
            line = block[i]

            if ('.line' in line
                    or '.end method' in line):

                break
            collected_lines.append(line)

        return linenum, i, collected_lines

    def parse(self, block: t.List[str]) -> t.Optional[Error]:
        ret_block: t.List[str] = []

        idx = 0

        while idx < len(block):
            line = block[idx]

            if '.line' in line:
                ret_block.append(line)
                linenum, idx, line_block = self.__assemble_line(
                    idx, block)

                ret_block.extend(line_block)
                smali_line = SmaliLine(linenum)

                err = smali_line.parse(line_block)

                if err:
                    return err

                self.lines[linenum] = smali_line

                continue
            elif '.locals' in line:
                self.locals_count = int(line.strip().split()[1])
            elif '.end method' in line:
                ret_block.append(line)

                break
            else:
                ret_block.append(line)

            idx += 1

        self.block = ret_block

        return None

    def write(self, fd: t.IO[t.Any]):
        logging.debug('Writing method [%s]', self.name)
        fd.write(self.header)
        fd.write('\n')

        if self.is_relined:
            fd.write('.locals {}'.format(self.locals_count))
            fd.write('\n')

            for line in self.lines.values():
                line.write(fd)
                fd.write('\n')
        else:
            # Dump block as is if we don't have proper lines

            for line in self.block:
                fd.write(line)
                fd.write('\n')
