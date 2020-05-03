import logging
import typing as t

from src.error import Error
from src.smali_method import SmaliMethod


class SmaliClass:
    def __init__(self, name: str):
        self.name: str = name
        self.sig: str = ''
        self.methods: t.List[SmaliMethod] = []
        self.header_block: t.List[str] = []

    def __parse_class_header(self, idx: int,
                             file_lines: t.List[str]
                             ) -> t.Tuple[int, t.List[str],
                                          str, t.Optional[Error]]:
        try:
            sig = file_lines[0].split()[-1][1:-1].strip()
        except IndexError:
            return 0, [], '', Error(
                'Could not parse class header: {}'.format(self.name))

        i = 1  # Skipping the first line
        header_block: t.List[str] = []

        for i in range(idx, len(file_lines)):
            line = file_lines[i]

            if '.method' in line:
                break

            header_block.append(line)

        return i, header_block, sig, None

    def __parse_method(self,
                       idx: int,
                       file_lines: t.List[str]
                       ) -> t.Tuple[int, t.Optional[SmaliMethod],
                                    t.Optional[Error]]:
        i = 0
        method_block: t.List[str] = []

        for i in range(idx, len(file_lines)):
            line = file_lines[i]

            method_block.append(line)

            if '.end method' in line:
                break

        method = SmaliMethod(self.name, method_block[0])
        err = method.parse(method_block[1:])

        if err:
            return -1, None, err

        return i, method, None

    def parse(self, file_path: str) -> t.Optional[Error]:
        logging.debug("Parsing SmaliClass: [%s]...", file_path)
        with open(file_path, 'r') as fd:
            file_lines = fd.read().splitlines()

            idx = 0
            idx, self.header_block, self.sig, err = self.__parse_class_header(
                idx, file_lines)

            if err:
                return err

            while idx < len(file_lines):
                line = file_lines[idx]

                if '.method' in line:
                    idx, method, err = self.__parse_method(idx, file_lines)

                    if err:
                        return err
                    if not method:
                        raise Exception('FAIL')

                    self.methods.append(method)

                idx += 1

        return None

    def write(self, fd: t.IO[t.Any]):
        logging.debug('Writing clazz [%s]', self.name)
        for line in self.header_block:
            fd.write(line)
            fd.write('\n')

        for method in self.methods:
            method.write(fd)

    # Removes the package from a class's name
    # `com.afjoseph.test.aaa` -> `aaa`
    def get_simple_name(self) -> str:
        if not '.' in self.name:
            return self.name

        return self.name.split('.')[-1].strip()
