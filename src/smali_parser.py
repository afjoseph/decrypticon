"""
## Functionality
* parse_apk: parse and categorize and APK
* reline_classes: Reline all classes in a directory
* apply_changes_to_disk: Reconstruct a directory based on the new tree
* rebuild_apk: Rebuilds an APK, given a file_path
"""

import collections
import glob
import logging
import os
import shutil
import subprocess
import tempfile
import typing as t

from src import util
from src.error import Error
from src.smali_class import SmaliClass
from src.smali_line import SmaliLine
from src.smali_method import SmaliMethod

NEW_LINE_THRESHOLD = 4


class SmaliParser:
    DUMMY_KEYSTORE_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                       '../example/test_project/dummy.keystore')
    DUMMY_KEYSTORE_PASS = 'bunnyfoofoo'
    DUMMY_KEYSTORE_ALIAS = 'key0'

    def __init__(self, focus_pkg: str):
        self.focus_pkg: str = focus_pkg
        self.classes: t.OrderedDict[str,
                                    SmaliClass] = collections.OrderedDict()

    def __add_obj_to_list_in_dict(self,
                                  obj: t.Union[str, t.List],
                                  key: str,
                                  dic: t.OrderedDict[t.Any, t.Any]):

        if key not in dic:
            dic[key] = []

        if isinstance(obj, list):
            dic[key].extend(obj)
        else:
            dic[key].append(obj)

    def __handle_directive(self, idx: int,
                           block: t.List[str]
                           ) -> t.Tuple[int, t.List[str]]:
        """
        drain a smali directive (a command starting with .) and update idx accordingly
        """

        directive: t.List[str] = []
        i = idx

        for i in range(idx, len(block)):
            directive.append(block[i].rstrip())

            if '.end' in block[i]:
                break

        return i, directive

    def __is_block_smali_directive(self, line: str) -> bool:
        if ('.annotation' in line.strip()
                # or '.field' in line.strip()
                or '.subannotation' in line.strip()
                or '.packed-switch' in line.strip()
                or '.sparse-switch' in line.strip()
                or '.array-data' in line.strip()):

            return True

        return False

    def __reline_method(self,
                        clazz_line_idx: int,
                        smali_method: SmaliMethod
                        ) -> t.Tuple[t.OrderedDict[str, SmaliLine],
                                     int, t.Optional[Error]]:
        logging.debug("__reline_method: %d -> %s",
                      clazz_line_idx, smali_method.name)
        relined_method_lines: t.OrderedDict[str,
                                            SmaliLine] = collections.OrderedDict()
        method_block: t.List[str] = [line
                                     for line in smali_method.block
                                     if '.line' not in line]

        counter: int = 0
        idx: int = 0
        collected_lines: t.List[str] = []

        # Add line directives to every NEW_LINE_THRESHOLD'th line

        while idx < len(method_block):
            line = method_block[idx]

            if not line:
                # For empty lines, just collect without incrementing 'counter'
                collected_lines.append(line)
                idx += 1

                continue

            elif self.__is_block_smali_directive(line):
                # For directives, just collect them all without incrementing 'counter'
                idx, directive = self.__handle_directive(
                    idx, method_block)

                if directive:
                    collected_lines.extend(directive)
                idx += 1
                # Directive is usually not the last instruciton in a method,
                #   so it is safe to move out now

                continue

            collected_lines.append(line)
            counter += 1

            if (counter == NEW_LINE_THRESHOLD
                    or line == method_block[-1]):
                new_line = SmaliLine(clazz_line_idx)
                err = new_line.parse(collected_lines)

                if err:
                    return None, -1, err

                collected_lines = []
                relined_method_lines[clazz_line_idx] = new_line
                clazz_line_idx += 1
                counter = 0

            idx += 1

        return relined_method_lines, clazz_line_idx, None

    def __can_reline_method(self, smali_method) -> bool:
        """
        For now, the only thing apktool complained about was abstract methods; one
          cannot have 'debug directives' (like `.line 1234`) in an abstract method
        """

        if ('abstract' in smali_method.header
                or 'native' in smali_method.header):

            return False

        return True

    def reline_classes(self) -> t.Optional[Error]:
        """
        Loops over self.classes to reline the parser tree.
        Results will overwrite the current parser tree
        """
        logging.info("reline_classes...")

        for smali_clazzname, smali_clazz in self.classes.items():
            clazz_line_idx = 1

            logging.debug("Relining %s", smali_clazzname)

            for smali_method in smali_clazz.methods:
                if not self.__can_reline_method(smali_method):
                    continue

                relined_method_lines, clazz_line_idx, err = self.__reline_method(
                    clazz_line_idx, smali_method)

                if err:
                    return err

                smali_method.lines = relined_method_lines

                # Append the relined_method_lines to method_block, with a .line directive
                #   accordingly
                method_block: t.List[str] = []

                for line_num, smali_line in relined_method_lines.items():
                    method_block.append('.line {}'.format(line_num))
                    method_block.extend(smali_line.block)
                smali_method.block = method_block
                smali_method.is_relined = True

        logging.info("Relining OK")

        return None

    def parse_apk(self, apk_path: str) -> t.Tuple[t.Optional[str],
                                                  t.Optional[str],
                                                  t.Optional[Error]]:
        disassembled_classes_path = tempfile.mkdtemp()

        logging.info('baksmaling apk [%s] to [%s]',
                     apk_path, disassembled_classes_path)
        if subprocess.run('apktool d {} --no-res --output {} -f 1>/dev/null'.format(
                apk_path, disassembled_classes_path), shell=True).returncode != 0:
            return None, None, Error('baksmali failed on apk [{}]'.format(apk_path))

        smali_filepaths = [os.path.join(root, name)
                           for root, _, files in os.walk(disassembled_classes_path)
                           for name in files
                           if name.endswith('.smali')
                           and self.focus_pkg in os.path.join(root, name)]

        logging.debug('Disassembled APK to %d smali files',
                      len(smali_filepaths))

        for path in smali_filepaths:
            # Read the first line of the smali file, which contains it's class name
            clazz_name = None
            with open(path, 'r') as fd:
                lines = fd.readlines()
                if not lines or len(lines) < 1:
                    return None, None, Error('Bad smali file {}'.format(path))

                # Change this:
                #   .class Lcom/aaa/bbb;
                # to this:
                #   com.aaa.bbb
                clazz_name = lines[0].split()[-1]
                clazz_name = clazz_name[1:-1].replace('/', '.')

            if not clazz_name:
                return None, None, Error('Couldnt parse class name {}'.format(path))

            clazz = SmaliClass(clazz_name)
            err = clazz.parse(path)
            self.classes[clazz_name] = clazz

            if err:
                return None, None, err

        pkg_name, err = util.get_pkg_name_from_apk(apk_path)
        if err:
            return None, None, err

        return disassembled_classes_path, pkg_name, None

    def rebuild_apk(self, classes_path) -> t.Tuple[str, t.Optional[Error]]:
        """
        Rebuild and resign a disassembled smali directory in [classes_path].
        Return a signed APK
        """
        logging.info('rebuilding APK in %s...', classes_path)
        if not classes_path or not os.path.isdir(classes_path):
            return '', Error('{} is not a directory'.format(classes_path))

        cmd = subprocess.run('apktool b', cwd=classes_path,
                             shell=True, capture_output=True)

        if cmd.returncode != 0:
            return '', Error('apktool b failed: {}\n{}'.format(cmd.stdout.decode(),
                                                               cmd.stderr.decode()))

        apk_path = glob.glob('{}/dist/*.apk'.format(classes_path))
        if not apk_path:
            return '', Error('Built APK in [{}] is not a file'.format(apk_path))
        apk_path = apk_path[0]
        signed_apk_path = '{}-signed.apk'.format(apk_path.strip('.apk'))

        logging.info("Signing rebuilt APK...")
        if subprocess.run('jarsigner -keystore {} -storepass {} {} {} >/dev/null'.format(
                self.DUMMY_KEYSTORE_PATH,
                self.DUMMY_KEYSTORE_PASS,
                apk_path,
                self.DUMMY_KEYSTORE_ALIAS), shell=True).returncode != 0:
            return '', Error('jarsigner failed')

        if subprocess.run('zipalign -v 4 {} {} >/dev/null'.format(
                apk_path,
                signed_apk_path), shell=True).returncode != 0:
            return '', Error('zipalign failed')

        return signed_apk_path, None

    def apply_changes_to_disk(self,
                              disassembled_classes_path: str,
                              out_smali_dir: str = None
                              ) -> t.Tuple[str, t.Optional[Error]]:
        """
        Takes a decompiled Smali directory in 'disassembled_classes_path' and
          replaces all classes in 'self.focus_pkg'
          with their equivalent in 'self.classes'

        if 'out_smali_dir' is not None, it would write the changes to the specified directory.
        If None, it would overwrite the directory
        """
        workspace: str = ''
        if not out_smali_dir:
            workspace = disassembled_classes_path
        else:
            workspace = out_smali_dir
            shutil.rmtree(workspace)
            shutil.copytree(disassembled_classes_path, workspace)

        logging.info(
            'Rewriting classes:\n\tPath [%s]\n\tfocus_pkg [%s]\n\tout directory [%s]',
            disassembled_classes_path, self.focus_pkg, workspace)

        focus_dir_arr = glob.glob('{}/**/{}'.format(workspace, self.focus_pkg))
        if not focus_dir_arr:
            return '', Error('focus_pkg {} is bad')

        if len(focus_dir_arr) != 1:
            return '', Error('focus_pkg {} is ambiguous. Be more granular')

        focus_dir = focus_dir_arr[0]
        if not os.path.isdir(focus_dir):
            return '', Error('{} not found in workspace [{}]. Focus pkg is invalid'.format(
                focus_dir, workspace))

        # Remove focus_dir on disk and replace it with the changes in SmaliParser
        shutil.rmtree(focus_dir, ignore_errors=True)
        os.makedirs(focus_dir)

        for _, clazz in self.classes.items():
            out_path = os.path.join(
                focus_dir,
                '{}.smali'.format(clazz.get_simple_name()))
            with open(out_path, 'w') as fd:
                clazz.write(fd)

        return workspace, None
