import argparse
import logging
import pickle
import subprocess
import sys
import time
import typing as t

import coloredlogs

from src import util
from src.frida_helper import FridaHelper
from src.invocation_processor import InvocationProcessor
from src.recorded_invocation import RecordedInvocation
from src.smali_parser import SmaliParser
from src.util import die, get_version


def parse_args():
    parser = argparse.ArgumentParser(prog='Decrypticon by @afjoseph')

    parser.add_argument('--mode',
                        help='REQUIRED: either "online" or "offline"')
    parser.add_argument('--apk',
                        help='REQUIRED: Target apk')
    parser.add_argument(
        '--focus_pkg', help='REQUIRED: Package to focus on during the APK analysis')
    parser.add_argument(
        '--out', help='OPTIONAL: Location of annotated smali directory')
    parser.add_argument(
        '--timeout', type=int, help='OPTIONAL FOR ONLINE MODE: Timeout awaiting invocations after this amount of seconds')
    parser.add_argument(
        '--hooks', help="REQUIRED FOR ONLINE MODE: file that contains functions to hook into (one function per line. See format from example/test_project/hooks)")
    parser.add_argument(
        '--pickle_from', help='REQUIRED FOR OFFLINE MODE: Take pickled recorded invocations from this file')
    parser.add_argument(
        '--pickle_to', help='OPTIONAL FOR ONLINE MODE: pickle recorded invocations to this file')
    parser.add_argument('--verbose', action='store_true')
    parser.add_argument('--version', action='version', version=get_version())

    args = parser.parse_args()

    if args.verbose:
        logging.basicConfig(format='%(levelname)s:%(message)s',
                            level=logging.DEBUG)
        coloredlogs.install(level='DEBUG')
    else:
        logging.basicConfig(
            format='%(levelname)s:%(message)s', level=logging.INFO)
        coloredlogs.install(level='INFO')

    # Checks
    # ======
    args.mode = args.mode.lower()
    if args.mode not in ('online', 'offline'):
        parser.print_help(sys.stderr)
        sys.exit(1)
    elif (args.mode == 'online'
          and not args.hooks
          or not args.apk
          or not args.focus_pkg):
        parser.print_help(sys.stderr)
        sys.exit(1)
    elif args.mode == 'offline' and not args.pickle_from:
        parser.print_help(sys.stderr)
        sys.exit(1)

    die() if not is_env_correct() else None

    err = util.is_apk(args.apk)
    die(err) if err else None

    if args.mode == 'online':
        if not util.is_frida_server_running():
            die('Frida server not running')

        if not util.is_single_emu_running():
            die('Single emu is not running')

    main(args)


def is_env_correct() -> bool:
    if subprocess.run('command -v adb >/dev/null', shell=True).returncode != 0:
        logging.error("ADB not in PATH")
        return False

    if subprocess.run('command -v jarsigner >/dev/null', shell=True).returncode != 0:
        logging.error("jarsigner not in PATH")
        return False

    if subprocess.run('command -v zipalign >/dev/null', shell=True).returncode != 0:
        logging.error("zipalign not in PATH")
        return False

    if subprocess.run('command -v apktool >/dev/null', shell=True).returncode != 0:
        logging.error("apktool not in PATH")
        return False

    if subprocess.run('command -v aapt >/dev/null', shell=True).returncode != 0:
        logging.error(
            "aapt not in PATH. Export the path of $ANDROID_HOME/build-tools/<SOME_BUILD_VERSION>")
        return False

    return True


def collect_recorded_invocations(args: t.List[t.Any],
                                 smali_parser: SmaliParser,
                                 pkg_name: str,
                                 relined_classes_path: str,
                                 ) -> t.List[RecordedInvocation]:
    recorded_invocations = None

    if args.mode == 'offline':
        logging.info('Running OFFLINE mode...')
        recorded_invocations = pickle.load(open(args.pickle_from, 'rb'))
        if not recorded_invocations:
            die('No pickled recorded invocations')

    elif args.mode == 'online':
        logging.info('Running ONLINE mode...')

        relined_apk_path, err = smali_parser.rebuild_apk(relined_classes_path)
        die(err) if err else None

        # Run APK
        # ============
        util.uninstall_apk(pkg_name)

        # Setting proxy to broken address so we don't
        #  broadcast anything we shouldn't broadcast
        if not util.set_emu_proxy('1.1.1.1', '1234'):
            die('Could not set proxy')

        if not util.install_apk(relined_apk_path):
            util.uninstall_apk(pkg_name)
            die('APK failed to install')

        if not util.run_app(pkg_name):
            util.uninstall_apk(pkg_name)
            die('Failed to launch app')

        # Inject Frida and hook functions
        # =================================
        frida_helper = FridaHelper()
        frida_helper.inject_frida(pkg_name)
        err = frida_helper.hook(args.hooks)
        die(err) if err else None

        if args.timeout:
            logging.info(
                "Awaiting invocations. Will process after timeout [%d seconds]", args.timeout)
            time.sleep(args.timeout)
        else:
            logging.info(
                "Awaiting invocations. Will process after user presses Enter")
            try:
                input("Press Enter when you're done...")
            except KeyboardInterrupt:
                pass

        recorded_invocations = frida_helper.recorded_invocations
        if not recorded_invocations:
            util.uninstall_apk(pkg_name)
            die('No recorded invocations')

        util.uninstall_apk(pkg_name)

    return recorded_invocations


def main(args: t.List[t.Any]):
    # Parse & Reline APK
    # ====================
    smali_parser = SmaliParser(args.focus_pkg)
    disassembled_classes_path, pkg_name, err = smali_parser.parse_apk(args.apk)
    die(err) if err else None

    err = smali_parser.reline_classes()
    die(err) if err else None

    relined_classes_path, err = smali_parser.apply_changes_to_disk(
        disassembled_classes_path)
    die(err) if err else None

    # Record invocations
    recorded_invocations = collect_recorded_invocations(
        args, smali_parser,
        pkg_name,
        relined_classes_path)

    # Process recorded invocations
    # ============================
    ip = InvocationProcessor()
    if args.pickle_to:
        ip.pickle_invocations(recorded_invocations, args.pickle_to)

    ip.annotate_smali_tree(recorded_invocations,
                           smali_parser)

    _, err = smali_parser.apply_changes_to_disk(
        disassembled_classes_path, out_smali_dir=args.out)
    die(err) if err else None

    logging.info('Annotated smali directory is in %s', args.out)
    logging.info("SUCCESS")


if __name__ == "__main__":
    try:
        parse_args()
    except KeyboardInterrupt as ex:
        sys.exit(1)
