import logging
import os
import random
import re
import string
import subprocess
import sys
import time
import typing as t

from src.error import Error


def is_frida_server_running() -> bool:
    cmd = subprocess.run('frida-ps -U', shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error('is_frida_running: $? != 0: %s', cmd.stdout.decode())
        return False

    return True


def reset_emu_proxy() -> bool:
    logging.info('Resetting proxy...')
    cmd = subprocess.run(
        'adb shell settings delete global http_proxy', shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error('delete_emu_proxy: $? != 0: %s', cmd.stdout.decode())
        return False

    cmd = subprocess.run(
        'adb shell settings delete global https_proxy', shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error('delete_emu_proxy: $? != 0: %s', cmd.stdout.decode())
        return False

    return True


def set_emu_proxy(ip: str, port: str) -> bool:
    logging.info('Setting proxy %s:%s...', ip, port)

    cmd = subprocess.run(
        'adb shell settings put global http_proxy {}:{}'.format(ip, port), shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error('set_emu_proxy: $? != 0: %s', cmd.stdout.decode())
        return False

    cmd = subprocess.run(
        'adb shell settings put global https_proxy {}:{}'.format(ip, port), shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error('set_emu_proxy: $? != 0: %s', cmd.stdout.decode())
        return False

    return True


def is_single_emu_running() -> bool:
    cmd = subprocess.run('adb devices', shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error('is_single_emu_running: shell command ret != 0')
        return False

    if 'emulator' not in cmd.stdout.decode():
        return False

    return True


def is_app_installed(app_name: str) -> bool:
    cmd = subprocess.run('adb shell pm list packages',
                         shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error("shell command's ret != 0")
        sys.exit(1)

    if app_name not in cmd.stdout.decode():
        return False

    return True


def get_pkg_name_from_apk(apk_path: str
                          ) -> t.Tuple[str, t.Optional[Error]]:
    cmd = subprocess.run(
        'aapt dump badging {}'.format(apk_path), shell=True, capture_output=True)
    if cmd.returncode != 0:
        return '', Error('aapt failed')

    pkg_line = [l
                for l in cmd.stdout.decode().split('\n')
                if re.search(r'package', l)]
    if not pkg_line:
        return '', Error('Not package name found in APK')

    pkg_name = re.match(r"package: name='(.*?)'", pkg_line[0]).group(1)

    return pkg_name, None


def uninstall_apk(pkg_name: str):
    logging.info('Uninstalling APK %s...', pkg_name)
    subprocess.run('adb uninstall {} >/dev/null 2>&1'.format(
        pkg_name), shell=True)


def install_apk(apk_path: str) -> bool:
    logging.info('Installing APK %s...', apk_path)
    cmd = subprocess.run('adb install -r {} 1>/dev/null'.format(apk_path),
                         shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error('install_apk: ret != 0: %s', cmd.stdout.decode())
        return False

    return True


def is_app_running(app_name: str) -> bool:
    cmd = subprocess.run('adb shell ps', shell=True, capture_output=True)
    if cmd.returncode != 0:
        logging.error("shell command's ret != 0")
        sys.exit(1)

    if app_name in cmd.stdout.decode():
        return True

    return False


def run_app(pkg_name: str) -> bool:
    if subprocess.run('adb shell am clear-debug-app {}'.format(pkg_name),
                      shell=True).returncode != 0:
        return False

    if subprocess.run('adb shell monkey -p {} 1 >/dev/null 2>&1'.format(pkg_name),
                      shell=True).returncode != 0:
        return False

    # Sleep for a bit...
    time.sleep(2)

    return True


def stop_app(app_name: str) -> bool:
    logging.info("Stopping app %s...", app_name)
    if subprocess.run('adb shell am force-stop {}'.format(app_name),
                      shell=True).returncode != 0:
        return False

    return True


def get_rand_word(N: int) -> str:
    return ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(N))


def is_apk(apk_path: str) -> t.Optional[Error]:
    try:
        with open(apk_path, 'rb') as fd:
            if fd.read()[0:4] != b'PK\x03\x04':
                return Error("%s is not an APK file", apk_path)
    except FileNotFoundError:
        return Error("%s is not a proper path", apk_path)

    return None


def die(err: t.Union[Error, str] = None):
    msg: str = ''
    if err:
        if isinstance(err, Error):
            msg = err.msg
        elif isinstance(err, str):
            msg = err

    if msg:
        logging.error(msg)

    sys.exit(1)


def get_version() -> str:
    version: str = ''
    with open(os.path.join(
            os.path.dirname(
                os.path.realpath(__file__)
            ), '../VERSION'), 'r') as fd:
        version = fd.read()

    return '%(prog)s {}'.format(version)
