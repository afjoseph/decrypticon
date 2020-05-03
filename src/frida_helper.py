import json
import logging
import os
import typing as t

import frida
import frida.core

from src.error import Error
from src.recorded_invocation import RecordedInvocation


class FridaHelper:
    def __init__(self):
        self.device: t.Any = None
        self.exports: t.Any = None
        self.pid: t.Any = None
        self.session: t.Any = None
        self.recorded_invocations: t.List[RecordedInvocation] = []

    def __parse_hooks(self, hook_file: str
                      ) -> t.Tuple[t.Optional[t.List[str]],
                                   t.Optional[Error]]:
        lines = []
        try:
            with open(hook_file, 'r', encoding="utf-8") as fd:
                for line in fd:
                    line = line.strip()
                    if not line:
                        continue

                    lines.append(line)
        except EnvironmentError:
            return None, Error("Couldn't parse hooks file properly")

        return lines, None

    def inject_frida(self, target_process: str):
        logging.info("Injecting frida...")
        self.device = frida.get_usb_device()
        # self.pid = self.device.spawn([process])
        # self.session = self.device.attach(self.pid)
        # self.device.resume(self.pid)
        self.session = self.device.attach(target_process)
        script = self.__load_script(self.session)
        self.exports = script.exports

    def hook(self, hook_file: str):
        target_methods, err = self.__parse_hooks(hook_file)

        if err:
            return err
        if not target_methods:
            return Error('Empty target_methods')

        logging.info("Hooking...")

        for method_sig in target_methods:
            self.exports.describe(method_sig)
            self.exports.hook_into(method_sig)

        return None

    def __load_script(self, session) -> t.Any:
        script = None
        try:
            with open(os.path.join(os.getcwd(), "src/hooker.js"), 'r', encoding="utf-8") as fd:
                script = session.create_script(fd.read(), runtime="v8")
                script.on("message", self.on_message)
                script.load()
        except EnvironmentError:
            raise IOError("Couldn't parse script properly")

        return script

    def on_message(self, msg: t.Any, _):
        logging.debug('msg: %s', json.dumps(msg, indent=4, sort_keys=True))
        if msg['type'] == 'error':
            logging.error(msg)
        elif msg['type'] == 'send':
            split = msg['payload'].split(':', 1)
            caller = split[0]
            message = split[1]

            if caller == 'hook_into':
                msg_json = json.loads(message)
                logging.debug('Message from hook_into: %s',
                              json.dumps(msg_json, indent=4))
                self.recorded_invocations.append(RecordedInvocation(
                    msg_json['caller_info'], msg_json['method_sig'],
                    msg_json['args'], msg_json['retval'], len(self.recorded_invocations)+1))
                logging.debug('=======================')

            elif caller == "describe":
                msg_json = json.loads(message)
                logging.debug("=======================")
                logging.debug("Message from describe: ")
                msg_args = msg_json["args"]
                logging.debug("args: ")
                logging.debug(json.dumps(msg_args, indent=4))

                msg_out = msg_json["out"]
                logging.debug("out: ")
                logging.debug(json.dumps(msg_out, indent=4))

                logging.debug("=======================")
            else:
                raise Exception("Unknown caller")
        else:
            logging.warning("Unknown message received")
            logging.warning(msg)
