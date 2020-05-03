"use strict";

function get_caller_info() {
  let stack = Java.cast(
    Java.use("java.lang.Thread").currentThread(),
    Java.use("java.lang.Thread")
  ).getStackTrace();

  return {
    class: stack[3].getClassName(),
    method: stack[3].getMethodName(),
    file: stack[3].getFileName(),
    line: stack[3].getLineNumber()
  };
}

function getStackTrace() {
  var th = Java.cast(
    Java.use("java.lang.Thread").currentThread(),
    Java.use("java.lang.Thread")
  );
  var stack = th.getStackTrace();

  let ret = "";
  for (var i = 0; i < stack.length; i++) {
    if (i === 0 || i === 1 || i === 2) {
      continue;
    }

    if (i > 6) break;

    ret +=
      "\t" +
      stack[i].getClassName() +
      "." +
      stack[i].getMethodName() +
      "(" +
      stack[i].getFileName() +
      ") @ " +
      stack[i].getLineNumber() +
      "\n";
  }

  return ret;
}

function get_class_name(method_sig) {
  let delim = method_sig.indexOf(";");
  if (delim === -1) return null;

  const clazz_name = method_sig.slice(1, delim).replace(/\//g, ".");
  return clazz_name;
}

function get_method_name(method_sig) {
  let delim_1 = method_sig.indexOf("->");
  if (delim_1 === -1) return null;

  let delim_2 = method_sig.indexOf("(");
  if (delim_2 === -1) return null;

  const method_name = method_sig.slice(delim_1 + 2, delim_2);
  return method_name;
}

function get_method_args(method_sig) {
  let delim_1 = method_sig.indexOf("(");
  if (delim_1 === -1) return null;

  let delim_2 = method_sig.indexOf(")");
  if (delim_2 === -1) return null;

  return method_sig.slice(delim_1 + 1, delim_2).replace(/;/g, "");
}

function get_arg_str_from_overload(overload) {
  let arg_str = "";
  overload.argumentTypes.forEach(type => {
    arg_str += type["name"].replace(/;/g, "");
  });

  return arg_str;
}

rpc.exports = {
  hookInto: function(method_sig) {
    Java.perform(() => {
      /*
       *  - Hook
       *  - Capture input, output and first stack trace element
       *  - Send them as a message when the function concludes
       */

      //console.log("[+] hooker.js: hook_into: method_sig: " + method_sig);
      let clazz_name = get_class_name(method_sig);
      if (clazz_name == null) {
        console.error(
          `[!] hooker.js: hook_into: clazz_name for ${method_sig} not found`
        );
        return false;
      }
      let method_name = get_method_name(method_sig);
      if (method_name == null) {
        console.error(
          `[!] hooker.js: hook_into: method_name for ${method_sig} not found`
        );
        return false;
      }
      let method_args = get_method_args(method_sig);
      if (method_args == null) {
        console.error(
          `[!] hooker.js: hook_into: method_args for ${method_sig} not found`
        );
        return false;
      }

      //console.warn(clazz_name)
      //console.warn(method_name)
      //console.warn(method_args)
      let clazz = Java.use(clazz_name);
      if (clazz == null) {
        console.error(`[!] hooker.js: hook_into: clazz for ${method_sig} null`);
        return false;
      }
      let method = clazz[method_name];
      if (method == null) {
        console.error(
          `[!] hooker.js: hook_into: method for ${method_sig} null`
        );
        return false;
      }

      let selected_overload = null;
      for (let i = 0; i < method.overloads.length; i++) {
        let arg_str = get_arg_str_from_overload(method.overloads[i]);
        //console.warn(`arg_str: ${arg_str}`);
        if (method_args === arg_str) {
          selected_overload = method.overloads[i];
        }
      }
      if (selected_overload == null) {
        console.error(
          `[!] hooker.js: hook_into: selected_overload for ${method_sig} null`
        );
        return false;
      }

      console.log(`[+] hooker.js: Hook to ${method_sig} successful`);
      selected_overload.implementation = function() {
        console.log(`[+] hooker.js: [${method_sig}] called...`);
        let retval = selected_overload.apply(this, arguments);
        //console.log(getStackTrace());

        let msg = "hook_into:";
        msg += JSON.stringify(
          {
            caller_info: get_caller_info(),
            method_sig: method_sig,
            //"overload_args_sig": method_args,
            args: arguments,
            retval: retval
          },
          0,
          2
        );
        send(msg);

        return retval;
      };
    });
  },
  describe: function(method_sig) {
    Java.perform(() => {
      //console.log(`[+] hooker.js: hook_into: hooking into -> ${method_sig}`);
      let clazz_name = get_class_name(method_sig);
      if (clazz_name == null) {
        console.error(
          `[!] hooker.js: describe: clazz_name for ${method_sig} not found`
        );
        return false;
      }
      let method_name = get_method_name(method_sig);
      if (method_name == null) {
        console.error(
          `[!] hooker.js: describe: method_name for ${method_sig} not found`
        );
        return false;
      }
      let method_args = get_method_args(method_sig);
      if (method_args == null) {
        console.error(
          `[!] hooker.js: describe: method_args for ${method_sig} not found`
        );
        return false;
      }

      //console.warn(clazz_name)
      //console.warn(method_name)
      //console.warn(method_args)
      let clazz = Java.use(clazz_name);
      if (clazz == null) {
        console.error(`[!] hooker.js: describe: clazz for ${method_sig} null`);
        return false;
      }
      let method = clazz[method_name];
      if (method == null) {
        console.error(`[!] hooker.js: describe: method for ${method_sig} null`);
        return false;
      }

      let selected_overload = null;
      for (let i = 0; i < method.overloads.length; i++) {
        let arg_str = get_arg_str_from_overload(method.overloads[i]);
        //console.warn(`arg_str: ${arg_str}`);
        if (method_args === arg_str) {
          selected_overload = method.overloads[i];
        }
      }
      if (selected_overload == null) {
        console.error(
          `[!] hooker.js: describe: selected_overload for ${method_sig} null`
        );
        return false;
      }

      console.log(
        `[+] hooker.js: ${JSON.stringify(
          {
            args: method_sig,
            overload_args: method_args
          },
          0,
          4
        )}`
      );
    });
  }
};
