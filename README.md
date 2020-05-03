Decrypticon: A Generic Android Simplifier
=========================================

- [Dependencies](#dependencies)
- [Usage](#usage)
    + [Offline Mode](#offline-mode)
- [Tests](#tests)
- [Real-life Use Case](#real-life-use-case)
- [Special Thanks](#special-thanks)

`Decrypticon` **monitors an Android app's execution** and then **annotates the disassembled codebase with the results of the marked functions' execution**. This allows the analyst to go through the annotated codebase and understand:

        * Input:
            * Android APK
            * A bunch of functions to mark
        * Processing:
            * Run the app and observe the marked functions
        * Output:
            * A disassembled codebase that annotates the arguments and returns values of each marked function

Dependencies
------------
* `ANDROID_HOME` must be in PATH, along with any verison of `build_tools`. Something like this should exist in your `.profile`:

    ```
    export ANDROID_HOME=$HOME/Library/Android/sdk
    export PATH="$ANDROID_HOME/platform-tools:$PATH"
    export PATH="$ANDROID_HOME/build-tools/27.0.3:$PATH"
    ```

* `jarsigner`
* `apktool` 2.4.+ (if you're running OSX: `brew install apktool` is good enough)
* `Python3` 3.7.+
* `virtualenv` 20.+

Usage
-----
* Make a `hooks` file that consists of the functions you want to monitor. [An example exists here](https://github.com/afjoseph/decrypticon/blob/c1173ed/example/test_project/hooks#L1). You can find signture using either `apktool` or `radare2`:

    ```
    Lcom/afjoseph/test/Cryptor;->get(III)Ljava/lang/String;
    Lcom/afjoseph/test/Cryptor;->second(III)Ljava/lang/String;
    Lcom/afjoseph/test/Cryptor;->third(III)Ljava/lang/String;
    ```

* Run an emulator. I recommend using my own `scripts/run_avd.sh`
* Run and install frida-server on the test device. I recommend using my own `scripts/install_frida_server.rb`
* A sample workflow should look like this


    ```
    $ cat hooks
    Lcom/afjoseph/test/Cryptor;->get(III)Ljava/lang/String;
    Lcom/afjoseph/test/Cryptor;->second(III)Ljava/lang/String;
    Lcom/afjoseph/test/Cryptor;->third(III)Ljava/lang/String;

    # Run an emulator
    $ ./scripts/run_avd.sh --android_api_level=28

    # Install Frida server on it
    $ ./scripts/install_frida_server

    # Initialize virtualenv
    $ virtualenv -p python3 venv
    $ venv/bin/pip3 install -r requirements.txt

    # Run Decrypticon
    venv/bin/python3 decrypticon.py \
      --mode online \
      --apk example/test_project/love.apk \
      --hooks hooks \
      --out example/test_project/annotated \
      --focus_pkg com/afjoseph/test
    ```

The above flow is exactly how the [test script](https://github.com/afjoseph/decrypticon/blob/c1173ed/#L1) looks like.

#### Offline Mode
Sometimes, you'd want to save the results of the marked functions (which the project identifies as _recorded invocations_). The `--pickle_to` flag can _pickle_ (Python term for "serialize") all recorded invocations in a file, which you can replay at any time later.

Let's assume you ran `Decrypticon` using `--mode=online` before and used `--pickle_to` flag to save all recorded invocations in `my_tender_pickles` file. You can reply those invocations to annotate the codebase again using the following:

    venv/bin/python3 decrypticon.py \
      --mode offline \
      --apk example/test_project/love.apk \
      --out example/test_project/annotated \
      --focus_pkg com/afjoseph/test --pickle_from my_tender_pickles

This would take `love.apk`, annotate it using the recorded invocations in `my_tender_pickles`, and then write the annotated codebase to `example/test_project/annotated`.

Tests
-----
Run `./scripts/run_test_suite.rb`. This is also a good location to see how the project is supposed to run.


Real-life Use Case
------------------
Take the [following Java code](https://github.com/afjoseph/decrypticon/blob/c1173ed/example/test_project/app/src/main/java/com/afjoseph/test/MainActivity.java#L25):

    Map<String, String> params = new HashMap<>();
    String address_1 = Cryptor.get(30, 20, 100);
    String enc_address_1 = Encryptor.Encrypt(address_1);
    params.put("address_1", enc_address_1);

    String country_1 = Cryptor.get(100, 200, 300);
    String enc_country_1 = Encryptor.Encrypt(address_1);
    params.put("country_1", enc_country_1);

    String token_1 = Cryptor.get(99, 66, 99);
    String enc_token_1 = Encryptor.Encrypt(token_1);
    params.put("token_1", enc_token_1);

    String address_2 = Cryptor.get(55, 22, 32);
    String enc_address_2 = Encryptor.Encrypt(address_2);
    params.put("address_2", enc_address_2);

    String country_2 = Cryptor.get(92, 22, 55);
    String enc_country_2 = Encryptor.Encrypt(address_2);
    params.put("country_2", enc_country_2);

    String token_2 = Cryptor.get(88, 72, 86);
    String enc_token_2 = Encryptor.Encrypt(token_2);
    params.put("token_2", enc_token_2);

An easier way to write this would be:

    params.put("address_1", "neverwhere");

Where `neverwhere` would be the value of the address, but this makes analysis pretty easy since `neverwhere` exists verbatim in the source code.

A common obfuscation scheme is to rely on layers of abstraction to "hide" the value of `neverwhere`. `Cryptor.get()` could look like this (this is a hypothetical function. The code is not compilable):

    public final class Cryptor {
      private static char[] arr = new char[]{'\ucad9', '\ue9a1', '\u1a1c', '\u00a9', '\u591c', '\u9e7e', '\u751c', '\u9cc9', '\u1191', '\ua7e5', '\ucd9e', '\ueca5', '\u1119', '\ucae5', '\u591e', '\u9a5c', '\u5cc0', '\u791a', '\u1ea1', '\u55d5', '\uccca' '\u70d1', '\u9ec1', '\ucc97', '\ua5ac', '\uc1ae', '\ue191', '\u177a', '\ucd1c', '\u5c51', '\u99ce', '\ueea9', '\u95d1', '\ucca9', '\u5199', '\uc711', '\u9daa', '\uac9e', '\uc9c7', '\u5e50', '\uc571', 'e', '\ue915', '\u51c1', '\uc7e5', '&', '\uaeee', '\uc0e0', '\u5e59', '\u7c99', '\u05ec', '\u510c', '\ucaac', '\ud9cc', '\ueaaa', '\u101a', '\ua75c', '\u9d05'};
      privage static int field_99 = 0;
      privage static int field_91 = 2;
      privage static int field_92 = 4;

      private static String get(int var0, int var1, int var2) {
        while(var5 < var8) {
          var10000 = field_91 + 1;
          field_92 = var10000 % 128;
          if (var10000 % 2 == 0) {
          }

          var4[var5] = (char)((int)((long)arr[var9 + var5] ^ (long)var5 * field_90 ^ (long)var7));
          ++var5;
        }

        int var10000 = 2 % 2;
        char var7 = var0;
        int var8 = var1;
        int var9 = var2;
        char[] var4 = new char[var1];
        int var5 = 0;
        var10000 = field_92 + 99;
        field_91 = var10000 % 128;
        switch(var10000 % 2 != 0 ? 66 : 35) {
          case 35:
          default:
            var10000 = 2 % 2;
            break;
          case 66:
            var10000 = 5 * 3;
        }

        String var12 = new String(var4);
        int var10001 = field_91 + 49;
        field_92 = var10001 % 128;
        switch(var10001 % 2 == 0 ? 28 : 47) {
          case 28:
          default:
            try {
              var10001 = ((Object[])null).length;
              return var12;
            } catch (Throwable var11) {
              throw var11;
            }
          case 47:
            return var12;
        }
      }
    }

In that case, there is no easy way of understanding what is the output of `Cryptor.get()`. An easy way of handling this would be to execute `Cryptor.get()` and monitor its value. That is what `Decrypticon` does, plus annotate the disassembled codebase with the args and return value. The _annotated_ smali code will have a bunch of `>>> DECRYPTICON` directives on the marked functions that reveal the execution flow:

After executing `Decrypticon`

    >>> DECRYPTICON:: func(30, 20, 100) = neverwhere
        invoke-static {v1, v2, v3}, Lcom/afjoseph/test/Cryptor;->get(III)Ljava/lang/String;

    ...

    >>> DECRYPTICON:: func(100, 200, 300) = usa
        invoke-static {v3, v4, v5}, Lcom/afjoseph/test/Cryptor;->get(III)Ljava/lang/String;

    ...

    >>> DECRYPTICON:: func(99, 66, 99) = 12341234
        invoke-static {v6, v5, v6}, Lcom/afjoseph/test/Cryptor;->get(III)Ljava/lang/String;

    ...

    >>> DECRYPTICON:: func(55, 22, 32) = baldurs_gate
        invoke-static {v9, v8, v7}, Lcom/afjoseph/test/Cryptor;->get(III)Ljava/lang/String;

    ...

    >>> DECRYPTICON:: func(92, 22, 55) = temeria
        invoke-static {v11, v8, v9}, Lcom/afjoseph/test/Cryptor;->get(III)Ljava/lang/String;

    ...

    >>> DECRYPTICON:: func(88, 72, 86) = abcdabcd
        invoke-static {v11, v12, v13}, Lcom/afjoseph/test/Cryptor;->get(III)Ljava/lang/String;

Special Thanks
--------------
I'd like to thank the following projects and their contributors. They were a **major** part of this project:
* [**Frida**](https://github.com/frida/frida/): Decrypticon relies on it.
* [**Radare2**](https://github.com/radareorg/radare2/): 99% of the analysis done here was made using `r2`
* [**dex-oracle**](https://github.com/CalebFenton/dex-oracle) and [**Simplify**](https://github.com/CalebFenton/simplify): Mr. Fenton's work was the reason I made this project: I encountered some obfuscated malware and ran it through both with good results. There was still quite a bit of manual work I needed to do, though. After checking both codebases, the problem I found was that `dex-oracle` was too simplistic since it **relied on heuristics and specific argument positioning**, which the malware didn't follow. `simplify` went **into an endless loop** trying to execute the marked instructions. After checking the GH issues on both, I realized that they were made with different ideas in mind. I thought that a solution in the middle must exist, to which `decrypticon` was my humble answer.
* My company, [Adjust](https://www.adjust.com/), for giving me the time and space to work on such a project.
* To all the future contributors who will help me make `decrypticon` better. Please reach out to me through Twitter (`@MalwareCheese`) or in the _Issues_ section in this repo.
