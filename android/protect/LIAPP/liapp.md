# LIAPP

## 样本

Dungeon Corporation : (An auto-farming RPG game!  (v3.28, armeabi-v7a)
[Google Play](https://play.google.com/store/apps/details?id=com.bigshotgames.legendaryItem)
[APK-DL (armeabi-v7a)](https://apk-dl.com/dungeon-corporation-an-autofarming-rpg-game/com.bigshotgames.legendaryItem)
[APKPure (arm64-v8a)](https://apkpure.com/dungeon-corporation-an-auto-farming-rpg-game/com.bigshotgames.legendaryItem)

## 保护

入口为 `android:name="com.lockincomp.liapp.LiappCommon"`
壳文件放在 `assets` 目录下
`LIAPPEgg.re` 为配置文件
文件加密每个文件 key 都不同

1. Java Stub 根据架构释放壳文件到 `files/.temp/` 下
2. 加载 `files/.temp/LIAPPClient.sc`
3. 调用 `LIAPPClient.sc!LC.I1(context, (String) null)`
4. 解密出 `linker` 到 `/data/user/0/{package}/files/.tmp.0.XXXXXXXX` 并加载
5. 调用 `linker!LIAPPFUNCTION`
5. `linker` 中解密 `libil2cpp.so` 和 `global-metadata.dat`
    释放到 `/data/user/0/{package}/files/libil2cpp.so` 和 `/data/user/0/{package}/files/global-metadata.dat`
6. 文件使用完之后使用 `unlink` 删除文件

### Java Stub

- `LiappCommon.attachBaseContext`
    - `LC.LCG1`
        - `LC.LCS1`
            - 根据架构释放壳文件到 `files/.temp/` 目录下
                |          |LIAPPEgg.sc            |LIAPPClient.sc            |LIAPPEggHound.sc|Alert.jar|linker                      |
                |-------|----------------------|------------------------|--------------------|---------|----------------------|
                |arm    |LIAPPEgg.sc            |LIAPPClient.sc            |LIAPPEggHound.sc|Alert.jar|LIAPPClientP.sc       |
                |arm64|LIAPPEgg_ARM64.sc|LIAPPClient_ARM64.sc|LIAPPEggHound.sc|Alert.jar|LIAPPClientP.sc       |
                |x86     |LIAPPEgg_x86.sc     |LIAPPClient_x86.sc      |LIAPPEggHound.sc|Alert.jar|LIAPPClientP_x86.sc|
        - `System.load("LIAPPClient.sc")`;
        - `LIAPPClient.sc!M1("/data/data/{package}/files/.temp/")` bind 目录监听
        - `LC.LCS2`
            - 释放 `LIAPPEgg.jar` 和 `LIAPPEggShell.jar`
            - 检查并释放 `LIAPPEgg[2-4].jar` 和 `LIAPPEggShell[2-4].jar`
        - `LIAPPClient.sc!LC.I1(context, (String) null)`
        - `LIAPPClient.sc!M2()` 释放连接

### LIAPPClient.sc

```cpp
// LIAPPClient.sc key
char byte_166BC[] = {0x06, 0xA9, 0x21, 0x40, 0x36, 0xB8, 0xA1, 0x5B, 0x51, 0x2E, 0x03, 0xD5, 0x34, 0x12, 0x00, 0x06};
// LIAPPClient.sc iv
char byte_166CC[] = {0x3D, 0xAF, 0xBA, 0x42, 0x9D, 0x9E, 0xB4, 0x30, 0xB4, 0x22, 0xDA, 0x80, 0x2C, 0x9F, 0xAC, 0x41};

void JNI_OnLoad() {
  memcpy(g_aes_iv, byte_166CC, 16); // linker aes key
}

int Java_com_lockincomp_liapp_LC_I1() {
  auto env4;
  extract_files(env4, jnienv, jc, arg1_context, arg2_str);
  return sub_70CC(env4);
}

int sub_70CC(env4) {
  return !!sub_57AC(env4, 'LIAPPEgg.sc', h, unuse_key1)
}

int sub_57AC(env4) {
  aes_iv = g_aes_iv;
  classes_dex_crc = read_classes_dex_crc_from_zip();
  classes_dex_crc = ~classes_dex_crc;
  aes_iv[12:16] = classes_dex_crc;
  memcpy(aes_key, byte_166BC, 16);
  char* linker_enc = "/data/user/0/{package}/files/.temp/LIAPPClientP.sc";
  char* linker_dec = "/data/user/0/{package}/files/.temp/.tmp.0.XXXXXXXX";
  sub_3270(env4, aes_key, aes_iv, linker_enc, linker_dec);
  auto h = dlopen(linker_dec);
  auto f = dlsym(h, "LIAPPFUNCTION");
  unlink(linker_dec);
  return f(.....);
}

int sub_3270(int env4, char* aes_key, char* aes_iv, char* infile, char* outfile) {
  auto infile = env4.fopen(infile);
  auto outfile = env4.fopen(outfile);
  while(buf_size = env4.fread(&buf, 1, 0xff, infile)) {
    sub_56EC(env4, aes_key, aes_iv, &buf, buf_size);
    env4.fwrite(&buf, 1, buf_size, outfile);
  }
  env4.fclose(infile);
  env4.fclose(outfile);
  return outfile.size();
}

void sub_56EC(int env4, char* aes_key, char* aes_iv, char* buf, int buf_size) {
  while (buf.enough(16)) {
    AES_cbc_decrypt(aes_key, aes_iv, buf.read(16), 16);
  }
}
```

## frida dump
```js
"use strict";

var liapp_linker_module_name = null;
var target_package_name = "com.bigshotgames.legendaryItem";
var decrypted_path = "/data/data/user/0/" + target_package_name + "/files/";

function patch_strstr() {
  // char *strstr(const char *haystack, const char *needle);
  Interceptor.attach(Module.findExportByName("libc.so", "strstr"), {
    onEnter: function (args) {
      //var haystack = Memory.readUtf8String(args[0]);
      var needle = Memory.readUtf8String(args[1]);

      this._patch = false;

      if (needle.indexOf("frida") != -1 || needle.indexOf("xposed") != -1) {
        this._patch = true;
      }
    },
    onLeave: function (retval) {
      if (this._patch) {
        retval.replace(0);
      }

      return retval;
    }
  });
}

function hook_unlink() {
  var old_unlink_ptr = Module.getExportByName('libc.so', 'unlink');
  var old_unlink = new NativeFunction(old_unlink_ptr, 'int', ['pointer']);
  Interceptor.replace(old_unlink_ptr, new NativeCallback(function (pathPtr) {
    var file = pathPtr.readCString();

    if (0 == file.indexOf(decrypted_path) && -1 == file.indexOf(decrypted_path + ".temp/")) {
      var backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
      var backtrace_map = backtrace.map(DebugSymbol.fromAddress);
      //var backtrace_str = backtrace_map.join("\n\t");
      //console.log("Backtrace:" + backtrace_str);
      if (backtrace_map.length > 0) {
        if (backtrace_map[0].moduleName == "LIAPPClient.sc" ||
          backtrace_map[0].moduleName == liapp_linker_module_name) {
          console.log('fake unlink file: ' + file);
          return 0;
        }
      }
    }

    return old_unlink(pathPtr);

  }, 'int', ['pointer']));
}

function hook_dlopen() {
  Interceptor.attach(Module.getExportByName('libc.so', 'dlopen'), {
    onEnter: function (args) {
      this._liapp_linker = false;
      var path = args[0].readCString();
      this.path = path;

      if (null == Module.findBaseAddress(path)) {
        console.log("dlopen: " + path);
      }
      if (null == liapp_linker_module_name &&
        0 == path.indexOf(decrypted_path + ".tmp.")
      ) {
        liapp_linker_module_name = path.substr(path.lastIndexOf('/') + 1);
        this._liapp_linker = true;
      }
    },
    onLeave: function (retval) {
      if (this._liapp_linker && null != liapp_linker_module_name) {
        var linker_base = Module.getBaseAddress(liapp_linker_module_name);
        console.log('==============================');
        console.log('linker loaded');
        console.log('linker name: ' + liapp_linker_module_name);
        console.log('linker path: ' + this.path);
        console.log('linker base: ' + linker_base);
        console.log('==============================');
      }
    }
  });
}

console.log('[*] Unpacker for LiApp Protect');

console.log('[*] Install hook strstr');
patch_strstr();

console.log('[*] Install hook unlink');
hook_unlink();

console.log('[*] Install hook dlopen');
hook_dlopen();

console.log('[*] Install over');

console.log('[*] Watting app run ...');

```