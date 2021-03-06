# Android 软件安全与逆向分析

---

[TOC]

## 读书笔记
### 第一章

### 第八章

---

## 逆向心得

### Dalvik 指令
- 实例方法中的p0寄存器代表当前类的this，p1代表第一个参数，后面以此类推
- 静态方法中的p0代表第一个参数，后面以此类推

***

### 注入代码

- Log注入

  1. 把 crack 文件夹放 入APK 反编译后的 smali 文件夹下

  2. 输出String：

    ```smali
  const-string v3, "try block"
  invoke-static {v3}, Lcrack/SmaliInject;->logStr(Ljava/lang/String;)V
  invoke-static {v2}, Lcrack/SmaliInject;->logStr(Ljava/lang/String;)V
  ```
  3. 输出int：

    ```smali
  invoke-static {v2}, Lcrack/SmaliInject;->logInt(I)V
  ```
  4. 输出long：（注意修改此处的 va 和 va+1 寄存器）

    ```smali
    invoke-static {va, va+1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;
    move-result-object va
    invoke-static {va}, Lcrack/SmaliInject;->logLong(Ljava/lang/Long;)V
    ```
  5. 输出boolean：

    ```smali
    invoke-static {v2}, Lcrack/SmaliInject;->logBool(Z)V
    ```
  6. 输出String到文件（追加模式，默认文件名为SD卡根目录下的SmaliInjectDebug.txt）：

    ```smali
    invoke-static {v11}, Lcrack/SmaliInject;->writeStrToFile(Ljava/lang/String;)V
    ```
  7. 输出Object 名称：

    ```smali
    invoke-static {v0}, Lcrack/SmaliInject;->logClassName(Ljava/lang/Object;)V
    ```
  8. 输出方法调用（v11的值代表需要输出多少层函数）：

    ```smali
    const/4 v11, 0x4

    invoke-static {v11}, Lcrack/SmaliInject;->printStackTrace(I)V
    ```
  9. 方法跟踪（默认文件名为SD卡根目录下的MyMethodTracing.trace）：

    ```smali
    invoke-static {}, Lcrack/SmaliInject;->startMethodTracing()V

    invoke-static {}, Lcrack/SmaliInject;->stopMethodTracing()V
    ```
  10. 打印String数组：

    ```smali
    invoke-static {v10}, Lcrack/SmaliInject;->logStrArray([Ljava/lang/String;)V
    ```
  11. 以十六进制输出byte数组（每行16字节）：

    ```smali
    invoke-static {v0}, Lcrack/SmaliInject;->logByteArrayInHex([B)V
    ```
  12. 输出文件File对象的完整路径：

    ```smali
    invoke-static {v11}, Lcrack/SmaliInject;->logFile(Ljava/io/File;)V
    ```
  13. 输出JSONObject对象的格式化文本：

    ```smali
    invoke-static {v2}, Lcrack/SmaliInject;->logJsonObj(Lorg/json/JSONObject;)V
    ```
  14. 输出Button的文本：

    ```smali
    invoke-static {v11}, Lcrack/SmaliInject;->logButton(Landroid/widget/Button;)V
    ```
  15. 输出List的所有item：

    ```smali
    invoke-static {v7}, Lcrack/SmaliInject;->logList(Ljava/util/List;)V
    ```
  16. 获取HttpURLConnection对象访问的网址：

    ```smali
    invoke-static {v3}, Lcrack/SmaliInject;->logHttpURLConnection(Ljava/net/HttpURLConnection;)V
    ```
  17. 方法运行到此：

    ```smali
    invoke-static {}, Lcrack/SmaliInject;->methodFlag()V
    ```
  18. 获取TextView信息：
  
    ```smali
    invoke-static {v0}, Lcrack/SmaliInject;->logTextView(Landroid/widget/TextView;)V
    ```
  19. 获取EditText信息：
  
    ```smali
    invoke-static {v0}, Lcrack/SmaliInject;->logEditText(Landroid/widget/EditText;)V
    ```

- 栈跟踪注入代码

  ```smali
  new-instance v0, Ljava/lang/Exception;
  const-string v1, "Print Trace"
  invoke-direct {v0, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V
  invoke-virtual {v0}, Ljava/lang/Exception;->printStackTrace()V
  ```

- MethodProfiling 注入的代码

  首先加入该权限：

  ```xml
  <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
  ```

  注入开始代码

  ```smali
  const-string v0, "MyMethodTracingFile"
  invoke-static {v0}, Landroid/os/Debug;->startMethodTracing(Ljava/lang/String;)V
  ```

  注入结束代码

  ```smali
  invoke-static {}, Landroid/os/Debug;->stopMethodTracing()V
  ```

***
### ARM 指令
- LSL 指令
  LSL 不改变 R0 的值

  ```asm
  LSL R1, R0, #2
  ```

- BFI 指令
>BFI{cond} Rd, Rn, #lsb, #width
用 Rn 中从 [0] 位开始的 width 位替换 Rd 中从 lsb 开始的 width 位。 Rd 中的其他位保持不变。

  如R2此时为0101，R3为0001，执行如下指令：

  ```asm
  BFI R3, R2, #1, #3
  ```
  用R2的第0位开始的3位覆盖R3第1位开始的3位，结果为R3=1011

***
### 正则表达式

- 匹配 Smali 跳转信息

  ```re
(if-\w+(?=\s)|:\w+_\w+)
```

- 搜索方法

```re
\.method.+MethodName\(.*\)
```


***
### 静态分析
- 查看类名

> aapt dump badging `apkfilename` | grep package | awk '{print $2}' | sed s/name=//g | sed s/\\'//g

- 查看启动Activity

> aapt dump badging `apkfilename` | grep launchable-activity | awk '{print $2}' | sed s/name=//g | sed s/\\'//g

- 获取PID

> adb shell "ps | grep `packagename` | awk '{ print $2 }'

- 获取Tracer PID

> cat /proc/`pid`/status | grep TracerPid | awk '{ print $2 }'

#### API特征

- 密码键盘

> Landroid/widget/Button;->getText()Ljava/lang/CharSequence;

- Log 特征

> Landroid/util/Log;->

- 签名验证

> Landroid/content/pm/PackageInfo;->signatures

- 防止截屏

```smali
invoke-virtual {p0}, Lcom/csii/ui/BaseActivity;->getWindow()Landroid/view/Window;

move-result-object v0

#v0=(Reference,Landroid/view/Window;);
const/16 v1, 0x2000

#v1=(PosShort);
invoke-virtual {v0, v1}, Landroid/view/Window;->addFlags(I)V
```

#### Drozer 使用方法

1. 端口转发 `adb forward tcp:31415 tcp:31415`  
2. 连接 `drozer.bat console connect`  
3. 检测攻击面 `run app.package.attacksurface cmb.pb`  
4. 数据库注入 `run scanner.provider.injection -a cmb.pb`  
5. 可导出 Activity `run app.activity.info -a cmb.pb`


***
### 动态调试

- 监控LogTag为ActivityManage的Log能了解当前弹出的Activity的名称

- 调试经验

> 查找ptrace()的调用情况

> 查找getpid()函数，可能跟检测进程的`/proc/pid/status`里的`TracerPid`有关

> 注意是不是载入armeabi-v7库

> 按下"/"可以把伪代码载入流程图

> kill -19 暂停进程

- jdb

1. adb shell am start -D -n `packagename`/`launchable-activity`
2. adb forward tcp:8600 jdwp:`pid`
3. jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=`monitor左边的端口`

- IDA 调试so库

1. adb push android_server /data/local/tmp
2. adb shell
3. cd /data/local/tmp
4. su -
5. chmod 777 ./android_server
6. ./android_server
7. 另外开启一个控制台
8. 设置端口转发

	```bash
	adb forward tcp:23946 tcp:23946
	```

9. 调试模式启动app

	```bash
	adb shell am start -D -n `packagename`/`launchable-activity`
	```

10. 启动IDA，选择debugger->attach->remote armlinux/android debugger，hostname写localhost，port写23946，并且设置Debug option
11. IDA选择进程
12. 在IDA中按G跳转到要调试的函数，F2下断点
13. 命令行启动 monitor，终端中执行

	> jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=`monitor左边的端口`


14. IDA中F9继续运行



***

### 抓包分析

- tcpdump

> tcpdump -p -vv -s 0 -w /sdcard/capture.cap