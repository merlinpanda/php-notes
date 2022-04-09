# php.ini相关的一些安全配置
## 屏蔽PHP错误信息
> ✅ 关闭display_errors

```
// php.ini
; This directive controls whether or not and where PHP will output errors,
; notices and warnings too. Error output is very useful during development, but
; it could be very dangerous in production environments. Depending on the code
; which is triggering the error, sensitive information could potentially leak
; out of your application such as database usernames and passwords or worse.
; For production environments, we recommend logging errors rather than
; sending them to STDOUT.
; Possible Values:
;   Off = Do not display any errors
;   stderr = Display errors to STDERR (affects only CGI/CLI binaries!)
;   On or stdout = Display errors to STDOUT
; Default Value: On
; Development Value: On
; Production Value: Off
; http://php.net/display-errors
; 如果是生产环境，这里应该设置为Off，避免将错误提示信息展示给用户
display_errors = Off
```

## 防止版本号暴露
默认情况下，HTTP请求返回的Response头数据中，X-Powered-By会显示出php版本号

> ✅  关闭expose_php 

```
// php.ini

;;;;;;;;;;;;;;;;;
; Miscellaneous ;
;;;;;;;;;;;;;;;;;

; Decides whether PHP may expose the fact that it is installed on the server
; (e.g. by adding its signature to the Web server header).  It is no security
; threat in any way, but it makes it possible to determine whether you use PHP
; on your server or not.
; http://php.net/expose-php
expose_php = Off
```

## 文件系统限制
在PHP中可以通过配置```open_basedir```来限制PHP访问文件系统的位置，将PHP执行权限限制在特定目录下，此目录之外的文件PHP将拒绝访问。

可以有效对抗文件包含、目录遍历等攻击
> 目录遍历攻击：攻击者为了访问非公开文件目录，通过非法截断或篡改目录路径得以访问某些目录的一种攻击，也被称为路径遍历攻击

> ✅   设置open_basedir，设置时需要注意，❗️❗️❗️目录最后要加上“/”，否则会认为是目录的前缀

```
// php.ini

; open_basedir, if set, limits all file operations to the defined directory
; and below.  This directive makes most sense if used in a per-directory
; or per-virtualhost web server configuration file.
; Note: disables the realpath cache
; http://php.net/open-basedir

open_basedir = /home/web/php/

```

## 禁用危险函数
PHP中有很多危险的内置功能函数，如果使用不当，可能会造成系统崩溃，在配置文件中添加需要禁用的函数，可以有效的避免webshell。

> webshell: 通常被称为网页后门，具有隐蔽性，攻击者在入侵一个网站后，通常会将自己的PHP后门文件与网站服务器Web目录下正常的网页文件混在一起，然后使用浏览器来访问，得到一个命令执行环境，从而达到控制网站服务器的目的。

| 函数名称 | 函数功能 | 危害 |
|---|---|---|
|chgrp()|改变文件或目录所属的用户组| 高|
|chown()|改变文件或目录的所有者|高|
|chroot()|可改变当前PHP进程的工作根目录，仅当系统支持CLI模式时PHP才能工作，且该函数不适用于Windows系统|高|
|dl()|在PHP运行过程中（非启动时）加载一个PHP外部模块|高|
|exec()|允许执行一个外部程序（如UNIX Shell或CMD命令等）|高|
|ini_alter()|是ini_set()函数的别名函数，功能与init_set()相同|高|
|ini_restore()|可用于将PHP环境配置参数恢复为初始值|高|
|ini_set()|可用于修改和设置PHP环境配置参数|高|
|passthru()|允许执行一个外部程序并回显输出，类似于exec()|高|
|pfsockopen()|建立一个Internet或UNIX域的socket持久连接|高|
|phpinfo()|输出PHP环境信息以及相关模块、web环境等信息|高|
|popen()|可通过popen()的参数传递一条命令，并对popen()所打开的文件进行执行|高|
|proc_get_status()|获取使用proc_open()所打开的进程的信息|高|
|proc_open()|执行一个命令并打开文件指针用于读取与写入|高|
|putenv()|用于在PHP运行时改变系统字符集环境|高|
|readlink()|返回符号连接指向的目标文件内容|中|
|scandir()|列出指定路径中文件和目录|中|
|shell_exec()|通过Shell执行命令，并将执行结果作为字符串返回|高|
|stream_socket_server()|建立一个Internet或UNIX服务器连接|中|
|symlink()|对已有的target建立一个名为link的符号连接|高|
|syslog()|可调用UNIX系统的系统层syslog()函数|中|
|system()|允许执行一个外部程序并回显输出，类似于passthru()|高|

> ✅ 设置disable_functions
```
// php.ini

; This directive allows you to disable certain functions.
; It receives a comma-delimited list of function names.
; http://php.net/disable-functions
disable_functions = phpinfo,eval,passthru,exec,system,chroot
```

