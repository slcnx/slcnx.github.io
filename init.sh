#!/bin/bash
#
#********************************************************************
#Author:                Songliangcheng
#QQ:                    2192383945
#Date:                  2020-11-10
#FileName：             linux_template_install.sh
#URL:                   http://www.magedu.com
#Description：          借鉴N49同学N49030 广州 程昱余脚本所写
#Copyright (C):        2020 All rights reserved
#********************************************************************
# openssh-server配置
PORT=22
ALLOW_ROOT_LOGIN=yes
ALLOW_PASS_LOGIN=yes
# root密码配置
ROOT_PASS="123456"
# 主机名配置
HOSTNAME=chengdu-huayang-linux39-template-0-167.magedu.local
# 网络配置
IPADDR=192.168.0.123
NETMASK=255.255.255.0
GATEWAY=192.168.0.1
DNS1=223.6.6.6 
AUTHOR=magedu
QQ=1062670898,2967305595
DESCRIBE="A test Script from www.magedu.com"
CURRENT_DIR=$(dirname $(readlink -f $0))

# 配置vimrc环境
set_vimrc() {
echo "开始配置vimrc环境"
cat>~/.vimrc<<EOF
set nu
set cul
set tabstop=2
set expandtab
set shiftwidth=2
set ai
set softtabstop=2
map <F2> :set paste <CR> o
map <F3> :set expandtab <CR> :%retab! <CR>  :wq! <CR>
map <F4> :set binary <CR> :set noendofline <CR>  :wq! <CR>
autocmd BufNewFile *.sh exec ":call SetTitle()"
function SetTitle()
        if expand("%:e") == 'sh'
        call setline(1,"#!/bin/bash")
        call setline(2,"#")
        call setline(3,"#********************************************************************")
        call setline(4,"#Author:                $1")
        call setline(5,"#QQ:                    $2")
        call setline(6,"#Date:                  ".strftime("%Y-%m-%d"))
        call setline(7,"#FileName：             ".expand("%"))
        call setline(8,"#URL:                   http://blog.mykernel.cn")
        call setline(9,"#Description：          $3")
        call setline(10,"#Copyright (C):        ".strftime("%Y")." All rights reserved")
        call setline(11,"#********************************************************************")
        call setline(12,"")
        endif
endfunc
autocmd BufNewFile * normal G
EOF

echo "配置成功"
}





# 配置中文
set_chinese() {
echo "开始配置中文"
yum -y install kde-l10n-Chinese  glibc-common
localedef -c -f UTF-8 -i zh_CN zh_CN.utf8
echo '
export LANG=zh_CN.utf8
' > /etc/profile.d/chinese.sh
echo "配置成功"
}
set_chinese_ubuntu() {
echo "开始配置中文"
apt update
if [ $? -ne 0 ]; then
	pkill apt-get
	pkill apt-get
	apt update
fi
apt-get install language-pack-zh* -y
echo 'LANG="zh_CN.UTF-8"' > /etc/default/locale
dpkg-reconfigure --frontend=noninteractive locales
update-locale LANG=zh_CN.UTF-8
echo "配置成功"
}


# 配置openssh-server
set_openssh_server() {
echo "开始配置openssh-server"
cat > /etc/ssh/sshd_config <<EOF
Port ${1:-22}
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
PermitRootLogin ${2:-prohibit-password}
AuthorizedKeysFile	.ssh/authorized_keys
PasswordAuthentication ${3:-yes}
#PubkeyAuthentication yes
ChallengeResponseAuthentication no
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
UsePAM yes
X11Forwarding yes
UseDNS no
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
Subsystem	sftp	/usr/libexec/openssh/sftp-server
EOF
echo "配置成功"
}
set_openssh_server_ubuntu() {
echo "开始配置openssh-server"
cat > /etc/ssh/sshd_config <<EOF
Port ${1:-22}
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
SyslogFacility AUTHPRIV
PermitRootLogin ${2:-prohibit-password}
AuthorizedKeysFile	.ssh/authorized_keys
PasswordAuthentication ${3:-yes}
#PubkeyAuthentication yes
ChallengeResponseAuthentication no
GSSAPIAuthentication yes
GSSAPICleanupCredentials no
UsePAM yes
X11Forwarding yes
UseDNS no
AcceptEnv LANG LC_CTYPE LC_NUMERIC LC_TIME LC_COLLATE LC_MONETARY LC_MESSAGES
AcceptEnv LC_PAPER LC_NAME LC_ADDRESS LC_TELEPHONE LC_MEASUREMENT
AcceptEnv LC_IDENTIFICATION LC_ALL LANGUAGE
AcceptEnv XMODIFIERS
Subsystem	sftp	/usr/lib/openssh/sftp-server
EOF
echo "配置成功"
}

# 配置root密码
set_root_passwd() {
echo "开始配置root密码"
echo "$1" | passwd --stdin root
echo "配置成功"
}
set_root_passwd_ubuntu() {
echo "开始配置root密码"
echo "root:$1" | chpasswd
echo "配置成功"
}


# 配置主机名
set_hostname() {
echo "开始配置主机名"
echo "$1" > /etc/hostname
hostnamectl set-hostname "$1"
echo "配置成功"
}

# 配置网卡名
set_ethX() {
echo "开始配置网卡名"
sed -Ei.bak '/GRUB_CMDLINE_LINUX=/s/quiet.*$/quiet net.ifnames=0 biosdevname=0"/' /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg > /dev/null
echo "配置成功"
}
set_ethX_ubuntu() {
echo "开始配置网卡名"
sed -Ei.bak '/GRUB_CMDLINE_LINUX=/s/quiet.*$/quiet net.ifnames=0 biosdevname=0"/' /etc/default/grub
update-grub
echo "配置成功"
}


# 获取掩码长度
mask2cdr ()
{
   # Assumes there's no "255." after a non-255 byte in the mask
   local x=${1##*255.}
   set -- 0^^^128^192^224^240^248^252^254^ $(( (${#1} - ${#x})*2 )) ${x%%.*}
   x=${1%%$3*}
   echo $(( $2 + (${#x}/4) ))
}


# 配置IP
set_ip() {
echo "开始配置IP"
cat > /etc/sysconfig/network-scripts/ifcfg-eth0 <<EOF
TYPE=Ethernet
BOOTPROTO=static
DEVICE=eth0
ONBOOT=yes
IPADDR=$1
NETMASK=$2
GATEWAY=$3
#DNS1=192.168.0.1
EOF


cat > /etc/resolv.conf <<EOF
nameserver $4
EOF

echo "配置成功"
}
set_ip_ubuntu() {
echo "开始配置IP"

cat > /etc/netplan/01-netcfg.yaml <<EOF
# This file describes the network interfaces available on your system
# For more information, see netplan(5).
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: no
      addresses: [$1/$(mask2cdr $2)]
      gateway4: $3
      nameservers:
        addresses: [$4]
EOF
netplan apply
echo "配置成功"
}



# 安装常用命令
set_install_basepkgs() {
echo "开始安装常用命令"
yum remove -y NetworkManager* firewalld*
# 卸载NetworkManger之后dns会出问题
echo 'nameserver 114.114.114.114' > /etc/resolv.conf
yum install -y vim wget tree  lrzsz gcc gcc-c++ automake pcre pcre-devel zlib zlib-devel openssl openssl-devel iproute net-tools iotop ntpdate lsof
echo "配置成功"

echo "关闭selinux"
sed -Ei.bak '/SELINUX=/s/(SELINUX=)enforcing/\1disabled/' /etc/selinux/config
echo "配置成功"
}


set_install_basepkgs_ubuntu() {
apt  purge ufw lxd lxd-client lxcfs lxc-common -y
apt install iproute2 ntpdate tcpdump telnet traceroute nfs-kernel-server nfs-common lrzsz tree openssl libssl-dev libpcre3 libpcre3-dev zlib1g-dev ntpdate tcpdump telnet traceroute gcc make openssh-server lrzsz tree openssl libssl-dev libpcre3 libpcre3-dev zlib1g-dev ntpdate tcpdump telnet traceroute iotop unzip zip lsof make curl iputils-ping net-tools -y 
}
# 优化系统资源限制
set_limit() {
echo "开始优化系统资源限制"
cat > /etc/security/limits.conf <<'EOF'
root  soft  core      unlimited
root  hard  core      unlimited
root  soft  nproc     1000000
root  hard  nproc     1000000
root  soft  nofile    1000000
root  hard  nofile    1000000
root  soft  memlock   32000
root  hard  memlock   32000
root  soft  msgqueue  8192000
root  hard  msgqueue  8192000
*     soft  core      unlimited
*     hard  core      unlimited
*     soft  nproc     1000000
*     hard  nproc     1000000
*     soft  nofile    1000000
*     hard  nofile    1000000
*     soft  memlock   32000
*     hard  memlock   32000
*     soft  msgqueue  8192000
*     hard  msgqueue  8192000
EOF
echo "配置成功"
}


# 开始优化内核参数
set_kernel_params() {
cat > /etc/sysctl.conf <<'EOF'
# 1：开启严格的反向路径校验。对每个进来的数据包，校验其反向路径是否是最佳路径。如果反向路径不是最佳路径，则直接丢弃该数据包。
#  减少DDoS攻击,校验数据包的反向路径，如果反向路径不合适，则直接丢弃数据包，避免过多的无效连接消耗系统资源。
#  防止IP Spoofing,校验数据包的反向路径，如果客户端伪造的源IP地址对应的反向路径不在路由表中，或者反向路径不是最佳路径，则直接丢弃数据包，不会向伪造IP的客户端回复响应。
net.ipv4.conf.default.rp_filter = 1
# 监听非本机
net.ipv4.ip_nonlocal_bind = 1
# 转发
net.ipv4.ip_forward = 1
#处理无源路由的包
net.ipv4.conf.default.accept_source_route = 0
#关闭sysrq功能
kernel.sysrq = 0
#core文件名中添加pid作为扩展名
kernel.core_uses_pid = 1
# tcp_syncookies是一个开关，是否打开SYN Cookie功能，该功能可以防止部分SYN攻击。tcp_synack_retries和tcp_syn_retries定义SYN的重试次数。
net.ipv4.tcp_syncookies = 1
# docker
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-arptables = 1
# docker运行时，需要设置为1
fs.may_detach_mounts = 1
#修改消息队列长度
kernel.msgmnb = 65536
kernel.msgmax = 65536
#设置最大内存共享段大小bytes
kernel.shmmax = 68719476736
kernel.shmall = 4294967296

net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_sack = 1
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 262144
# net.core.somaxconn 是Linux中的一个kernel参数，表示socket监听（listen）的backlog上限。什么是backlog呢？backlog就是socket的监听队列，当一个请求（request）尚未被处理或建立时，他会进入backlog。而socket server可以一次性处理backlog中的所有请求，处理后的请求不再位于监听队列中。当server处理请求较慢，以至于监听队列被填满后，新来的请求会被拒绝。 
net.core.somaxconn = 20480
net.core.optmem_max = 81920
# tcp_max_syn_backlog 进入SYN包的最大请求队列.默认1024.对重负载服务器,增加该值显然有好处.
net.ipv4.tcp_max_syn_backlog = 262144
net.ipv4.tcp_syn_retries = 3
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 15
# 在使用 iptables 做 nat 时，发现内网机器 ping 某个域名 ping 的通，而使用 curl 测试不通, 原来是 net.ipv4.tcp_timestamps 设置了为 1 ，即启用时间戳
net.ipv4.tcp_timestamps = 0
# tw_reuse 只对客户端起作用，开启后客户端在1s内回收
net.ipv4.tcp_tw_reuse = 1
# recycle 同时对服务端和客户端启作用。如果服务端断开一个NAT用户可能会影响。
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_fin_timeout = 1
# Nginx 之类的中间代理一定要关注这个值，因为它对你的系统起到一个保护的作用，一旦端口全部被占用，服务就异常了。 tcp_max_tw_buckets 能帮你降低这种情况的发生概率，争取补救时间。
net.ipv4.tcp_max_tw_buckets = 20000
# 这个值表示系统所能处理不属于任何进程的socket数量，当我们需要快速建立大量连接时，就需要关注下这个值了。 
net.ipv4.tcp_max_orphans = 327680
# 15. 现大量fin-wait-1
#首先，fin发送之后，有可能会丢弃，那么发送多少次这样的fin包呢？fin包的重传，也会采用退避方式，在2.6.358内核中采用的是指数退避，2s，4s，最后的重试次数是由
net.ipv4.tcp_synack_retries = 1
net.ipv4.tcp_syncookies = 1
# KeepAlive的空闲时长，或者说每次正常发送心跳的周期，默认值为7200s（2小时）
net.ipv4.tcp_keepalive_time = 300
# KeepAlive探测包的发送间隔，默认值为75s
net.ipv4.tcp_keepalive_intvl = 30
# 在tcp_keepalive_time之后，没有接收到对方确认，继续发送保活探测包次数，默认值为9（次）
net.ipv4.tcp_keepalive_probes = 3
# 允许超载使用内存，避免内存快到极限报错
vm.overcommit_memory = 1
# 0,内存不足启动oom killer. 1内存不足,kernel panic(系统重启) 或oom. 2. 内存不足, 强制kernel panic. (系统重启) 
vm.panic_on_oom=0
vm.swappiness = 10
#net.ipv4.conf.eth1.rp_filter = 0
#net.ipv4.conf.lo.arp_ignore = 1
#net.ipv4.conf.lo.arp_announce = 2
#net.ipv4.conf.all.arp_ignore = 1
#net.ipv4.conf.all.arp_announce = 2
net.ipv4.tcp_mem = 786432 1048576 1572864
net.ipv4.tcp_rmem = 4096 87380 4194304
net.ipv4.tcp_wmem = 4096 16384 4194304
# 随机端口的范围
net.ipv4.ip_local_port_range = 10001 65000

# inotify监听文件数量
fs.inotify.max_user_watches=89100

# 文件打开数量
# 所有进程 
fs.file-max=52706963
# 单个进程
fs.nr_open=52706963
EOF
echo "配置成功"
}


# 镜像
set_mirrors_aliyun_ubuntu() {
sed -i.bak -e 's@us.archive.ubuntu.com@mirrors.aliyun.com@g'  -e 's@security.ubuntu.com@mirrors.aliyun.com@g' /etc/apt/sources.list	
apt update
}

# 配置时间同步
set_time_sync() {
echo "开始配置时间同步"
echo '*/5 * * * * /usr/sbin/ntpdate time1.aliyun.com &> /dev/null' > /var/spool/cron/root
echo "配置成功"
}
# 配置时间同步
set_time_sync_ubuntu() {
echo "开始配置时间同步"
echo '*/5 * * * * /usr/sbin/ntpdate time1.aliyun.com &> /dev/null' > /var/spool/cron/crontabs/root
echo "配置成功"
}

function usage {
cat << END
	$(basename $0) OPTION ...
		--port=<port>                              ssh服务监听的端口, 默认22
		--allow-root-login=<prohibit-password|yes> ssh配置是否让root能登陆,默认prohibit-password.
		--allow-pass-login=<yes|no>                ssh配置是否让pass能登陆,默认yes
		--root-password=<root_pass>                配置root登陆密码,默认123456
		--hostname=<hostname>                      配置主机名,cd-hy-linux39-centos-0-167.magedu.local
		--ipaddr=<ipaddr>                          配置IP, 默认192.168.0.123
		--netmask=<netmask>                        配置掩码, 默认255.255.255.0
		--gateway=<gateway>                        配置网关,默认192.168.0.1
		--dns=<dns>                                配置DNS, 默认223.6.6.6
		--author=<author>                          配置vimrc生成脚本的作者, 默认magedu
		--qq=<author>                              配置vimrc生成脚本的qq, 我的班主任萌萌老师: 2967305595
		--desc=<desc>                              配置vimrc生成脚本的描述, 默认: A test Script from magedu
        --chinese=                                 配置中文, openstack python2, 不要启用
        --eth0=                                    配置eth0接口
        --resourceslimit=                          配置资源限制
        --kernelparams=                            配置内核优化
        --basepkgs=                                配置基础包
        --umirror=                                  配置镜像加速, only ubuntu
		

    # 所有功能 非中文
	# bash $(basename $0) \
	--port=22 --allow-root-login=yes --allow-pass-login=yes \
	--root-password=123456 \
	--hostname=ubuntu-template.magedu.local \
	--ipaddr=192.168.0.123 --netmask=255.255.255.0 --gateway=192.168.0.1 \
	--dns=223.6.6.6 \
	--author=songliangcheng --qq=2192383945 --desc="A test toy" \
	--resourceslimit=1 \
	--kernelparams=1 \
	--basepkgs=1 \
	--chinese=0 \
	--eth0=0 \
	--umirror=1 


    示例：只配置主机名和vimrc和参数优化 中文
	# bash $(basename $0) \
	--hostname=ubuntu-template.magedu.local \
	--author=songliangcheng --qq=2192383945 --desc="A test toy" \
	--resourceslimit=1 \
	--kernelparams=1 \
	--basepkgs=1 \
	--chinese=1 \
	--eth0=0 \
	--umirror=1 
    
	示例： 无操作
	bash -x linux_template_install.sh --resourceslimit=0 --kernelparams=0 --basepkgs=0 --chinese=0  --eth0=0 --umirror=0

END

}


ssh=0
pass=0
hname=0
vimrc=0
net=0
chinese=0
eth0=0
resourceslimit=0
kernelparams=0
basepkgs=0
umirror=0
for option
do
    case "$option" in
        -*=*) value=`echo "$option" | sed -e 's/[-_a-zA-Z0-9]*=//'` ;;
           *) value="" ;;
    esac

    case "$option" in
        --help)                         
			usage
			exit 1
			;; 
		--port=*)
			PORT="$value"			
			ssh=1
			;;
		--allow-root-login=*)
			ALLOW_ROOT_LOGIN="$value"
			ssh=1
			;;
		--allow-pass-login=*)
			ALLOW_PASS_LOGIN="$value"
			ssh=1
			;;
		--root-password=*)
			ROOT_PASS="$value"
			pass=1
			;;
		--hostname=*)
			HOSTNAME="$value"
			hname=1
			;;
		--ipaddr=*)
			IPADDR="$value"
			net=1
			;;
		--netmask=*)
			NETMASK="$value"
			net=1
			;;
		--gateway=*)
			GATEWAY="$value"
			net=1
			;;
		--dns=*)
			DNS1="$value"
			net=1
			;;
		--author=*)
			AUTHOR="$value"
			vimrc=1
			;;
		--qq=*)
			QQ="$value"
			vimrc=1
			;;
		--desc=*)
			DESCRIBE="$value"
			vimrc=1
			;;
        --chinese=*)
          chinese="$value"
          ;;
        --eth0=*)
          eth0="$value"
          ;;
        --resourceslimit=*)
          resourceslimit="$value"
          ;;
        --kernelparams=*)
          kernelparams="$value"
          ;;
        --basepkgs=*)
          basepkgs="$value"
          ;;
        --umirror=*)
          umirror="$value"
          ;;
        *)
            echo "$0: error: invalid option \"$option\""
			usage
            exit 1
        ;;
esac
done


[ -z "$option" ] &&  echo "$0: error: invalid option \"$option\"" && exit 1




centos_init() {
if [ $vimrc -eq 1 ]; then
# 配置vim环境
set_vimrc "$AUTHOR" "$QQ" "$DESCRIBE"
fi

if [ $chinese -eq 1 ]; then
# 配置中文
set_chinese
fi

if [ $ssh -eq 1 ]; then
# 配置ssh
# ubuntu: Subsystem	sftp /usr/lib/openssh/sftp-server
# set_openssh_server 端口 是否允许root登陆 是否允许密码登陆
set_openssh_server $PORT $ALLOW_ROOT_LOGIN $ALLOW_PASS_LOGIN
fi

if [ $pass -eq 1 ]; then
# 配置root密码
set_root_passwd "$ROOT_PASS"
fi

if [ $hname -eq 1 ]; then
# 配置主机名
# 地区-机房-业务-服务-ip后缀.域名.后缀
# chengdu-huayang-linux39-centos-0-167.magedu.local
set_hostname "$HOSTNAME"
fi

if [ $eth0 -eq 1 ]; then
set_ethX
fi

if [ $net -eq 1 ]; then
# set_ip IP MASK GATEWAY
set_ip "$IPADDR" "$NETMASK" "$GATEWAY" "$DNS1"
fi

if [ $basepkgs -eq 1 ]; then
# 安装基础包
set_install_basepkgs
fi
if [ $resourceslimit -eq 1 ]; then
# 配置限制和内核参数
set_limit
fi
if [ $kernelparams -eq 1 ]; then
set_kernel_params
fi
# 配置时间同步
set_time_sync
# 提示
# Set Logon failure handling
#限制登入失败三次，普通账号锁定5分钟，root账号锁定5分钟
if ! grep -q root_unlock_time=300 /etc/pam.d/sshd; then
	sed -i '/^#%PAM-1.0/a\auth required pam_tally2.so deny=3 unlock_time=300 even_deny_root root_unlock_time=300' /etc/pam.d/sshd
fi 
}
ubuntu_init() {

if [ $umirror -eq 1 ]; then
# 配置镜像源
set_mirrors_aliyun_ubuntu
fi

if [ $chinese -eq 1 ]; then
# 配置中文
set_chinese_ubuntu
fi

if [ $vimrc -eq 1 ]; then
set_vimrc "$AUTHOR" "$QQ" "$DESCRIBE"
fi

if [ $ssh -eq 1 ]; then
set_openssh_server_ubuntu $PORT $ALLOW_ROOT_LOGIN $ALLOW_PASS_LOGIN
fi

if [ $pass -eq 1 ]; then
set_root_passwd_ubuntu "$ROOT_PASS"
fi

if [ $hname -eq 1 ]; then
set_hostname "$HOSTNAME"
fi

if [ $eth0 -eq 1 ]; then
set_ethX_ubuntu
fi
if [ $net -eq 1 ]; then
set_ip_ubuntu "$IPADDR" "$NETMASK" "$GATEWAY" "$DNS1"
fi
if [ $basepkgs -eq 1 ]; then
set_install_basepkgs_ubuntu
fi
if [ $resourceslimit -eq 1 ]; then
# 配置限制和内核参数
set_limit
fi

if [ $kernelparams -eq 1 ]; then
set_kernel_params
fi
# 配置时间同步
set_time_sync_ubuntu
}

# Set Shell History and TMOUT
#  HISTSIZE has been set to 10000
sed -i 's/^HISTSIZE=.*$/HISTSIZE=10000/g' /etc/profile 
# HISTTIMEFORMAT has been set to "Number-Time-User-Command"
echo 'export HISTTIMEFORMAT="%F %T `whoami` "' > /etc/profile.d/secuirty.sh
# 终端超时10分钟
echo TMOUT=600 >> /etc/profile.d/secuirty.sh

if which apt &> /dev/null; then
ubuntu_init
else
centos_init
fi
cat << EOF
# reboot
请reboot, 验证ip, 域名解析, kernel params, crontab, ssh, alias
EOF

cd $CURRENT_DIR
rm -f $0