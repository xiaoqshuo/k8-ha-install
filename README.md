- 部署博客 https://www.cnblogs.com/xiaoqshuo/p/10195143.html

## 1，环境部署
#### 1.1.1 软件信息
|服务|版本|
|:--|:--|
|kubernetes|v1.12.4|
|CentOS 7.6|CentOS Linux release 7.6.1810 (Core)|
|Docker|v18.06|
|etcd|v3.3.11|
|calico|3.1.4|

#### 1.1.2 硬件信息

|IP|角色|安装软件|
|:--|:--|:--|
|192.168.2.101|k8s master|etcd，kube-apiserver，kube-controller-manager，kube-scheduler|
|192.168.2.102|k8s master|etcd，kube-apiserver，kube-controller-manager，kube-scheduler|
|192.168.2.103|k8s master|etcd，kube-apiserver，kube-controller-manager，kube-scheduler|
|192.168.2.111|k8s node01|docker，kubelet，kube-proxy|
|192.168.2.112|k8s node02|docker，kubelet，kube-proxy|
|192.168.2.113|k8s node02|docker，kubelet，kube-proxy|

### 1.2 安装前准备
#### 1.2.1 配置时区
````
ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
echo 'Asia/Shanghai' >/etc/timezone
ntpdate time.windows.com
````

#### 1.2.2 下载常用命令
````
yum -y install vim tree wget lrzsz
````

#### 1.2.3  配置登录超时以及历史显示格式
````
cat  << EOF >> /etc/profile
###########################
export PS1='\[\e[32;1m\][\u@\h \W]# \[\e[0m\]'
export HISTTIMEFORMAT="root_%F %T : "
alias grep='grep --color=auto'
EOF
````

#### 1.2.4  配置yum源
- 备份源

````
mkdir /etc/yum.repos.d/bak
cp /etc/yum.repos.d/*.repo /etc/yum.repos.d/bak/
````

- CentOS-Base.repo

````
curl -o /etc/yum.repos.d/CentOS-Base.repo http://mirrors.aliyun.com/repo/Centos-7.repo
````

- epel.repo

````
wget -O /etc/yum.repos.d/epel.repo http://mirrors.aliyun.com/repo/epel-7.repo
````

- docker-ce.repo

````
# 删除已安装的Docker
yum remove docker \
                  docker-client \
                  docker-client-latest \
                  docker-common \
                  docker-latest \
                  docker-latest-logrotate \
                  docker-logrotate \
                  docker-selinux \
                  docker-engine-selinux \
                  docker-engine

# 安装 docker-ce 使用命令
yum install -y yum-utils device-mapper-persistent-data lvm2

# 配置docker-ce 官方源
yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

# 配置docker-ce 阿里云源
yum-config-manager --add-repo http://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo
````

- kubernetes.repo

````
cat <<EOF > /etc/yum.repos.d/kubernetes.repo
[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=https://mirrors.aliyun.com/kubernetes/yum/doc/yum-key.gpg https://mirrors.aliyun.com/kubernetes/yum/doc/rpm-package-key.gpg
EOF
````

- 生成缓存，系统更新

````
yum makecache
yum update -y
````

#### 1.2.5 设置SELINUX为permissive模式
````
vi /etc/selinux/config
SELINUX=permissive

setenforce 0
````

#### 1.2.6 设置iptables参数
````
cat <<EOF >  /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-ip6tables = 1
net.bridge.bridge-nf-call-iptables = 1
net.ipv4.ip_forward = 1
EOF

sysctl --system
````

#### 1.2.7  禁用swap
````
swapoff -a

# 禁用fstab中的swap项目
vi /etc/fstab
#/dev/mapper/centos-swap swap                    swap    defaults        0 0

# 确认swap已经被禁用
cat /proc/swaps
Filename                Type        Size    Used    Priority
````

#### 1.2.8 limit配置
````
ulimit -SHn 65535
````

#### 1.2.9 hosts文件配置
````
cat << EOF >> /etc/hosts
192.168.2.100 k8s-master-lb
192.168.2.101 k8s-master01
192.168.2.102 k8s-master02
192.168.2.103 k8s-master03
192.168.2.111 k8s-node01
192.168.2.112 k8s-node02
192.168.2.113 k8s-node03
EOF
````

````
[root@k8s-master01 ~]# more /etc/hosts
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
192.168.2.100 k8s-master-lb
192.168.2.101 k8s-master01
192.168.2.101 k8s-master02
192.168.2.102 k8s-master03
192.168.2.111 k8s-node01
192.168.2.111 k8s-node02
192.168.2.112 k8s-node03
````

#### 1.2.10 所有节点加载ipvs模块
````
modprobe ip_vs
modprobe ip_vs_rr
modprobe ip_vs_wrr
modprobe ip_vs_sh
modprobe nf_conntrack_ipv4
````

#### 1.2.11 关闭防火墙
````
systemctl disable firewalld
systemctl stop firewalld
````

#### 1.2.12 重启主机
````
reboot
````

#### 1.2.13 所有节点互信
````
ssh-keygen -t rsa

for i in k8s-master01 k8s-master02 k8s-master03 k8s-node01 k8s-node02 k8s-node03;do ssh-copy-id -i .ssh/id_rsa.pub $i;done
````

#### 1.2.14 安装证书工具（k8s-master01）
````
mkdir /opt/ssl
cd /opt/ssl
wget https://pkg.cfssl.org/R1.2/cfssl_linux-amd64 
wget https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
wget https://pkg.cfssl.org/R1.2/cfssl-certinfo_linux-amd64
chmod +x *
mv cfssl_linux-amd64 /usr/local/bin/cfssl
mv cfssljson_linux-amd64 /usr/local/bin/cfssljson
mv cfssl-certinfo_linux-amd64 /usr/bin/cfssl-certinfo
````

#### 1.2.15 生成证书（k8s-master01）
- 创建 CA 配置文件 ca-config.json

````
cat > ca-config.json <<EOF
{
  "signing": {
    "default": {
      "expiry": "87600h"
    },
    "profiles": {
      "kubernetes": {
         "expiry": "87600h",
         "usages": [
            "signing",
            "key encipherment",
            "server auth",
            "client auth"
        ]
      }
    }
  }
}
EOF
````

- 创建 CA 证书签名请求 ca-csr.json

````
cat > ca-csr.json << EOF
{
    "CN": "Kubernetes",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "Beijing",
            "ST": "Beijing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF
````


- 生成证书

````
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
````

## 2 部署Etcd集群
### 2.1 生成 Etcd 证书

- 创建 Etcd 服务器 CA 证书签名请求 etcd-csr.json

````
cat > etcd-csr.json << EOF
{
    "CN": "etcd",
    "hosts": [
    "127.0.0.1",
    "192.168.2.101",
    "192.168.2.102",
    "192.168.2.103"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "L": "BeiJing",
            "ST": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF
````

- 生成证书

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
````

````
# ls *.pem
ca-key.pem  ca.pem  etcd-key.pem  etcd.pem
````
````
mkdir /etc/kubernetes/etcd/{bin,cfg,ssl} -p
cp ca-key.pem  ca.pem  etcd-key.pem  etcd.pem /etc/kubernetes/etcd/ssl/
````


### 2.2 部署Etcd
- 二进制包下载地址：https://github.com/etcd-io/etcd/releases/tag/v3.3.11

````
wget https://github.com/etcd-io/etcd/releases/download/v3.3.11/etcd-v3.3.11-linux-amd64.tar.gz
tar zxvf etcd-v3.3.11-linux-amd64.tar.gz
mv etcd-v3.3.11-linux-amd64/{etcd,etcdctl} /etc/kubernetes/etcd/bin
````

#### 2.2.1 创建etcd配置文件
- 以下部署步骤在规划的三个etcd节点操作一样，唯一不同的是etcd配置文件中的服务器IP要写当前的：

- 例如：k8s-master01

````
cat > /etc/kubernetes/etcd/cfg/etcd  << EOF
#[Member]
ETCD_NAME="k8s-master01"
ETCD_DATA_DIR="/var/lib/etcd/default.etcd"
ETCD_LISTEN_PEER_URLS="https://192.168.2.101:2380"
ETCD_LISTEN_CLIENT_URLS="https://192.168.2.101:2379"

#[Clustering]
ETCD_INITIAL_ADVERTISE_PEER_URLS="https://192.168.2.101:2380"
ETCD_ADVERTISE_CLIENT_URLS="https://192.168.2.101:2379"
ETCD_INITIAL_CLUSTER="k8s-master01=https://192.168.2.101:2380,k8s-master02=https://192.168.2.102:2380,k8s-master03=https://192.168.2.103:2380"
ETCD_INITIAL_CLUSTER_TOKEN="etcd-cluster"
ETCD_INITIAL_CLUSTER_STATE="new"
EOF
````

- ETCD_NAME 节点名称
- ETCD_DATA_DIR 数据目录
- ETCD_LISTEN_PEER_URLS 集群通信监听地址
- ETCD_LISTEN_CLIENT_URLS 客户端访问监听地址
- ETCD_INITIAL_ADVERTISE_PEER_URLS 集群通告地址
- ETCD_ADVERTISE_CLIENT_URLS 客户端通告地址
- ETCD_INITIAL_CLUSTER 集群节点地址
- ETCD_INITIAL_CLUSTER_TOKEN 集群Token
- ETCD_INITIAL_CLUSTER_STATE 加入集群的当前状态，new是新集群，existing表示加入已有集群

#### 2.2.2 systemd管理etcd
````
# cat  /usr/lib/systemd/system/etcd.service
[Unit]
Description=Etcd etcd
After=network.target
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
EnvironmentFile=/etc/kubernetes/etcd/cfg/etcd
ExecStart=/etc/kubernetes/etcd/bin/etcd \
--name=${ETCD_NAME} \
--data-dir=${ETCD_DATA_DIR} \
--listen-peer-urls=${ETCD_LISTEN_PEER_URLS} \
--listen-client-urls=${ETCD_LISTEN_CLIENT_URLS},http://127.0.0.1:2379 \
--advertise-client-urls=${ETCD_ADVERTISE_CLIENT_URLS} \
--initial-advertise-peer-urls=${ETCD_INITIAL_ADVERTISE_PEER_URLS} \
--initial-cluster=${ETCD_INITIAL_CLUSTER} \
--initial-cluster-token=${ETCD_INITIAL_CLUSTER_TOKEN} \
--initial-cluster-state=new \
--cert-file=/etc/kubernetes/etcd/ssl/etcd.pem \
--key-file=/etc/kubernetes/etcd/ssl/etcd-key.pem \
--peer-cert-file=/etc/kubernetes/etcd/ssl/etcd.pem \
--peer-key-file=/etc/kubernetes/etcd/ssl/etcd-key.pem \
--trusted-ca-file=/etc/kubernetes/etcd/ssl/ca.pem \
--peer-trusted-ca-file=/etc/kubernetes/etcd/ssl/ca.pem
Restart=on-failure
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
````

#### 2.2.3 分发 etcd 集群 配置文件及证书
- 注：修改其它 etcd 配置文件
    - 修改为当前服务器的主机名 
    - 修改为当前服务器的ip地址

````
USER=root
CONTROL_PLANE_IPS="k8s-master02 k8s-master03 k8s-node01 k8s-node02 k8s-node03"
for host in $CONTROL_PLANE_IPS; do
    ssh "${USER}"@$host "mkdir -p /etc/kubernetes/"
    scp -r /etc/kubernetes/etcd/ "${USER}"@$host:/etc/kubernetes/
    scp -r /usr/lib/systemd/system/etcd.service "${USER}"@$host:/usr/lib/systemd/system/etcd.service
done
````

#### 2.2.4 启动并设置开启启动
````
systemctl start etcd
systemctl enable etcd
````

#### 2.2.5 验证 etcd 集群
````
# /etc/kubernetes/etcd/bin/etcdctl \
--ca-file=/etc/kubernetes/etcd/ssl/ca.pem --cert-file=/etc/kubernetes/etcd/ssl/etcd.pem --key-file=/etc/kubernetes/etcd/ssl/etcd-key.pem \
--endpoints="https://192.168.2.101:2379,https://192.168.2.102:2379,https://192.168.2.103:2379" \
cluster-health

# 结果
member ad9328796634e0d0 is healthy: got healthy result from https://192.168.2.101:2379
member f03f45bbcae9634b is healthy: got healthy result from https://192.168.2.103:2379
member fddf9c47e41c5ec2 is healthy: got healthy result from https://192.168.2.102:2379
cluster is healthy
````



## 3， 部署 kubernetes master节点
### 3.1 Haproxy+keepalived配置k8s master高可用（每台master都进行操作，红色字体改成对应主机的即可）
- keepalived 提供 kube-apiserver 对外服务的 VIP；
- haproxy 监听 VIP，后端连接所有 kube-apiserver 实例，提供健康检查和负载均衡功能；
- 运行 keepalived 和 haproxy 的节点称为 LB 节点。由于 keepalived 是一主多备运行模式，故至少两个 LB 节点。
- 本文档复用 master 节点的三台机器，haproxy 监听的端口(8443) 需要与 kube-apiserver 的端口 6443 不同，避免冲突。
- keepalived 在运行过程中周期检查本机的 haproxy 进程状态，如果检测到 haproxy 进程异常，则触发重新选主的过程，VIP 将飘移到新选出来的主节点，从而实现 VIP 的高可用。
- 所有组件（如 kubeclt、apiserver、controller-manager、scheduler 等）都通过 VIP 和 haproxy 监听的 8443 端口访问 kube-apiserver 服务。

#### 3.1.1 安装haproxy和keepalived
````
yum install -y keepalived haproxy
````

#### 3.1.2 master配置haproxy代理api-server服务
````
cp /etc/haproxy/haproxy.cfg{,.bak}
cat > /etc/haproxy/haproxy.cfg << EOF
global
    log /dev/log    local0
    log /dev/log    local1 notice
    chroot /var/lib/haproxy
    stats socket /var/run/haproxy-admin.sock mode 660 level admin
    stats timeout 30s
    user haproxy
    group haproxy
    daemon
    nbproc 1

defaults
    log     global
    timeout connect 5000
    timeout client  10m
    timeout server  10m

listen  admin_stats
    bind 0.0.0.0:10080
    mode http
    log 127.0.0.1 local0 err
    stats refresh 30s
    stats uri /status
    stats realm welcome login\ Haproxy
    stats auth admin:123456
    stats hide-version
    stats admin if TRUE

listen kube-master
    bind 0.0.0.0:8443
    mode tcp
    option tcplog
    balance roundrobin
    server 192.168.2.101 192.168.2.101:6443 check inter 2000 fall 2 rise 2 weight 1
    server 192.168.2.102 192.168.2.102:6443 check inter 2000 fall 2 rise 2 weight 1
    server 192.168.2.103 192.168.2.103:6443 check inter 2000 fall 2 rise 2 weight 1
EOF
````

- haproxy 在 10080 端口输出 status 信息；
- haproxy 监听所有接口的 8443 端口，该端口与环境变量 ${KUBE_APISERVER} 指定的端口必须一致；
- server 字段列出所有 kube-apiserver 监听的 IP 和端口；

#### 3.1.3 三个master配置keepalived服务
````
cp /etc/keepalived/keepalived.conf{,.bak}
cat >  /etc/keepalived/keepalived.conf << EOF
global_defs {
    router_id lb-master-100
}

vrrp_script check-haproxy {
    script "killall -0 haproxy"
    interval 3
}

vrrp_instance VI-kube-master {
    state MASTER
    priority 120
    dont_track_primary
    interface ens160
    virtual_router_id 68
    advert_int 3
    track_script {
        check-haproxy
    }
    virtual_ipaddress {
        192.168.2.100 #VIP，访问此IP调用api-server
    }
}
EOF
````

- 使用 killall -0 haproxy 命令检查所在节点的 haproxy 进程是否正常。
- router_id、virtual_router_id 用于标识属于该 HA 的 keepalived 实例，如果有多套 keepalived HA，则必须各不相同；
- 其他2个backup把nopreempt去掉，及priority分别设置110和100即可。
- 例如：

````
cp /etc/keepalived/keepalived.conf{,.bak}
cat >  /etc/keepalived/keepalived.conf << EOF
global_defs {
    router_id lb-master-100
}

vrrp_script check-haproxy {
    script "killall -0 haproxy"
    interval 3
}

vrrp_instance VI-kube-master {
    state BACKUP
    priority 110
    dont_track_primary
    interface ens160
    virtual_router_id 68
    advert_int 3
    track_script {
        check-haproxy
    }
    virtual_ipaddress {
        192.168.2.100 #VIP，访问此IP调用api-server
    }
}
EOF
````

#### 3.1.4 启动haproxy和keepalived服务
````
#haproxy
systemctl enable haproxy
systemctl start haproxy

#keepalive
systemctl enable keepalived
systemctl start keepalived
````

#### 3.1.5 查看haproxy和keepalived服务状态以及VIP情况
````
systemctl status haproxy|grep Active
systemctl status keepalived|grep Active
````

#### 3.1.6 查看VIP所属情况
````
systemctl status haproxy|grep Active
systemctl status keepalived|grep Active
````

- 如果Active: active (running)表示正常。 

#### 3.1.7 查看VIP所属情况
````
# ip addr show | grep 192.168.2.100
    inet 192.168.2.100/32 scope global ens160
````

### 3.2 部署kubectl命令工具
- kubectl 是 kubernetes 集群的命令行管理工具，本文档介绍安装和配置它的步骤。
- kubectl 默认从 ~/.kube/config 文件读取 kube-apiserver 地址、证书、用户名等信息，如果没有配置，执行 kubectl 命令时可能会出错。
- ~/.kube/config只需要部署一次，然后拷贝到其他的master。

#### 3.2.1 下载kubectl
- 下载二进制包：https://github.com/kubernetes/kubernetes/blob/master/CHANGELOG-1.12.md#server-binaries
- 下载这个包（kubernetes-server-linux-amd64.tar.gz）就够了，包含了所需的所有组件。

````
wget https://dl.k8s.io/v1.12.4/kubernetes-server-linux-amd64.tar.gz
tar zxvf kubernetes-server-linux-amd64.tar.gz
cd kubernetes/server/bin
cp kube-apiserver kube-scheduler kube-controller-manager kubectl /etc/kubernetes/server/bin/
````

#### 3.2.2 创建请求证书
- admin-csr.json

````
cat > admin-csr.json <<EOF
{
  "CN": "admin",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "ST": "BeiJing",
      "L": "BeiJing",
      "O": "system:masters",
      "OU": "System"
    }
  ]
}
EOF
````

- O 为 system:masters，kube-apiserver 收到该证书后将请求的 Group 设置为 system:masters；
- 预定义的 ClusterRoleBinding cluster-admin 将 Group system:masters 与 Role cluster-admin 绑定，该 Role 授予所有 API的权限；
- 该证书只会被 kubectl 当做 client 证书使用，所以 hosts 字段为空；
- 生成证书和私钥

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin
````

- 移动证书

````
cp ca-key.pem  ca.pem admin.pem admin-key.pem /etc/kubernetes/server/ssl/
````

#### 3.2.3 创建~/.kube/config文件
````
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/server/ssl/ca.pem \
  --embed-certs=true \
  --server=https://192.168.2.100:8443 \
  --kubeconfig=kubectl.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials admin \
  --client-certificate=/etc/kubernetes/server/ssl/admin.pem \
  --client-key=/etc/kubernetes/server/ssl/admin-key.pem \
  --embed-certs=true \
  --kubeconfig=kubectl.kubeconfig

# 设置上下文参数
kubectl config set-context kubernetes \
  --cluster=kubernetes \
  --user=admin \
  --kubeconfig=kubectl.kubeconfig
  
# 设置默认上下文
kubectl config use-context kubernetes --kubeconfig=kubectl.kubeconfig
````

#### 3.2.4 分发~/.kube/config文件
````
cp kubectl.kubeconfig ~/.kube/config
for i in k8s-master02 k8s-master03;do scp -r ~/.kube/ $i:~/;done
````

### 3.3 部署apiserver组件
#### 3.3.1 生成 apiserver 证书
- apiserver-csr.json

````
cat > apiserver-csr.json <<EOF
{
    "CN": "kubernetes",
    "hosts": [
      "127.0.0.1",
      "192.168.2.101",
      "192.168.2.102",
      "192.168.2.103",
      "192.168.2.100",
      "10.254.0.1",
      "kubernetes",
      "kubernetes.default",
      "kubernetes.default.svc",
      "kubernetes.default.svc.cluster",
      "kubernetes.default.svc.cluster.local"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
        {
            "C": "CN",
            "ST": "BeiJing",
            "L": "BeiJing",
            "O": "k8s",
            "OU": "System"
        }
    ]
}
EOF
````
- hosts 字段指定授权使用该证书的 IP 或域名列表，这里列出了 VIP 、apiserver 节点 IP、kubernetes 服务 IP 和域名；
- 域名最后字符不能是 .(如不能为 kubernetes.default.svc.cluster.local.)，否则解析时失败，提示： x509: cannot parse dnsName "kubernetes.default.svc.cluster.local."；
- 如果使用非 cluster.local 域名，如 bqding.com，则需要修改域名列表中的最后两个域名为：kubernetes.default.svc.bqding、kubernetes.default.svc.bqding.com

- 生成证书和私钥

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes apiserver-csr.json | cfssljson -bare apiservier
````

- 移动证书

````
cp apiservier*.pem /etc/kubernetes/server/ssl/
````

#### 3.3.2 创建加密配置文件
````
cat > /etc/kubernetes/server/cfg/encryption-config.yaml <<EOF
kind: EncryptionConfig
apiVersion: v1
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: $(head -c 32 /dev/urandom | base64)
      - identity: {}
EOF
````

####  3.3.3 kube-apiserver 配置文件

````
# cat /etc/kubernetes/server/cfg/kube-apiserver
KUBE_APISERVER_OPTS=" --enable-admission-plugins=Initializers,NamespaceLifecycle,NodeRestriction,LimitRanger,ServiceAccount,DefaultStorageClass,ResourceQuota \
  --anonymous-auth=false \
  --experimental-encryption-provider-config=/etc/kubernetes/server/ssl/encryption-config.yaml \
  --advertise-address=192.168.2.101 \
  --bind-address=192.168.2.101 \
  --insecure-port=0 \
  --authorization-mode=Node,RBAC \
  --runtime-config=api/all \
  --enable-bootstrap-token-auth \
  --service-cluster-ip-range=10.254.0.0/16 \
  --service-node-port-range=30000-32700 \
  --tls-cert-file=/etc/kubernetes/server/ssl/apiservier.pem \
  --tls-private-key-file=/etc/kubernetes/server/ssl/apiservier-key.pem \
  --client-ca-file=/etc/kubernetes/server/ssl/ca.pem \
  --kubelet-client-certificate=/etc/kubernetes/server/ssl/apiservier.pem \
  --kubelet-client-key=/etc/kubernetes/server/ssl/apiservier-key.pem \
  --service-account-key-file=/etc/kubernetes/server/ssl/ca-key.pem \
  --etcd-cafile=/etc/kubernetes/etcd/ssl/ca.pem \
  --etcd-certfile=/etc/kubernetes/etcd/ssl/etcd.pem \
  --etcd-keyfile=/etc/kubernetes/etcd/ssl/etcd-key.pem \
  --etcd-servers=https://192.168.2.101:2379,https://192.168.2.102:2379,https://192.168.2.103:2379 \
  --enable-swagger-ui=true \
  --allow-privileged=true \
  --apiserver-count=3 \
  --audit-log-maxage=30 \
  --audit-log-maxbackup=3 \
  --audit-log-maxsize=100 \
  --audit-log-path=/var/log/kube-apiserver-audit.log \
  --event-ttl=1h \
  --alsologtostderr=true \
  --logtostderr=false \
  --log-dir=/var/log/kubernetes \
  --v=2"
````

- --experimental-encryption-provider-config：启用加密特性；
- --authorization-mode=Node,RBAC： 开启 Node 和 RBAC 授权模式，拒绝未授权的请求；
- --enable-admission-plugins：启用 ServiceAccount 和 NodeRestriction；
- --service-account-key-file：签名 ServiceAccount Token 的公钥文件，kube-controller-manager 的 --service-account-private-key-file 指定私钥文件，两者配对使用；
- --tls-*-file：指定 apiserver 使用的证书、私钥和 CA 文件。--client-ca-file 用于验证 client (kue-controller-manager、kube-scheduler、kubelet、kube-proxy 等)请求所带的证书；
- --kubelet-client-certificate、--kubelet-client-key：如果指定，则使用 https 访问 kubelet APIs；需要为证书对应的用户(上面 kubernetes*.pem 证书的用户为 kubernetes) 用户定义 RBAC 规则，否则访问 kubelet API 时提示未授权；
- --bind-address： 不能为 127.0.0.1，是本机IP地址，否则外界不能访问它的安全端口 6443；
- --insecure-port=0：关闭监听非安全端口(8080)；
- --service-cluster-ip-range： 指定 Service Cluster IP 地址段；
- --service-node-port-range： 指定 NodePort 的端口范围；
- --runtime-config=api/all=true： 启用所有版本的 APIs，如 autoscaling/v2alpha1；
- --enable-bootstrap-token-auth：启用 kubelet bootstrap 的 token 认证；
- --apiserver-count=3：指定集群运行模式，多台 kube-apiserver 会通过 leader 选举产生一个工作节点，其它节点处于阻塞状态；

#### 3.3.4 systemd管理kube-apiserver组件

````
# cat /usr/lib/systemd/system/kube-apiserver.service
[Unit]
Description=Kubernetes API Server
Documentation=https://github.com/kubernetes/kubernetes
After=network.target

[Service]
EnvironmentFile=-/etc/kubernetes/server/cfg/kube-apiserver
ExecStart=/etc/kubernetes/server/bin/kube-apiserver $KUBE_APISERVER_OPTS
Restart=on-failure
RestartSec=5
Type=notify
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
````

#### 3.3.5 创建日志目录
````
mkdir -p /var/log/kubernetes
````

#### 3.3.6 分发配置文件以及证书
- 修改其它 master 节点 配置文件里的 当前IP地址

````
USER=root
for host in k8s-master02 k8s-master03;do 
	ssh "${USER}"@$host "mkdir -p /var/log/kubernetes" 
	scp -r /etc/kubernetes/server/ "${USER}"@$host:/etc/kubernetes/ 
	scp /usr/lib/systemd/system/kube-apiserver.service "${USER}"@$host:/usr/lib/systemd/system/kube-apiserver.service 
done
````

#### 3.3.7 启动api-server服务
````
systemctl daemon-reload
systemctl enable kube-apiserver
systemctl start kube-apiserver
````

#### 3.3.8 检查kube-apiserve服务
````
# netstat -ptln | grep kube-apiserve
tcp        0      0 192.168.2.101:6443      0.0.0.0:*               LISTEN      15786/kube-apiserve
````

- 集群状态

````
# kubectl cluster-info
Kubernetes master is running at https://192.168.2.100:8443

To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
````

#### 3.3.9 授予kubernetes证书访问kubelet api权限
````
kubectl create clusterrolebinding kube-apiserver:kubelet-apis --clusterrole=system:kubelet-api-admin --user kubernetes
````

### 3.4 部署controller-manager组件
- 该集群包含 3 个节点，启动后将通过竞争选举机制产生一个 leader 节点，其它节点为阻塞状态。当 leader 节点不可用后，剩余节点将再次进行选举产生新的 leader 节点，从而保证服务的可用性。
为保证通信安全，本文档先生成 x509 证书和私钥，kube-controller-manager 在如下两种情况下使用该证书：
    - 与 kube-apiserver 的安全端口通信时;
    - 在安全端口(https，10252) 输出 prometheus 格式的 metrics；

#### 3.4.1 创建kube-controller-manager证书请求
````
cat > kube-controller-manager-csr.json << EOF
{
    "CN": "system:kube-controller-manager",
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "hosts": [
      "127.0.0.1",
      "192.168.2.101",
      "192.168.2.102",
      "192.168.2.103"
    ],
    "names": [
      {
        "C": "CN",
        "ST": "BeiJing",
        "L": "BeiJing",
        "O": "system:kube-controller-manager",
        "OU": "System"
      }
    ]
}
EOF
````

- hosts 列表包含所有 kube-controller-manager 节点 IP；
- CN 为 system:kube-controller-manager、O 为 system:kube-controller-manager，kubernetes 内置的 ClusterRoleBindings system:kube-controller-manager 赋予 kube-controller-manager 工作所需的权限。
- 生成证书和私钥

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
````

- 移动证书

````
cp kube-controller-manager*.pem /etc/kubernetes/server/ssl/
````

#### 3.4.2 创建 kube-controller-manager.kubeconfig 文件
````
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/server/ssl/ca.pem \
  --embed-certs=true \
  --server=https://192.168.2.100:8443 \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-credentials system:kube-controller-manager \
  --client-certificate=/etc/kubernetes/server/ssl/kube-controller-manager.pem \
  --client-key=/etc/kubernetes/server/ssl/kube-controller-manager-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-context system:kube-controller-manager \
  --cluster=kubernetes \
  --user=system:kube-controller-manager \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config use-context system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig
````


#### 3.4.3 controller-manager 配置文件

````
# cat /etc/kubernetes/server/cfg/kube-controller-manager
KUBE_CONTROLLER_MANAGER_OPTS="--port=0 \
  --secure-port=10252 \
  --bind-address=127.0.0.1 \
  --kubeconfig=/etc/kubernetes/server/cfg/kube-controller-manager.kubeconfig \
  --authentication-kubeconfig=/etc/kubernetes/server/cfg/kube-controller-manager.kubeconfig \
  --service-cluster-ip-range=10.254.0.0/16 \
  --cluster-name=kubernetes \
  --cluster-signing-cert-file=/etc/kubernetes/server/ssl/ca.pem \
  --cluster-signing-key-file=/etc/kubernetes/server/ssl/ca-key.pem \
  --experimental-cluster-signing-duration=8760h \
  --root-ca-file=/etc/kubernetes/server/ssl/ca.pem \
  --service-account-private-key-file=/etc/kubernetes/server/ssl/ca-key.pem \
  --leader-elect=true \
  --feature-gates=RotateKubeletServerCertificate=true \
  --controllers=*,bootstrapsigner,tokencleaner \
  --horizontal-pod-autoscaler-use-rest-clients=true \
  --horizontal-pod-autoscaler-sync-period=10s \
  --tls-cert-file=/etc/kubernetes/server/ssl/kube-controller-manager.pem \
  --tls-private-key-file=/etc/kubernetes/server/ssl/kube-controller-manager-key.pem \
  --use-service-account-credentials=true \
  --alsologtostderr=true \
  --logtostderr=false \
  --log-dir=/var/log/kubernetes \
  --v=2"
````

- --port=0：关闭监听 http /metrics 的请求，同时 --address 参数无效，--bind-address 参数有效；
- --secure-port=10252、--bind-address=0.0.0.0: 在所有网络接口监听 10252 端口的 https /metrics 请求；
- --kubeconfig：指定 kubeconfig 文件路径，kube-controller-manager 使用它连接和验证 kube-apiserver；
- --cluster-signing-*-file：签名 TLS Bootstrap 创建的证书；
- --experimental-cluster-signing-duration：指定 TLS Bootstrap 证书的有效期；
- --root-ca-file：放置到容器 ServiceAccount 中的 CA 证书，用来对 kube-apiserver 的证书进行校验；
- --service-account-private-key-file：签名 ServiceAccount 中 Token 的私钥文件，必须和 kube-apiserver 的 --service-account-key-file 指定的公钥文件配对使用；
- --service-cluster-ip-range ：指定 Service Cluster IP 网段，必须和 kube-apiserver 中的同名参数一致；
- --leader-elect=true：集群运行模式，启用选举功能；被选为 leader 的节点负责处理工作，其它节点为阻塞状态；
- --feature-gates=RotateKubeletServerCertificate=true：开启 kublet server 证书的自动更新特性；
- --controllers=*,bootstrapsigner,tokencleaner：启用的控制器列表，tokencleaner 用于自动清理过期的 Bootstrap token；
- --horizontal-pod-autoscaler-*：custom metrics 相关参数，支持 autoscaling/v2alpha1；
- --tls-cert-file、--tls-private-key-file：使用 https 输出 metrics 时使用的 Server 证书和秘钥；
- --use-service-account-credentials=true:

#### 3.4.4 systemd管理controller-manager组件
````
# cat /usr/lib/systemd/system/kube-controller-manager.service
[Unit]
Description=Kubernetes Controller Manager
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/server/cfg/kube-controller-manager
ExecStart=/etc/kubernetes/server/bin/kube-controller-manager $KUBE_CONTROLLER_MANAGER_OPTS
Restart=on
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
````

#### 3.4.5 分发配置文件以及证书
````
USER=root
for host in k8s-master02 k8s-master03;do 
	ssh "${USER}"@$host "mkdir -p /var/log/kubernetes" 
	scp /etc/kubernetes/server/ssl/kube-controller-manager*.pem "${USER}"@$host:/etc/kubernetes/server/ssl/
	scp /usr/lib/systemd/system/kube-controller-manager.service "${USER}"@$host:/usr/lib/systemd/system/kube-controller-manager.service
	scp /etc/kubernetes/server/cfg/kube-controller-manager "${USER}"@$host:/etc/kubernetes/server/cfg/kube-controller-manager  
	scp /etc/kubernetes/server/cfg/kube-controller-manager.kubeconfig "${USER}"@$host:/etc/kubernetes/server/cfg/kube-controller-manager.kubeconfig  
done
````

#### 3.4.6 启动kube-controller-manager服务
````
systemctl daemon-reload
systemctl enable kube-controller-manager
systemctl start kube-controller-manager
````

#### 3.4.7 检查kube-controller-manager服务
````
# netstat -lnpt|grep kube-controlle
tcp        0      0 127.0.0.1:10252         0.0.0.0:*               LISTEN      3090/kube-controlle
````

#### 3.4.8 查看当前kube-controller-manager的leader
````
# kubectl get endpoints kube-controller-manager --namespace=kube-system  -o yaml

apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"k8s-master01_28c03ae9-18a9-11e9-a6d8-000c2927a0d0","leaseDurationSeconds":15,"acquireTime":"2019-01-15T09:37:38Z","renewTime":"2019-01-15T09:42:06Z","leaderTransitions":1}'
  creationTimestamp: 2019-01-15T09:37:14Z
  name: kube-controller-manager
  namespace: kube-system
  resourceVersion: "2413"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-controller-manager
  uid: 24132473-18a9-11e9-936a-000c2927a0d0
````

### 3.5 部署kube-scheduler组件
- 该集群包含 3 个节点，启动后将通过竞争选举机制产生一个 leader 节点，其它节点为阻塞状态。当 leader 节点不可用后，剩余节点将再次进行选举产生新的 leader 节点，从而保证服务的可用性。
- 为保证通信安全，本文档先生成 x509 证书和私钥，kube-scheduler 在如下两种情况下使用该证书：
    - 与 kube-apiserver 的安全端口通信;
    - 在安全端口(https，10251) 输出 prometheus 格式的 metrics；

#### 3.5.1 创建kube-scheduler证书请求
````
# cat > kube-scheduler-csr.json << EOF
{
    "CN": "system:kube-scheduler",
    "hosts": [
      "127.0.0.1",
      "192.168.2.101",
      "192.168.2.102",
      "192.168.2.103"
    ],
    "key": {
        "algo": "rsa",
        "size": 2048
    },
    "names": [
      {
        "C": "CN",
        "ST": "BeiJing",
        "L": "BeiJing",
        "O": "system:kube-scheduler",
        "OU": "System"
      }
    ]
}
EOF
````

- hosts 列表包含所有 kube-scheduler 节点 IP；
- CN 为 system:kube-scheduler、O 为 system:kube-scheduler，kubernetes 内置的 ClusterRoleBindings system:kube-scheduler 将赋予 kube-scheduler 工作所需的权限。
- 生成证书和私钥

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes  kube-scheduler-csr.json | cfssljson -bare  kube-scheduler
````

- 移动证书

````
cp kube-scheduler*.pem /etc/kubernetes/server/ssl/
````

#### 3.5.2 创建 kube-scheduler.kubeconfig 文件
````
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/server/ssl/ca.pem \
  --embed-certs=true \
  --server=https://192.168.2.100:8443 \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-credentials system:kube-scheduler \
  --client-certificate=/etc/kubernetes/server/ssl/kube-scheduler.pem \
  --client-key=/etc/kubernetes/server/ssl/kube-scheduler-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-context system:kube-scheduler \
  --cluster=kubernetes \
  --user=system:kube-scheduler \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config use-context system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig
````


#### 3.5.3 kube-scheduler 配置文件
````
# cat /etc/kubernetes/server/cfg/kube-scheduler
KUBE_SCHEDULER_OPTS=" --address=127.0.0.1 \
  --kubeconfig=/etc/kubernetes/server/cfg/kube-scheduler.kubeconfig \
  --leader-elect=true \
  --alsologtostderr=true \
  --logtostderr=false \
  --log-dir=/var/log/kubernetes \
  --v=2"
````

- --address：在 127.0.0.1:10251 端口接收 http /metrics 请求；kube-scheduler 目前还不支持接收 https 请求；
- --kubeconfig：指定 kubeconfig 文件路径，kube-scheduler 使用它连接和验证 kube-apiserver；
- --leader-elect=true：集群运行模式，启用选举功能；被选为 leader 的节点负责处理工作，其它节点为阻塞状态；

#### 3.5.4 systemd管理kube-scheduler组件

````
# cat /usr/lib/systemd/system/kube-scheduler.service
[Unit]
Description=Kubernetes Scheduler
Documentation=https://github.com/kubernetes/kubernetes

[Service]
EnvironmentFile=-/etc/kubernetes/server/cfg/kube-scheduler
ExecStart=/etc/kubernetes/server/bin/kube-scheduler $KUBE_SCHEDULER_OPTS
Restart=on-failure
RestartSec=5


[Install]
WantedBy=multi-user.target
````

#### 3.5.5 分发配置文件以及证书
````
USER=root
for host in k8s-master02 k8s-master03;do 
	ssh "${USER}"@$host "mkdir -p /var/log/kubernetes" 
	scp /etc/kubernetes/server/ssl/kube-scheduler*.pem "${USER}"@$host:/etc/kubernetes/server/ssl/
	scp /usr/lib/systemd/system/kube-scheduler.service "${USER}"@$host:/usr/lib/systemd/system/kube-scheduler.service
	scp /etc/kubernetes/server/cfg/kube-scheduler "${USER}"@$host:/etc/kubernetes/server/cfg/kube-scheduler  
	scp /etc/kubernetes/server/cfg/kube-scheduler.kubeconfig "${USER}"@$host:/etc/kubernetes/server/cfg/kube-scheduler.kubeconfig  
done
````

#### 3.5.6 启动kube-scheduler服务
````
systemctl daemon-reload
systemctl enable kube-scheduler
systemctl start kube-scheduler
````

#### 3.5.7 检查kube-scheduler服务
````
# netstat -lnpt|grep kube-scheduler
tcp        0      0 127.0.0.1:10251         0.0.0.0:*               LISTEN      3155/kube-scheduler
````
#### 3.5.8 查看当前kube-scheduler的leader
````
# kubectl get endpoints kube-scheduler --namespace=kube-system  -o yaml
apiVersion: v1
kind: Endpoints
metadata:
  annotations:
    control-plane.alpha.kubernetes.io/leader: '{"holderIdentity":"k8s-master01_eb23817d-18a9-11e9-8445-000c2927a0d0","leaseDurationSeconds":15,"acquireTime":"2019-01-15T09:43:05Z","renewTime":"2019-01-15T09:44:32Z","leaderTransitions":1}'
  creationTimestamp: 2019-01-15T09:37:03Z
  name: kube-scheduler
  namespace: kube-system
  resourceVersion: "2594"
  selfLink: /api/v1/namespaces/kube-system/endpoints/kube-scheduler
  uid: 1d51b563-18a9-11e9-bfed-000c296ab1b4
````

### 3.6 在所有master节点上验证功能是否正常
````
# kubectl get componentstatuses
NAME                 STATUS      MESSAGE                                                                                                                                  ERROR
controller-manager   Unhealthy   Get http://127.0.0.1:10252/healthz: net/http: HTTP/1.x transport connection broken: malformed HTTP response "\x15\x03\x01\x00\x02\x02"
scheduler            Healthy     ok
etcd-2               Healthy     {"health":"true"}
etcd-0               Healthy     {"health":"true"}
etcd-1               Healthy     {"health":"true"}
````



## 4， 部署 kubernetes node节点
- 依赖包

````
yum install -y epel-release wget conntrack ipvsadm ipset jq iptables curl sysstat libseccomp && /usr/sbin/modprobe ip_vs
````

### 4.1  在 Node 安装docker
- 列出 docker-ce 所有的版本

````
yum list docker-ce --showduplicates | sort -r
````

- 指定版本安装 docker-ce （推荐）

````
yum install -y docker-ce-18.06.1.ce-3.el7
````

- 启动docker-ce

````
systemctl enable docker && systemctl start docker
````

### 4.2 部署kubelet组件
- kublet 运行在每个 worker 节点上，接收 kube-apiserver 发送的请求，管理 Pod 容器，执行交互式命令，如 exec、run、logs 等。
- kublet 启动时自动向 kube-apiserver 注册节点信息，内置的 cadvisor 统计和监控节点的资源使用情况。
- 为确保安全，本文档只开启接收 https 请求的安全端口，对请求进行认证和授权，拒绝未授权的访问(如 apiserver、heapster)。

#### 4.2.1 下载 kubelet 二进制文件
````
wget https://dl.k8s.io/v1.12.4/kubernetes-server-linux-amd64.tar.gz
tar -xzvf kubernetes-server-linux-amd64.tar.gz
cd kubernetes/server/bin/
cp kubelet kube-proxy /etc/kubernetes/server/bin/
````

#### 4.2.2 创建kubelet bootstrap kubeconfig文件 （k8s-master01上执行）
````
#创建 token
export BOOTSTRAP_TOKEN=$(kubeadm token create \
  --description kubelet-bootstrap-token \
  --groups system:bootstrappers:k8s-master01 \
  --kubeconfig ~/.kube/config)

# 设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/server/ssl/ca.pem \
  --embed-certs=true \
  --server=https://192.168.2.100:8443 \
  --kubeconfig=kubelet-bootstrap-k8s-master01.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials kubelet-bootstrap \
  --token=${BOOTSTRAP_TOKEN} \
  --kubeconfig=kubelet-bootstrap-k8s-master01.kubeconfig

# 设置上下文参数
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kubelet-bootstrap \
  --kubeconfig=kubelet-bootstrap-k8s-master01.kubeconfig

# 设置默认上下文
kubectl config use-context default --kubeconfig=kubelet-bootstrap-k8s-master01.kubeconfig
````

- kubelet bootstrap kubeconfig文件创建三次，分别把k8s-master01改成k8s-master02、k8s-master03。
- 证书中写入 Token 而非证书，证书后续由 controller-manager 创建。

#### 4.2.3 查看 kubeadm 为各节点创建的 token
````
# kubeadm token list --kubeconfig ~/.kube/config
TOKEN                     TTL       EXPIRES                     USAGES                   DESCRIPTION               EXTRA GROUPS
cpwqfo.x1vxl10wzq1e3eid   23h       2019-01-17T10:00:48+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-master02
hfn1ki.7550z7bywogn1hjm   23h       2019-01-17T10:00:32+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-master03
sexqfs.8vb2su8o8iinp1jh   23h       2019-01-17T09:57:36+08:00   authentication,signing   kubelet-bootstrap-token   system:bootstrappers:k8s-master01
````

- 创建的 token 有效期为 1 天，超期后将不能再被使用，且会被 kube-controller-manager 的 tokencleaner 清理(如果启用该 controller 的话)；
- kube-apiserver 接收 kubelet 的 bootstrap token 后，将请求的 user 设置为 system:bootstrap:，group 设置为 system:bootstrappers；

- 查看各 token 关联的 Secret

````
# kubectl get secrets  -n kube-system
NAME                                             TYPE                                  DATA   AGE
attachdetach-controller-token-tprrl              kubernetes.io/service-account-token   3      16h
bootstrap-signer-token-k9xbg                     kubernetes.io/service-account-token   3      16h
bootstrap-token-cpwqfo                           bootstrap.kubernetes.io/token         7      4m4s
bootstrap-token-hfn1ki                           bootstrap.kubernetes.io/token         7      4m20s
bootstrap-token-sexqfs                           bootstrap.kubernetes.io/token         7      7m16s
certificate-controller-token-8pm9l               kubernetes.io/service-account-token   3      16h
clusterrole-aggregation-controller-token-l6z4j   kubernetes.io/service-account-token   3      16h
cronjob-controller-token-ntrcn                   kubernetes.io/service-account-token   3      16h
daemon-set-controller-token-hpsgr                kubernetes.io/service-account-token   3      16h
default-token-jh6zz                              kubernetes.io/service-account-token   3      16h
deployment-controller-token-l6s7n                kubernetes.io/service-account-token   3      16h
disruption-controller-token-zdb4r                kubernetes.io/service-account-token   3      16h
endpoint-controller-token-8k7lw                  kubernetes.io/service-account-token   3      16h
expand-controller-token-fwrbt                    kubernetes.io/service-account-token   3      16h
generic-garbage-collector-token-v6ll5            kubernetes.io/service-account-token   3      16h
horizontal-pod-autoscaler-token-9f5t5            kubernetes.io/service-account-token   3      16h
job-controller-token-vcjvp                       kubernetes.io/service-account-token   3      16h
namespace-controller-token-zx28b                 kubernetes.io/service-account-token   3      16h
node-controller-token-d9nl5                      kubernetes.io/service-account-token   3      16h
persistent-volume-binder-token-7lcfq             kubernetes.io/service-account-token   3      16h
pod-garbage-collector-token-gx445                kubernetes.io/service-account-token   3      16h
pv-protection-controller-token-lv2n4             kubernetes.io/service-account-token   3      16h
pvc-protection-controller-token-cpvk7            kubernetes.io/service-account-token   3      16h
replicaset-controller-token-52xhf                kubernetes.io/service-account-token   3      16h
replication-controller-token-qbs4f               kubernetes.io/service-account-token   3      16h
resourcequota-controller-token-gphkl             kubernetes.io/service-account-token   3      16h
service-account-controller-token-vk9mn           kubernetes.io/service-account-token   3      16h
service-controller-token-mntf7                   kubernetes.io/service-account-token   3      16h
statefulset-controller-token-ljnbs               kubernetes.io/service-account-token   3      16h
token-cleaner-token-v65g8                        kubernetes.io/service-account-token   3      16h
ttl-controller-token-w5cpc                       kubernetes.io/service-account-token   3      16h
````

#### 4.2.4 创建 kubelet 参数配置文件
- 从 v1.10 开始，kubelet 部分参数需在配置文件中配置，kubelet --help 会提示：

````
DEPRECATED: This parameter should be set via the config file specified by the Kubelet's --config flag
````

- 创建 kubelet 参数配置模板文件

````
cat > kubelet.config.json <<EOF
{
  "kind": "KubeletConfiguration",
  "apiVersion": "kubelet.config.k8s.io/v1beta1",
  "authentication": {
    "x509": {
      "clientCAFile": "/etc/kubernetes/server/ssl/ca.pem"
    },
    "webhook": {
      "enabled": true,
      "cacheTTL": "2m0s"
    },
    "anonymous": {
      "enabled": false
    }
  },
  "authorization": {
    "mode": "Webhook",
    "webhook": {
      "cacheAuthorizedTTL": "5m0s",
      "cacheUnauthorizedTTL": "30s"
    }
  },
  "address": "NodeIP",
  "port": 10250,
  "readOnlyPort": 0,
  "cgroupDriver": "cgroupfs",
  "hairpinMode": "promiscuous-bridge",
  "serializeImagePulls": false,
  "featureGates": {
    "RotateKubeletClientCertificate": true,
    "RotateKubeletServerCertificate": true
  },
  "clusterDomain": "cluster.local.",
  "clusterDNS": ["10.254.0.2"]
}
EOF
````

- address：API 监听地址，不能为 127.0.0.1，否则 kube-apiserver、heapster 等不能调用 kubelet 的 API；
- readOnlyPort=0：关闭只读端口(默认 10255)，等效为未指定；
- authentication.anonymous.enabled：设置为 false，不允许匿名�访问 10250 端口；
- authentication.x509.clientCAFile：指定签名客户端证书的 CA 证书，开启 HTTP 证书认证；
- authentication.webhook.enabled=true：开启 HTTPs bearer token 认证；
- 对于未通过 x509 证书和 webhook 认证的请求(kube-apiserver 或其他客户端)，将被拒绝，提示 Unauthorized；
- authroization.mode=Webhook：kubelet 使用 SubjectAccessReview API 查询 kube-apiserver 某 user、group 是否具有操作资源的权限(RBAC)；
- featureGates.RotateKubeletClientCertificate、featureGates.RotateKubeletServerCertificate：自动 rotate 证书，证书的有效期取决于 kube-controller-manager 的 --experimental-cluster-signing-duration 参数；
- 需要 root 账户运行；

#### 4.2.5 创建 kubelet systemd unit文件
````
[Unit]
Description=Kubernetes Kubelet
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=docker.service
Requires=docker.service

[Service]
WorkingDirectory=/var/lib/kubelet
ExecStart=/etc/kubernetes/server/bin/kubelet \
  --bootstrap-kubeconfig=/etc/kubernetes/server/cfg/kubelet-bootstrap.kubeconfig \
  --cert-dir=/etc/kubernetes/server/ssl \
  --kubeconfig=/etc/kubernetes/server/cfg/kubelet.kubeconfig \
  --config=/etc/kubernetes/server/cfg/kubelet.config.json \
  --network-plugin=cni \
  --hostname-override=NodeIP \
  --pod-infra-container-image=registry.cn-hangzhou.aliyuncs.com/google_containers/pause-amd64:3.1 \
  --allow-privileged=true \
  --alsologtostderr=true \
  --logtostderr=false \
  --log-dir=/var/log/kubernetes \
  --v=2
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
````

- 如果设置了 --hostname-override 选项，则 kube-proxy 也需要设置该选项，否则会出现找不到 Node 的情况；
- --bootstrap-kubeconfig：指向 bootstrap kubeconfig 文件，kubelet 使用该文件中的用户名和 token 向 kube-apiserver 发送 TLS Bootstrapping 请求；
- K8S approve kubelet 的 csr 请求后，在 --cert-dir 目录创建证书和私钥文件，然后写入 --kubeconfig 文件；

#### 4.2.6 分发配置文件以及证书
````
USER=root
for host in k8s-node01 k8s-node02 k8s-node03;do 
	ssh "${USER}"@$host "mkdir -p /etc/kubernetes/server/{bin,cfg,ssl}" 
	scp /etc/kubernetes/server/bin/kubelet "${USER}"@$host:/etc/kubernetes/server/bin/kubelet
	scp /etc/kubernetes/server/bin/kube-proxy "${USER}"@$host:/etc/kubernetes/server/bin/kube-proxy
	scp /usr/lib/systemd/system/kubelet.service "${USER}"@$host:/usr/lib/systemd/system/kubelet.service
	scp /etc/kubernetes/server/cfg/kubelet.config.json "${USER}"@$host:/etc/kubernetes/server/cfg/kubelet.config.json
	scp /etc/kubernetes/server/ssl/ca*.pem "${USER}"@$host:/etc/kubernetes/server/ssl/ 
done
scp /etc/kubernetes/server/cfg/kubelet-bootstrap-k8s-master01.kubeconfig k8s-node01:/etc/kubernetes/server/cfg/kubelet-bootstrap.kubeconfig
scp /etc/kubernetes/server/cfg/kubelet-bootstrap-k8s-master02.kubeconfig k8s-node02:/etc/kubernetes/server/cfg/kubelet-bootstrap.kubeconfig
scp /etc/kubernetes/server/cfg/kubelet-bootstrap-k8s-master03.kubeconfig k8s-node03:/etc/kubernetes/server/cfg/kubelet-bootstrap.kubeconfig 
````

- 修改配置文件中 NodeIP 为当前 node ip 地址

#### 4.2.7 Bootstrap Token Auth和授予权限
- kublet 启动时查找配置的 --kubeletconfig 文件是否存在，如果不存在则使用 --bootstrap-kubeconfig 向 kube-apiserver 发送证书签名请求 (CSR)。
- kube-apiserver 收到 CSR 请求后，对其中的 Token 进行认证（事先使用 kubeadm 创建的 token），认证通过后将请求的 user 设置为 system:bootstrap:，group 设置为 system:bootstrappers，这一过程称为 Bootstrap Token Auth。
- 默认情况下，这个 user 和 group 没有创建 CSR 的权限，kubelet 启动失败，错误日志如下：

````
# sudo journalctl -u kubelet -a |grep -A 2 'certificatesigningrequests'
Jan 16 10:57:58 k8s-node01 kubelet[13154]: F0116 10:57:58.720659   13154 server.go:262] failed to run Kubelet: cannot create certificate signing request: certificatesigningrequests.certificates.k8s.io is forbidden: User "system:bootstrap:sexqfs" cannot create resource "certificatesigningrequests" in API group "certificates.k8s.io" at the cluster scope
Jan 16 10:57:58 k8s-node01 kubelet[13154]: goroutine 1 [running]:
Jan 16 10:57:58 k8s-node01 kubelet[13154]: k8s.io/kubernetes/vendor/github.com/golang/glog.stacks(0xc420b42500, 0xc4208c6000, 0x137, 0x36f)
````

- 解决办法是：创建一个 clusterrolebinding，将 group system:bootstrappers 和 clusterrole system:node-bootstrapper 绑定

````
# kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --group=system:bootstrappers
clusterrolebinding.rbac.authorization.k8s.io/kubelet-bootstrap created
````

#### 4.2.8 启动kubelet服务
````
systemctl daemon-reload 
systemctl enable kubelet 
systemctl restart kubelet
````

- 关闭 swap 分区，否则 kubelet 会启动失败；
- 必须先创建工作和日志目录；
- kubelet 启动后使用 --bootstrap-kubeconfig 向 kube-apiserver 发送 CSR 请求，当这个 CSR 被 approve 后，kube-controller-manager 为 kubelet 创建 TLS 客户端证书、私钥和 --kubeletconfig 文件。

- **注意**：kube-controller-manager 需要配置 --cluster-signing-cert-file 和 --cluster-signing-key-file 参数，才会为 TLS Bootstrap 创建证书和私钥。

- 三个 work 节点的 csr 均处于 pending 状态；
- **此时kubelet的进程有，但是监听端口还未启动，需要进行下面步骤！**

#### 4.2.9 approve kubelet csr请求
- 可以手动或自动 approve CSR 请求。推荐使用自动的方式，因为从 v1.8 版本开始，可以自动轮转approve csr 后生成的证书。

#### 4.2.9.1 手动approve csr请求
- 查看 CSR 列表

````
# kubectl get csr
NAME                                                   AGE     REQUESTOR                 CONDITION
node-csr-_66QdtyS-i4S8DVmFcT8O3TMqvj6I5tKbXIuzEIjHbY   3m46s   system:bootstrap:sexqfs   Pending
node-csr-c9EwBERPn8pjoCkYvX7jV-GansnNO4V2kPT3msYFVu4   3m46s   system:bootstrap:cpwqfo   Pending
node-csr-tPZAgKp8z-3nZMe4rPR2WEscJB-ox61VMQtijy6BO_M   3m46s   system:bootstrap:hfn1ki   Pending
````

- approve CSR 

````
# kubectl certificate approve node-csr-_66QdtyS-i4S8DVmFcT8O3TMqvj6I5tKbXIuzEIjHbY
certificatesigningrequest.certificates.k8s.io/node-csr-_66QdtyS-i4S8DVmFcT8O3TMqvj6I5tKbXIuzEIjHbY approved
````

- 查看 Approve 结果

````
# kubectl get csr
NAME                                                   AGE     REQUESTOR                 CONDITION
node-csr-_66QdtyS-i4S8DVmFcT8O3TMqvj6I5tKbXIuzEIjHbY   4m34s   system:bootstrap:sexqfs   Approved,Issued
node-csr-c9EwBERPn8pjoCkYvX7jV-GansnNO4V2kPT3msYFVu4   4m34s   system:bootstrap:cpwqfo   Pending
node-csr-tPZAgKp8z-3nZMe4rPR2WEscJB-ox61VMQtijy6BO_M   4m34s   system:bootstrap:hfn1ki   Pending
````
````
# kubectl describe csr node-csr-_66QdtyS-i4S8DVmFcT8O3TMqvj6I5tKbXIuzEIjHbY
Name:               node-csr-_66QdtyS-i4S8DVmFcT8O3TMqvj6I5tKbXIuzEIjHbY
Labels:             <none>
Annotations:        <none>
CreationTimestamp:  Wed, 16 Jan 2019 10:59:33 +0800
Requesting User:    system:bootstrap:sexqfs
Status:             Approved,Issued
Subject:
         Common Name:    system:node:192.168.2.111
         Serial Number:
         Organization:   system:nodes
Events:  <none>
````

- Requesting User：请求 CSR 的用户，kube-apiserver 对它进行认证和授权；
- Subject：请求签名的证书信息；
- 证书的 CN 是 system:node:192.168.80.10， Organization 是 system:nodes，kube-apiserver 的 Node 授权模式会授予该证书的相关权限；

#### 4.2.9.2 自动approve csr请求
- 创建三个 ClusterRoleBinding，分别用于自动 approve client、renew client、renew server 证书

````
# cat > csr-crb.yaml <<EOF
 # Approve all CSRs for the group "system:bootstrappers"
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: auto-approve-csrs-for-group
 subjects:
 - kind: Group
   name: system:bootstrappers
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: system:certificates.k8s.io:certificatesigningrequests:nodeclient
   apiGroup: rbac.authorization.k8s.io
---
 # To let a node of the group "system:nodes" renew its own credentials
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: node-client-cert-renewal
 subjects:
 - kind: Group
   name: system:nodes
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: system:certificates.k8s.io:certificatesigningrequests:selfnodeclient
   apiGroup: rbac.authorization.k8s.io
---
# A ClusterRole which instructs the CSR approver to approve a node requesting a
# serving cert matching its client cert.
kind: ClusterRole
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: approve-node-server-renewal-csr
rules:
- apiGroups: ["certificates.k8s.io"]
  resources: ["certificatesigningrequests/selfnodeserver"]
  verbs: ["create"]
---
 # To let a node of the group "system:nodes" renew its own server credentials
 kind: ClusterRoleBinding
 apiVersion: rbac.authorization.k8s.io/v1
 metadata:
   name: node-server-cert-renewal
 subjects:
 - kind: Group
   name: system:nodes
   apiGroup: rbac.authorization.k8s.io
 roleRef:
   kind: ClusterRole
   name: approve-node-server-renewal-csr
   apiGroup: rbac.authorization.k8s.io
EOF
````

- auto-approve-csrs-for-group：自动 approve node 的第一次 CSR； 注意第一次 CSR 时，请求的 Group 为 system:bootstrappers；
- node-client-cert-renewal：自动 approve node 后续过期的 client 证书，自动生成的证书 Group 为 system:nodes;
- node-server-cert-renewal：自动 approve node 后续过期的 server 证书，自动生成的证书 Group 为 system:nodes;

- 生效配置

````
# kubectl apply -f csr-crb.yaml
````

#### 4.2.10 查看kubelet情况
- 等待一段时间(1-10 分钟)，三个节点的 CSR 都被自动 approve
````
# kubectl get csr
NAME                                                   AGE   REQUESTOR                 CONDITION
node-csr-_66QdtyS-i4S8DVmFcT8O3TMqvj6I5tKbXIuzEIjHbY   21m   system:bootstrap:sexqfs   Approved,Issued
node-csr-c9EwBERPn8pjoCkYvX7jV-GansnNO4V2kPT3msYFVu4   21m   system:bootstrap:cpwqfo   Approved,Issued
node-csr-tPZAgKp8z-3nZMe4rPR2WEscJB-ox61VMQtijy6BO_M   21m   system:bootstrap:hfn1ki   Approved,Issued
````

- 所有节点均 ready

````
# kubectl get node
NAME            STATUS   ROLES    AGE     VERSION
192.168.2.111   Ready    <none>   17m     v1.12.4
192.168.2.112   Ready    <none>   7m45s   v1.12.4
192.168.2.113   Ready    <none>   7m44s   v1.12.4
````

-  kube-controller-manager 为各 node 生成了 kubeconfig 文件和公私钥

````
# tree /etc/kubernetes/server/
/etc/kubernetes/server/
├── bin
│   ├── kubectl
│   ├── kubelet
│   └── kube-proxy
├── cfg
│   ├── kubelet-bootstrap.kubeconfig
│   ├── kubelet.config.json
│   └── kubelet.kubeconfig
└── ssl
    ├── ca-key.pem
    ├── ca.pem
    ├── kubelet-client-2019-01-16-11-03-54.pem
    ├── kubelet-client-current.pem -> /etc/kubernetes/server/ssl/kubelet-client-2019-01-16-11-03-54.pem
    ├── kubelet.crt
    └── kubelet.key
````

- kubelet-server 证书会周期轮转

#### 4.2.11 Kubelet提供的API接口
- kublet 启动后监听多个端口，用于接收 kube-apiserver 或其它组件发送的请求

````
# netstat -lnpt|grep kubelet
tcp        0      0 127.0.0.1:10248         0.0.0.0:*               LISTEN      13537/kubelet
tcp        0      0 192.168.2.111:10250     0.0.0.0:*               LISTEN      13537/kubelet
tcp        0      0 127.0.0.1:39767         0.0.0.0:*               LISTEN      13537/kubelet
````

- 4194: cadvisor http 服务 (随机端口)；
- 10248: healthz http 服务；
- 10250: https API 服务；注意：未开启只读端口 10255；

- kubelet 接收 10250 端口的 https 请求：
    - /pods、/runningpods
    - /metrics、/metrics/cadvisor、/metrics/probes
    - /spec
    - /stats、/stats/container
    - /logs
    - /run/、"/exec/", "/attach/", "/portForward/", "/containerLogs/" 等管理；
    - 详情参考：https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/server/server.go#L434:3
- 由于关闭了匿名认证，同时开启了 webhook 授权，所有访问 10250 端口 https API 的请求都需要被认证和授权。

- 例如执行 kubectl ec -it nginx-ds-5rmws -- sh 命令时，kube-apiserver 会向 kubelet 发送如下请求：

````
POST /exec/default/nginx-ds-5rmws/my-nginx?command=sh&input=1&output=1&tty=1
````

- 预定义的 ClusterRole system:kubelet-api-admin 授予访问 kubelet 所有 API 的权限：

````
# kubectl describe clusterrole system:kubelet-api-admin
Name:         system:kubelet-api-admin
Labels:       kubernetes.io/bootstrapping=rbac-defaults
Annotations:  rbac.authorization.kubernetes.io/autoupdate: true
PolicyRule:
  Resources      Non-Resource URLs  Resource Names  Verbs
  ---------      -----------------  --------------  -----
  nodes/log      []                 []              [*]
  nodes/metrics  []                 []              [*]
  nodes/proxy    []                 []              [*]
  nodes/spec     []                 []              [*]
  nodes/stats    []                 []              [*]
  nodes          []                 []              [get list watch proxy]
````

#### 4.2.12 kubet api认证和授权
- kublet的配置文件kubelet.config.json配置了如下认证参数：
    - authentication.anonymous.enabled：设置为 false，不允许匿名访问 10250 端口；
    - authentication.x509.clientCAFile：指定签名客户端证书的 CA 证书，开启 HTTPs 证书认证；
    - authentication.webhook.enabled=true：开启 HTTPs bearer token 认证；
- 同时配置了如下授权参数：
    - authroization.mode=Webhook：开启 RBAC 授权；
- kubelet 收到请求后，使用 clientCAFile 对证书签名进行认证，或者查询 bearer token 是否有效。如果两者都没通过，则拒绝请求，提示 Unauthorized

````
# curl -s --cacert /etc/kubernetes/server/ssl/ca.pem https://192.168.2.111:10250/metrics
# curl -s --cacert /etc/kubernetes/server/ssl/ca.pem -H "Authorization: Bearer 123456"  https://192.168.2.111:10250/metrics
````

- 证书认证和授权

````
# curl -s --cacert /etc/kubernetes/server/ssl/ca.pem --cert /etc/kubernetes/server/ssl/kube-controller-manager.pem --key /etc/kubernetes/server/ssl/kube-controller-manager-key.pem https://192.168.2.111:10250/metrics


#  curl -s --cacert /etc/kubernetes/server/ssl/ca.pem --cert /etc/kubernetes/server/ssl/admin.pem --key /etc/kubernetes/server/ssl/admin-key.pem https://192.168.2.111:10250/metrics|head
````

- bear token 认证和授权
- 创建一个 ServiceAccount，将它和 ClusterRole system:kubelet-api-admin 绑定，从而具有调用 kubelet API 的权限

````
kubectl create sa kubelet-api-test
kubectl create clusterrolebinding kubelet-api-test --clusterrole=system:kubelet-api-admin --serviceaccount=default:kubelet-api-test
SECRET=$(kubectl get secrets | grep kubelet-api-test | awk '{print $1}')
TOKEN=$(kubectl describe secret ${SECRET} | grep -E '^token' | awk '{print $2}')
echo ${TOKEN}

curl -s --cacert /etc/kubernetes/server/ssl/ca.pem -H "Authorization: Bearer ${TOKEN}" https://192.168.2.111:10250/metrics|head
````



### 4.3 部署kube-proxy组件
- kube-proxy 运行在所有 worker 节点上，，它监听 apiserver 中 service 和 Endpoint 的变化情况，创建路由规则来进行服务负载均衡。
- 本文档讲解部署 kube-proxy 的部署，使用 ipvs 模式。

#### 4.3.1 生成 kube-proxy 证书
- 配置

````
cat << EOF | tee kube-proxy-csr.json
{
  "CN": "system:kube-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "Beijing",
      "ST": "Beijing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF
````
- CN：指定该证书的 User 为 system:kube-proxy；
- 预定义的 RoleBinding system:node-proxier 将User system:kube-proxy 与 Role system:node-proxier 绑定，该 Role 授予了调用 kube-apiserver Proxy 相关 API 的权限；
- 该证书只会被 kube-proxy 当做 client 证书使用，所以 hosts 字段为空；

- 生成证书

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy
````

- 移动证书

````
mkdir /etc/kubernetes/server/{bin,cfg,ssl} -p
cp kube-proxy-key.pem  kube-proxy.pem /etc/kubernetes/server/ssl/
````

#### 4.3.2 创建和分发kubeconfig文件
````
kubectl config set-cluster kubernetes \
  --certificate-authority=/etc/kubernetes/server/ssl/ca.pem \
  --embed-certs=true \
  --server=https://192.168.2.100:8443 \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials kube-proxy \
  --client-certificate=/etc/kubernetes/server/ssl/kube-proxy.pem \
  --client-key=/etc/kubernetes/server/ssl/kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
````

- -embed-certs=true：将 ca.pem 和 admin.pem 证书内容嵌入到生成的 kubectl-proxy.kubeconfig 文件中(不加时，写入的是证书文件路径)


#### 4.3.3 创建 kube-proxy systemd unit 文件
- 从 v1.10 开始，kube-proxy 部分参数可以配置文件中配置。可以使用 --write-config-to 选项生成该配置文件，或者参考 kubeproxyconfig 的类型定义源文件 ：https://github.com/kubernetes/kubernetes/blob/master/pkg/proxy/apis/kubeproxyconfig/types.go

````
# cat /usr/lib/systemd/system/kube-proxy.service 
[Unit]
Description=Kubernetes Kube-Proxy Server
Documentation=https://github.com/GoogleCloudPlatform/kubernetes
After=network.target

[Service]
WorkingDirectory=/var/lib/kube-proxy
ExecStart=/etc/kubernetes/server/bin/kube-proxy \
  --bind-address=192.168.2.111 \
  --hostname-override=k8s-node01\
  --cluster-cidr=172.16.0.0/16 \
  --kubeconfig=/etc/kubernetes/server/cfg/kube-proxy.kubeconfig \
  --feature-gates=SupportIPVSProxyMode=true \
  --masquerade-all \
  --proxy-mode=ipvs \
  --ipvs-min-sync-period=5s \
  --ipvs-sync-period=5s \
  --ipvs-scheduler=rr \
  --logtostderr=true \
  --v=2 \
  --logtostderr=false \
  --log-dir=/var/lib/kube-proxy/log

Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
````

- bind-address: 监听地址；
- clientConnection.kubeconfig: 连接 apiserver 的 kubeconfig 文件；
- clusterCIDR: kube-proxy 根据 --cluster-cidr 判断集群内部和外部流量，指定 --cluster-cidr 或 --masquerade-all选项后 kube-proxy 才会对访问 Service IP 的请求做 SNAT；
- hostname-override: 参数值必须与 kubelet 的值一致，否则 kube-proxy 启动后会找不到该 Node，从而不会创建任何 ipvs 规则；
- proxy-mode: 使用 ipvs 模式；
- 修改改对应主机的信息。其中clusterc idr为docker0网络地址。

#### 4.3.4 分发配置文件以及证书
````
USER=root
for host in k8s-node01 k8s-node02 k8s-node03;do 
	ssh "${USER}"@$host "mkdir -p mkdir -p /var/lib/kube-proxy/log" 
	scp /usr/lib/systemd/system/kube-proxy.service "${USER}"@$host:/usr/lib/systemd/system/kube-proxy.service
	scp /etc/kubernetes/server/cfg/kube-proxy.kubeconfig "${USER}"@$host:/etc/kubernetes/server/cfg/kube-proxy.kubeconfig
	scp /etc/kubernetes/server/ssl/kube-proxy*.pem "${USER}"@$host:/etc/kubernetes/server/ssl/ 
done
````

#### 4.3.5 启动kube-proxy服务
````
systemctl daemon-reload
systemctl enable kube-proxy
systemctl restart kube-proxy
````

#### 4.3.6 检查启动结果
````
systemctl status kube-proxy|grep Active
````

- 确保状态为 active (running)，否则查看日志，确认原因：

````
journalctl -u kube-proxy
````

- 查看监听端口状态

````
# netstat -lnpt|grep kube-proxy
tcp        0      0 127.0.0.1:10249         0.0.0.0:*               LISTEN      21237/kube-proxy
tcp6       0      0 :::10256                :::*                    LISTEN      21237/kube-proxy
````

- 10249：http prometheus metrics port
- 10256：http healthz port

#### 4.3.7 查看ipvs路由规则
````
# ipvsadm -L -n
IP Virtual Server version 1.2.1 (size=4096)
Prot LocalAddress:Port Scheduler Flags
  -> RemoteAddress:Port           Forward Weight ActiveConn InActConn
TCP  10.254.0.1:443 rr
  -> 192.168.2.101:6443           Masq    1      0          0
  -> 192.168.2.102:6443           Masq    1      0          0
  -> 192.168.2.103:6443           Masq    1      0          0
````

- 可见将所有到 kubernetes cluster ip 443 端口的请求都转发到 kube-apiserver 的 6443 端口。

## 5，配置 calico 网络
### 5.1 calico安装
- 主要参考官方文档 https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/calico

#### 5.1.1 下载calico.yaml rbac.yaml
````
curl https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/rbac.yaml -O
curl https://docs.projectcalico.org/v3.1/getting-started/kubernetes/installation/hosted/calico.yaml -O
````

#### 5.1.2 配置 calico 文件
- etcd 地址

````
ETCD_ENDPOINTS="https://192.168.2.101:2379,https://192.168.2.102:2379,https://192.168.2.103:2379"
sed -i "s#.*etcd_endpoints:.*#  etcd_endpoints: \"${ETCD_ENDPOINTS}\"#g" calico.yaml
sed -i "s#__ETCD_ENDPOINTS__#${ETCD_ENDPOINTS}#g" calico.yaml
````

- etcd 证书

````
ETCD_CERT=`cat /etc/kubernetes/etcd/ssl/etcd.pem | base64 | tr -d '\n'`
ETCD_KEY=`cat /etc/kubernetes/etcd/ssl/etcd-key.pem | base64 | tr -d '\n'`
ETCD_CA=`cat /etc/kubernetes/etcd/ssl/ca.pem | base64 | tr -d '\n'`

sed -i "s#.*etcd-cert:.*#  etcd-cert: ${ETCD_CERT}#g" calico.yaml
sed -i "s#.*etcd-key:.*#  etcd-key: ${ETCD_KEY}#g" calico.yaml
sed -i "s#.*etcd-ca:.*#  etcd-ca: ${ETCD_CA}#g" calico.yaml

sed -i 's#.*etcd_ca:.*#  etcd_ca: "/calico-secrets/etcd-ca"#g' calico.yaml
sed -i 's#.*etcd_cert:.*#  etcd_cert: "/calico-secrets/etcd-cert"#g' calico.yaml
sed -i 's#.*etcd_key:.*#  etcd_key: "/calico-secrets/etcd-key"#g' calico.yaml

sed -i "s#__ETCD_KEY_FILE__#/etc/kubernetes/etcd/ssl/etcd-key.pem#g" calico.yaml
sed -i "s#__ETCD_CERT_FILE__#/etc/kubernetes/etcd/ssl/etcd.pem#g" calico.yaml
sed -i "s#__ETCD_CA_CERT_FILE__#/etc/kubernetes/etcd/ssl/ca.pem#g" calico.yaml
sed -i "s#__KUBECONFIG_FILEPATH__#/etc/cni/net.d/calico-kubeconfig#g" calico.yaml
````

- 配置calico bgp 并且修改ip cidr:172.16.0.0/16

````
sed -i '/CALICO_IPV4POOL_IPIP/{n;s/Always/off/g}' calico.yaml
sed -i '/CALICO_IPV4POOL_CIDR/{n;s/192.168.0.0/172.16.0.0/g}' calico.yaml
````

#### 5.1.3 kubectl安装calico
````
kubectl apply -f calico.yaml
````

- **注意** : 因为calico-node需要获取操作系统的权限运行，所以要在apiserver、kubelet中加入````--allow-privileged=true````
- **注意** : kubelet配置calico，加入 ````--network-plugin=cni````
- **注意** : Kube-Proxy配置 ````--cluster-cidr=172.16.0.0/16 ````
- 重启对应服务

#### 5.1.4 查看一下状态
````
# kubectl get pod -n kube-system -o wide
NAME                                       READY   STATUS    RESTARTS   AGE     IP              NODE            NOMINATED NODE
calico-kube-controllers-7875f976cd-gxfdj   1/1     Running   1          20m     192.168.2.113   192.168.2.113   <none>
calico-node-78gtd                          2/2     Running   2          20m     192.168.2.111   192.168.2.111   <none>
calico-node-dxw6z                          2/2     Running   2          20m     192.168.2.113   192.168.2.113   <none>
calico-node-wvrxd                          2/2     Running   2          20m     192.168.2.112   192.168.2.112   <none>
````

## 6，部署kubernetes DNS(在master执行）
### 6.1 下载配置文件
````
wget https://github.com/kubernetes/kubernetes/releases/download/v1.12.4/kubernetes.tar.gz
tar -zxvf kubernetes.tar.gz
mv kubernetes/cluster/addons/dns/coredns/coredns.yaml.base /etc/kubernetes/coredns/coredns.yaml
````

### 6.2 修改配置文件
````
sed -i 's#kubernetes __PILLAR__DNS__DOMAIN__#kubernetes cluster.local.#g' coredns.yaml
sed -i 's#clusterIP: __PILLAR__DNS__SERVER__#clusterIP: 10.254.0.2#g' coredns.yaml
````
### 6.3 创建coreDNS
````
kubectl apply -f coredns.yaml
````

### 6.4 查看coreDNS服务状态
````
kubectl get pod -n kube-system -o wide
NAME                                       READY   STATUS    RESTARTS   AGE     IP              NODE            NOMINATED NODE
calico-kube-controllers-7875f976cd-gxfdj   1/1     Running   1          20m     192.168.2.113   192.168.2.113   <none>
calico-node-78gtd                          2/2     Running   2          20m     192.168.2.111   192.168.2.111   <none>
calico-node-dxw6z                          2/2     Running   2          20m     192.168.2.113   192.168.2.113   <none>
calico-node-wvrxd                          2/2     Running   2          20m     192.168.2.112   192.168.2.112   <none>
coredns-74c656b9f-9f8l8                    1/1     Running   0          3m56s   172.16.70.131   192.168.2.113   <none>
````

````
kubectl get svc --all-namespaces
NAMESPACE     NAME         TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)         AGE
default       kubernetes   ClusterIP   10.254.0.1      <none>        443/TCP         24h
kube-system   kube-dns     ClusterIP   10.254.0.2      <none>        53/UDP,53/TCP   27s
````



## 7，验证集群功能
### 7.1 查看节点状况
````
# kubectl get nodes
NAME            STATUS   ROLES    AGE     VERSION
192.168.2.111   Ready    <none>   3h39m   v1.12.4
192.168.2.112   Ready    <none>   3h30m   v1.12.4
192.168.2.113   Ready    <none>   3h30m   v1.12.4
````

### 7.2 创建nginx web测试文件
````
# cat > nginx-web.yml << EOF
apiVersion: v1
kind: Service
metadata:
  name: nginx-web
  labels:
    tier: frontend
spec:
  type: NodePort
  selector:
    tier: frontend
  ports:
  - name: http
    port: 80
    targetPort: 80
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: nginx-con
  labels:
    tier: frontend
spec:
  replicas: 3
  template:
    metadata:
      labels:
        tier: frontend
    spec:
      containers:
      - name: nginx-pod
        image: nginx
        ports:
        - containerPort: 80
EOF
````

- 执行nginx-web.yaml文件

````
kubectl create -f nginx-web.yml
````

### 7.3 查看各个Node上Pod IP的连通性
````
# kubectl get pod -o wide
NAME                         READY   STATUS    RESTARTS   AGE   IP               NODE            NOMINATED NODE
nginx-con-594b8d6b48-47b5l   1/1     Running   0          12s   172.16.70.135    192.168.2.113   <none>
nginx-con-594b8d6b48-f2pzv   1/1     Running   0          12s   172.16.200.9     192.168.2.111   <none>
nginx-con-594b8d6b48-g99mm   1/1     Running   0          12s   172.16.141.196   192.168.2.112   <none>
````

- nginx 的 Pod IP 分别是 172.16.70.135、172.16.200.9 、 172.16.141.196，在所有 Node 上分别 ping 这三个 IP，看是否连通

````
# ping -c 3 172.16.70.135
PING 172.16.70.135 (172.16.70.135) 56(84) bytes of data.
64 bytes from 172.16.70.135: icmp_seq=1 ttl=63 time=0.346 ms
64 bytes from 172.16.70.135: icmp_seq=2 ttl=63 time=0.145 ms
64 bytes from 172.16.70.135: icmp_seq=3 ttl=63 time=0.161 ms

--- 172.16.70.135 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1999ms
rtt min/avg/max/mdev = 0.145/0.217/0.346/0.092 ms
````
````
# ping -c 3 172.16.200.9
PING 172.16.200.9 (172.16.200.9) 56(84) bytes of data.
64 bytes from 172.16.200.9: icmp_seq=1 ttl=63 time=0.261 ms
64 bytes from 172.16.200.9: icmp_seq=2 ttl=63 time=0.187 ms
64 bytes from 172.16.200.9: icmp_seq=3 ttl=63 time=0.221 ms

--- 172.16.200.9 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 1999ms
rtt min/avg/max/mdev = 0.187/0.223/0.261/0.030 ms
````
````
# ping -c 3 172.16.141.196
PING 172.16.141.196 (172.16.141.196) 56(84) bytes of data.
64 bytes from 172.16.141.196: icmp_seq=1 ttl=63 time=0.379 ms
64 bytes from 172.16.141.196: icmp_seq=2 ttl=63 time=0.221 ms
64 bytes from 172.16.141.196: icmp_seq=3 ttl=63 time=0.233 ms

--- 172.16.141.196 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2000ms
rtt min/avg/max/mdev = 0.221/0.277/0.379/0.074 ms
````

### 7.4 查看server的集群ip
````
# kubectl get svc
NAME         TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)        AGE
kubernetes   ClusterIP   10.254.0.1      <none>        443/TCP        43h
nginx-web    NodePort    10.254.29.144   <none>        80:30945/TCP   11m
````

- 10.254.29.144 为nginx service的集群ip，代理的是前面的三个pod容器应用。
- PORT 80是集群IP的端口，30945是node节点上的端口，可以用nodeip:nodeport方式访问服务

### 7.5 访问服务可达性
- 用局域网的任意其他主机访问应用，nodeip:nodeprot方式 （这里nodeip是私网，所以用局域网的其他主机访问）

````
# curl -I 192.168.2.111:30945
HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Thu, 17 Jan 2019 03:43:21 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 25 Dec 2018 09:56:47 GMT
Connection: keep-alive
ETag: "5c21fedf-264"
Accept-Ranges: bytes
````

- 在calico 网络的主机上使用集群ip访问应用

````
curl -I 10.254.29.144
HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Thu, 17 Jan 2019 03:44:06 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 25 Dec 2018 09:56:47 GMT
Connection: keep-alive
ETag: "5c21fedf-264"
Accept-Ranges: bytes
````

### 7.6 创建一个简单的centos 测试 coreDNS 
- centos.yaml

````
# cat centos.yaml
apiVersion: v1
kind: Pod
metadata:
  name: centos-test
  namespace: default
spec:
  containers:
  - image: centos
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: centoschao
  restartPolicy: Always
````

- 创建

````
kubectl create -f centos.yaml
````

- 进入容器 下载 curl nslookup 

````
#  kubectl exec -it centos-test -- yum install bind-utils curl -y
````

- 验证

````
# kubectl exec -it centos-test -- curl -I 192.168.2.100:30945
HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Thu, 17 Jan 2019 04:57:53 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 25 Dec 2018 09:56:47 GMT
Connection: keep-alive
ETag: "5c21fedf-264"
Accept-Ranges: bytes
````
````
# kubectl exec -it centos-test -- curl -I  nginx-web.default.svc.cluster.local
HTTP/1.1 200 OK
Server: nginx/1.15.8
Date: Thu, 17 Jan 2019 04:58:56 GMT
Content-Type: text/html
Content-Length: 612
Last-Modified: Tue, 25 Dec 2018 09:56:47 GMT
Connection: keep-alive
ETag: "5c21fedf-264"
Accept-Ranges: bytes
````
````
# kubectl exec -it centos-test -- nslookup nginx-web.default.svc.cluster.local
Server:		10.254.0.2
Address:	10.254.0.2#53

Name:	nginx-web.default.svc.cluster.local
Address: 10.254.29.144
````

## 8 ，部署 metrics
### 8.1 生成证书
- front-proxy-csr.json

````
# cat > front-proxy-csr.json << EOF
{
  "CN": "system:front-proxy",
  "hosts": [],
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
    {
      "C": "CN",
      "L": "Beijing",
      "ST": "Beijing",
      "O": "k8s",
      "OU": "System"
    }
  ]
}
EOF
````

- 生成证书

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes front-proxy-csr.json | cfssljson -bare front-proxy
````

- 分发证书

````
USER=root
CONTROL_PLANE_IPS="k8s-master01 k8s-master02 k8s-master03 k8s-node01 k8s-node02 k8s-node03"
for host in $CONTROL_PLANE_IPS; do
    scp front-proxy-key.pem front-proxy.pem "${USER}"@$host:/etc/kubernetes/server/ssl/
done
````

### 8.2 安装之前需要为kubernetes增加配置项
- 为/usr/lib/systemd/systemcontroller-manager增加启动项

````
  --horizontal-pod-autoscaler-use-rest-clients=true
````

- 为/usr/lib/systemd/system/kube-apiserver.service增加启动项

````
  --requestheader-client-ca-file=/etc/kubernetes/server/ssl/ca.pem  \
  --requestheader-allowed-names=aggregator  \
  --requestheader-extra-headers-prefix=X-Remote-Extra- \
  --requestheader-group-headers=X-Remote-Group \
  --requestheader-username-headers=X-Remote-User \
  --proxy-client-cert-file=/etc/kubernetes/server/ssl/front-proxy.pem \
  --proxy-client-key-file=/etc/kubernetes/server/ssl/front-proxy-key.pem \
  --enable-aggregator-routing=true
````

- 启动服务

````
systemctl daemon-reload
systemctl restart kube-apiserver
systemctl restart kube-controller-manager
````

### 8.3 下载 metrics 配置文件
````
wget https://github.com/kubernetes/kubernetes/releases/download/v1.12.4/kubernetes.tar.gz
tar zxvf kubernetes.tar.gz
cp -a kubernetes/cluster/addons/metrics-server/ /etc/kubernetes/
````

### 8.4 更改配置文件
````
# cat > metrics-server-deployment.yaml << EOF
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: metrics-server
  namespace: kube-system
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: metrics-server
  namespace: kube-system
  labels:
    k8s-app: metrics-server
spec:
  selector:
    matchLabels:
      k8s-app: metrics-server
  template:
    metadata:
      name: metrics-server
      labels:
        k8s-app: metrics-server
    spec:
      serviceAccountName: metrics-server
      volumes:
      # mount in tmp so we can safely use from-scratch images and/or read-only containers
      - name: tmp-dir
        emptyDir: {}
      containers:
      - name: metrics-server
        image: xiaoqshuo/metrics-server-amd64:v0.3.1
        imagePullPolicy: Always
        command:
        - /metrics-server
        - --kubelet-insecure-tls
        - --kubelet-preferred-address-types=InternalIP
        volumeMounts:
        - name: tmp-dir
          mountPath: /tmp
EOF
````

### 8.5 创建 metrics
````
# kubectl apply -f metrics-server
````

### 8.6 查看状态
````
# kubectl get -n kube-system all -o wide| grep metrics

pod/metrics-server-56f4b88678-x9djk            1/1     Running   0          26m     172.16.200.12   192.168.2.111   <none>

service/metrics-server         ClusterIP   10.254.130.198   <none>        443/TCP         65m   k8s-app=metrics-server


deployment.apps/metrics-server            1         1         1            1           34m   metrics-server            xiaoqshuo/metrics-server-amd64:v0.3.1          k8s-app=metrics-server
replicaset.apps/metrics-server-56f4b88678            1         1         1       26m   metrics-server            xiaoqshuo/metrics-server-amd64:v0.3.1           k8s-app=metrics-server,pod-template-hash=56f4b88678
````

## 9，部署 dashboard
- 参考：
    - https://github.com/kubernetes/dashboard#getting-started
    - https://github.com/kubernetes/dashboard/wiki/Creating-sample-user

### 9.1 下载配置文件
````
wget https://raw.githubusercontent.com/kubernetes/dashboard/v1.10.1/src/deploy/recommended/kubernetes-dashboard.yaml
````

### 9.2 修改配置文件
- kubernetes-dashboard.yaml 修改镜像增加 NodePort

````
# ------------------- Dashboard Service ------------------- #

kind: Service
apiVersion: v1
metadata:
  labels:
    k8s-app: kubernetes-dashboard
  name: kubernetes-dashboard
  namespace: kube-system
spec:
  type: NodePort
  ports:
    - port: 443
      targetPort: 8443
      nodePort: 30000
  selector:
    k8s-app: kubernetes-dashboard
````

- user-admin.yaml

````
# cat > user-admin.yaml << EOF
# ------------------- ServiceAccount ------------------- #

apiVersion: v1
kind: ServiceAccount
metadata:
  name: user-admin
  namespace: kube-system

---
# ------------------- ClusterRoleBinding ------------------- #

apiVersion: rbac.authorization.k8s.io/v1beta1
kind: ClusterRoleBinding
metadata:
  name: user-admin
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: cluster-admin
subjects:
- kind: ServiceAccount
  name: user-admin
  namespace: kube-system
EOF
````

### 9.3 创建 dashboard
````
kubectl apply -f kubernetes-dashboard.yaml 
kubectl apply -f user-admin.yaml
````

### 9.4 查看状态
````
# kubectl get -n kube-system all -o wide| grep dashboard

pod/kubernetes-dashboard-66468c4f76-nfdwv      1/1     Running   0          20m     172.16.195.1    192.168.2.103   <none>
service/kubernetes-dashboard   NodePort    10.254.58.73     <none>        443:30000/TCP   21m   k8s-app=kubernetes-dashboard


deployment.apps/kubernetes-dashboard      1         1         1            1           21m   kubernetes-dashboard      xiaoqshuo/kubernetes-dashboard-amd64:v1.10.1   k8s-app=kubernetes-dashboard

replicaset.apps/kubernetes-dashboard-66468c4f76      1         1         1       20m   kubernetes-dashboard      xiaoqshuo/kubernetes-dashboard-amd64:v1.10.1    k8s-app=kubernetes-dashboard,pod-template-hash=66468c4f76
````

### 9.5 获取token
````
kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep user-admin | awk '{print $1}')
````

### 9.5 UI访问
- 火狐浏览器 访问 https://192.168.2.100:30000/#!/login

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190117162244915-629409416.png)




- **参考**：
    - https://zhangguanzhang.github.io/2018/09/18/kubernetes-1-11-x-bin/
    - https://www.cnblogs.com/harlanzhang/p/10116118.html
    - http://blog.51cto.com/lizhenliang/2325770
    - https://www.cnblogs.com/root0/p/9953287.html
    - http://blog.51cto.com/ylw6006/2316767
    - https://blog.csdn.net/mario_hao/article/details/80559354
    - https://www.cnblogs.com/MrVolleyball/p/9920964.html
