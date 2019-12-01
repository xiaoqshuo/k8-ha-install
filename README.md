# k8s 1.14.8 二进制离线部署

- 参考

````
https://www.kubernetes.org.cn/5163.html
```

## 1，kubernetes 介绍

- Kubernetes（K8S）是Google开源的容器集群管理系统，K8S在Docker容器技术的基础之上，大大地提高了容器化部署应用简单高效。并且具备了完整的集群管理能力，涵盖项目周期的各个环节。
- Docker与Kubernetes联系：Docker是一个容器引擎，用于运行容器，Kubernetes是一个容器编排系统，不具备容器引擎功能，相比Docker是一个更高级封装，而他们在一起堪称珠联璧合。

## 2，集群环境规划

### 2.1 软件环境

| 服务       | 版本                                 |
| :--------- | :----------------------------------- |
| CentOS 7.6 | CentOS Linux release 7.6.1810 (Core) |
| kubernetes | v1.14.8                              |
| Docker     | v18.09                               |
| etcd       | v3.3.17                              |
| Calico     | v3.10.1                              |
| CoreDNS    | v1.5.2                               |

### 2.2 服务器角色

| IP              | hostname | application                                                  | CPU  | Memory |
| :-------------- | :------- | :----------------------------------------------------------- | ---- | ------ |
| 192.168.154.130 | VIP      |                                                              |      |        |
| 192.168.154.131 | k8s-m1   | etcd，kube-apiserver，kube-controller-manager，kube-scheduler，haproxy，keepalived，nginx，docker-distribution | 2C   | 2G     |
| 192.168.154.132 | k8s-m2   | etcd，kube-apiserver，kube-controller-manager，kube-scheduler，haproxy，keepalived | 2C   | 2G     |
| 192.168.154.133 | k8s-m3   | etcd，kube-apiserver，kube-controller-manager，kube-scheduler，haproxy，keepalived | 2C   | 2G     |
| 192.168.154.134 | k8s-n1   | docker，kubelet，kube-proxy                                  | 2C   | 2G     |
| 192.168.154.135 | k8s-n2   | docker，kubelet，kube-proxy                                  | 2C   | 2G     |

## 3，部署前环境准备

- 所有的操作都在master1上进行

- 登录maser1服务器
- 创建k8s模板目录

````
mkdir -p /etc/kubernetes/template
````

- 上传 k8s 相关包

````
链接：https://pan.baidu.com/s/1rCwv6ZUGpiF6iCBDSeBVEw 
提取码：o97i 
复制这段内容后打开百度网盘手机App，操作更方便哦
````

- 进入 k8s 模板目录，解压相关包

````
cd  /etc/kubernetes/template
# 配置文件
tar zxvf k8s-Binary_deployment_1.14.8_cfg.tar.gz
# 命令
tar zxvf k8s-Binary_deployment_1.14.8_bin.tar.gz
# 镜像
tar zxvf k8s-Binary_deployment_1.14.8_images.tar.gz
# rpm 包
tar zxvf k8s-Binary_deployment_1.14.8_k8s-centos76-repo.tar.gz
````

- 在k8s集群环境变量文件修改配置IP，网段等：k8s_env

````
# 声明集群成员信息
declare -A MasterArray otherMaster NodeArray AllNode Other
MasterArray=(['k8s-m1']=192.168.154.131 ['k8s-m2']=192.168.154.132 ['k8s-m3']=192.168.154.133)
Master1=(['k8s-m1']=192.168.154.131)
otherMaster=(['k8s-m2']=192.168.154.132 ['k8s-m3']=192.168.154.133)
NodeArray=(['k8s-n1']=192.168.154.134 ['k8s-n2']=192.168.154.135)
# 下面复制上面的信息粘贴即可
AllNode=(['k8s-m1']=192.168.154.131 ['k8s-m2']=192.168.154.132 ['k8s-m3']=192.168.154.133 ['k8s-n1']=192.168.154.134 ['k8s-n2']=192.168.154.135)
Other=(['k8s-m2']=192.168.154.132 ['k8s-m3']=192.168.154.133 ['k8s-n1']=192.168.154.134 ['k8s-n2']=192.168.154.135)

# 高可用集群haproxy+keepalived虚拟IP
export VIP=192.168.154.130
#export INGRESS_VIP=192.168.154.129
[ "${#MasterArray[@]}" -eq 1 ] && export VIP=${MasterArray[@]} || export API_PORT=8443
export KUBE_APISERVER=https://${VIP}:${API_PORT:=6443}

# 节点密码
export HOST_PWD="root"

# 声明需要安装的的k8s版本
export KUBE_VERSION=v1.14.8

# k8s 模板目录
export TEMP_DIR=/etc/kubernetes/template/k8s-Binary_deployment_1.14.8

# k8s 项目目录
export PROJECT_DIR=/etc/kubernetes/k8s-Binary_deployment_1.14.8

# k8s 日志路径
export LOG_DIR=/var/log/kubernetes

# k8s 工作目录
export WORK_DIR=/var/lib/kubernetes

# 节点间互联网络接口名称
export IFACE="ens33"

# 服务网段，部署前路由不可达，部署后集群内路由可达
export SERVICE_CIDR="10.254.0.0/16"

# Pod 网段，建议 /16 段地址，部署前路由不可达，部署后集群内路由可达
export CLUSTER_CIDR="172.30.0.0/16"

# 服务端口范围 (NodePort Range)
export NODE_PORT_RANGE="1024-32700"

# kubernetes 服务 IP (一般是 SERVICE_CIDR 中第一个IP)
export CLUSTER_KUBERNETES_SVC_IP="10.254.0.1"

# 集群 DNS 服务 IP (从 SERVICE_CIDR 中预分配)
export CLUSTER_DNS_SVC_IP="10.254.0.2"

# 集群 DNS 域名（末尾不带点号）
export CLUSTER_DNS_DOMAIN="cluster.local"

# etcd
export ETCD_VERSION=v3.3.17
export ETCD_DATA_DIR=/var/lib/etcd/data
export ETCD_WAL_DIR=/var/lib/etcd/wal
export ETCD_SVC=$( xargs -n1<<<${MasterArray[@]} | sort | sed 's#^#https://#;s#$#:2379#;$s#\n##' | paste -d, -s - )
export ETCD_INITIAL_CLUSTER=$( for i in ${!MasterArray[@]};do echo $i=https://${MasterArray[$i]}:2380; done | sort | paste -d, -s - )

# docker registry
export DOCKER_REGISTRY_PORT=8888
export DOCKER_REGISTRY="registry.k8s.com:${DOCKER_REGISTRY_PORT}"

# yum repo
export YUM_REPO_PORT=88
export YUM_REPO="http://${Master1}:${YUM_REPO_PORT}"
````

- 加载集群变量

````
source /etc/kubernetes/template/k8s-Binary_deployment_1.14.8/k8s_env
````

- 配置本地repo

````
cd /etc/yum.repos.d/
mkdir bak
mv *repo bak
cp ${TEMP_DIR}/cfg/k8s.repo .
sed -i "s@##YUM_REPO##@file://${TEMP_DIR}/k8s-centos76-repo@g" k8s.repo
````
### 3.1 配置节点互信

````
yum install -y sshpass

#分发公钥
ssh-keygen -t rsa -P "" -f /root/.ssh/id_rsa
for NODE in ${!AllNode[@]};do
    echo "--- $NODE ${AllNode[$NODE]} ---" 
    sshpass -p ${HOST_PWD} ssh-copy-id -i /root/.ssh/id_rsa.pub -o StrictHostKeyChecking=no root@${AllNode[$NODE]}
    ssh root@${AllNode[$NODE]} "hostname"
done 
````

### 3.2 所有节点设置永久主机名

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} "hostnamectl set-hostname ${NODE}"
done
````

### 3.3 添加所有节点信息到hosts文件

````
echo "### k8s cluster ###" >> /etc/hosts
for NODE in ${!AllNode[@]};do echo ${AllNode[$NODE]} ${NODE} ; done | sort | paste -d -s - >> /etc/hosts
````

- 分发hosts文件

````
for NODE in "${!Other[@]}"; do
    echo "--- $NODE ${Other[$NODE]} ---"
    scp /etc/hosts ${Other[$NODE]}:/etc/hosts
done
````

### 3.4 关闭 firewalld 防火墙 以及 swap 分区

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} " systemctl disable --now firewalld NetworkManager "
    ssh ${AllNode[$NODE]} " sed -ri 's/SELINUX=enforcing/SELINUX=disabled/g' /etc/selinux/config "
    ssh ${AllNode[$NODE]} " sed -ri '/^[^#]*swap/s@^@#@' /etc/fstab "
done
````

### 3.5 部署集群内网yum仓库

- 安装 nginx

````
yum -y install nginx createrepo
````

- 修改配置文件

````
cd ${TEMP_DIR}/cfg
sed -i "s@##YUM_REPO_PORT##@${YUM_REPO_PORT}@g"  ${TEMP_DIR}/cfg/k8srepo.conf
sed -i "s@##TEMP_DIR##@${TEMP_DIR}@g"  ${TEMP_DIR}/cfg/k8srepo.conf
cp ${TEMP_DIR}/cfg/k8srepo.conf /etc/nginx/conf.d/
````

- 启动 nginx

````
nginx
````

- 分发 yum repo文件

-  生成repo索引

````
createrepo ${TEMP_DIR}/k8s-centos76-repo/
````

- 配置 yum repo

````
cd ${TEMP_DIR}/cfg
sed -i "s@##YUM_REPO##@${YUM_REPO}@g"  ${TEMP_DIR}/cfg/k8s.repo
````

- 分发 yum repo

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} "mkdir -p /etc/yum.repos.d/bak && mv /etc/yum.repos.d/*.repo /etc/yum.repos.d/bak/"
    scp ${TEMP_DIR}/cfg/k8s.repo ${AllNode[$NODE]}:/etc/yum.repos.d/
    ssh ${AllNode[$NODE]} "yum makecache"
done
````

- 所有节点安装命令

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} " yum -y install vim tree wget lrzsz net-tools expect unzip yum-utils device-mapper-persistent-data lvm2  conntrack ipvsadm ipset jq iptables curl sysstat libseccomp bash-completion socat ntp ntpdate  docker-distribution  docker-ce-18.09.9-3.el7 perl "
done
````

### 3.6 配置ipvs内核模块 

- 加载集群变量

````
source /etc/kubernetes/template/k8s-Binary_deployment_1.14.8/k8s_env
````

-  所有机器选择需要开机加载的内核模块,以下是 ipvs 模式需要加载的模块并设置开机自动加载 

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} " yum install ipvsadm ipset sysstat conntrack libseccomp -y " 
    scp ${TEMP_DIR}/cfg/ipvs.conf ${AllNode[$NODE]}:/etc/modules-load.d/ipvs.conf
    ssh ${AllNode[$NODE]} " systemctl enable --now systemd-modules-load.service "
    ssh ${AllNode[$NODE]} " systemctl status systemd-modules-load.service | grep active "
done

# 上面如果systemctl enable命令报错可以systemctl status -l systemd-modules-load.service看看哪个内核模块加载不了,在/etc/modules-load.d/ipvs.conf里注释掉它再enable试试
````

### 3.7 配置系统参数

-  所有机器需要设定/etc/sysctl.d/k8ssysctl.conf的系统参数。

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    scp ${TEMP_DIR}/cfg/k8ssysctl.conf ${AllNode[$NODE]}:/etc/sysctl.d/k8ssysctl.conf
    ssh ${AllNode[$NODE]} " sysctl --system "
done
````

### 3.8 安装docker-ce

-  检查系统内核和模块是否适合运行 docker (仅适用于 linux 系统) 

````
bash ${TEMP_DIR}/bin/check-config.sh
````

- 安装 docker-ce

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} " mkdir -p /etc/docker/  && yum -y install yum-utils device-mapper-persistent-data lvm2 docker-ce-18.09.9-3.el7 "
done
````

- 配置 daemon.json

````
sed -i "s@##DOCKER_REGISTRY##@${DOCKER_REGISTRY}@g"  ${TEMP_DIR}/cfg/daemon.json

````

-  设置docker开机启动,CentOS安装完成后docker需要手动设置docker命令补全 

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} " yum install -y bash-completion && cp /usr/share/bash-completion/completions/docker /etc/bash_completion.d/ "
    scp ${TEMP_DIR}/cfg/daemon.json ${AllNode[$NODE]}:/etc/docker/daemon.json
    ssh ${AllNode[$NODE]} " systemctl enable --now docker "
    ssh ${AllNode[$NODE]} " systemctl status docker | grep active "
done
````

### 3.9 部署集群内网docker镜像仓库

- 参考：docker 镜像搭建 文档

````
yum -y install docker-distribution
systemctl enable --now docker-distribution
systemctl status docker-distribution
````

- 配置TLS
  - 为了启用TLS协议传输，需要生成自签名证书。命令如下：

````
mkdir ${TEMP_DIR}/crts/ && cd ${TEMP_DIR}/crts
openssl req \
  -newkey rsa:2048 -nodes -keyout k8s.com.key \
  -x509 -days 3650 -out k8s.com.crt -subj \
  "/C=CN/ST=GD/L=SZ/O=Global Security/OU=IT Department/CN=*.k8s.com"
````

- 编辑镜像仓库服务配置文件/etc/docker-distribution/registry/config.yml。

````
cat > /etc/docker-distribution/registry/config.yml << EOF
version: 0.1
log:
  fields:
    service: registry
storage:
    cache:
        layerinfo: inmemory
    filesystem:
        rootdirectory: /var/lib/registry
http:
   addr: :${DOCKER_REGISTRY_PORT}
   tls:
       certificate: ${TEMP_DIR}/crts/k8s.com.crt
       key: ${TEMP_DIR}/crts/k8s.com.key
EOF
````

- 修改完毕后，刷新systemd配置。命令如下：

````
systemctl daemon-reload
````

- 重启Docker Distribution服务。命令如下：

````
systemctl restart docker-distribution
````

- 分发配置自签名证书

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    scp ${TEMP_DIR}/crts/k8s.com.crt ${AllNode[$NODE]}:/etc/pki/ca-trust/source/anchors/
    ssh ${AllNode[$NODE]} " update-ca-trust extract "
done
````

- 重启docker

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} " systemctl restart docker "
done
````

- 添加hosts解析

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} "echo "$(hostname -i) $(echo ${DOCKER_REGISTRY}| awk -F '[:]' '{print $1}')" >> /etc/hosts"
done
````

- 导入镜像

````
cd ${TEMP_DIR}/images/
for i in `ls`;do docker load -i $i ;done
````

- 打tag

````
docker images | awk '{print "docker tag "$1":"$2" ""'"${DOCKER_REGISTRY}"'""/"$1":"$2}' | xargs -i bash -c "{}"
docker images | awk '{print "docker push ""'"${DOCKER_REGISTRY}"'""/"$1":"$2}' | xargs -i bash -c "{}"
````

### 3.10 重启更新加载

````
# 重启其他所有节点
for NODE in "${!Other[@]}"; do
    echo "--- $NODE ${Other[$NODE]} ---"
    ssh ${Other[$NODE]} " reboot "
done
# 重启当前master节点
reboot
````


## 4，部署 ETCD

- 加载集群变量

````
source /etc/kubernetes/template/k8s-Binary_deployment_1.14.8/k8s_env
````

- 安装证书工具

````
cp ${TEMP_DIR}/bin/cfssl ${TEMP_DIR}/bin/cfssljson ${TEMP_DIR}/bin/cfssl-certinfo /usr/local/bin/
````

- 生成 CA 证书

````
cd ${TEMP_DIR}/pki/
cfssl gencert -initca ca-csr.json | cfssljson -bare ca -
````

### 4.1 生成 etcd 证书

- 创建 Etcd 服务器 CA 证书签名请求 etcd-csr.json

````
cd ${TEMP_DIR}/pki/
sed -i '/"hosts":/r '<(xargs -n1<<<${MasterArray[@]} | sort | sed 's#^\w.*\+#    "&",#')  etcd-csr.json
````

- 生成证书

````
cd ${TEMP_DIR}/pki/
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes etcd-csr.json | cfssljson -bare etcd
# ls *.pem
ca-key.pem  ca.pem  etcd-key.pem  etcd.pem
````

### 4.2 创建分发etcd 配置文件证书

````
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/systemd/etcd.service 
sed -i "s@##ETCD_DATA_DIR##@${ETCD_DATA_DIR}@g" ${TEMP_DIR}/cfg/etcd
sed -i "s@##ETCD_WAL_DIR##@${ETCD_WAL_DIR}@g" ${TEMP_DIR}/cfg/etcd
sed -i "s@##ETCD_INITIAL_CLUSTER##@${ETCD_INITIAL_CLUSTER}@g" ${TEMP_DIR}/cfg/etcd

for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} "mkdir -p ${PROJECT_DIR}/{pki,etcd} ${ETCD_DATA_DIR} ${ETCD_WAL_DIR}"
    scp ${TEMP_DIR}/bin/{etcd,etcdctl}  ${MasterArray[$NODE]}:/usr/local/bin/
    scp ${TEMP_DIR}/pki/*.pem ${MasterArray[$NODE]}:${PROJECT_DIR}/pki/
    scp ${TEMP_DIR}/systemd/etcd.service ${MasterArray[$NODE]}:/usr/lib/systemd/system/etcd.service
    scp ${TEMP_DIR}/cfg/etcd ${MasterArray[$NODE]}:${PROJECT_DIR}/etcd/etcd
    ssh ${MasterArray[$NODE]} "sed -i "s@##ETCD_NAME##@${NODE}@g"  ${PROJECT_DIR}/etcd/etcd"
    ssh ${MasterArray[$NODE]} "sed -i "s@##PUBLIC_IP##@${MasterArray[$NODE]}@g"  ${PROJECT_DIR}/etcd/etcd"
    ssh ${MasterArray[$NODE]} 'systemctl daemon-reload'
done
````

### 4.3 启动 etcd

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'systemctl enable --now etcd' &
done
wait
````

### 4.4 验证etcd
- 加载集群变量

````
source /etc/kubernetes/template/k8s-Binary_deployment_1.14.8/k8s_env
````


````
# 验证命令
etcdctl \
--ca-file=${PROJECT_DIR}/pki/ca.pem \
--cert-file=${PROJECT_DIR}/pki/etcd.pem \
--key-file=${PROJECT_DIR}/pki/etcd-key.pem \
--endpoints="${ETCD_SVC}" \
cluster-health

# 查看 etcd 主节点
ETCDCTL_API=3 \
    etcdctl   \
   --cert ${PROJECT_DIR}/pki/etcd.pem  \
   --key ${PROJECT_DIR}/pki/etcd-key.pem \
   --cacert ${PROJECT_DIR}/pki/ca.pem \
    --endpoints ${ETCD_SVC} endpoint status

# 查看 etcd key
ETCDCTL_API=3 \
    etcdctl   \
   --cert ${PROJECT_DIR}/pki/etcd.pem  \
   --key ${PROJECT_DIR}/pki/etcd-key.pem \
   --cacert ${PROJECT_DIR}/pki/ca.pem \
    --endpoints ${ETCD_SVC} get / --prefix --keys-only
````

## 5，部署 master 节点

### 5.1 Haproxy+keepalived配置k8s master高可用

- keepalived 提供 kube-apiserver 对外服务的 VIP；
- haproxy 监听 VIP，后端连接所有 kube-apiserver 实例，提供健康检查和负载均衡功能；
- 运行 keepalived 和 haproxy 的节点称为 LB 节点。由于 keepalived 是一主多备运行模式，故至少两个 LB 节点。
- 本文档复用 master 节点的三台机器，haproxy 监听的端口(8443) 需要与 kube-apiserver 的端口 6443 不同，避免冲突。
- keepalived 在运行过程中周期检查本机的 haproxy 进程状态，如果检测到 haproxy 进程异常，则触发重新选主的过程，VIP 将飘移到新选出来的主节点，从而实现 VIP 的高可用。
- 所有组件（如 kubeclt、apiserver、controller-manager、scheduler 等）都通过 VIP 和 haproxy 监听的 8443 端口访问 kube-apiserver 服务。

#### 5.1.1 配置 haproxy分发配置文件
- 注入master信息

````
sed -i '$r '<(paste <( seq -f'    server k8s-m%g' ${#MasterArray[@]} ) <( xargs -n1<<<${MasterArray[@]} | sort | sed 's#$#:6443 check inter 2000 fall 2 rise 2 weight 1#')) ${TEMP_DIR}/cfg/haproxy.cfg
````

- 分发配置文件

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} "yum install -y keepalived haproxy"
    scp ${TEMP_DIR}/cfg/haproxy.cfg ${MasterArray[$NODE]}:/etc/haproxy/haproxy.cfg
done
````

#### 5.1.2 配置 keepalived分发配置文件
- 修改配置文件

````
sed -i "s@##VIP##@${VIP}@g"  ${TEMP_DIR}/cfg/keepalived.conf 
sed -i "s@##eth0##@${IFACE}@g"  ${TEMP_DIR}/cfg/keepalived.conf
\cp ${TEMP_DIR}/cfg/keepalived.conf  /etc/keepalived/keepalived.conf
sed -i "s@##120##@120@g"  /etc/keepalived/keepalived.conf
````

- 分发配置文件

````
Num=120
for NODE in "${!otherMaster[@]}"; do
    echo "--- $NODE ${otherMaster[$NODE]} ---"
    scp ${TEMP_DIR}/cfg/keepalived.conf ${otherMaster[$NODE]}:/etc/keepalived/keepalived.conf  
    ssh ${otherMaster[$NODE]} "sed -i "s@MASTER@BACKUP@g" /etc/keepalived/keepalived.conf"
    for (( i=0; i<${#otherMaster[@]};i++));do
    ssh ${otherMaster[$NODE]} "sed -i "s@##120##@$(($Num-10))@g" /etc/keepalived/keepalived.conf"
    Num=$(($Num-10))
    done
done
````

#### 5.1.3 启动haproxy和keepalived服务

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'systemctl enable --now haproxy' &
    ssh ${MasterArray[$NODE]} 'systemctl enable --now keepalived' &
done
wait
````

#### 5.1.4 查看服务状态以及VIP情况

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'systemctl status haproxy|grep Active'
    ssh ${MasterArray[$NODE]} 'systemctl status keepalived|grep Active' 
    ssh ${MasterArray[$NODE]} "ip addr show | grep ${VIP}"
done
````



### 5.2 部署 kubectl 命令工具

- kubectl 是 kubernetes 集群的命令行管理工具，本文档介绍安装和配置它的步骤。
- kubectl 默认从 ~/.kube/config 文件读取 kube-apiserver 地址、证书、用户名等信息，如果没有配置，执行 kubectl 命令时可能会出错。

#### 5.2.1 分发 MASTER 命令文件

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    scp ${TEMP_DIR}/bin/kube{-apiserver,-scheduler,-controller-manager,ctl,adm}  ${MasterArray[$NODE]}:/usr/local/bin/
done
````

#### 5.2.2 创建请求证书

````
cd ${TEMP_DIR}/pki/
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes admin-csr.json | cfssljson -bare admin
````

- 分发证书

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    scp ${TEMP_DIR}/pki/admin*.pem  ${MasterArray[$NODE]}:${PROJECT_DIR}/pki/
done
````

#### 5.2.3 创建  ~/.kube/config 文件

````
cd ${TEMP_DIR}/cfg/
kubectl config set-cluster kubernetes \
  --certificate-authority=${PROJECT_DIR}/pki/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kubectl.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials admin \
  --client-certificate=${PROJECT_DIR}/pki/admin.pem \
  --client-key=${PROJECT_DIR}/pki/admin-key.pem \
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

- 分发 kubeconfig

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} " mkdir -p ~/.kube/ "
    scp ${TEMP_DIR}/cfg/kubectl.kubeconfig  ${MasterArray[$NODE]}:~/.kube/config
    ssh ${MasterArray[$NODE]} "kubectl completion bash > /etc/bash_completion.d/kubectl"
done
````



### 5.3 部署 apiserver 组件

#### 5.3.1 配置 apiserver 证书

- apiserver-csr.json

````
cd ${TEMP_DIR}/pki/
sed -i '/"hosts":/r '<(echo ${CLUSTER_KUBERNETES_SVC_IP} | sed 's#^\w.*\+#      "&",#') apiserver-csr.json
sed -i '/"hosts":/r '<(xargs -n1<<<${MasterArray[@]} | sort | sed 's#^\w.*\+#      "&",#') apiserver-csr.json
sed -i '/"hosts":/r '<(echo ${VIP}| sed 's#^\w.*\+#      "&",#') apiserver-csr.json
````

- 生成 apiserver 证书和私钥

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes apiserver-csr.json | cfssljson -bare apiserver
````

- 生成 front-proxy 证书和私钥

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes front-proxy-csr.json | cfssljson -bare front-proxy
````

#### 5.3.2 创建加密配置文件

````
cat > ${TEMP_DIR}/cfg/encryption-config.yaml <<EOF
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

#### 5.3.3 kube-apiserver 配置文件

````
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/cfg/kube-apiserver 
sed -i "s@##SERVICE_CIDR##@${SERVICE_CIDR}@g" ${TEMP_DIR}/cfg/kube-apiserver 
sed -i "s@##NODE_PORT_RANGE##@${NODE_PORT_RANGE}@g" ${TEMP_DIR}/cfg/kube-apiserver 
sed -i "s@##ETCD_SVC##@${ETCD_SVC}@g" ${TEMP_DIR}/cfg/kube-apiserver 
sed -i "s@##LOG_DIR##@${LOG_DIR}@g" ${TEMP_DIR}/cfg/kube-apiserver
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/systemd/kube-apiserver.service
````

#### 5.3.4 分发配置文件

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} "mkdir -p ${PROJECT_DIR}/server/ ${LOG_DIR}"
    scp ${TEMP_DIR}/pki/apiserver*.pem ${MasterArray[$NODE]}:${PROJECT_DIR}/pki/
    scp ${TEMP_DIR}/pki/front-proxy*.pem ${MasterArray[$NODE]}:${PROJECT_DIR}/pki/
    scp ${TEMP_DIR}/cfg/encryption-config.yaml   ${MasterArray[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/cfg/kube-apiserver   ${MasterArray[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/cfg/kubectl.kubeconfig   ${MasterArray[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/systemd/kube-apiserver.service ${MasterArray[$NODE]}:/usr/lib/systemd/system/kube-apiserver.service
    ssh ${MasterArray[$NODE]} "sed -i "s@##PUBLIC_IP##@${MasterArray[$NODE]}@g"  ${PROJECT_DIR}/server/kube-apiserver"
    ssh ${MasterArray[$NODE]} 'systemctl daemon-reload'
done
````

#### 5.3.5 启动 api-server

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'systemctl enable --now kube-apiserver' &
done
wait
````

### 5.3.6 检查kube-apiserve服务

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'netstat -ptln | grep kube-apiserve' 
done
````

- 集群状态

````
kubectl cluster-info
````

#### 5.3.7 授予kubernetes证书访问kubelet api权限

````
kubectl create clusterrolebinding kube-apiserver:kubelet-apis --clusterrole=system:kubelet-api-admin --user kubernetes
````

### 5.4 部署 controllers-manager 组件

- 该集群包含 3 个节点，启动后将通过竞争选举机制产生一个 leader 节点，其它节点为阻塞状态。当 leader 节点不可用后，剩余节点将再次进行选举产生新的 leader 节点，从而保证服务的可用性。

  为保证通信安全，本文档先生成 x509 证书和私钥，kube-controller-manager 在如下两种情况下使用该证书：

  - 与 kube-apiserver 的安全端口通信时;
  - 在安全端口(https，10252) 输出 prometheus 格式的 metrics；

#### 5.4.1 创建kube-controller-manager证书请求

````
cd ${TEMP_DIR}/pki/
sed -i '/"hosts":/r '<(xargs -n1<<<${MasterArray[@]} | sort | sed 's#^\w.*\+#      "&",#') kube-controller-manager-csr.json
````

- 生成证书和私钥

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-controller-manager-csr.json | cfssljson -bare kube-controller-manager
````

- 分发证书

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} "mkdir -p ${PROJECT_DIR}/server/ ${LOG_DIR}"
    scp ${TEMP_DIR}/pki/kube-controller-manager*.pem ${MasterArray[$NODE]}:${PROJECT_DIR}/pki/
done
````

#### 5.4.2 创建 kube-controller-manager.kubeconfig 文件

````
cd ${TEMP_DIR}/cfg/
kubectl config set-cluster kubernetes \
  --certificate-authority=${PROJECT_DIR}/pki/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-credentials system:kube-controller-manager \
  --client-certificate=${PROJECT_DIR}/pki/kube-controller-manager.pem \
  --client-key=${PROJECT_DIR}/pki/kube-controller-manager-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config set-context system:kube-controller-manager \
  --cluster=kubernetes \
  --user=system:kube-controller-manager \
  --kubeconfig=kube-controller-manager.kubeconfig

kubectl config use-context system:kube-controller-manager --kubeconfig=kube-controller-manager.kubeconfig
````

#### 5.4.3 controller-manager 配置文件

````
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/cfg/kube-controller-manager
sed -i "s@##SERVICE_CIDR##@${SERVICE_CIDR}@g" ${TEMP_DIR}/cfg/kube-controller-manager
sed -i "s@##LOG_DIR##@${LOG_DIR}@g" ${TEMP_DIR}/cfg/kube-controller-manager
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/systemd/kube-controller-manager.service
````

#### 5.4.4 分发配置文件

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} "mkdir -p ${PROJECT_DIR}/server/ ${LOG_DIR}"
    scp ${TEMP_DIR}/cfg/kube-controller-manager.kubeconfig   ${MasterArray[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/cfg/kube-controller-manager   ${MasterArray[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/systemd/kube-controller-manager.service ${MasterArray[$NODE]}:/usr/lib/systemd/system/kube-controller-manager.service
    ssh ${MasterArray[$NODE]} 'systemctl daemon-reload'
done
````

#### 5.4.5 启动kube-controller-manager服务

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'systemctl enable --now kube-controller-manager.service' &
done
wait
````

#### 5.4.6 检查kube-controller-manage服务

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'netstat -ptln | grep kube-controll' 
done
````

- #### 查看当前kube-controller-manager的leader

````
kubectl get endpoints kube-controller-manager --namespace=kube-system  -o yaml
````



###  5.5 部署kube-scheduler组件

- 该集群包含 3 个节点，启动后将通过竞争选举机制产生一个 leader 节点，其它节点为阻塞状态。当 leader 节点不可用后，剩余节点将再次进行选举产生新的 leader 节点，从而保证服务的可用性。
- 为保证通信安全，本文档先生成 x509 证书和私钥，kube-scheduler 在如下两种情况下使用该证书：
  - 与 kube-apiserver 的安全端口通信;
  - 在安全端口(https，10251) 输出 prometheus 格式的 metrics；

#### 5.5.1 创建kube-scheduler证书请求

````
cd ${TEMP_DIR}/pki/
sed -i '/"hosts":/r '<(xargs -n1<<<${MasterArray[@]} | sort | sed 's#^\w.*\+#      "&",#') kube-scheduler-csr.json
````

- 生成证书和私钥

````
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes  kube-scheduler-csr.json | cfssljson -bare  kube-scheduler
````

- 分发证书

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} "mkdir -p ${PROJECT_DIR}/server/ ${LOG_DIR}"
    scp ${TEMP_DIR}/pki/kube-scheduler*.pem ${MasterArray[$NODE]}:${PROJECT_DIR}/pki/
done
````

#### 5.5.2 创建 kube-scheduler.kubeconfig 文件

````
cd ${TEMP_DIR}/cfg/
kubectl config set-cluster kubernetes \
  --certificate-authority=${PROJECT_DIR}/pki/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-credentials system:kube-scheduler \
  --client-certificate=${PROJECT_DIR}/pki/kube-scheduler.pem \
  --client-key=${PROJECT_DIR}/pki/kube-scheduler-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config set-context system:kube-scheduler \
  --cluster=kubernetes \
  --user=system:kube-scheduler \
  --kubeconfig=kube-scheduler.kubeconfig

kubectl config use-context system:kube-scheduler --kubeconfig=kube-scheduler.kubeconfig
````

#### 5.5.3 kube-scheduler 配置文件

````
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/cfg/kube-scheduler
sed -i "s@##LOG_DIR##@${LOG_DIR}@g" ${TEMP_DIR}/cfg/kube-scheduler
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/systemd/kube-scheduler.service
````

#### 5.5.4 分发证书与配置文件

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} "mkdir -p ${PROJECT_DIR}/server/ ${LOG_DIR}"
    scp ${TEMP_DIR}/cfg/kube-scheduler   ${MasterArray[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/cfg/kube-scheduler.kubeconfig   ${MasterArray[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/systemd/kube-scheduler.service ${MasterArray[$NODE]}:/usr/lib/systemd/system/kube-scheduler.service
    ssh ${MasterArray[$NODE]} 'systemctl daemon-reload'
done
````

#### 5.5.5 启动kube-scheduler服务

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'systemctl enable --now kube-scheduler.service' &
done
wait
````

#### 5.5.6 检查kube-scheduler服务

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    ssh ${MasterArray[$NODE]} 'netstat -ptln | grep kube-schedule' 
done
````

- #### 查看当前kube-scheduler的leader

````
kubectl get endpoints kube-scheduler --namespace=kube-system  -o yaml
````

### 5.6 在所有master节点上验证功能是否正常

````
# kubectl get componentstatuses
NAME                 STATUS      MESSAGE                                                                                                                       
controller-manager   Healthy     ok
scheduler            Healthy     ok
etcd-2               Healthy     {"health":"true"}
etcd-0               Healthy     {"health":"true"}
etcd-1               Healthy     {"health":"true"}
````

## 6， 部署 kubernetes node节点

### 6.1  部署kubelet组件

- kublet 运行在每个 worker 节点上，接收 kube-apiserver 发送的请求，管理 Pod 容器，执行交互式命令，如 exec、run、logs 等。
- kublet 启动时自动向 kube-apiserver 注册节点信息，内置的 cadvisor 统计和监控节点的资源使用情况。
- 为确保安全，本文档只开启接收 https 请求的安全端口，对请求进行认证和授权，拒绝未授权的访问(如 apiserver、heapster)。

#### 6.1.1 分发 kubelet 命令文件

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    scp ${TEMP_DIR}/bin/kube{let,-proxy} ${AllNode[$NODE]}:/usr/local/bin/
    ssh ${AllNode[$NODE]} "yum install -y  wget conntrack ipvsadm ipset jq iptables curl sysstat libseccomp"
done
````

#### 6.1.2 创建kubelet bootstrap kubeconfig文件 （k8s-master1上执行）

````
#创建 token
cd ${TEMP_DIR}/cfg/
export BOOTSTRAP_TOKEN=$(kubeadm token create \
  --description kubelet-bootstrap-token \
  --groups system:bootstrappers:k8s-bootstrap \
  --kubeconfig ~/.kube/config)

# 设置集群参数
kubectl config set-cluster kubernetes \
  --certificate-authority=${PROJECT_DIR}/pki/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kubelet-bootstrap.kubeconfig

# 设置客户端认证参数
kubectl config set-credentials kubelet-bootstrap \
  --token=${BOOTSTRAP_TOKEN} \
  --kubeconfig=kubelet-bootstrap.kubeconfig

# 设置上下文参数
kubectl config set-context default \
  --cluster=kubernetes \
  --user=kubelet-bootstrap \
  --kubeconfig=kubelet-bootstrap.kubeconfig

# 设置默认上下文
kubectl config use-context default --kubeconfig=kubelet-bootstrap.kubeconfig
````

- 证书中写入 Token 而非证书，证书后续由 controller-manager 创建。

- 创建的 token 有效期为 1 天，超期后将不能再被使用，且会被 kube-controller-manager 的 tokencleaner 清理(如果启用该 controller 的话)；
- kube-apiserver 接收 kubelet 的 bootstrap token 后，将请求的 user 设置为 system:bootstrap:，group 设置为 system:bootstrappers；
- 查看 kubeadm 为各节点创建的 token ````  kubeadm token list --kubeconfig ~/.kube/config ````

#### 6.1.3 创建 kubelet 参数配置文件

````
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/cfg/kubelet-config.yaml
sed -i "s@##CLUSTER_DNS_DOMAIN##@${CLUSTER_DNS_DOMAIN}@g" ${TEMP_DIR}/cfg/kubelet-config.yaml
sed -i "s@##CLUSTER_DNS_SVC_IP##@${CLUSTER_DNS_SVC_IP}@g" ${TEMP_DIR}/cfg/kubelet-config.yaml
sed -i "s@##CLUSTER_CIDR##@${CLUSTER_CIDR}@g" ${TEMP_DIR}/cfg/kubelet-config.yaml
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/systemd/kubelet.service
sed -i "s@##WORK_DIR##@${WORK_DIR}@g" ${TEMP_DIR}/systemd/kubelet.service
sed -i "s@##DOCKER_REGISTRY##@${DOCKER_REGISTRY}@g" ${TEMP_DIR}/systemd/kubelet.service
````

#### 6.1.4 分发配置文件与kubelet-bootstrap.kubeconfig

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} "mkdir -p ${PROJECT_DIR}/{server,pki}/ ${WORK_DIR}/kubelet/logs "
    scp ${TEMP_DIR}/pki/ca.pem   ${AllNode[$NODE]}:${PROJECT_DIR}/pki/
    scp ${TEMP_DIR}/cfg/kubelet-bootstrap.kubeconfig   ${AllNode[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/cfg/kubelet-config.yaml   ${AllNode[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/systemd/kubelet.service ${AllNode[$NODE]}:/usr/lib/systemd/system/kubelet.service
    ssh ${AllNode[$NODE]} "sed -i "s@##PUBLIC_IP##@${AllNode[$NODE]}@g"  ${PROJECT_DIR}/server/kubelet-config.yaml"   
    ssh ${AllNode[$NODE]} "sed -i "s@##NODE_NAME##@${NODE}@g"  /usr/lib/systemd/system/kubelet.service"  
    ssh ${AllNode[$NODE]} 'systemctl daemon-reload'
done
````

#### 6.1.5 创建user和group的CSR权限，不创建kubelet会启动失败

````
kubectl create clusterrolebinding kubelet-bootstrap --clusterrole=system:node-bootstrapper --group=system:bootstrappers
````

#### 6.1.7  启动 kubelet 服务 

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} 'systemctl enable --now kubelet.service' &
done
wait
````

- 检查服务端口

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} 'systemctl status kubelet.service | grep active'
    ssh ${AllNode[$NODE]} 'netstat -lntup | grep  kubele'
done
````


- 10248: healthz http 服务；
- 10250: https 服务，访问该端口时需要认证和授权（即使访问 /healthz 也需要）；
- 未开启只读端口 10255；
- 从 K8S v1.10 开始，去除了 –cadvisor-port 参数（默认 4194 端口），不支持访问 cAdvisor UI & API
- kubelet 启动后使用 –bootstrap-kubeconfig 向 kube-apiserver 发送 CSR 请求，当这个CSR 被 approve 后，kube-controller-manager 为 kubelet 创建 TLS 客户端证书、私钥和 –kubeletconfig 文件。 注意：kube-controller-manager 需要配置 –cluster-signing-cert-file 和 –cluster-signing-key-file 参数，才会为 TLS Bootstrap 创建证书和私钥。
-  此时kubelet的进程存在，但是监听端口还未启动，需要进行下面步骤！

#### 6.1.8 自动approve CSR请求

- 创建三个ClusterRoleBinding，分别用于自动approve client、renew client、renew server证书

````
for NODE in "${!MasterArray[@]}"; do
    echo "--- $NODE ${MasterArray[$NODE]} ---"
    scp ${TEMP_DIR}/cfg/csr-crb.yaml   ${MasterArray[$NODE]}:${PROJECT_DIR}/server/
done
kubectl apply -f ${PROJECT_DIR}/server/csr-crb.yaml
````

- auto-approve-csrs-for-group 自动approve node的第一次CSR，注意第一次CSR时，请求的Group为system:bootstrappers
- node-client-cert-renewal 自动approve node后续过期的client证书，自动生成的证书Group为system:nodes
- node-server-cert-renewal 自动approve node后续过期的server证书，自动生成的证书Group

#### 6.1.9 **手动approve server cert csr**

- 基于安全考虑，CSR approving controllers不会自动approve kubelet server证书签名请求，需要手动approve

````
kubectl get csr | grep Pending | awk '{print $1}' | xargs kubectl certificate approve
````

#### 6.1.10 **bear token认证和授权**

- 创建一个ServiceAccount，将它和ClusterRole system:kubelet-api-admin绑定，从而具有调用kubelet API的权限

````
kubectl create sa kubelet-api-test
kubectl create clusterrolebinding kubelet-api-test --clusterrole=system:kubelet-api-admin --serviceaccount=default:kubelet-api-test
SECRET=$(kubectl get secrets | grep kubelet-api-test | awk '{print $1}')
TOKEN=$(kubectl describe secret ${SECRET} | grep -E '^token' | awk '{print $2}')
echo ${TOKEN}
````

#### 6.1.11 查看kubelet状态

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} 'netstat -ptln | grep kubelet' 
done

# 查看csr请求状态
kubectl get csr

# 查看节点信息
kubectl get node
````



### 6.2 部署 kube-proxy 组件

- kube-proxy运行在所有worker节点上，它监听apiserver中service和endpoint的变化情况，创建路由规则提供服务IP和负载均衡功能。这里使用ipvs模式的kube-proxy进行部署
- 在各个节点需要安装ipvsadm和ipset命令，加载ip_vs内核模块

#### 6.2.1 创建kube-proxy 证书

- 生成证书

````
cd ${TEMP_DIR}/pki/
cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=kubernetes kube-proxy-csr.json | cfssljson -bare kube-proxy
````

- 分发证书

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} "mkdir -p ${PROJECT_DIR}/{server,pki}/ ${LOG_DIR}"
    scp ${TEMP_DIR}/pki/kube-proxy*.pem ${AllNode[$NODE]}:${PROJECT_DIR}/pki/
done
````

#### 6.2.2 创建和分发kubeconfig文件

````
cd ${TEMP_DIR}/cfg/
kubectl config set-cluster kubernetes \
  --certificate-authority=${PROJECT_DIR}/pki/ca.pem \
  --embed-certs=true \
  --server=${KUBE_APISERVER} \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-credentials kube-proxy \
  --client-certificate=${PROJECT_DIR}/pki/kube-proxy.pem \
  --client-key=${PROJECT_DIR}/pki/kube-proxy-key.pem \
  --embed-certs=true \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config set-context default \
  --cluster=kubernetes \
  --user=kube-proxy \
  --kubeconfig=kube-proxy.kubeconfig

kubectl config use-context default --kubeconfig=kube-proxy.kubeconfig
````

- -embed-certs=true：将 ca.pem 和 admin.pem 证书内容嵌入到生成的 kubectl-proxy.kubeconfig 文件中(不加时，写入的是证书文件路径)

#### 6.2.3 创建 kube-proxy systemd unit 文件

- 从 v1.10 开始，kube-proxy 部分参数可以配置文件中配置。可以使用 --write-config-to 选项生成该配置文件，或者参考 kubeproxyconfig 的类型定义源文件 ：https://github.com/kubernetes/kubernetes/blob/master/pkg/proxy/apis/kubeproxyconfig/types.go

````
sed -i "s@##PROJECT_DIR##@${PROJECT_DIR}@g" ${TEMP_DIR}/systemd/kube-proxy.service
sed -i "s@##WORK_DIR##@${WORK_DIR}@g" ${TEMP_DIR}/systemd/kube-proxy.service
sed -i "s@##CLUSTER_CIDR##@${CLUSTER_CIDR}@g" ${TEMP_DIR}/systemd/kube-proxy.service
````

- bind-address: 监听地址；
- clientConnection.kubeconfig: 连接 apiserver 的 kubeconfig 文件；
- clusterCIDR: kube-proxy 根据 --cluster-cidr 判断集群内部和外部流量，指定 --cluster-cidr 或 --masquerade-all选项后 kube-proxy 才会对访问 Service IP 的请求做 SNAT；
- hostname-override: 参数值必须与 kubelet 的值一致，否则 kube-proxy 启动后会找不到该 Node，从而不会创建任何 ipvs 规则；
- proxy-mode: 使用 ipvs 模式；
- 修改改对应主机的信息。其中clusterc idr为docker0网络地址。

#### 6.2.4 分发配置文件

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} "mkdir -p ${PROJECT_DIR}/{server,pki}/ ${WORK_DIR}/kube-proxy/logs "
    scp ${TEMP_DIR}/cfg/kube-proxy.kubeconfig   ${AllNode[$NODE]}:${PROJECT_DIR}/server/
    scp ${TEMP_DIR}/systemd/kube-proxy.service ${AllNode[$NODE]}:/usr/lib/systemd/system/kube-proxy.service
    ssh ${AllNode[$NODE]} "sed -i "s@##PUBLIC_IP##@${AllNode[$NODE]}@g"  /usr/lib/systemd/system/kube-proxy.service"   
    ssh ${AllNode[$NODE]} "sed -i "s@##NODE_NAME##@${NODE}@g"  /usr/lib/systemd/system/kube-proxy.service"  
    ssh ${AllNode[$NODE]} 'systemctl daemon-reload'
done
````

#### 6.2.5 启动kube-proxy服务

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} 'systemctl enable --now kube-proxy.service' &
done
wait
````

#### 6.2.6 查看 kube-proxy 状态

````
for NODE in "${!AllNode[@]}"; do
    echo "--- $NODE ${AllNode[$NODE]} ---"
    ssh ${AllNode[$NODE]} 'netstat -ptln | grep kube-proxy' 
done
````



## 7,其他组件安装部署

### 7.1 calico安装

#### 7.1.1 配置文件

````
cp -a ${TEMP_DIR}/calico ${PROJECT_DIR}/
cd ${PROJECT_DIR}/calico/
````

#### 7.1.2 配置 calico 文件

- etcd 地址

````
sed -i "s#.*etcd_endpoints:.*#  etcd_endpoints: \"${ETCD_SVC}\"#g" calico.yaml
sed -i "s#__ETCD_ENDPOINTS__#${ETCD_SVC}#g" calico.yaml
````

- etcd 证书

````
ETCD_CERT=`cat ${PROJECT_DIR}/pki/etcd.pem | base64 | tr -d '\n'`
ETCD_KEY=`cat ${PROJECT_DIR}/pki/etcd-key.pem | base64 | tr -d '\n'`
ETCD_CA=`cat ${PROJECT_DIR}/pki/ca.pem | base64 | tr -d '\n'`

sed -i "s#.*etcd-cert:.*#  etcd-cert: ${ETCD_CERT}#g" calico.yaml
sed -i "s#.*etcd-key:.*#  etcd-key: ${ETCD_KEY}#g" calico.yaml
sed -i "s#.*etcd-ca:.*#  etcd-ca: ${ETCD_CA}#g" calico.yaml

sed -i 's#.*etcd_ca:.*#  etcd_ca: "/calico-secrets/etcd-ca"#g' calico.yaml
sed -i 's#.*etcd_cert:.*#  etcd_cert: "/calico-secrets/etcd-cert"#g' calico.yaml
sed -i 's#.*etcd_key:.*#  etcd_key: "/calico-secrets/etcd-key"#g' calico.yaml

sed -i "s#__ETCD_KEY_FILE__#${PROJECT_DIR}/pki/etcd-key.pem#g" calico.yaml
sed -i "s#__ETCD_CERT_FILE__#${PROJECT_DIR}/pki/etcd.pem#g" calico.yaml
sed -i "s#__ETCD_CA_CERT_FILE__#${PROJECT_DIR}/pki/ca.pem#g" calico.yaml
sed -i "s#__KUBECONFIG_FILEPATH__#/etc/cni/net.d/calico-kubeconfig#g" calico.yaml
````

- 配置calico bgp 并且修改ip cidr:

````
sed -i "/CLUSTER_TYPE/{n;s@##IFACE##@${IFACE}@g}" calico.yaml
sed -i '/CALICO_IPV4POOL_IPIP/{n;s/Always/off/g}' calico.yaml
sed -i "/CALICO_IPV4POOL_CIDR/{n;s@192.168.0.0/16@${CLUSTER_CIDR}@g}" calico.yaml
sed -i "s#image: calico#image: ${DOCKER_REGISTRY}/quay.io/calico#g" calico.yaml
````

- 配置 caicoctl

````
sed -i "s#image: quay.io#image: ${DOCKER_REGISTRY}/quay.io#g" calicoctl.yaml
````

#### 7.1.3 部署 calico

````
kubectl apply -f ${PROJECT_DIR}/calico
````



### 7.2，部署kubernetes DNS

#### 7.2.1 配置文件

````
cp -a ${TEMP_DIR}/coredns ${PROJECT_DIR}/
cd ${PROJECT_DIR}/coredns/
````

#### 7.2.2 修改配置文件

````
sed -i "s#kubernetes __PILLAR__DNS__DOMAIN__#kubernetes ${CLUSTER_DNS_DOMAIN}#g" coredns.yaml
sed -i "s#clusterIP: __PILLAR__DNS__SERVER__#clusterIP: ${CLUSTER_DNS_SVC_IP}#g" coredns.yaml
sed -i "s#image: k8s.gcr.io#image: ${DOCKER_REGISTRY}/coredns#g" coredns.yaml
````

#### 7.2.3 部署coreDNS

````
kubectl apply -f ${PROJECT_DIR}/coredns/
````

#### 7.2.4 验证 dns

````
cat > ${PROJECT_DIR}/buxybox.yaml <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: busybox
  namespace: default
spec:
  containers:
  - name: busybox
    image: ${DOCKER_REGISTRY}/busybox:1.28.3
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
  restartPolicy: Always
EOF
````

- 使用 nslookup 查看

````
# kubectl exec -ti busybox -- nslookup kubernetes
Server:    10.254.0.2
Address 1: 10.254.0.2 kube-dns.kube-system.svc.cluster.local

Name:      kubernetes
Address 1: 10.254.0.1 kubernetes.default.svc.cluster.local
````



### 7.3 部署 metrics

### 7.3.1 metrics 配置文件

- 使用官方配置文件

````
cp -a ${TEMP_DIR}/metrics-server ${PROJECT_DIR}/
cd ${PROJECT_DIR}/metrics-server
````

#### 7.3.2 更改配置文件

````
sed -i "s#image: k8s.gcr.io#image: ${DOCKER_REGISTRY}/registry.cn-hangzhou.aliyuncs.com/google_containers#g" metrics-server-deployment.yaml
````

#### 7.3.3 配置权限

````
kubectl create clusterrolebinding cluster-front-proxy --clusterrole=cluster-admin --user=system:front-proxy
````

#### 7.3.3 部署 metrics

````
kubectl apply -f ${PROJECT_DIR}/metrics-server
````

### 7.4 部署 dashboard

#### 7.4.1 配置文件

````
cp -a ${TEMP_DIR}/dashboard ${PROJECT_DIR}/
cd ${PROJECT_DIR}/dashboard
````

#### 7.4.2 创建dashboard证书

````
cd ${PROJECT_DIR}/pki/
#生成证书
dashboard_ip=$(echo "$VIP,${MasterArray[@]}" | tr " " ",")
openssl genrsa -out dashboard.key 2048 
openssl req -days 3650 -new -out dashboard.csr -key dashboard.key -subj "/CN=${dashboard_ip}"
openssl x509 -req -in dashboard.csr -signkey dashboard.key -out dashboard.crt 
#创建新的证书secret
kubectl create secret generic kubernetes-dashboard-certs --from-file="${PROJECT_DIR}/pki/dashboard.key,${PROJECT_DIR}/pki/dashboard.crt" -n kube-system
````

#### 7.4.3 修改配置文件

````
cd ${PROJECT_DIR}/dashboard
sed -i "s#image: k8s.gcr.io#image: ${DOCKER_REGISTRY}/registry.cn-hangzhou.aliyuncs.com/google_containers#g" kubernetes-dashboard.yaml
````

#### 7.4.4 部署 dashboard

````
kubectl apply -f ${PROJECT_DIR}/dashboard
````

#### 7.4.5 获取token

````
kubectl -n kube-system describe secret $(kubectl -n kube-system get secret | grep user-admin | awk '{print $1}')
````

### 7.5 部署 Nginx ingress

#### 7.5.1 配置文件

````
cp -a ${TEMP_DIR}/ingress-nginx ${PROJECT_DIR}/
cd ${PROJECT_DIR}/ingress-nginx
````

#### 7.5.2 修改配置文件

````
cd ${PROJECT_DIR}/ingress-nginx
sed -i "s#image: quay.io#image: ${DOCKER_REGISTRY}/quay.io#g"  mandatory.yaml
````

#### 7.5.3 部署 nginx-ingress

````
cd ${PROJECT_DIR}/ingress-nginx
kubectl create -f mandatory.yaml
````

