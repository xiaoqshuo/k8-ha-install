````
    博客地址：https://www.cnblogs.com/xiaoqshuo/p/10320342.html
````
## 1，简介
- Kubernetes 暴露服务的有三种方式，分别为 LoadBlancer Service、NodePort Service、Ingress。
- Kubernetes中为了实现服务实例间的负载均衡和不同服务间的服务发现，创造了Serivce对象，同时又为从集群外部访问集群创建了Ingress对象。

### 1.1 NodePort 类型
- 如果设置 type 的值为 "NodePort"，Kubernetes master 将从给定的配置范围内（默认：30000-32767）分配端口，每个 Node 将从该端口（每个 Node 上的同一端口）代理到 Service。该端口将通过 Service 的 spec.ports[*].nodePort 字段被指定。
- 如果需要指定的端口号，可以配置 nodePort 的值，系统将分配这个端口，否则调用 API 将会失败（比如，需要关心端口冲突的可能性）。
- 这可以让开发人员自由地安装他们自己的负载均衡器，并配置 Kubernetes 不能完全支持的环境参数，或者直接暴露一个或多个 Node 的 IP 地址。
- 需要注意的是，Service 将能够通过 <NodeIP>:spec.ports[*].nodePort 和 spec.clusterIp:spec.ports[*].port 而对外可见。
- NodePort Service 是通过在节点上暴漏端口，然后通过将端口映射到具体某个服务上来实现服务暴漏，比较直观方便，但是对于集群来说，随着 Service 的不断增加，需要的端口越来越多，很容易出现端口冲突，而且不容易管理。当然对于小规模的集群服务，还是比较不错的。


### 1.2 LoadBalancer 类型
- LoadBlancer Service 是 Kubernetes 结合云平台的组件，如国外 GCE、AWS、国内阿里云等等，使用它向使用的底层云平台申请创建负载均衡器来实现，有局限性，对于使用云平台的集群比较方便。
- 使用支持外部负载均衡器的云提供商的服务，设置 type 的值为 "LoadBalancer"，将为 Service 提供负载均衡器。 负载均衡器是异步创建的，关于被提供的负载均衡器的信息将会通过 Service 的 status.loadBalancer 字段被发布出去。
- 来自外部负载均衡器的流量将直接打到 backend Pod 上，不过实际它们是如何工作的，这要依赖于云提供商。 在这些情况下，将根据用户设置的 loadBalancerIP 来创建负载均衡器。 某些云提供商允许设置 loadBalancerIP。如果没有设置 loadBalancerIP，将会给负载均衡器指派一个临时 IP。 如果设置了 loadBalancerIP，但云提供商并不支持这种特性，那么设置的 loadBalancerIP 值将会被忽略掉。

### 1.3 Ingress 解析
- ingress就是从kubernetes集群外访问集群的入口，将用户的URL请求转发到不同的service上。Ingress相当于nginx、apache等负载均衡方向代理服务器，其中还包括规则定义，即URL的路由信息，路由信息得的刷新由Ingress controller来提供。
- 通常情况下，service和pod的IP仅可在集群内部访问。集群外部的请求需要通过负载均衡转发到service在Node上暴露的NodePort上，然后再由kube-proxy将其转发给相关的Pod。
- Ingress可以给service提供集群外部访问的URL、负载均衡、SSL终止、HTTP路由等。为了配置这些Ingress规则，集群管理员需要部署一个Ingress controller，它监听Ingress和service的变化，并根据规则配置负载均衡并提供访问入口。
- Ingress Controller 实质上可以理解为是个监视器，Ingress Controller 通过不断地跟 kubernetes API 打交道，实时的感知后端 service、pod 等变化，比如新增和减少 pod，service 增加与减少等；当得到这些变化信息后，Ingress Controller 再结合下文的 Ingress 生成配置，然后更新反向代理负载均衡器，并刷新其配置，达到服务发现的作用。

### 1.3.1 Nginx Ingress 
- nginx-ingress 可以实现 7/4 层的代理功能（4 层代理基于 ConfigMap；7 层的Nginx反向代理）  ，主要负责向外暴露服务，同时提供负载均衡等附加功能
    - 反向代理负载均衡器，通常以Service的Port方式运行，接收并按照ingress定义的规则进行转发，通常为nginx，haproxy，traefik等
    - ingress是kubernetes的一个资源对象，用于编写定义规则，通过它定义某个域名的请求过来之后转发到集群中指定的 Service。它可以通过 Yaml 文件定义，可以给一个或多个 Service 定义一个或多个 Ingress 规则。
    - Ingress Controller 可以理解为控制器，它通过不断的跟 Kubernetes API 监听交互，实时获取后端 Service、Pod 等的变化，比如新增、删除等，然后结合 Ingress 定义的规则生成配置，然后动态更新上边的 Nginx 负载均衡器，并刷新使配置生效，来达到服务自动发现的作用。
- nginx-ingress 模块在运行时主要包括三个主体：NginxController、Store、SyncQueue。
    - Store 主要负责从 kubernetes APIServer 收集运行时信息，感知各类资源（如 ingress、service等）的变化，并及时将更新事件消息（event）写入一个环形管道。
    - SyncQueue 协程定期扫描 syncQueue 队列，发现有任务就执行更新操作，即借助 Store 完成最新运行数据的拉取，然后根据一定的规则产生新的 nginx 配置，（有些更新必须 reload，就本地写入新配置，执行 reload），然后执行动态更新操作，即构造 POST 数据，向本地 Nginx Lua 服务模块发送 post 请求，实现配置更新。
    - NginxController 作为中间的联系者，监听 updateChannel，一旦收到配置更新事件，就向同步队列 syncQueue 里写入一个更新请求。


## 2，部署 Nginx ingress
- 下载地址：https://github.com/kubernetes/ingress-nginx/archive/nginx-0.22.0.tar.gz

- ingress-nginx文件位于deploy目录下，各文件的作用：
    - configmap.yaml:提供configmap可以在线更行nginx的配置，修改L4负载均衡配置的configmap
    - namespace.yaml:创建一个独立的命名空间 ingress-nginx
    - rbac.yaml:创建对应的role rolebinding 用于rbac
    - with-rbac.yaml:有应用rbac的nginx-ingress-controller组件
    - mandatory.yaml:是其它组件yaml之和

### 2.1 修改 with-rbac.yaml 或者 mandatory.yaml
- kind: DaemonSet：官方原始文件使用的是deployment，replicate 为 1，这样将会在某一台节点上启动对应的nginx-ingress-controller pod。外部流量访问至该节点，由该节点负载分担至内部的service。测试环境考虑防止单点故障，改为DaemonSet然后删掉replicate ，配合亲和性部署在制定节点上启动nginx-ingress-controller pod，确保有多个节点启动nginx-ingress-controller pod，后续将这些节点加入到外部硬件负载均衡组实现高可用性。
- hostNetwork: true：添加该字段，暴露nginx-ingress-controller pod的服务端口（80）
- nodeSelector: 增加亲和性部署，有custom/ingress-controller-ready 标签的节点才会部署该DaemonSet

````
# with-rbac.yaml
apiVersion: apps/v1
# kind: Deployment
kind: DeamonSet
metadata:
  name: nginx-ingress-controller
  namespace: ingress-nginx
  labels:
    app.kubernetes.io/name: ingress-nginx
    app.kubernetes.io/part-of: ingress-nginx
spec:
#  replicas: 1
  selector:
    matchLabels:
      app.kubernetes.io/name: ingress-nginx
      app.kubernetes.io/part-of: ingress-nginx
  template:
    metadata:
      labels:
        app.kubernetes.io/name: ingress-nginx
        app.kubernetes.io/part-of: ingress-nginx
      annotations:
        prometheus.io/port: "10254"
        prometheus.io/scrape: "true"
    spec:
      serviceAccountName: nginx-ingress-serviceaccount
      hostNetwork: true
      containers:
        - name: nginx-ingress-controller
          image: quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.22.0
          args:
            - /nginx-ingress-controller
            - --configmap=$(POD_NAMESPACE)/nginx-configuration
            - --tcp-services-configmap=$(POD_NAMESPACE)/tcp-services
            - --udp-services-configmap=$(POD_NAMESPACE)/udp-services
            - --publish-service=$(POD_NAMESPACE)/ingress-nginx
            - --annotations-prefix=nginx.ingress.kubernetes.io
          securityContext:
            allowPrivilegeEscalation: true
            capabilities:
              drop:
                - ALL
              add:
                - NET_BIND_SERVICE
            # www-data -> 33
            runAsUser: 33
          env:
            - name: POD_NAME
              valueFrom:
                fieldRef:
                  fieldPath: metadata.name
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
          ports:
            - name: http
              containerPort: 80
            - name: https
              containerPort: 443
          livenessProbe:
            failureThreshold: 3
            httpGet:
              path: /healthz
              port: 10254
              scheme: HTTP
            initialDelaySeconds: 10
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
          readinessProbe:
            failureThreshold: 3
            httpGet:
              path: /healthz
              port: 10254
              scheme: HTTP
            periodSeconds: 10
            successThreshold: 1
            timeoutSeconds: 1
      nodeSelector:
        custom/ingress-controller-ready: "true"
---
````

### 2.3 为需要部署nginx-ingress-controller的节点设置lable
````
kubectl label nodes 192.168.2.101 custom/ingress-controller-ready=true
kubectl label nodes 192.168.2.102 custom/ingress-controller-ready=true
kubectl label nodes 192.168.2.103 custom/ingress-controller-ready=true
````

### 2.4 创建 nginx-ingress
````
kubectl create -f mandatory.yaml
````
- 或

````
kubectl create -f configmap.yaml
kubectl create -f namespace.yaml
kubectl create -f rbac.yaml
kubectl create -f with-rbac.yaml
````

## 3，测试ingress 
### 3.1 创建一个apache的Service

````
# cat > my-apache.yaml << EOF
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: my-apache
spec:
  replicas: 2
  template:
    metadata:
      labels:
        run: my-apache
    spec:
      containers:
      - name: my-apache
        image: httpd
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: my-apache
spec:
  metadata:
    labels:
      run: my-apache
spec:
  type: NodePort
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30002
  selector:
    run: my-apache
EOF
````

### 3.2 创建一个 nginx 的Service

````
# cat > my-nginx.yaml << EOF
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: my-nginx
spec:
  replicas: 2
  template:
    metadata:
      labels:
        run: my-nginx
    spec:
      containers:
      - name: my-nginx
        image: nginx
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: my-nginx
spec:
  template:
    matadata:
      lables:
        run: my-nginx
spec:
  type: NodePort
  ports:
  - port: 80
    targetPort: 80
    nodePort: 30001
  selector:
    run: my-nginx
EOF
````

### 3.3 配置ingress转发文件
- host: 对应的域名 
- path: url上下文 
- backend:后向转发 到对应的 serviceName: servicePort:

````
# cat > test-ingress.yaml << EOF
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: test-ingress
  namespace: default
spec:
  rules:
  - host: test.apache.ingress
    http:
      paths:
      - path: /
        backend:
          serviceName: my-apache
          servicePort: 80
  - host: test.nginx.ingress
    http:
      paths:
      - path: /
        backend:
          serviceName: my-nginx
          servicePort: 80
EOF
````
    
### 3.4 查看状态
````
# kubectl get ingress
NAME           HOSTS                                    ADDRESS   PORTS   AGE
test-ingress   test.apache.ingress,test.nginx.ingress             80      23s
````

````
# kubectl get deploy,pod,svc
NAME                              DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE
deployment.extensions/my-apache   2         2         2            1           12s
deployment.extensions/my-nginx    2         2         2            2           12s

NAME                             READY   STATUS              RESTARTS   AGE
pod/my-apache-57874fd49c-dc4vx   1/1     Running             0          12s
pod/my-apache-57874fd49c-lfhld   0/1     ContainerCreating   0          12s
pod/my-nginx-756f645cd7-fvq9d    1/1     Running             0          11s
pod/my-nginx-756f645cd7-ngj99    1/1     Running             0          12s

NAME                               TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)        AGE
service/kubernetes                 ClusterIP   10.254.0.1       <none>        443/TCP        10d
service/my-apache                  NodePort    10.254.95.131    <none>        80:30002/TCP   12s
service/my-nginx                   NodePort    10.254.92.19     <none>        80:30001/TCP   11s
````

### 3.5 解析域名到ipvs虚拟VIP，访问测试
#### 3.5.1 通过-H 指定模拟的域名
- test.apache.ingress

````
# curl -v http://192.168.2.100 -H 'host: test.apache.ingress'
* About to connect() to 192.168.2.100 port 80 (#0)
*   Trying 192.168.2.100...
* Connected to 192.168.2.100 (192.168.2.100) port 80 (#0)
> GET / HTTP/1.1
> User-Agent: curl/7.29.0
> Accept: */*
> host: test.apache.ingress
>
< HTTP/1.1 200 OK
< Server: nginx/1.15.8
< Date: Fri, 25 Jan 2019 08:24:37 GMT
< Content-Type: text/html
< Content-Length: 45
< Connection: keep-alive
< Last-Modified: Mon, 11 Jun 2007 18:53:14 GMT
< ETag: "2d-432a5e4a73a80"
< Accept-Ranges: bytes
<
<html><body><h1>It works!</h1></body></html>
* Connection #0 to host 192.168.2.100 left intact
````

- test.nginx.ingress

````
# curl -v http://192.168.2.100 -H 'host: test.nginx.ingress'
* About to connect() to 192.168.2.100 port 80 (#0)
*   Trying 192.168.2.100...
* Connected to 192.168.2.100 (192.168.2.100) port 80 (#0)
> GET / HTTP/1.1
> User-Agent: curl/7.29.0
> Accept: */*
> host: test.nginx.ingress
>
< HTTP/1.1 200 OK
< Server: nginx/1.15.8
< Date: Fri, 25 Jan 2019 08:24:53 GMT
< Content-Type: text/html
< Content-Length: 612
< Connection: keep-alive
< Vary: Accept-Encoding
< Last-Modified: Tue, 25 Dec 2018 09:56:47 GMT
< ETag: "5c21fedf-264"
< Accept-Ranges: bytes
<
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
    body {
        width: 35em;
        margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif;
    }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and
working. Further configuration is required.</p>

<p>For online documentation and support please refer to
<a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at
<a href="http://nginx.com/">nginx.com</a>.</p>

<p><em>Thank you for using nginx.</em></p>
</body>
</html>
* Connection #0 to host 192.168.2.100 left intact
````

#### 3.5.2 浏览器访问
- http://test.apache.ingress/

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190125162827274-551666581.png)

- http://k8s-master-lb:30002/

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190125162817113-1046298768.png)

- http://test.nginx.ingress/

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190125162857447-139645825.png)

- http://k8s-master-lb:30001/

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190125162918742-959649420.png)

## 4，部署monitoring
### 4.1 配置 ingress 

````
# cat > monitoring/prometheus-grafana-ingress.yaml << EOF
apiVersion: extensions/v1beta1
kind: Ingress
metadata:
  name: prometheus-grafana-ingress
  namespace: ingress-nginx
spec:
  rules:
  - host: grafana.k8s.ing
    http:
      paths:
      - path: /
        backend:
          serviceName: grafana
          servicePort: 3000
  - host: prometheus.k8s.ing
    http:
      paths:
      - path: /
        backend:
          serviceName: prometheus-server
          servicePort: 9090
EOF
````

### 4.2 在ingress-nginx官网deploy/monitoring目录下载相关yaml文件

````
# ls monitoring/
configuration.yaml  grafana.yaml  prometheus-grafana-ingress.yaml  prometheus.yaml
````

### 4.3 部署服务

````
# kubectl apply -f monitoring/
````

### 4.4 查看状态

````
# kubectl get pod,svc,ingress -n ingress-nginx
NAME                                    READY   STATUS    RESTARTS   AGE
pod/grafana-5ccff7668d-7lk6q            1/1     Running   0          2d14h
pod/prometheus-server-7f87788f6-7zcfx   1/1     Running   0          2d14h

NAME                                       TYPE        CLUSTER-IP       EXTERNAL-IP   PORT(S)          AGE
service/glusterfs-dynamic-pvc-grafana      ClusterIP   10.254.146.102   <none>        1/TCP            2d14h
service/glusterfs-dynamic-pvc-prometheus   ClusterIP   10.254.160.58    <none>        1/TCP            2d14h
service/grafana                            NodePort    10.254.244.77    <none>        3000:30303/TCP   2d14h
service/prometheus-server                  NodePort    10.254.168.143   <none>        9090:32090/TCP   2d14h

NAME                                            HOSTS                                ADDRESS   PORTS   AGE
ingress.extensions/prometheus-grafana-ingress   grafana.k8s.ing,prometheus.k8s.ing             80      2d14h
````

### 4.5 配置grafana
- 解析打开页面：http://grafana.k8s.ing

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190128093110674-1841402693.png)

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190128093207645-427896327.png)

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190128093318611-1566198628.png)

- 导入 json 文件
- 在ingress-nginx官网deploy/grafana/dashboards目录下载相关nginx.json文件

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190128093356631-695724552.png)

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190128093423617-1660855050.png)

![](https://img2018.cnblogs.com/blog/1306461/201901/1306461-20190128093548620-2103278897.png)


- 参考：
    - https://blog.csdn.net/shida_csdn/article/details/84032019
    - http://blog.51cto.com/devingeng/2149377
    - https://www.jianshu.com/p/ed97007604d7
