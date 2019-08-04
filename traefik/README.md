## 1，traefik 简介
- traefik：HTTP层路由，官网：http://traefik.cn/，文档：https://docs.traefik.io/user-guide/kubernetes/
	- 功能和nginx ingress类似。
	- 相对于nginx ingress，traefix能够实时跟Kubernetes API 交互，感知后端 Service、Pod 变化，自动更新配置并热重载。Traefik 更快速更方便，同时支持更多的特性，使反向代理、负载均衡更直接更高效。
	
## 2，下载traefik文件
````
git clone https://github.com/containous/traefik.git
````

- k8s traefik 文件

````
# ls traefik/examples/k8s/
cheese-default-ingress.yaml  cheese-deployments.yaml  cheese-ingress.yaml  cheese-services.yaml  cheeses-ingress.yaml  traefik-deployment.yaml  traefik-ds.yaml  traefik-rbac.yaml  ui.yaml
```

- 提取修改三个文件即可

````
traefik-ds.yaml  traefik-rbac.yaml  ui.yaml
````

- **注** ：可以参考本项目的yaml文件

## 3，创建证书
### 3.1 使用部署k8s集群的证书 ca.pem ca-key.pem
````
# ls /etc/kubernetes/server/ssl/
admin-key.pem       apiservier.pem  encryption-config.yaml  kube-controller-manager-key.pem         kubelet-client-current.pem  kube-proxy-key.pem      kube-scheduler.pem
admin.pem           ca-key.pem      front-proxy-key.pem     kube-controller-manager.pem             kubelet.crt                 kube-proxy.pem
apiservier-key.pem  ca.pem          front-proxy.pem         kubelet-client-2019-01-17-10-41-42.pem  kubelet.key                 kube-scheduler-key.pem
````

- 把证书写入到k8s的secret，如果不在当前路径，必须写绝对路径

````
kubectl create secret generic traefik-cert --from-file=ca-key.pem --from-file=ca.pem -n kube-system
````

- 配置 ConfigMap yaml 文件

````
# traefik-cm.yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: traefik-conf
  namespace: kube-system
data:
  traefik.toml: |+
    defaultEntryPoints = ["http", "https"]
    [entryPoints]
      [entryPoints.http]
      address = ":80"
      [entryPoints.https]
      address = ":443"
        [entryPoints.https.tls]
          [[entryPoints.https.tls.certificates]]
          CertFile = "/etc/kubernetes/server/ssl/ca.pem"
          KeyFile = "/etc/kubernetes/server/ssl/ca-key.pem"
````
 
### 3.2 使用openssl创建证书
````
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout tls.key -out tls.crt -subj "/CN=k8s-master-lb"
```

- 把证书写入到k8s的secret，如果不在当前路径，必须写绝对路径

````
kubectl -n kube-system create secret generic traefik-cert --from-file=tls.key --from-file=tls.crt
````

- 配置 ConfigMap yaml 文件

````
# traefik-cm.yaml
kind: ConfigMap
apiVersion: v1
metadata:
  name: traefik-conf
  namespace: kube-system
data:
  traefik.toml: |+
    defaultEntryPoints = ["http", "https"]
    [entryPoints]
      [entryPoints.http]
      address = ":80"
        # [entryPoints.http.redirect]
        # entryPoint = "https"
      [entryPoints.https]
      address = ":443"
        [entryPoints.https.tls]
          [[entryPoints.https.tls.certificates]]
          certFile = "/ssl/tls.crt"
          keyFile = "/ssl/tls.key"
````

## 4，创建 traefik
````
# ls
traefik-cm.yaml  traefik-ds.yaml  traefik-rbac.yaml  ui.yaml
````
````
kubectl apply -f .
````
### 4.1 查看集群状态
````
# kubectl get all -n kube-system | grep traefik

pod/traefik-ingress-controller-f7sxs           1/1     Running   0          30m
pod/traefik-ingress-controller-h56m9           1/1     Running   0          30m
pod/traefik-ingress-controller-rxtd8           1/1     Running   0          30m
pod/traefik-ingress-controller-sb6qp           1/1     Running   0          30m
pod/traefik-ingress-controller-vgf8z           1/1     Running   0          30m
pod/traefik-ingress-controller-wczg5           1/1     Running   0          30m
service/traefik-ingress-service   ClusterIP   10.254.212.72    <none>        80/TCP,8080/TCP   30m


service/traefik-web-ui            NodePort    10.254.62.243    <none>        8080:30011/TCP    79m
daemonset.apps/traefik-ingress-controller   6         6         6       6            6           <none>          30m

````


### 4.2 报错
- 查看集群 kube-proxy 使用的模式

````
# curl 127.0.0.1:10249/proxyMode
ipvs
````

- 如果该集群使用的是 ipvs ，按照默认配置文件启会报错，报错如下：

````
# kubectl logs -n kube-system pod/traefik-ingress-controller-h56m9
E0124 10:29:15.640039       1 reflector.go:205] github.com/containous/traefik/vendor/k8s.io/client-go/informers/factory.go:86: Failed to list *v1.Endpoints: Get https://10.254.0.1:443/api/v1/endpoints?limit=500&resourceVersion=0: dial tcp 10.254.0.1:443: i/o timeout
E0124 10:29:15.640981       1 reflector.go:205] github.com/containous/traefik/vendor/k8s.io/client-go/informers/factory.go:86: Failed to list *v1beta1.Ingress: Get https://10.254.0.1:443/apis/extensions/v1beta1/ingresses?limit=500&resourceVersion=0: dial tcp 10.254.0.1:443: i/o timeout
E0124 10:29:15.642025       1 reflector.go:205] github.com/containous/traefik/vendor/k8s.io/client-go/informers/factory.go:86: Failed to list *v1.Service: Get https://10.254.0.1:443/api/v1/services?limit=500&resourceVersion=0: dial tcp 10.254.0.1:443: i/o timeout
````


- 需修改配置文件 traefik-ds.yaml，注释 hostPort，添加 hostNetwork: true

````
# traefik-ds.yaml
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: traefik-ingress-controller
  namespace: kube-system
---
kind: DaemonSet
apiVersion: extensions/v1beta1
metadata:
  name: traefik-ingress-controller
  namespace: kube-system
  labels:
    k8s-app: traefik-ingress-lb
spec:
  template:
    metadata:
      labels:
        k8s-app: traefik-ingress-lb
        name: traefik-ingress-lb
    spec:
      serviceAccountName: traefik-ingress-controller
      terminationGracePeriodSeconds: 60
      volumes:
      - name: traefik-cert
        secret:
          secretName: traefik-cert
      - name: traefik-conf
        configMap:
          name: traefik-conf
      hostNetwork: true
      containers:
      - image: traefik:v1.7.7
        name: traefik-ingress-lb
        ports:
        - name: http
          containerPort: 80
#          hostPort: 80
        - name: https
          containerPort: 443
#          hostPort: 443
        - name: admin
          containerPort: 8080
#          hostPort: 8080
        volumeMounts:
        - mountPath: "/ssl"
          name: "traefik-cert"
        - mountPath: "/config"
          name: "traefik-conf"
        securityContext:
          capabilities:
            drop:
            - ALL
            add:
            - NET_BIND_SERVICE
        args:
        - --api
        - --kubernetes
        - --logLevel=INFO
        - --configfile=/config/traefix.toml
---
kind: Service
apiVersion: v1
metadata:
  name: traefik-ingress-service
  namespace: kube-system
spec:
  selector:
    k8s-app: traefik-ingress-lb
  ports:
    - protocol: TCP
      port: 80
      name: web
    - protocol: TCP
      port: 8080
      name: admin
````

## 5，打开Traefix的Web UI：http://k8s-master-lb:30011/

