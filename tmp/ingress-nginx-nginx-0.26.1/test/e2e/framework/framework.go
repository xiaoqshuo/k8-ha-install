/*
Copyright 2017 Jetstack Ltd.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package framework

import (
	"fmt"
	"strings"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	apiextcs "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"

	"github.com/pkg/errors"
	"k8s.io/klog"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// RequestScheme define a scheme used in a test request.
type RequestScheme string

// These are valid test request schemes.
const (
	HTTP  RequestScheme = "http"
	HTTPS RequestScheme = "https"
)

var (
	// KubectlPath defines the full path of the kubectl binary
	KubectlPath = "/usr/local/bin/kubectl"
)

// Framework supports common operations used by e2e tests; it will keep a client & a namespace for you.
type Framework struct {
	BaseName string

	// A Kubernetes and Service Catalog client
	KubeClientSet          kubernetes.Interface
	KubeConfig             *restclient.Config
	APIExtensionsClientSet apiextcs.Interface

	// To make sure that this framework cleans up after itself, no matter what,
	// we install a Cleanup action before each test and clear it after. If we
	// should abort, the AfterSuite hook should run all Cleanup actions.
	cleanupHandle CleanupActionHandle

	Namespace string
}

// NewDefaultFramework makes a new framework and sets up a BeforeEach/AfterEach for
// you (you can write additional before/after each functions).
func NewDefaultFramework(baseName string) *Framework {
	f := &Framework{
		BaseName: baseName,
	}

	BeforeEach(f.BeforeEach)
	AfterEach(f.AfterEach)

	return f
}

// BeforeEach gets a client and makes a namespace.
func (f *Framework) BeforeEach() {
	f.cleanupHandle = AddCleanupAction(f.AfterEach)

	By("Creating a kubernetes client")
	kubeConfig, err := restclient.InClusterConfig()
	if err != nil {
		panic(err.Error())
	}

	Expect(err).NotTo(HaveOccurred())

	f.KubeConfig = kubeConfig
	f.KubeClientSet, err = kubernetes.NewForConfig(kubeConfig)
	Expect(err).NotTo(HaveOccurred())

	By("Building a namespace api object")
	ingressNamespace, err := CreateKubeNamespace(f.BaseName, f.KubeClientSet)
	Expect(err).NotTo(HaveOccurred())

	f.Namespace = ingressNamespace

	By("Starting new ingress controller")
	err = f.NewIngressController(f.Namespace, f.BaseName)
	Expect(err).NotTo(HaveOccurred())

	err = WaitForPodsReady(f.KubeClientSet, DefaultTimeout, 1, f.Namespace, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/name=ingress-nginx",
	})
	Expect(err).NotTo(HaveOccurred())
}

// AfterEach deletes the namespace, after reading its events.
func (f *Framework) AfterEach() {
	RemoveCleanupAction(f.cleanupHandle)

	By("Waiting for test namespace to no longer exist")
	err := DeleteKubeNamespace(f.KubeClientSet, f.Namespace)
	Expect(err).NotTo(HaveOccurred())

	if CurrentGinkgoTestDescription().Failed {
		log, err := f.NginxLogs()
		Expect(err).ToNot(HaveOccurred())
		By("Dumping NGINX logs after a failure running a test")
		Logf("%v", log)

		pod, err := getIngressNGINXPod(f.Namespace, f.KubeClientSet)
		if err != nil {
			return
		}

		cmd := fmt.Sprintf("cat /etc/nginx/nginx.conf")
		o, err := f.ExecCommand(pod, cmd)
		if err != nil {
			return
		}

		By("Dumping NGINX configuration after a failure running a test")
		Logf("%v", o)
	}
}

// IngressNginxDescribe wrapper function for ginkgo describe. Adds namespacing.
func IngressNginxDescribe(text string, body func()) bool {
	return Describe("[ingress-nginx] "+text, body)
}

// MemoryLeakIt is wrapper function for ginkgo It.  Adds "[MemoryLeak]" tag and makes static analysis easier.
func MemoryLeakIt(text string, body interface{}, timeout ...float64) bool {
	return It(text+" [MemoryLeak]", body, timeout...)
}

// GetNginxIP returns the number of TCP port where NGINX is running
func (f *Framework) GetNginxIP() string {
	s, err := f.KubeClientSet.
		CoreV1().
		Services(f.Namespace).
		Get("ingress-nginx", metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "unexpected error obtaining NGINX IP address")
	return s.Spec.ClusterIP
}

// GetNginxPodIP returns the IP addres/es of the running pods
func (f *Framework) GetNginxPodIP() []string {
	e, err := f.KubeClientSet.
		CoreV1().
		Endpoints(f.Namespace).
		Get("ingress-nginx", metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "unexpected error obtaining NGINX IP address")
	eips := make([]string, 0)
	for _, s := range e.Subsets {
		for _, a := range s.Addresses {
			eips = append(eips, a.IP)
		}
	}

	return eips
}

// GetURL returns the URL should be used to make a request to NGINX
func (f *Framework) GetURL(scheme RequestScheme) string {
	ip := f.GetNginxIP()
	return fmt.Sprintf("%v://%v", scheme, ip)
}

// WaitForNginxServer waits until the nginx configuration contains a particular server section
func (f *Framework) WaitForNginxServer(name string, matcher func(cfg string) bool) {
	err := wait.Poll(Poll, DefaultTimeout, f.matchNginxConditions(name, matcher))
	Expect(err).NotTo(HaveOccurred(), "unexpected error waiting for nginx server condition/s")
	time.Sleep(5 * time.Second)
}

// WaitForNginxConfiguration waits until the nginx configuration contains a particular configuration
func (f *Framework) WaitForNginxConfiguration(matcher func(cfg string) bool) {
	err := wait.Poll(Poll, DefaultTimeout, f.matchNginxConditions("", matcher))
	Expect(err).NotTo(HaveOccurred(), "unexpected error waiting for nginx server condition/s")
	time.Sleep(5 * time.Second)
}

func nginxLogs(client kubernetes.Interface, namespace string) (string, error) {
	pod, err := getIngressNGINXPod(namespace, client)
	if err != nil {
		return "", err
	}

	if isRunning, err := podRunningReady(pod); err == nil && isRunning {
		return Logs(pod)
	}

	return "", fmt.Errorf("no nginx ingress controller pod is running (logs)")
}

// NginxLogs returns the logs of the nginx ingress controller pod running
func (f *Framework) NginxLogs() (string, error) {
	return nginxLogs(f.KubeClientSet, f.Namespace)
}

func (f *Framework) matchNginxConditions(name string, matcher func(cfg string) bool) wait.ConditionFunc {
	return func() (bool, error) {
		pod, err := getIngressNGINXPod(f.Namespace, f.KubeClientSet)
		if err != nil {
			return false, nil
		}

		var cmd string
		if name == "" {
			cmd = fmt.Sprintf("cat /etc/nginx/nginx.conf")
		} else {
			cmd = fmt.Sprintf("cat /etc/nginx/nginx.conf | awk '/## start server %v/,/## end server %v/'", name, name)
		}

		o, err := f.ExecCommand(pod, cmd)
		if err != nil {
			return false, nil
		}

		var match bool
		errs := InterceptGomegaFailures(func() {
			if klog.V(10) && len(o) > 0 {
				klog.Infof("nginx.conf:\n%v", o)
			}

			// passes the nginx config to the passed function
			if matcher(strings.Join(strings.Fields(o), " ")) {
				match = true
			}
		})

		if match {
			return true, nil
		}

		if len(errs) > 0 {
			klog.V(2).Infof("Errors waiting for conditions: %v", errs)
		}

		return false, nil
	}
}

func (f *Framework) getNginxConfigMap() (*v1.ConfigMap, error) {
	return f.getConfigMap("nginx-configuration")
}

func (f *Framework) getConfigMap(name string) (*v1.ConfigMap, error) {
	if f.KubeClientSet == nil {
		return nil, fmt.Errorf("KubeClientSet not initialized")
	}

	config, err := f.KubeClientSet.
		CoreV1().
		ConfigMaps(f.Namespace).
		Get(name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	return config, err
}

// GetNginxConfigMapData gets ingress-nginx's nginx-configuration map's data
func (f *Framework) GetNginxConfigMapData() (map[string]string, error) {
	config, err := f.getNginxConfigMap()
	if err != nil {
		return nil, err
	}
	if config.Data == nil {
		config.Data = map[string]string{}
	}

	return config.Data, err
}

// SetNginxConfigMapData sets ingress-nginx's nginx-configuration configMap data
func (f *Framework) SetNginxConfigMapData(cmData map[string]string) {
	f.SetConfigMapData("nginx-configuration", cmData)
}

func (f *Framework) SetConfigMapData(name string, cmData map[string]string) {
	config, err := f.getConfigMap(name)
	Expect(err).NotTo(HaveOccurred())
	Expect(config).NotTo(BeNil(), "expected a configmap but none returned")

	config.Data = cmData

	_, err = f.KubeClientSet.
		CoreV1().
		ConfigMaps(f.Namespace).
		Update(config)
	Expect(err).NotTo(HaveOccurred())

	time.Sleep(5 * time.Second)
}

func (f *Framework) CreateConfigMap(name string, data map[string]string) {
	_, err := f.KubeClientSet.CoreV1().ConfigMaps(f.Namespace).Create(&v1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: f.Namespace,
		},
		Data: data,
	})
	Expect(err).NotTo(HaveOccurred(), "failed to create configMap")
}

// UpdateNginxConfigMapData updates single field in ingress-nginx's nginx-configuration map data
func (f *Framework) UpdateNginxConfigMapData(key string, value string) {
	config, err := f.GetNginxConfigMapData()
	Expect(err).NotTo(HaveOccurred(), "unexpected error reading configmap")

	config[key] = value

	f.SetNginxConfigMapData(config)
}

// DeleteNGINXPod deletes the currently running pod. It waits for the replacement pod to be up.
// Grace period to wait for pod shutdown is in seconds.
func (f *Framework) DeleteNGINXPod(grace int64) {
	ns := f.Namespace
	pod, err := getIngressNGINXPod(ns, f.KubeClientSet)
	Expect(err).NotTo(HaveOccurred(), "expected ingress nginx pod to be running")

	err = f.KubeClientSet.CoreV1().Pods(ns).Delete(pod.GetName(), metav1.NewDeleteOptions(grace))
	Expect(err).NotTo(HaveOccurred(), "unexpected error deleting ingress nginx pod")

	err = wait.Poll(Poll, DefaultTimeout, func() (bool, error) {
		pod, err := getIngressNGINXPod(ns, f.KubeClientSet)
		if err != nil || pod == nil {
			return false, nil
		}
		return pod.GetName() != "", nil
	})
	Expect(err).NotTo(HaveOccurred(), "unexpected error while waiting for ingress nginx pod to come up again")
}

// UpdateDeployment runs the given updateFunc on the deployment and waits for it to be updated
func UpdateDeployment(kubeClientSet kubernetes.Interface, namespace string, name string, replicas int, updateFunc func(d *appsv1.Deployment) error) error {
	deployment, err := kubeClientSet.AppsV1().Deployments(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if updateFunc != nil {
		if err := updateFunc(deployment); err != nil {
			return err
		}
	}

	if *deployment.Spec.Replicas != int32(replicas) {
		klog.Infof("updating replica count from %v to %v...", *deployment.Spec.Replicas, replicas)
		deployment, err := kubeClientSet.AppsV1().Deployments(namespace).Get(name, metav1.GetOptions{})
		if err != nil {
			return err
		}

		deployment.Spec.Replicas = NewInt32(int32(replicas))
		_, err = kubeClientSet.AppsV1().Deployments(namespace).Update(deployment)
		if err != nil {
			return errors.Wrapf(err, "scaling the number of replicas to %v", replicas)
		}
	}

	err = WaitForPodsReady(kubeClientSet, DefaultTimeout, replicas, namespace, metav1.ListOptions{
		LabelSelector: fields.SelectorFromSet(fields.Set(deployment.Spec.Template.ObjectMeta.Labels)).String(),
	})
	if err != nil {
		return errors.Wrapf(err, "waiting for nginx-ingress-controller replica count to be %v", replicas)
	}

	return nil
}

// UpdateIngress runs the given updateFunc on the ingress
func UpdateIngress(kubeClientSet kubernetes.Interface, namespace string, name string, updateFunc func(d *extensions.Ingress) error) error {
	ingress, err := kubeClientSet.ExtensionsV1beta1().Ingresses(namespace).Get(name, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if err := updateFunc(ingress); err != nil {
		return err
	}

	_, err = kubeClientSet.ExtensionsV1beta1().Ingresses(namespace).Update(ingress)
	return err
}

// NewSingleIngressWithTLS creates a simple ingress rule with TLS spec included
func NewSingleIngressWithTLS(name, path, host string, tlsHosts []string, ns, service string, port int, annotations *map[string]string) *extensions.Ingress {
	return newSingleIngressWithRules(name, path, host, ns, service, port, annotations, tlsHosts)
}

// NewSingleIngress creates a simple ingress rule
func NewSingleIngress(name, path, host, ns, service string, port int, annotations *map[string]string) *extensions.Ingress {
	return newSingleIngressWithRules(name, path, host, ns, service, port, annotations, nil)
}

// NewSingleIngressWithMultiplePaths creates a simple ingress rule with multiple paths
func NewSingleIngressWithMultiplePaths(name string, paths []string, host, ns, service string, port int, annotations *map[string]string) *extensions.Ingress {
	spec := extensions.IngressSpec{
		Rules: []extensions.IngressRule{
			{
				Host: host,
				IngressRuleValue: extensions.IngressRuleValue{
					HTTP: &extensions.HTTPIngressRuleValue{},
				},
			},
		},
	}

	for _, path := range paths {
		spec.Rules[0].IngressRuleValue.HTTP.Paths = append(spec.Rules[0].IngressRuleValue.HTTP.Paths, extensions.HTTPIngressPath{
			Path: path,
			Backend: extensions.IngressBackend{
				ServiceName: service,
				ServicePort: intstr.FromInt(port),
			},
		})
	}

	return newSingleIngress(name, ns, annotations, spec)
}

func newSingleIngressWithRules(name, path, host, ns, service string, port int, annotations *map[string]string, tlsHosts []string) *extensions.Ingress {

	spec := extensions.IngressSpec{
		Rules: []extensions.IngressRule{
			{
				Host: host,
				IngressRuleValue: extensions.IngressRuleValue{
					HTTP: &extensions.HTTPIngressRuleValue{
						Paths: []extensions.HTTPIngressPath{
							{
								Path: path,
								Backend: extensions.IngressBackend{
									ServiceName: service,
									ServicePort: intstr.FromInt(port),
								},
							},
						},
					},
				},
			},
		},
	}

	if len(tlsHosts) > 0 {
		spec.TLS = []extensions.IngressTLS{
			{
				Hosts:      tlsHosts,
				SecretName: host,
			},
		}
	}

	return newSingleIngress(name, ns, annotations, spec)
}

// NewSingleIngressWithBackendAndRules creates an ingress with both a default backend and a rule
func NewSingleIngressWithBackendAndRules(name, path, host, ns, defaultService string, defaultPort int, service string, port int, annotations *map[string]string) *extensions.Ingress {
	spec := extensions.IngressSpec{
		Backend: &extensions.IngressBackend{
			ServiceName: defaultService,
			ServicePort: intstr.FromInt(defaultPort),
		},
		Rules: []extensions.IngressRule{
			{
				Host: host,
				IngressRuleValue: extensions.IngressRuleValue{
					HTTP: &extensions.HTTPIngressRuleValue{
						Paths: []extensions.HTTPIngressPath{
							{
								Path: path,
								Backend: extensions.IngressBackend{
									ServiceName: service,
									ServicePort: intstr.FromInt(port),
								},
							},
						},
					},
				},
			},
		},
	}

	return newSingleIngress(name, ns, annotations, spec)
}

// NewSingleCatchAllIngress creates a simple ingress with a catch-all backend
func NewSingleCatchAllIngress(name, ns, service string, port int, annotations *map[string]string) *extensions.Ingress {
	spec := extensions.IngressSpec{
		Backend: &extensions.IngressBackend{
			ServiceName: service,
			ServicePort: intstr.FromInt(port),
		},
	}
	return newSingleIngress(name, ns, annotations, spec)
}

func newSingleIngress(name, ns string, annotations *map[string]string, spec extensions.IngressSpec) *extensions.Ingress {
	if annotations == nil {
		annotations = &map[string]string{}
	}

	ing := &extensions.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:        name,
			Namespace:   ns,
			Annotations: *annotations,
		},
		Spec: spec,
	}

	return ing
}
