/*
Copyright 2018 The Kubernetes Authors.

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

package servicebackend

import (
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/parnurzeal/gorequest"

	corev1 "k8s.io/api/core/v1"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"

	"k8s.io/ingress-nginx/test/e2e/framework"
)

var _ = framework.IngressNginxDescribe("Service backend - 503", func() {
	f := framework.NewDefaultFramework("service-backend")

	BeforeEach(func() {
	})

	AfterEach(func() {
	})

	It("should return 503 when backend service does not exist", func() {
		host := "nonexistent.svc.com"

		bi := buildIngressWithNonexistentService(host, f.Namespace, "/")
		f.EnsureIngress(bi)

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, "proxy_pass http://upstream_balancer;")
			})

		resp, _, errs := gorequest.New().
			Get(f.GetURL(framework.HTTP)).
			Set("Host", host).
			End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(503))
	})

	It("should return 503 when all backend service endpoints are unavailable", func() {
		host := "unavailable.svc.com"

		bi, bs := buildIngressWithUnavailableServiceEndpoints(host, f.Namespace, "/")

		svc := f.EnsureService(bs)
		Expect(svc).NotTo(BeNil())

		f.EnsureIngress(bi)

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, "proxy_pass http://upstream_balancer;")
			})

		resp, _, errs := gorequest.New().
			Get(f.GetURL(framework.HTTP)).
			Set("Host", host).
			End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(503))
	})

})

func buildIngressWithNonexistentService(host, namespace, path string) *extensions.Ingress {
	backendService := "nonexistent-svc"
	return &extensions.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name:      host,
			Namespace: namespace,
		},
		Spec: extensions.IngressSpec{
			Rules: []extensions.IngressRule{
				{
					Host: host,
					IngressRuleValue: extensions.IngressRuleValue{
						HTTP: &extensions.HTTPIngressRuleValue{
							Paths: []extensions.HTTPIngressPath{
								{
									Path: path,
									Backend: extensions.IngressBackend{
										ServiceName: backendService,
										ServicePort: intstr.FromInt(80),
									},
								},
							},
						},
					},
				},
			},
		},
	}
}

func buildIngressWithUnavailableServiceEndpoints(host, namespace, path string) (*extensions.Ingress, *corev1.Service) {
	backendService := "unavailable-svc"
	return &extensions.Ingress{
			ObjectMeta: metav1.ObjectMeta{
				Name:      host,
				Namespace: namespace,
			},
			Spec: extensions.IngressSpec{
				Rules: []extensions.IngressRule{
					{
						Host: host,
						IngressRuleValue: extensions.IngressRuleValue{
							HTTP: &extensions.HTTPIngressRuleValue{
								Paths: []extensions.HTTPIngressPath{
									{
										Path: path,
										Backend: extensions.IngressBackend{
											ServiceName: backendService,
											ServicePort: intstr.FromInt(80),
										},
									},
								},
							},
						},
					},
				},
			},
		}, &corev1.Service{
			ObjectMeta: metav1.ObjectMeta{
				Name:      backendService,
				Namespace: namespace,
			},
			Spec: corev1.ServiceSpec{Ports: []corev1.ServicePort{
				{
					Name:       "tcp",
					Port:       80,
					TargetPort: intstr.FromInt(80),
					Protocol:   "TCP",
				},
			},
				Selector: map[string]string{
					"app": backendService,
				},
			},
		}
}
