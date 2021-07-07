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

package lua

import (
	"fmt"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
	extensions "k8s.io/api/extensions/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"k8s.io/ingress-nginx/test/e2e/framework"
)

var _ = framework.IngressNginxDescribe("Dynamic Certificate", func() {
	f := framework.NewDefaultFramework("dynamic-certificate")
	host := "foo.com"

	BeforeEach(func() {
		f.NewEchoDeploymentWithReplicas(1)
	})

	It("picks up the certificate when we add TLS spec to existing ingress", func() {
		ensureIngress(f, host, framework.EchoService)

		ing, err := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace).Get(host, metav1.GetOptions{})
		Expect(err).ToNot(HaveOccurred())
		ing.Spec.TLS = []extensions.IngressTLS{
			{
				Hosts:      []string{host},
				SecretName: host,
			},
		}
		_, err = framework.CreateIngressTLSSecret(f.KubeClientSet,
			ing.Spec.TLS[0].Hosts,
			ing.Spec.TLS[0].SecretName,
			ing.Namespace)
		Expect(err).ToNot(HaveOccurred())
		_, err = f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace).Update(ing)
		Expect(err).ToNot(HaveOccurred())
		time.Sleep(waitForLuaSync)

		ensureHTTPSRequest(f.GetURL(framework.HTTPS), host, host)
	})

	It("picks up the previously missing secret for a given ingress without reloading", func() {
		ing := framework.NewSingleIngressWithTLS(host, "/", host, []string{host}, f.Namespace, framework.EchoService, 80, nil)
		f.EnsureIngress(ing)

		time.Sleep(waitForLuaSync)

		ip := f.GetNginxPodIP()
		mf, err := f.GetMetric("nginx_ingress_controller_success", ip[0])
		Expect(err).ToNot(HaveOccurred())
		Expect(mf).ToNot(BeNil())

		rc0, err := extractReloadCount(mf)
		Expect(err).ToNot(HaveOccurred())

		ensureHTTPSRequest(fmt.Sprintf("%s?id=dummy_log_splitter_foo_bar", f.GetURL(framework.HTTPS)), host, "ingress.local")

		_, err = framework.CreateIngressTLSSecret(f.KubeClientSet,
			ing.Spec.TLS[0].Hosts,
			ing.Spec.TLS[0].SecretName,
			ing.Namespace)
		Expect(err).ToNot(HaveOccurred())

		time.Sleep(waitForLuaSync)

		By("serving the configured certificate on HTTPS endpoint")
		ensureHTTPSRequest(f.GetURL(framework.HTTPS), host, host)

		log, err := f.NginxLogs()
		Expect(err).ToNot(HaveOccurred())
		Expect(log).ToNot(BeEmpty())

		By("skipping Nginx reload")
		mf, err = f.GetMetric("nginx_ingress_controller_success", ip[0])
		Expect(err).ToNot(HaveOccurred())
		Expect(mf).ToNot(BeNil())

		rc1, err := extractReloadCount(mf)
		Expect(err).ToNot(HaveOccurred())

		Expect(rc0).To(BeEquivalentTo(rc1))
	})

	Context("given an ingress with TLS correctly configured", func() {
		BeforeEach(func() {
			ing := f.EnsureIngress(framework.NewSingleIngressWithTLS(host, "/", host, []string{host}, f.Namespace, framework.EchoService, 80, nil))

			time.Sleep(waitForLuaSync)

			ensureHTTPSRequest(f.GetURL(framework.HTTPS), host, "ingress.local")

			_, err := framework.CreateIngressTLSSecret(f.KubeClientSet,
				ing.Spec.TLS[0].Hosts,
				ing.Spec.TLS[0].SecretName,
				ing.Namespace)
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(waitForLuaSync)

			By("configuring certificate_by_lua and skipping Nginx configuration of the new certificate")
			f.WaitForNginxServer(ing.Spec.TLS[0].Hosts[0],
				func(server string) bool {
					return strings.Contains(server, "listen 443")
				})

			time.Sleep(waitForLuaSync)

			By("serving the configured certificate on HTTPS endpoint")
			ensureHTTPSRequest(f.GetURL(framework.HTTPS), host, host)
		})

		/*
			TODO(elvinefendi): this test currently does not work as expected
			because Go transport code strips (https://github.com/golang/go/blob/431b5c69ca214ce4291f008c1ce2a50b22bc2d2d/src/crypto/tls/handshake_messages.go#L424)
			trailing dot from SNI as suggest by the standard (https://tools.ietf.org/html/rfc6066#section-3).
		*/
		It("supports requests with domain with trailing dot", func() {
			ensureHTTPSRequest(f.GetURL(framework.HTTPS), host+".", host)
		})

		It("picks up the updated certificate without reloading", func() {
			ing, err := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace).Get(host, metav1.GetOptions{})
			Expect(err).ToNot(HaveOccurred())

			ensureHTTPSRequest(fmt.Sprintf("%s?id=dummy_log_splitter_foo_bar", f.GetURL(framework.HTTPS)), host, host)

			_, err = framework.CreateIngressTLSSecret(f.KubeClientSet,
				ing.Spec.TLS[0].Hosts,
				ing.Spec.TLS[0].SecretName,
				ing.Namespace)
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(waitForLuaSync)

			By("configuring certificate_by_lua and skipping Nginx configuration of the new certificate")
			f.WaitForNginxServer(ing.Spec.TLS[0].Hosts[0],
				func(server string) bool {
					return strings.Contains(server, "listen 443")
				})

			By("serving the configured certificate on HTTPS endpoint")
			ensureHTTPSRequest(f.GetURL(framework.HTTPS), host, host)

			log, err := f.NginxLogs()
			Expect(err).ToNot(HaveOccurred())
			Expect(log).ToNot(BeEmpty())
			index := strings.Index(log, "id=dummy_log_splitter_foo_bar")
			restOfLogs := log[index:]

			By("skipping Nginx reload")
			Expect(restOfLogs).ToNot(ContainSubstring(logRequireBackendReload))
			Expect(restOfLogs).ToNot(ContainSubstring(logBackendReloadSuccess))
		})

		It("falls back to using default certificate when secret gets deleted without reloading", func() {
			ing, err := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace).Get(host, metav1.GetOptions{})

			ensureHTTPSRequest(fmt.Sprintf("%s?id=dummy_log_splitter_foo_bar", f.GetURL(framework.HTTPS)), host, host)

			ip := f.GetNginxPodIP()
			mf, err := f.GetMetric("nginx_ingress_controller_success", ip[0])
			Expect(err).ToNot(HaveOccurred())
			Expect(mf).ToNot(BeNil())

			rc0, err := extractReloadCount(mf)
			Expect(err).ToNot(HaveOccurred())

			err = f.KubeClientSet.CoreV1().Secrets(ing.Namespace).Delete(ing.Spec.TLS[0].SecretName, nil)
			Expect(err).ToNot(HaveOccurred())

			time.Sleep(waitForLuaSync * 2)

			By("serving the default certificate on HTTPS endpoint")
			ensureHTTPSRequest(f.GetURL(framework.HTTPS), host, "ingress.local")

			mf, err = f.GetMetric("nginx_ingress_controller_success", ip[0])
			Expect(err).ToNot(HaveOccurred())
			Expect(mf).ToNot(BeNil())

			rc1, err := extractReloadCount(mf)
			Expect(err).ToNot(HaveOccurred())

			By("skipping Nginx reload")
			Expect(rc0).To(BeEquivalentTo(rc1))
		})

		It("picks up a non-certificate only change", func() {
			newHost := "foo2.com"
			ing, err := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace).Get(host, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			ing.Spec.Rules[0].Host = newHost
			_, err = f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace).Update(ing)
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(waitForLuaSync)

			By("serving the configured certificate on HTTPS endpoint")
			ensureHTTPSRequest(f.GetURL(framework.HTTPS), newHost, "ingress.local")
		})

		It("removes HTTPS configuration when we delete TLS spec", func() {
			ing, err := f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace).Get(host, metav1.GetOptions{})
			Expect(err).NotTo(HaveOccurred())
			ing.Spec.TLS = []extensions.IngressTLS{}
			_, err = f.KubeClientSet.ExtensionsV1beta1().Ingresses(f.Namespace).Update(ing)
			Expect(err).ToNot(HaveOccurred())
			time.Sleep(waitForLuaSync)

			ensureRequest(f, host)
		})
	})
})

func extractReloadCount(mf *dto.MetricFamily) (float64, error) {
	vec, err := expfmt.ExtractSamples(&expfmt.DecodeOptions{
		Timestamp: model.Now(),
	}, mf)

	if err != nil {
		return 0, err
	}

	return float64(vec[0].Value), nil
}
