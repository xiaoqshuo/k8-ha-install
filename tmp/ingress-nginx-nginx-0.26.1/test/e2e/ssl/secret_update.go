/*
Copyright 2017 The Kubernetes Authors.

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

package ssl

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/parnurzeal/gorequest"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/ingress-nginx/test/e2e/framework"
)

var _ = framework.IngressNginxDescribe("SSL", func() {
	f := framework.NewDefaultFramework("ssl")

	BeforeEach(func() {
		f.NewEchoDeployment()
	})

	AfterEach(func() {
	})

	It("should not appear references to secret updates not used in ingress rules", func() {
		host := "ssl-update"

		dummySecret := f.EnsureSecret(&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "dummy",
				Namespace: f.Namespace,
			},
			Data: map[string][]byte{
				"key": []byte("value"),
			},
		})

		ing := f.EnsureIngress(framework.NewSingleIngressWithTLS(host, "/", host, []string{host}, f.Namespace, framework.EchoService, 80, nil))
		_, err := framework.CreateIngressTLSSecret(f.KubeClientSet,
			ing.Spec.TLS[0].Hosts,
			ing.Spec.TLS[0].SecretName,
			ing.Namespace)
		Expect(err).ToNot(HaveOccurred())

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, "server_name ssl-update") &&
					strings.Contains(server, "listen 443")
			})

		log, err := f.NginxLogs()
		Expect(err).ToNot(HaveOccurred())
		Expect(log).ToNot(BeEmpty())

		Expect(log).ToNot(ContainSubstring(fmt.Sprintf("starting syncing of secret %v/dummy", f.Namespace)))
		time.Sleep(5 * time.Second)
		dummySecret.Data["some-key"] = []byte("some value")
		f.KubeClientSet.CoreV1().Secrets(f.Namespace).Update(dummySecret)
		time.Sleep(5 * time.Second)
		Expect(log).ToNot(ContainSubstring(fmt.Sprintf("starting syncing of secret %v/dummy", f.Namespace)))
		Expect(log).ToNot(ContainSubstring(fmt.Sprintf("error obtaining PEM from secret %v/dummy", f.Namespace)))
	})

	It("should return the fake SSL certificate if the secret is invalid", func() {
		host := "invalid-ssl"

		// create a secret without cert or key
		f.EnsureSecret(&v1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      host,
				Namespace: f.Namespace,
			},
		})

		f.EnsureIngress(framework.NewSingleIngressWithTLS(host, "/", host, []string{host}, f.Namespace, framework.EchoService, 80, nil))

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, "server_name invalid-ssl") &&
					strings.Contains(server, "listen 443")
			})

		req := gorequest.New()
		resp, _, errs := req.
			Get(f.GetURL(framework.HTTPS)).
			TLSClientConfig(&tls.Config{ServerName: host, InsecureSkipVerify: true}).
			Set("Host", host).
			End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(http.StatusOK))

		// check the returned secret is the fake one
		cert := resp.TLS.PeerCertificates[0]
		Expect(cert.DNSNames[0]).Should(Equal("ingress.local"))
		Expect(cert.Subject.Organization[0]).Should(Equal("Acme Co"))
		Expect(cert.Subject.CommonName).Should(Equal("Kubernetes Ingress Controller Fake Certificate"))

		// verify the log contains a warning about invalid certificate
		log, err := f.NginxLogs()
		Expect(err).ToNot(HaveOccurred())
		Expect(log).ToNot(BeEmpty())
		Expect(log).To(ContainSubstring(fmt.Sprintf("%v/invalid-ssl\" contains no keypair or CA certificate", f.Namespace)))
	})
})
