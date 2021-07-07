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

package annotations

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/parnurzeal/gorequest"
	"k8s.io/ingress-nginx/test/e2e/framework"
)

var _ = framework.IngressNginxDescribe("Annotations - AuthTLS", func() {
	f := framework.NewDefaultFramework("authtls")

	BeforeEach(func() {
		f.NewEchoDeploymentWithReplicas(2)
	})

	AfterEach(func() {
	})

	It("should set valid auth-tls-secret", func() {
		host := "authtls.foo.com"
		nameSpace := f.Namespace

		clientConfig, err := framework.CreateIngressMASecret(
			f.KubeClientSet,
			host,
			host,
			nameSpace)
		Expect(err).ToNot(HaveOccurred())

		annotations := map[string]string{
			"nginx.ingress.kubernetes.io/auth-tls-secret": nameSpace + "/" + host,
		}

		f.EnsureIngress(framework.NewSingleIngressWithTLS(host, "/", host, []string{host}, nameSpace, framework.EchoService, 80, &annotations))

		assertSslClientCertificateConfig(f, host, "on", "1")

		// Send Request without Client Certs
		req := gorequest.New()
		uri := "/"
		resp, _, errs := req.
			Get(f.GetURL(framework.HTTPS)+uri).
			TLSClientConfig(&tls.Config{ServerName: host, InsecureSkipVerify: true}).
			Set("Host", host).
			End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(http.StatusBadRequest))

		// Send Request Passing the Client Certs
		resp, _, errs = req.
			Get(f.GetURL(framework.HTTPS)+uri).
			TLSClientConfig(clientConfig).
			Set("Host", host).
			End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(http.StatusOK))
	})

	It("should set valid auth-tls-secret, sslVerify to off, and sslVerifyDepth to 2", func() {
		host := "authtls.foo.com"
		nameSpace := f.Namespace

		_, err := framework.CreateIngressMASecret(
			f.KubeClientSet,
			host,
			host,
			nameSpace)
		Expect(err).ToNot(HaveOccurred())

		annotations := map[string]string{
			"nginx.ingress.kubernetes.io/auth-tls-secret":        nameSpace + "/" + host,
			"nginx.ingress.kubernetes.io/auth-tls-verify-client": "off",
			"nginx.ingress.kubernetes.io/auth-tls-verify-depth":  "2",
		}

		f.EnsureIngress(framework.NewSingleIngressWithTLS(host, "/", host, []string{host}, nameSpace, framework.EchoService, 80, &annotations))

		assertSslClientCertificateConfig(f, host, "off", "2")

		// Send Request without Client Certs
		req := gorequest.New()
		uri := "/"
		resp, _, errs := req.
			Get(f.GetURL(framework.HTTPS)+uri).
			TLSClientConfig(&tls.Config{ServerName: host, InsecureSkipVerify: true}).
			Set("Host", host).
			End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(http.StatusOK))
	})

	It("should set valid auth-tls-secret, pass certificate to upstream, and error page", func() {
		host := "authtls.foo.com"
		nameSpace := f.Namespace

		errorPath := "/error"

		clientConfig, err := framework.CreateIngressMASecret(
			f.KubeClientSet,
			host,
			host,
			nameSpace)
		Expect(err).ToNot(HaveOccurred())

		annotations := map[string]string{
			"nginx.ingress.kubernetes.io/auth-tls-secret":                       nameSpace + "/" + host,
			"nginx.ingress.kubernetes.io/auth-tls-error-page":                   f.GetURL(framework.HTTP) + errorPath,
			"nginx.ingress.kubernetes.io/auth-tls-pass-certificate-to-upstream": "true",
		}

		f.EnsureIngress(framework.NewSingleIngressWithTLS(host, "/", host, []string{host}, nameSpace, framework.EchoService, 80, &annotations))

		assertSslClientCertificateConfig(f, host, "on", "1")

		sslErrorPage := fmt.Sprintf("error_page 495 496 = %s;", f.GetURL(framework.HTTP)+errorPath)
		sslUpstreamClientCert := "proxy_set_header ssl-client-cert $ssl_client_escaped_cert;"

		f.WaitForNginxServer(host,
			func(server string) bool {
				return strings.Contains(server, sslErrorPage) &&
					strings.Contains(server, sslUpstreamClientCert)
			})

		// Send Request without Client Certs
		req := gorequest.New()
		uri := "/"
		resp, _, errs := req.
			Get(f.GetURL(framework.HTTPS)+uri).
			TLSClientConfig(&tls.Config{ServerName: host, InsecureSkipVerify: true}).
			Set("Host", host).
			RedirectPolicy(noRedirectPolicyFunc).
			End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(http.StatusFound))
		Expect(resp.Header.Get("Location")).Should(Equal(f.GetURL(framework.HTTP) + errorPath))

		// Send Request Passing the Client Certs
		resp, _, errs = req.
			Get(f.GetURL(framework.HTTPS)+uri).
			TLSClientConfig(clientConfig).
			Set("Host", host).
			End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(http.StatusOK))
	})
})

func assertSslClientCertificateConfig(f *framework.Framework, host string, verifyClient string, verifyDepth string) {
	sslClientCertDirective := fmt.Sprintf("ssl_client_certificate /etc/ingress-controller/ssl/%s-%s.pem;", f.Namespace, host)
	sslVerify := fmt.Sprintf("ssl_verify_client %s;", verifyClient)
	sslVerifyDepth := fmt.Sprintf("ssl_verify_depth %s;", verifyDepth)

	f.WaitForNginxServer(host,
		func(server string) bool {
			return strings.Contains(server, sslClientCertDirective) &&
				strings.Contains(server, sslVerify) &&
				strings.Contains(server, sslVerifyDepth)
		})
}
