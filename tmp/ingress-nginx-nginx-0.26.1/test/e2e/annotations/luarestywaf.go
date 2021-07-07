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

package annotations

import (
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/parnurzeal/gorequest"

	"k8s.io/ingress-nginx/test/e2e/framework"
)

var _ = framework.IngressNginxDescribe("Annotations - lua-resty-waf", func() {
	f := framework.NewDefaultFramework("luarestywaf")

	BeforeEach(func() {
		f.NewEchoDeployment()
	})

	Context("when lua-resty-waf is enabled", func() {
		It("should return 403 for a malicious request that matches a default WAF rule and 200 for other requests", func() {
			host := "foo"
			createIngress(f, host, framework.EchoService, 80, map[string]string{"nginx.ingress.kubernetes.io/lua-resty-waf": "active"})

			url := fmt.Sprintf("%s?msg=<A href=\"http://mysite.com/\">XSS</A>", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusForbidden))
		})
		It("should not apply ignored rulesets", func() {
			host := "foo"
			createIngress(f, host, framework.EchoService, 80, map[string]string{
				"nginx.ingress.kubernetes.io/lua-resty-waf":                 "active",
				"nginx.ingress.kubernetes.io/lua-resty-waf-ignore-rulesets": "41000_sqli, 42000_xss"})

			url := fmt.Sprintf("%s?msg=<A href=\"http://mysite.com/\">XSS</A>", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusOK))
		})
		It("should apply the score threshold", func() {
			host := "foo"
			createIngress(f, host, framework.EchoService, 80, map[string]string{
				"nginx.ingress.kubernetes.io/lua-resty-waf":                 "active",
				"nginx.ingress.kubernetes.io/lua-resty-waf-score-threshold": "20"})

			url := fmt.Sprintf("%s?msg=<A href=\"http://mysite.com/\">XSS</A>", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusOK))
		})
		It("should not reject request with an unknown content type", func() {
			host := "foo"
			contenttype := "application/octet-stream"
			createIngress(f, host, framework.EchoService, 80, map[string]string{
				"nginx.ingress.kubernetes.io/lua-resty-waf-allow-unknown-content-types": "true",
				"nginx.ingress.kubernetes.io/lua-resty-waf":                             "active"})

			url := fmt.Sprintf("%s?msg=my-message", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				Set("Content-Type", contenttype).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusOK))
		})
		It("should not fail a request with multipart content type when multipart body processing disabled", func() {
			contenttype := "multipart/form-data; boundary=alamofire.boundary.3fc2e849279e18fc"
			host := "foo"
			createIngress(f, host, framework.EchoService, 80, map[string]string{
				"nginx.ingress.kubernetes.io/lua-resty-waf-process-multipart-body": "false",
				"nginx.ingress.kubernetes.io/lua-resty-waf":                        "active"})

			url := fmt.Sprintf("%s?msg=my-message", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				Set("Content-Type", contenttype).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusOK))
		})
		It("should fail a request with multipart content type when multipart body processing enabled by default", func() {
			contenttype := "multipart/form-data; boundary=alamofire.boundary.3fc2e849279e18fc"
			host := "foo"
			createIngress(f, host, framework.EchoService, 80, map[string]string{
				"nginx.ingress.kubernetes.io/lua-resty-waf": "active"})

			url := fmt.Sprintf("%s?msg=my-message", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				Set("Content-Type", contenttype).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusBadRequest))
		})
		It("should apply configured extra rules", func() {
			host := "foo"
			createIngress(f, host, framework.EchoService, 80, map[string]string{
				"nginx.ingress.kubernetes.io/lua-resty-waf": "active",
				"nginx.ingress.kubernetes.io/lua-resty-waf-extra-rules": `[=[
						{ "access": [
								{ "actions": { "disrupt" : "DENY" },
								"id": 10001,
								"msg": "my custom rule",
								"operator": "STR_CONTAINS",
								"pattern": "foo",
								"vars": [ { "parse": [ "values", 1 ], "type": "REQUEST_ARGS" } ] }
							],
							"body_filter": [],
							"header_filter":[]
						}
					]=]`,
			})

			url := fmt.Sprintf("%s?msg=my-message", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusOK))

			url = fmt.Sprintf("%s?msg=my-foo-message", f.GetURL(framework.HTTP))
			resp, _, errs = gorequest.New().
				Get(url).
				Set("Host", host).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusForbidden))
		})
	})
	Context("when lua-resty-waf is not enabled", func() {
		It("should return 200 even for a malicious request", func() {
			host := "foo"
			createIngress(f, host, framework.EchoService, 80, map[string]string{})

			url := fmt.Sprintf("%s?msg=<A href=\"http://mysite.com/\">XSS</A>", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusOK))
		})
		It("should run in simulate mode", func() {
			host := "foo"
			createIngress(f, host, framework.EchoService, 80, map[string]string{"nginx.ingress.kubernetes.io/lua-resty-waf": "simulate"})

			url := fmt.Sprintf("%s?msg=<A href=\"http://mysite.com/\">XSS</A>", f.GetURL(framework.HTTP))
			resp, _, errs := gorequest.New().
				Get(url).
				Set("Host", host).
				End()

			Expect(len(errs)).Should(Equal(0))
			Expect(resp.StatusCode).Should(Equal(http.StatusOK))

			time.Sleep(5 * time.Second)
			log, err := f.NginxLogs()
			Expect(err).ToNot(HaveOccurred())
			Expect(log).To(ContainSubstring("Request score greater than score threshold"))
		})
	})
})

func createIngress(f *framework.Framework, host, service string, port int, annotations map[string]string) {
	ing := framework.NewSingleIngress(host, "/", host, f.Namespace, service, port, &annotations)
	f.EnsureIngress(ing)

	f.WaitForNginxServer(host,
		func(server string) bool {
			return Expect(server).Should(ContainSubstring(fmt.Sprintf("server_name %v", host)))
		})

	time.Sleep(1 * time.Second)

	resp, body, errs := gorequest.New().
		Get(f.GetURL(framework.HTTP)).
		Set("Host", host).
		End()

	Expect(len(errs)).Should(Equal(0))
	Expect(resp.StatusCode).Should(Equal(http.StatusOK))
	Expect(body).Should(ContainSubstring(fmt.Sprintf("host=%v", host)))
}
