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

package defaultbackend

import (
	"fmt"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"github.com/parnurzeal/gorequest"

	appsv1 "k8s.io/api/apps/v1"

	"k8s.io/ingress-nginx/test/e2e/framework"
)

var _ = framework.IngressNginxDescribe("Custom Default Backend", func() {
	f := framework.NewDefaultFramework("custom-default-backend")

	BeforeEach(func() {
		f.NewEchoDeploymentWithReplicas(1)

		framework.UpdateDeployment(f.KubeClientSet, f.Namespace, "nginx-ingress-controller", 1,
			func(deployment *appsv1.Deployment) error {
				args := deployment.Spec.Template.Spec.Containers[0].Args
				args = append(args, fmt.Sprintf("--default-backend-service=$(POD_NAMESPACE)/%v", framework.EchoService))
				deployment.Spec.Template.Spec.Containers[0].Args = args
				_, err := f.KubeClientSet.AppsV1().Deployments(f.Namespace).Update(deployment)

				return err
			})

		f.WaitForNginxServer("_",
			func(server string) bool {
				return strings.Contains(server, "set $proxy_upstream_name \"upstream-default-backend\"")
			})
	})

	It("uses custom default backend", func() {
		resp, _, errs := gorequest.New().Get(f.GetURL(framework.HTTP)).End()
		Expect(errs).Should(BeEmpty())
		Expect(resp.StatusCode).Should(Equal(http.StatusOK))
	})
})
