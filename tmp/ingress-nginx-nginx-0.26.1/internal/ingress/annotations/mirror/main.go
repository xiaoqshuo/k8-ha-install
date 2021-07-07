/*
Copyright 2019 The Kubernetes Authors.

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

package mirror

import (
	networking "k8s.io/api/networking/v1beta1"

	"k8s.io/ingress-nginx/internal/ingress/annotations/parser"
	"k8s.io/ingress-nginx/internal/ingress/resolver"
)

// Config returns the mirror to use in a given location
type Config struct {
	URI         string `json:"uri"`
	RequestBody string `json:"requestBody"`
}

type mirror struct {
	r resolver.Resolver
}

// NewParser creates a new mirror configuration annotation parser
func NewParser(r resolver.Resolver) parser.IngressAnnotation {
	return mirror{r}
}

// ParseAnnotations parses the annotations contained in the ingress
// rule used to configure mirror
func (a mirror) Parse(ing *networking.Ingress) (interface{}, error) {
	config := &Config{}
	var err error

	config.URI, err = parser.GetStringAnnotation("mirror-uri", ing)
	if err != nil {
		config.URI = ""
	}

	config.RequestBody, err = parser.GetStringAnnotation("mirror-request-body", ing)
	if err != nil || config.RequestBody != "off" {
		config.RequestBody = "on"
	}

	return config, nil
}
