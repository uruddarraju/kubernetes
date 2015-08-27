/*
Copyright 2014 The Kubernetes Authors All rights reserved.

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

package union

import (
	"k8s.io/kubernetes/pkg/auth/authorizer"
	"k8s.io/kubernetes/pkg/util/errors"
)

// unionAuthRequestHandler authenticates requests using a chain of authenticator.Requests
type unionAuthzHandler []authorizer.Authorizer

// New returns a request authenticator that validates credentials using a chain of authenticator.Request objects
func New(authorizationHandlers ...authorizer.Authorizer) authorizer.Authorizer {
	return unionAuthzHandler(authorizationHandlers)
}

// AuthenticateRequest authenticates the request using a chain of authenticator.Request objects.  The first
// success returns that identity.  Errors are only returned if no matches are found.
func (authzHandler unionAuthzHandler) Authorize(a authorizer.Attributes) error {
	var errlist []error
	for _, currAuthzHandler := range authzHandler {
		err := currAuthzHandler.Authorize(a)
		if err != nil {
			errlist = append(errlist, err)
			continue
		}
		return nil
	}

	return errors.NewAggregate(errlist)
}
