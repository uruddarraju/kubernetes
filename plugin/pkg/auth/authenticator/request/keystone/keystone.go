/*
Copyright 2015 The Kubernetes Authors All rights reserved.

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

package keystone

import (
	"encoding/base64"
	"errors"
	"net/http"
	"strings"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/auth/authenticator"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/auth/user"
	"github.com/golang/glog"
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack"
)

type OpenstackClient struct {
	authURL string
}

func (osClient *OpenstackClient) AuthenticatePassword(username string, password string) (user.Info, bool, error) {
	opts := gophercloud.AuthOptions{
		IdentityEndpoint: osClient.authURL,
		Username:         username,
		Password:         password,
	}

	_, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		glog.Info("Failed: Starting openstack authenticate client")
		return nil, false, errors.New("Failed to authenticate")
	}

	return &user.DefaultInfo{Name: username}, true, nil
}

type KeystoneAuthenticator struct {
	osClient authenticator.Password
}

// New returns a request authenticator that validates credentials using openstack keystone
func NewKeystoneAuthenticator(authURL string) (*KeystoneAuthenticator, error) {
	if authURL == "" {
		return nil, errors.New("Auth URL is empty")
	}

	osClient := OpenstackClient{authURL}

	return &KeystoneAuthenticator{
		osClient: &osClient,
	}, nil
}

// AuthenticateRequest authenticates the request using the "Authorization: Basic" header in the request
func (a *KeystoneAuthenticator) AuthenticateRequest(req *http.Request) (user.Info, bool, error) {
	auth := strings.TrimSpace(req.Header.Get("Authorization"))
	if auth == "" {
		return nil, false, errors.New("Authorization header isempty, failing request")
	}
	parts := strings.Split(auth, " ")
	if len(parts) < 2 || strings.ToLower(parts[0]) != "basic" {
		return nil, false, errors.New("invalid header")
	}

	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false, err
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		return nil, false, errors.New("malformed basic auth header")
	}

	username := pair[0]
	password := pair[1]

	return a.osClient.AuthenticatePassword(username, password)

}
