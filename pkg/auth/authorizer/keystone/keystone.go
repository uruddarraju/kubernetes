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

package keystone

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/kubernetes/pkg/auth/authorizer"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/util"
	"github.com/golang/glog"
	"github.com/rackspace/gophercloud"
	"github.com/rackspace/gophercloud/openstack"
	"github.com/rackspace/gophercloud/openstack/identity/v2/tenants"
	"github.com/rackspace/gophercloud/openstack/identity/v2/users"
	"github.com/rackspace/gophercloud/pagination"
)

type osConfig struct {
	AuthUrl    string `json:"auth-url"`
	Username   string `json:"user-name"`
	UserId     string `json:"user-id"`
	Password   string `json:"password"`
	ApiKey     string `json:"api-key"`
	TenantId   string `json:"tenant-id"`
	TenantName string `json:"tenant-name"`
	Region     string `json:"region"`
}

type OpenstackClient struct {
	provider   *gophercloud.ProviderClient
	authClient *gophercloud.ServiceClient
	config     *osConfig
}

type keystoneAuthorizer struct {
	osClient  Interface
	userMap   map[string]string
	tenantMap map[string]string
}

func newOpenstackClient(config *osConfig) (*OpenstackClient, error) {

	if config == nil {
		err := errors.New("no OpenStack cloud provider config file given")
		return nil, err
	}

	opts := gophercloud.AuthOptions{
		IdentityEndpoint: config.AuthUrl,
		Username:         config.Username,
		Password:         config.Password,
		TenantID:         config.TenantId,
		AllowReauth:      true,
	}

	provider, err := openstack.AuthenticatedClient(opts)
	if err != nil {
		glog.Info("Failed: Starting openstack authenticate client")
		return nil, err
	}
	authClient := openstack.NewIdentityV2(provider)

	return &OpenstackClient{
		provider,
		authClient,
		config,
	}, nil
}

func readConfig(reader io.Reader) (config osConfig, err error) {
	decoder := json.NewDecoder(reader)
	err = decoder.Decode(&config)
	if err != nil {
		return config, err
	}
	return config, nil
}

func NewKeystoneAuthorizer(configFile string, period time.Duration) (*keystoneAuthorizer, error) {

	file, err := os.Open(configFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	openstackConfig, err := readConfig(file)
	if err != nil {
		return nil, err
	}

	osClient, err := newOpenstackClient(&openstackConfig)
	if err != nil {
		return nil, err
	}
	tenantMap := make(map[string]string)
	userMap := make(map[string]string)

	ka := &keystoneAuthorizer{
		osClient:  osClient,
		tenantMap: tenantMap,
		userMap:   userMap,
	}

	if err := ka.syncUserMap(); err != nil {
		glog.Errorf("Error syncing users: %v", err)
		return nil, err
	}

	if err := ka.syncTenantMap(); err != nil {
		glog.Errorf("Error syncing tenants: %v", err)
		return nil, err
	}

	go util.Forever(func() {
		glog.V(4).Info("Syncing users")
		if err := ka.syncUserMap(); err != nil {
			glog.Errorf("Error syncing users: %v", err)
		}
	}, period*time.Second)

	go util.Forever(func() {
		if err := ka.syncTenantMap(); err != nil {
			glog.Errorf("Error syncing tenants: %v", err)
		}
	}, period*time.Second)

	return ka, nil
}

// Authorizer implements authorizer.Authorize
func (ka *keystoneAuthorizer) Authorize(a authorizer.Attributes) error {
	if strings.HasPrefix(a.GetUserName(), "system:serviceaccount:") {
		return nil
	}
	if isWhiteListedUser(a.GetUserName()) {
		return nil
	}
	hasRole, err := ka.osClient.roleCheck(ka.userMap[a.GetUserName()], ka.tenantMap[a.GetNamespace()])
	if err != nil {
		glog.V(4).Infof("Keystone authorization failed: %v", err)
		return errors.New("Keystone authorization failed")
	}
	if hasRole {
		return nil
	} else {
		return errors.New("User not authorized through keystone for namespace")
	}
	return errors.New("Keystone authorization failed")
}

func (ka *keystoneAuthorizer) syncTenantMap() error {
	tenantMap := make(map[string]string)
	tenantList, err := ka.osClient.getTenants()
	if err != nil {
		return err
	}
	for _, tenant := range tenantList {
		if tenant.Enabled {
			tenantMap[tenant.Name] = tenant.ID
		}
	}
	ka.tenantMap = tenantMap // The old map is garbage collected as there is no reference to it anymore
	return nil
}

func (ka *keystoneAuthorizer) syncUserMap() error {
	userMap := make(map[string]string)
	userList, err := ka.osClient.getUsers()
	if err != nil {
		return err
	}
	for _, user := range userList {
		if user.Enabled {
			userMap[user.Username] = user.ID
		}
	}
	ka.userMap = userMap // The old map is garbage collected as there is no reference to it anymore
	return nil
}

// Checks if a user has access to a tenant
func (osClient *OpenstackClient) roleCheck(userID string, tenantID string) (bool, error) {
	if userID == "" {
		return false, errors.New("UserID null during authorization")
	}
	if tenantID == "" {
		return false, errors.New("UserID null during authorization")
	}
	hasRole := false
	pager := users.ListRoles(osClient.authClient, tenantID, userID)
	err := pager.EachPage(func(page pagination.Page) (bool, error) {
		roleList, err := users.ExtractRoles(page)
		if err != nil {
			return false, err
		}
		if len(roleList) > 0 {
			hasRole = true
		}
		return true, nil
	})

	if err != nil {
		return false, err
	}
	return hasRole, nil
}

func (osClient *OpenstackClient) getTenants() (tenantList []tenants.Tenant, err error) {
	tenantList = make([]tenants.Tenant, 0)
	opts := tenants.ListOpts{}
	pager := tenants.List(osClient.authClient, &opts)
	err = pager.EachPage(func(page pagination.Page) (bool, error) {
		tenantList, err = tenants.ExtractTenants(page)
		if err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return tenantList, nil
}

func (osClient *OpenstackClient) getUsers() (userList []users.User, err error) {
	userList = make([]users.User, 0)
	pager := users.List(osClient.authClient)
	err = pager.EachPage(func(page pagination.Page) (bool, error) {
		userList, err = users.ExtractUsers(page)
		if err != nil {
			return false, err
		}
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return userList, nil
}

func isWhiteListedUser(username string) bool {
	whiteList := map[string]bool{
		"kubelet":                   true,
		"kube_proxy":                true,
		"system:scheduler":          true,
		"system:controller_manager": true,
		"system:logging":            true,
		"system:monitoring":         true,
	}
	return whiteList[username]
}