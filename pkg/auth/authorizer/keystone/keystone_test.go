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
	"github.com/GoogleCloudPlatform/kubernetes/pkg/auth/authorizer"
	"github.com/GoogleCloudPlatform/kubernetes/pkg/auth/user"
	"github.com/rackspace/gophercloud/openstack/identity/v2/tenants"
	"github.com/rackspace/gophercloud/openstack/identity/v2/users"
	"strings"
	"testing"
)

func getTenantSampleSet() (tenantList []tenants.Tenant, err error) {
	tenantList = make([]tenants.Tenant, 0)
	tenantList = append(tenantList, tenants.Tenant{Name: "tenant1", ID: "123", Enabled: true})
	tenantList = append(tenantList, tenants.Tenant{Name: "tenant2", ID: "234", Enabled: true})
	tenantList = append(tenantList, tenants.Tenant{Name: "tenant3", ID: "345", Enabled: true})

	return tenantList, nil
}

func getUserSampleSet() (userList []users.User, err error) {
	userList = make([]users.User, 0)
	userList = append(userList, users.User{Username: "user1", ID: "12", Enabled: true})
	userList = append(userList, users.User{Username: "user2", ID: "23", Enabled: true})
	userList = append(userList, users.User{Username: "user3", ID: "34", Enabled: true})
	userList = append(userList, users.User{Username: "user4", ID: "56", Enabled: true})

	return userList, nil
}

func sampleRoleSet() map[string][]string {
	roleMap := make(map[string][]string)
	roleMap["123:12"] = []string{"admin"}
	roleMap["234:12"] = []string{"admin", "user"}
	roleMap["456:23"] = []string{"admin"}
	return roleMap
}

type testOpenstackClient struct {
}

func (osClient *testOpenstackClient) getTenants() (tenantList []tenants.Tenant, err error) {
	return getTenantSampleSet()
}

func (osClient *testOpenstackClient) getUsers() (userList []users.User, err error) {
	return getUserSampleSet()
}

func (osClient *testOpenstackClient) roleCheck(userID string, tenantID string) (bool, error) {
	roleMap := sampleRoleSet()
	key := tenantID + ":" + userID
	if len(roleMap[key]) > 0 {
		return true, nil
	}
	return false, nil
}

func TestReadConfig(t *testing.T) {

	cfg, err := readConfig(strings.NewReader(`
{
  "auth-url": "https://auth-url/v2.0",
  "user-name": "username",
  "password": "password",
  "region": "na-east",
  "tenant-id": "31213d3bc3144cfaacb60f040206baae",
  "tenant-name": "tenant"
}
`))
	if err != nil {
		t.Fatalf("Should succeed when a valid config is provided: %s", err)
	}
	if cfg.AuthUrl != "https://auth-url/v2.0" {
		t.Errorf("expected username \"https://auth-url/v2.0\" got %s", cfg.AuthUrl)
	}
	if cfg.Username != "username" {
		t.Errorf("expected username \"username\" got %s", cfg.Username)
	}
	if cfg.Password != "password" {
		t.Errorf("expected password \"password\" got %s", cfg.Password)
	}
	if cfg.Region != "na-east" {
		t.Errorf("expected region \"na-east\" got %s", cfg.Region)
	}
	if cfg.TenantId != "31213d3bc3144cfaacb60f040206baae" {
		t.Errorf("expected tenant id \"31213d3bc3144cfaacb60f040206baae\" got %s", cfg.TenantId)
	}
	if cfg.TenantName != "tenant" {
		t.Errorf("expected tenant name \"tenant\" got %s", cfg.TenantName)
	}
}

func TestAuthorize(t *testing.T) {

	testCases := []struct {
		attr      authorizer.Attributes
		name      string
		ExpectErr bool
	}{
		{
			attr: authorizer.AttributesRecord{
				User: &user.DefaultInfo{},
			},
			ExpectErr: true,
			name:      "null username",
		},
		{
			attr: authorizer.AttributesRecord{
				User: &user.DefaultInfo{
					Name: "user1",
				},
			},
			name:      "null namespace",
			ExpectErr: true,
		},
		{
			attr: authorizer.AttributesRecord{
				User: &user.DefaultInfo{
					Name: "user1",
				},
				Namespace: "tenant1",
			},
			name:      "namespace user match",
			ExpectErr: false,
		},
		{
			attr: authorizer.AttributesRecord{
				User: &user.DefaultInfo{
					Name: "user1",
				},
				Namespace: "tenant2",
			},
			name:      "namespace user multi role match",
			ExpectErr: false,
		},
		{
			attr: authorizer.AttributesRecord{
				User: &user.DefaultInfo{
					Name: "user3",
				},
				Namespace: "tenant1",
			},
			name:      "namespace user role mis-match",
			ExpectErr: true,
		},
	}

	for k, testCase := range testCases {

		auth := keystoneAuthorizer{
			osClient: &testOpenstackClient{},
		}

		auth.syncTenantMap()
		auth.syncUserMap()

		err := auth.Authorize(testCase.attr)

		if testCase.ExpectErr && err == nil {
			t.Errorf("%s: %s: Expected error, got none", testCase.name, k)
			continue
		}
		if !testCase.ExpectErr && err != nil {
			t.Errorf("%s: %s: Did not expect error, got err:%v", testCase.name, k, err)
			continue
		}
	}
}
