package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"log"
//	"encoding/base64"
	"os"
	"time"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/plugin"
)

type roleStorageEntry struct {
	
	name string
	Policies []string `json:"policies" mapstructure:"policies"`
}

func main() {
	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.Parse(os.Args[1:])

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	if err := plugin.Serve(&plugin.ServeOpts{
		BackendFactoryFunc: Factory,
		TLSProviderFunc:    tlsProviderFunc,
	}); err != nil {
		log.Fatal(err)
	}
}

func Factory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(c)
	if err := b.Setup(ctx, c); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend
}

func Backend(c *logical.BackendConfig) *backend {
	var b backend

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathAuthRenew,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"login"},
		},
		Paths: []*framework.Path{
			&framework.Path{
				Pattern: "login",
				Fields: map[string]*framework.FieldSchema{
					"username": &framework.FieldSchema{
						Type: framework.TypeString,
					},
					"password": &framework.FieldSchema{
						Type: framework.TypeString,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthLogin,
				},
			},
			
			&framework.Path{
				Pattern: "role/" + framework.MatchAllRegex("appname"),
				Fields: map[string]*framework.FieldSchema{
					"policies": &framework.FieldSchema{
						Type: framework.TypeString,
					},
					"appname": &framework.FieldSchema{
					Type:        framework.TypeString,
					},
				},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathAuthPolicy,
					logical.ReadOperation: b.pathAuthPolicyRead,
				},
			},
		},
	}

	return &b
}
func (b *backend) setRoleEntry(ctx context.Context, s logical.Storage, roleName string, role *roleStorageEntry, previousRoleID []string) error {
	if roleName == "" {
		return fmt.Errorf("missing role name")
	}

	if role == nil {
		return fmt.Errorf("nil role")
	}

	

	// Create a storage entry for the role
	entry, err := logical.StorageEntryJSON("role/"+strings.ToLower(roleName), role)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role %q", roleName)
	}

	

	// Save the role entry only after all the validations
	if err = s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// roleEntry reads the role from storage
func (b *backend) roleEntry(ctx context.Context, s logical.Storage, roleName string) (*roleStorageEntry, error) {
	if roleName == "" {
		return nil, fmt.Errorf("missing role_name")
	}

	var role roleStorageEntry

	if entry, err := s.Get(ctx, "role/"+strings.ToLower(roleName)); err != nil {
		return nil, nil
	} else if entry == nil {
		return nil, nil
	} else if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	
	
	role.name = roleName
	
		role.name = strings.ToLower(roleName)
	

	return &role, nil
}


func (b *backend) pathAuthPolicy(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

		b.Logger().Info("Entered Policy Write Function")
		policies := d.Get("policies").(string)
		roleid := d.Get("appname").(string)
		b.Logger().Info("Policies : ",policies)
		b.Logger().Info("ROLE ID : ",roleid)
		policy2 := strings.Split(policies, ",")
		b.Logger().Info("",policy2)
		role := &roleStorageEntry{
			name:              roleid,
			Policies:           policy2,
			
		}

		b.setRoleEntry(ctx, req.Storage, role.name, role, policy2)
		
		return nil,nil
}

func (b *backend) pathAuthPolicyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

		b.Logger().Info("Entered Policy Write Function")
		policies := d.Get("policies").(string)
		aname := d.Get("appname").(string)
		b.Logger().Info("Policies : ",policies)			
		role, _ := b.roleEntry(ctx, req.Storage, aname)
		if role == nil {
			return nil,nil
	}
		b.Logger().Info("Policies : ",role.Policies)
		b.Logger().Info("APp : ",role.name)

		jsonMap := map[string]interface{}{

		"App" : role.name,
		"Policy" : role.Policies,
	}

	//err4 := json.Unmarshal([]byte(jsonStr), &jsonMap)
	//if err4 != nil {
	//	b.Logger().Info("unmarshalling error for json:", err4)
	//}
	resp := &logical.Response{
		Data: jsonMap,
	}
		return resp, nil
}


func (b *backend) pathAuthLogin(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.Logger().Info("Entered Login Function")
	username := d.Get("username").(string)
	password := d.Get("password").(string)
	b.Logger().Info("username: ", username)
	b.Logger().Info("password: ", password)
	cred := make(map[string]string)
	cred["app1"]="app1"
	cred["app2"]="app2"
	policy := make(map[string][]string)
	policy["app1"]=[]string{"log-reader","log-writer"}
	policy["app2"]=[]string{"log-writer"}
	policy["app3"]=[]string{"log-reader"}
	policy["app4"]=[]string{}
	role, _ := b.roleEntry(ctx, req.Storage, username)
	policy_ret := []string{}
	if role != nil {
		policy_ret = []string(role.Policies)		
	} else {
		//policy_ret = []string{"default","test"}
		policy_ret = []string{"default"}
	}
	if password == cred[username] {
			return &logical.Response{
				Auth: &logical.Auth{
					InternalData: map[string]interface{}{
						"secret_value": "abcd1234",
					},
					Policies: policy_ret,//role.Policies,//[]string(policy[aname]),
					LeaseOptions: logical.LeaseOptions{
						TTL:       3000 * time.Second,
						MaxTTL:    600 * time.Minute,
						Renewable: true,
					},
				},
			}, nil
	} else {
		return nil,errors.New("Verification Failed")
	}
}

func (b *backend) pathAuthRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	if req.Auth == nil {
		return nil, errors.New("request auth was nil")
	}

	secretValue := req.Auth.InternalData["secret_value"].(string)
	if secretValue != "abcd1234" {
		return nil, errors.New("internal data does not match")
	}

	return framework.LeaseExtend(30*time.Second, 60*time.Minute, b.System())(ctx, req, d)
}




