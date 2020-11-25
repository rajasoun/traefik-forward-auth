package tfa

import (
	"fmt"
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

func TestNewConfig(t *testing.T) {
	setup(t)
	type args struct {
		args []string
	}
	tests := []struct {
		name    string
		args    args
		want    *Config
		wantErr bool
	}{
		{
			name: "test empty args",
			args: args{},
			want: &Config{
				LogLevel:        "warn",
				LogFormat:       "text",
				CookieName:      "_forward_auth",
				UserInfoCookie:  "_user_info",
				CSRFCookieName:  "_forward_auth_csrf",
				DefaultAction:   "auth",
				DefaultProvider: "google",
				LifetimeString:  43200,
				Path:            "/_oauth",
				Lifetime:        43200000000000,
				Rules:           map[string]*Rule{},
			},
			wantErr: false,
		},
		{
			name: "test args",
			args: args{[]string{
				"--cookie-name=cookiename",
				"--csrf-cookie-name", "\"csrfcookiename\"",
				"--default-provider", "\"oidc\"",
				"--rule.1.action=allow",
				"--rule.1.rule=PathPrefix(`/one`)",
				"--rule.1.provider=test_provider",
				"--rule.1.whitelist=test3.com,example.org",
				"--rule.1.domains=test2.com,example.org",
				"--rule.two.action=auth",
				"--rule.two.rule=\"Host(`two.com`) && Path(`/two`)\"",
			}},
			want: &Config{
				LogLevel:        "warn",
				LogFormat:       "text",
				AuthHost:        "",
				CookieName:      "cookiename",
				UserInfoCookie:  "_user_info",
				CSRFCookieName:  "csrfcookiename",
				DefaultAction:   "auth",
				DefaultProvider: "oidc",
				LifetimeString:  43200,
				LogoutRedirect:  "",
				Path:            "/_oauth",
				Rules: map[string]*Rule{
					"1": {
						Action:   "allow",
						Rule:     "PathPrefix(`/one`)",
						Provider: "test_provider",
						Whitelist: []string{
							"test3.com",
							"example.org",
						},
						Domains: []string{
							"test2.com",
							"example.org",
						},
					},
					"two": {
						Action:   "auth",
						Rule:     "Host(`two.com`) \u0026\u0026 Path(`/two`)",
						Provider: "oidc",
					},
				},
				Lifetime: 43200000000000,
			},
			wantErr: false,
		},
		{
			name: "test invalid route param",
			args: args{[]string{
				"--cookie-name=cookiename",
				"--csrf-cookie-name", "\"csrfcookiename\"",
				"--default-provider", "\"oidc\"",
				"--rule.two.invalid=auth",
			}},
			want:    &Config{},
			wantErr: true,
		},
		{
			name: "test no route param value",
			args: args{[]string{
				"--cookie-name=cookiename",
				"--csrf-cookie-name", "\"csrfcookiename\"",
				"--default-provider", "\"oidc\"",
				"--rule.1.action=",
			}},
			want:    &Config{},
			wantErr: true,
		},
		{
			name: "test no route name",
			args: args{[]string{
				"--cookie-name=cookiename",
				"--csrf-cookie-name", "\"csrfcookiename\"",
				"--default-provider", "\"oidc\"",
				"--rule..=abc",
			}},
			want:    &Config{},
			wantErr: true,
		},
		{
			name: "test unknown flag",
			args: args{[]string{
				"--cookie-name=cookiename",
				"--csrf-cookie-name", "\"csrfcookiename\"",
				"--default-provider", "\"oidc\"",
				"--xyz..=abc",
			}},
			want:    &Config{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secMgr := mockSecretsMgr{}
			got, err := NewConfig(tt.args.args, secMgr)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(fmt.Sprintf("%v", got), fmt.Sprintf("%v", tt.want)) && !tt.wantErr {
				t.Errorf("NewConfig() = \n\n %v, \n\nwant %v", fmt.Sprintf("%v", got), tt.want)
			}
		})
	}
}

func setup(t *testing.T) {
	os.Setenv("PROVIDERS_OIDC_ISSUER_URL", "")
	os.Setenv("PROVIDERS_OIDC_CLIENT_ID", "")
	os.Setenv("PROVIDERS_OIDC_CLIENT_SECRET", "")
	os.Setenv("DEFAULT_PROVIDER", "google")
}

type mockSecretsMgr struct{}

func (mockSecretsMgr) getAwsSession(secretMgrAccessKey, secretMgrSecretKey, secretMgrRegion string) (secretsmanageriface.SecretsManagerAPI, error) {
	return &secretsmanager.SecretsManager{}, nil
}
func (mockSecretsMgr) getSecret(svc secretsmanageriface.SecretsManagerAPI, secretName string) (string, string, error) {
	return "", "", nil
}
