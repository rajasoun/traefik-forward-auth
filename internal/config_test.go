package tfa

import (
	"os"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

func TestNewConfig(t *testing.T) {

	os.Setenv("PROVIDERS_OIDC_ISSUER_URL", "")
	os.Setenv("PROVIDERS_OIDC_CLIENT_ID", "")
	os.Setenv("PROVIDERS_OIDC_CLIENT_SECRET", "")

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
			name: "empty args",
			args: args{},
			want: &Config{
				LogLevel:        "warn",
				LogFormat:       "text",
				CookieName:      "_forward_auth",
				UserInfoCookie:  "_user_info",
				CSRFCookieName:  "_forward_auth_csrf",
				DefaultAction:   "auth",
				DefaultProvider: "oidc",
				LifetimeString:  43200,
				Path:            "/_oauth",
				Lifetime:        43200000000000,
				Rules:           map[string]*Rule{},
			},
			wantErr: false,
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
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewConfig() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockSecretsMgr struct{}

func (mockSecretsMgr) getAwsSession(secretMgrAccessKey, secretMgrSecretKey, secretMgrRegion string) (secretsmanageriface.SecretsManagerAPI, error) {
	return &secretsmanager.SecretsManager{}, nil
}
func (mockSecretsMgr) getSecret(svc secretsmanageriface.SecretsManagerAPI, secretName string) (string, string, error) {
	return "", "", nil
}
