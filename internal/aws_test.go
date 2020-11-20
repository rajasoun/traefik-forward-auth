package tfa

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

func Test_getAwsSession(t *testing.T) {
	creds := credentials.NewStaticCredentials(secretMgrAccessKey, secretMgrSecretKey, "")
	_, err := creds.Get()
	if err != nil {
		fmt.Printf("bad credentials: %s", err)
	}
	cfg := aws.NewConfig().WithRegion(secretMgrRegion).WithCredentials(creds)
	sess, err := session.NewSession(cfg)
	if err != nil {
		fmt.Println("session failed:", err)
	}

	type args struct {
		secretMgrAccessKey string
		secretMgrSecretKey string
		secretMgrRegion    string
	}
	tests := []struct {
		name    string
		args    args
		want    *session.Session
		wantErr bool
	}{
		{
			name: "test create config for session",
			args: args{
				secretMgrAccessKey: secretMgrAccessKey,
				secretMgrSecretKey: secretMgrSecretKey,
				secretMgrRegion:    secretMgrRegion,
			},
			want:    sess,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getAwsSession(tt.args.secretMgrAccessKey, tt.args.secretMgrSecretKey, tt.args.secretMgrRegion)
			if (err != nil) != tt.wantErr {
				t.Errorf("getAwsSession() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.Config, tt.want.Config) {
				t.Errorf("\n\n getAwsSession() = %+v, \n\n want %v", got, tt.want)
			}
		})
	}
}

func Test_getSecret(t *testing.T) {
	mockSvc := &mockSecretsManagerClient{}

	type args struct {
		svc        secretsmanageriface.SecretsManagerAPI
		secretName string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		want1   string
		wantErr bool
	}{
		{
			name: "",
			args: args{
				svc:        mockSvc,
				secretName: secretName,
			},
			want:    "HashKey",
			want1:   "BlockKey",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := getSecret(tt.args.svc, tt.args.secretName)
			if (err != nil) != tt.wantErr {
				t.Errorf("getSecret() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getSecret() got = %v, want %v", got, tt.want)
			}
			if got1 != tt.want1 {
				t.Errorf("getSecret() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}

var (
	secretMgrAccessKey string = "AMC7VVW06NF6NG1BN8WGQR4GGSHYHMKN"
	secretMgrSecretKey string = "R78IRDN6920MJPE2RD7MFQ9Y2GN5AKTJ"
	secretMgrRegion    string = "us-east-1"
	secretName         string = "traefik-forward-auth"
)

type mockSecretsManagerClient struct {
	secretsmanageriface.SecretsManagerAPI
}

func (m *mockSecretsManagerClient) GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	payload := `{"hash-key":"HashKey","block-key":"BlockKey"}`
	return &secretsmanager.GetSecretValueOutput{SecretString: &payload}, nil
}
