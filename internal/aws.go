package tfa

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

// SecretsMgr interface has the methods that are required to access secrets stored in aws
type SecretsMgr interface {
	getAwsSession(secretMgrAccessKey, secretMgrSecretKey, secretMgrRegion string) (secretsmanageriface.SecretsManagerAPI, error)
	getSecret(svc secretsmanageriface.SecretsManagerAPI, secretName string) (string, string, error)
}

type secretsMgr struct{}

func (secretsMgr) getAwsSession(secretMgrAccessKey, secretMgrSecretKey, secretMgrRegion string) (secretsmanageriface.SecretsManagerAPI, error) {
	creds := credentials.NewStaticCredentials(secretMgrAccessKey, secretMgrSecretKey, "")
	_, err := creds.Get()
	if err != nil {
		return nil, err
	}
	cfg := aws.NewConfig().WithRegion(secretMgrRegion).WithCredentials(creds)

	sess, err := session.NewSession(cfg)
	if err != nil {
		return nil, err
	}

	svc := secretsmanager.New(sess,
		aws.NewConfig().WithRegion(secretMgrRegion))

	return svc, nil
}

func (secretsMgr) getSecret(svc secretsmanageriface.SecretsManagerAPI, secretName string) (string, string, error) {
	input := &secretsmanager.GetSecretValueInput{
		SecretId:     aws.String(secretName),
		VersionStage: aws.String("AWSCURRENT"),
	}
	result, err := svc.GetSecretValue(input)
	if err != nil {
		return "", "", err
	}
	if result.SecretString == nil {
		return "", "", fmt.Errorf("secret string empty")
	}

	payload := struct {
		HashKey  string `json:"hash-key,omitempty"`
		BlockKey string `json:"block-key,omitempty"`
	}{}
	if err := json.Unmarshal([]byte(*result.SecretString), &payload); err != nil {
		return "", "", err
	}
	return payload.HashKey, payload.BlockKey, nil
}
