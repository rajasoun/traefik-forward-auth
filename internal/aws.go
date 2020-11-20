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

func getAwsSession(secretMgrAccessKey, secretMgrSecretKey, secretMgrRegion string) (*session.Session, error) {
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
	return sess, nil
}

func getSecret(svc secretsmanageriface.SecretsManagerAPI, secretName string) (string, string, error) {
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
