package tfa

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
)

func getAwsSession(secretMgrAccessKey, secretMgrSecretKey, secretMgrRegion string) (*session.Session, error) {
	creds := credentials.NewStaticCredentials(secretMgrAccessKey, secretMgrSecretKey, "")

	_, err := creds.Get()
	if err != nil {
		fmt.Printf("bad credentials: %s", err)
		return nil, err
	}
	cfg := aws.NewConfig().WithRegion(secretMgrRegion).WithCredentials(creds)

	sess, err := session.NewSession(cfg)
	if err != nil {
		fmt.Println("session failed:", err)
		return nil, err
	}
	return sess, nil
}

func getSecret(sess *session.Session, secretName, secretMgrRegion string) (string, string, error) {
	// Create a Secrets Manager client
	svc := secretsmanager.New(sess,
		aws.NewConfig().WithRegion(secretMgrRegion))
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
