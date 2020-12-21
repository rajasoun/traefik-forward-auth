package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

// OIDC provider
type OIDC struct {
	IssuerURL    string `long:"issuer-url" env:"ISSUER_URL" description:"Issuer URL"`
	ClientID     string `long:"client-id" env:"CLIENT_ID" description:"Client ID"`
	ClientSecret string `long:"client-secret" env:"CLIENT_SECRET" description:"Client Secret" json:"-"`

	OAuthProvider

	provider               *oidc.Provider
	verifier               *oidc.IDTokenVerifier
	APIResourceURI         string `long:"resource-uri" env:"API_RESOURCE_URI" description:"API resource uri"`
	APIAccessTokenEndpoint string `long:"token-endpoint" env:"API_ACCESS_TOKEN_ENDPOINT" description:"API access token endpoint"`
}

// Name returns the name of the provider
func (o *OIDC) Name() string {
	return "oidc"
}

// Setup performs validation and setup
func (o *OIDC) Setup() error {
	// Check parms
	if o.IssuerURL == "" || o.ClientID == "" || o.ClientSecret == "" {
		return errors.New("providers.oidc.issuer-url, providers.oidc.client-id, providers.oidc.client-secret must be set")
	}

	var err error
	o.ctx = context.Background()

	// Try to initiate provider
	o.provider, err = oidc.NewProvider(o.ctx, o.IssuerURL)
	if err != nil {
		return err
	}

	// Create oauth2 config
	o.Config = &oauth2.Config{
		ClientID:     o.ClientID,
		ClientSecret: o.ClientSecret,
		Endpoint:     o.provider.Endpoint(),

		// "openid" is a required scope for OpenID Connect flows.
		Scopes: []string{oidc.ScopeOpenID, "profile", "email"},
	}

	// Create OIDC verifier
	o.verifier = o.provider.Verifier(&oidc.Config{
		ClientID: o.ClientID,
	})

	return nil
}

// GetLoginURL provides the login url for the given redirect uri and state
func (o *OIDC) GetLoginURL(redirectURI, state string) string {
	return o.OAuthGetLoginURL(redirectURI, state)
}

// ExchangeCode exchanges the given redirect uri and code for a token
func (o *OIDC) ExchangeCode(redirectURI, code string) (string, error) {
	token, err := o.OAuthExchangeCode(redirectURI, code)
	if err != nil {
		return "", err
	}

	// Extract ID token
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return "", errors.New("Missing id_token")
	}

	return rawIDToken, nil
}

// GetUserFromCode provides user information
func (o *OIDC) GetUserFromCode(code, redirectURI string) (User, error) {
	accessToken, err := getAccessToken(o.APIAccessTokenEndpoint, code, o.ClientID, o.ClientSecret, "authorization_code", redirectURI)
	if err != nil {
		return User{}, err
	}

	return getUserInfo(o.APIResourceURI, accessToken)
}

func getAccessToken(APIAccessTokenEndpoint, code, clientID, clientSecret, authorizationCode, redirectURI string) (string, error) {

	url := fmt.Sprintf("%s?code=%s&client_id=%s&client_secret=%s&grant_type=%s&redirect_uri=%s",
		APIAccessTokenEndpoint, code, clientID, clientSecret, authorizationCode, redirectURI)
	resp, err := http.Post(url, "", nil)
	if err != nil {
		return "", fmt.Errorf("access token endpoint post: %w", err)
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("resource endpoint post response read all: \n%s\n error: %w", string(data), err)
	}

	token := struct {
		AccessToken string `json:"access_token"`
	}{}
	err = json.Unmarshal(data, &token)
	if err != nil {
		return "", fmt.Errorf("access token endpoint post json unmarshal: %w", err)
	}
	if token.AccessToken == "" {
		return "", fmt.Errorf("access token empty: %s", string(data))
	}
	return token.AccessToken, nil
}

func getUserInfo(APIResourceURI, accessToken string) (User, error) {
	req, err := http.NewRequest("GET", APIResourceURI, nil)
	if err != nil {
		return User{}, fmt.Errorf("resource endpoint get request: %w", err)
	}
	req.Header.Add("Authorization", "Bearer "+accessToken)

	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return User{}, fmt.Errorf("resource endpoint get client do: %w", err)
	}

	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return User{}, fmt.Errorf("resource endpoint get response read all: \n%s\n error: %w", string(data), err)
	}

	user := User{}
	if err := json.Unmarshal(data, &user); err != nil {
		return User{}, fmt.Errorf("resource endpoint get response unmarshal: \ntoken: %s\n%s\n error: %w", accessToken, string(data), err)
	}
	return user, nil
}

// GetUser uses the given token and returns a complete provider.User object
func (o *OIDC) GetUser(token string) (User, error) {
	var user User

	// Parse & Verify ID Token
	idToken, err := o.verifier.Verify(o.ctx, token)
	if err != nil {
		return user, err
	}

	// Extract custom claims
	if err := idToken.Claims(&user); err != nil {
		return user, err
	}

	return user, nil
}
