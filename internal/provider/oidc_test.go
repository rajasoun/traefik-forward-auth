package provider

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var mockServer *httptest.Server

func TestOIDC_GetUserFromCode(t *testing.T) {
	teardownSubTest := setupSubTest(t)
	defer teardownSubTest(t)
	type fields struct {
		OAuthProvider          OAuthProvider
		IssuerURL              string
		ClientID               string
		ClientSecret           string
		provider               *oidc.Provider
		verifier               *oidc.IDTokenVerifier
		APIResourceURI         string
		APIAccessTokenEndpoint string
	}
	type args struct {
		code        string
		redirectURI string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    User
		wantErr bool
	}{
		{
			name: "test1",
			fields: fields{
				APIAccessTokenEndpoint: "http://" + mockServer.Listener.Addr().String() + "/path1",
				APIResourceURI:         "http://" + mockServer.Listener.Addr().String() + "/path2",
			},
			args: args{
				code:        "9WFt1LbLRt46ISEfUGiXqVL7JE25Ee2CegwAAAEx",
				redirectURI: "https%3A%2F%2FredirectURI",
			},
			want:    User{ID: "user_id", Email: "user@domain.com"},
			wantErr: false,
		},
		{
			name: "test2",
			fields: fields{
				APIAccessTokenEndpoint: "http://" + mockServer.Listener.Addr().String() + "/err",
				APIResourceURI:         "http://" + mockServer.Listener.Addr().String() + "/err",
			},
			args: args{
				code:        "9WFt1LbLRt46ISEfUGiXqVL7JE25Ee2CegwAAAEx",
				redirectURI: "https%3A%2F%2FredirectURI",
			},
			want:    User{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OIDC{
				OAuthProvider:          tt.fields.OAuthProvider,
				IssuerURL:              tt.fields.IssuerURL,
				ClientID:               tt.fields.ClientID,
				ClientSecret:           tt.fields.ClientSecret,
				provider:               tt.fields.provider,
				verifier:               tt.fields.verifier,
				APIResourceURI:         tt.fields.APIResourceURI,
				APIAccessTokenEndpoint: tt.fields.APIAccessTokenEndpoint,
			}
			got, _, err := o.GetUserFromCode(tt.args.code, tt.args.redirectURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("OIDC.GetUserFromCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OIDC.GetUserFromCode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func setupSubTest(t *testing.T) func(t *testing.T) {
	mockServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Println("Path : ", r.URL.Path)
		if strings.Contains(r.URL.Path, "/path1") {
			w.Write([]byte(`{"access_token":"aodifuvboadifubv"}`))
		}
		if strings.Contains(r.URL.Path, "/path2") {
			w.Write([]byte(`{"sub":"user_id","email":"user@domain.com"}`))
		}
		if strings.Contains(r.URL.Path, "/err") {
		}
	}))
	return func(t *testing.T) {}
}

func teardownSubTest(t *testing.T) func(t *testing.T) {
	defer mockServer.Close()
	return func(t *testing.T) {}
}

func TestOIDC_Setup(t *testing.T) {
	type fields struct {
		IssuerURL              string
		ClientID               string
		ClientSecret           string
		OAuthProvider          OAuthProvider
		provider               *oidc.Provider
		verifier               *oidc.IDTokenVerifier
		APIResourceURI         string
		APIAccessTokenEndpoint string
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name:    "test_setup_empty",
			fields:  fields{},
			wantErr: true,
		},
		{
			name: "test_setup_invalid",
			fields: fields{
				IssuerURL:    "IssuerURL",
				ClientID:     "ClientID",
				ClientSecret: "ClientSecret",
			},
			wantErr: true,
		},
		{
			name: "test_setup_all_val",
			fields: fields{
				IssuerURL:    "https://accounts.google.com",
				ClientID:     "ClientID",
				ClientSecret: "ClientSecret",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OIDC{
				IssuerURL:              tt.fields.IssuerURL,
				ClientID:               tt.fields.ClientID,
				ClientSecret:           tt.fields.ClientSecret,
				OAuthProvider:          tt.fields.OAuthProvider,
				provider:               tt.fields.provider,
				verifier:               tt.fields.verifier,
				APIResourceURI:         tt.fields.APIResourceURI,
				APIAccessTokenEndpoint: tt.fields.APIAccessTokenEndpoint,
			}
			if err := o.Setup(); (err != nil) != tt.wantErr {
				t.Errorf("OIDC.Setup() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOIDC_Name(t *testing.T) {
	type fields struct {
		IssuerURL              string
		ClientID               string
		ClientSecret           string
		OAuthProvider          OAuthProvider
		provider               *oidc.Provider
		verifier               *oidc.IDTokenVerifier
		APIResourceURI         string
		APIAccessTokenEndpoint string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name:   "test Name",
			fields: fields{},
			want:   "oidc",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OIDC{
				IssuerURL:              tt.fields.IssuerURL,
				ClientID:               tt.fields.ClientID,
				ClientSecret:           tt.fields.ClientSecret,
				OAuthProvider:          tt.fields.OAuthProvider,
				provider:               tt.fields.provider,
				verifier:               tt.fields.verifier,
				APIResourceURI:         tt.fields.APIResourceURI,
				APIAccessTokenEndpoint: tt.fields.APIAccessTokenEndpoint,
			}
			if got := o.Name(); got != tt.want {
				t.Errorf("OIDC.Name() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOIDC_GetLoginURL(t *testing.T) {
	type fields struct {
		IssuerURL              string
		ClientID               string
		ClientSecret           string
		OAuthProvider          OAuthProvider
		provider               *oidc.Provider
		verifier               *oidc.IDTokenVerifier
		APIResourceURI         string
		APIAccessTokenEndpoint string
		Resource               string
		Config                 *oauth2.Config
	}
	type args struct {
		redirectURI string
		state       string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   string
	}{
		{
			name: "",
			fields: fields{
				Config:   &oauth2.Config{},
				Resource: "Resource",
			},
			args: args{
				redirectURI: "redirectURI",
				state:       "state",
			},
			want: "?client_id=&redirect_uri=redirectURI&resource=Resource&response_type=code&state=state",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &OIDC{
				IssuerURL:    tt.fields.IssuerURL,
				ClientID:     tt.fields.ClientID,
				ClientSecret: tt.fields.ClientSecret,
				OAuthProvider: OAuthProvider{
					Resource: tt.fields.Resource,
					Config:   tt.fields.Config,
				},
				provider:               tt.fields.provider,
				verifier:               tt.fields.verifier,
				APIResourceURI:         tt.fields.APIResourceURI,
				APIAccessTokenEndpoint: tt.fields.APIAccessTokenEndpoint,
			}
			if got := o.GetLoginURL(tt.args.redirectURI, tt.args.state); got != tt.want {
				t.Errorf("OIDC.GetLoginURL() = %v, want %v", got, tt.want)
			}
		})
	}
}
