package provider

import (
	"context"
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestOAuthProvider_ConfigCopy(t *testing.T) {
	type fields struct {
		Resource string
		Config   *oauth2.Config
		ctx      context.Context
	}
	type args struct {
		redirectURI string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   oauth2.Config
	}{
		{
			name: "test copy config",
			fields: fields{
				Config: &oauth2.Config{},
			},
			args: args{
				redirectURI: "redirectURI",
			},
			want: oauth2.Config{
				RedirectURL: "redirectURI",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OAuthProvider{
				Resource: tt.fields.Resource,
				Config:   tt.fields.Config,
				ctx:      tt.fields.ctx,
			}
			if got := p.ConfigCopy(tt.args.redirectURI); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OAuthProvider.ConfigCopy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuthProvider_OAuthGetLoginURL(t *testing.T) {
	type fields struct {
		Resource string
		Config   *oauth2.Config
		ctx      context.Context
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
			name: "test OAuthGetLoginURL",
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
		{
			name: "test OAuthGetLoginURL no Resource",
			fields: fields{
				Config: &oauth2.Config{},
			},
			args: args{
				redirectURI: "redirectURI",
				state:       "state",
			},
			want: "?client_id=&redirect_uri=redirectURI&response_type=code&state=state",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OAuthProvider{
				Resource: tt.fields.Resource,
				Config:   tt.fields.Config,
				ctx:      tt.fields.ctx,
			}
			if got := p.OAuthGetLoginURL(tt.args.redirectURI, tt.args.state); got != tt.want {
				t.Errorf("OAuthProvider.OAuthGetLoginURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOAuthProvider_OAuthExchangeCode(t *testing.T) {
	type fields struct {
		Resource string
		Config   *oauth2.Config
		ctx      context.Context
	}
	type args struct {
		redirectURI string
		code        string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    *oauth2.Token
		wantErr bool
	}{
		{
			name: "test Unsupported OAuthExchangeCode",
			fields: fields{
				Config:   &oauth2.Config{},
				Resource: "Resource",
				ctx:      context.Background(),
			},
			args: args{
				redirectURI: "http://accounts.google.com",
				code:        "code",
			},
			want:    nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &OAuthProvider{
				Resource: tt.fields.Resource,
				Config:   tt.fields.Config,
				ctx:      tt.fields.ctx,
			}
			got, err := p.OAuthExchangeCode(tt.args.redirectURI, tt.args.code)
			if (err != nil) != tt.wantErr {
				t.Errorf("OAuthProvider.OAuthExchangeCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("OAuthProvider.OAuthExchangeCode() = %v, want %v", got, tt.want)
			}
		})
	}
}
