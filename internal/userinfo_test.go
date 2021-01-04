package tfa

import (
	"strings"
	"testing"
)

func Test_saveAccessToken(t *testing.T) {
	InitCodeStore()
	type args struct {
		cookie string
		code   string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test saveAccessToken",
			args: args{
				cookie: "test_cookie",
				code:   "test_code",
			},
			want: "test_code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveAccessToken(tt.args.cookie, tt.args.code)
			if strings.Compare(accessTokenStore.tokens[tt.args.cookie], tt.want) != 0 {
				t.Errorf("saveAccessToken() want : %v, got : %v", tt.want, accessTokenStore.tokens[tt.args.cookie])
			}
		})
	}
}

func Test_getAccessToken(t *testing.T) {
	InitCodeStore()
	type args struct {
		cookie string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test getAccessToken",
			args: args{
				cookie: "test_cookie",
			},
			want: "test_code",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saveAccessToken(tt.args.cookie, tt.want)
			if got := getAccessToken(tt.args.cookie); got != tt.want {
				t.Errorf("getAccessToken() = %v, want %v", got, tt.want)
			}
		})
	}
}
