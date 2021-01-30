package tfa

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/containous/traefik/v2/pkg/rules"
	"github.com/rajasoun/traefik-forward-auth/internal/provider"
	"github.com/sirupsen/logrus"
	"golang.org/x/oauth2"
)

var (
	reqSrv *http.Request
	router *rules.Router
)

func setupTestServer(t *testing.T) func(t *testing.T) {
	reqSrv, _ = http.NewRequest("GET", "http://domain.com", nil)
	reqSrv.Header.Set("X-Forwarded-Method", "method")
	reqSrv.Header.Set("X-Forwarded-Proto", "proto")
	reqSrv.Header.Set("X-Forwarded-Host", "host")
	reqSrv.Header.Set("X-Forwarded-Uri", "uri")
	reqSrv.Header.Set("X-Forwarded-For", "source_ip")
	reqSrv.AddCookie(&http.Cookie{Name: "test_cookie", Value: "test_cookie"})
	router, _ = rules.NewRouter()
	return func(t *testing.T) {}
}

func TestServer_logger(t *testing.T) {
	setupTestServer(t)
	type fields struct {
		router *rules.Router
	}
	type args struct {
		r       *http.Request
		handler string
		rule    string
		msg     string
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *logrus.Entry
	}{
		{
			name:   "test logger",
			fields: fields{},
			args: args{
				r:       reqSrv,
				handler: "handler",
				rule:    "rule",
				msg:     "msg",
			},
			want: logrus.StandardLogger().WithFields(logrus.Fields{
				"handler":   "handler",
				"rule":      "rule",
				"method":    "method",
				"proto":     "proto",
				"host":      "host",
				"uri":       "uri",
				"source_ip": "source_ip",
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log = logrus.StandardLogger()
			s := &Server{
				router: tt.fields.router,
			}
			if got := s.logger(tt.args.r, tt.args.handler, tt.args.rule, tt.args.msg); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Server.logger() = \n%+v, want \n%+v", got, tt.want)
			}
		})
	}
}

func TestNewServer(t *testing.T) {
	setupTestServer(t)
	type fields struct {
		config *Config
	}
	tests := []struct {
		name   string
		want   *Server
		fields fields
	}{
		{
			name: "test server config1",
			want: &Server{},
			fields: fields{
				config: &Config{
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
					},
					DefaultAction: "allow",
				},
			},
		},
		{
			name: "test server config2",
			want: &Server{},
			fields: fields{
				config: &Config{
					Rules: map[string]*Rule{
						"1": {
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
					},
				},
			},
		},
	}
	for _, tt := range tests {
		config = tt.fields.config
		t.Run(tt.name, func(t *testing.T) {
			if got := NewServer(); got == nil {
				t.Errorf("NewServer() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServer_RootHandler(t *testing.T) {
	setupTestServer(t)
	type fields struct {
		router *rules.Router
	}
	type args struct {
		w http.ResponseWriter
		r *http.Request
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "test RootHandler",
			args: args{
				r: reqSrv,
				w: httptest.NewRecorder(),
			},
			fields: fields{
				router: router,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				router: tt.fields.router,
			}
			s.RootHandler(tt.args.w, tt.args.r)
		})
	}
}

func TestServer_authRedirect(t *testing.T) {
	setupTestServer(t)
	type fields struct {
		router *rules.Router
		config *Config
	}
	type args struct {
		logger *logrus.Entry
		w      http.ResponseWriter
		r      *http.Request
		p      provider.Provider
	}
	tests := []struct {
		name   string
		fields fields
		args   args
	}{
		{
			name: "test authRedirect",
			fields: fields{
				router: router,
				config: &Config{
					CSRFCookieName: "_forward_auth_csrf",
				},
			},
			args: args{
				r: reqSrv,
				w: httptest.NewRecorder(),
				logger: logrus.StandardLogger().WithFields(logrus.Fields{
					"handler":   "handler",
					"rule":      "rule",
					"method":    "method",
					"proto":     "proto",
					"host":      "host",
					"uri":       "uri",
					"source_ip": "source_ip",
				}),
				p: &provider.OIDC{
					OAuthProvider: provider.OAuthProvider{
						Config: &oauth2.Config{},
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				router: tt.fields.router,
			}
			config = tt.fields.config
			s.authRedirect(tt.args.logger, tt.args.w, tt.args.r, tt.args.p, "")
		})
	}
}
