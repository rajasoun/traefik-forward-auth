package tfa

import (
	"net/http"
	"reflect"
	"testing"

	"github.com/containous/traefik/v2/pkg/rules"
	"github.com/sirupsen/logrus"
)

var (
	reqSrv *http.Request
)

func setupTestServer(t *testing.T) func(t *testing.T) {
	reqSrv, _ = http.NewRequest("GET", "http://domain.com", nil)
	reqSrv.Header.Set("X-Forwarded-Method", "method")
	reqSrv.Header.Set("X-Forwarded-Proto", "proto")
	reqSrv.Header.Set("X-Forwarded-Host", "host")
	reqSrv.Header.Set("X-Forwarded-Uri", "uri")
	reqSrv.Header.Set("X-Forwarded-For", "source_ip")
	reqSrv.AddCookie(&http.Cookie{Name: "test_cookie", Value: "test_cookie"})
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
