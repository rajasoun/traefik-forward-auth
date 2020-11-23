package tfa

import (
	"reflect"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestNewDefaultLogger(t *testing.T) {
	tests := []struct {
		name   string
		want   logrus.Level
		fmtr   logrus.Formatter
		config *Config
	}{
		{
			name: "test_prettyFormatter",
			want: logrus.DebugLevel,
			fmtr: &logrus.TextFormatter{
				DisableColors: true,
				FullTimestamp: true,
			},
			config: &Config{
				LogFormat: "pretty",
				LogLevel:  "debug",
			},
		},
		{
			name: "test_JSONFormatter",
			want: logrus.DebugLevel,
			fmtr: &logrus.JSONFormatter{},
			config: &Config{
				LogFormat: "json",
				LogLevel:  "debug",
			},
		},
		{
			name: "test_default",
			want: logrus.DebugLevel,
			fmtr: &logrus.TextFormatter{
				DisableColors: true,
				FullTimestamp: true,
			},
			config: &Config{
				LogFormat: "default",
				LogLevel:  "debug",
			},
		},
		{
			name: "test_log_level_trace",
			want: logrus.TraceLevel,
			fmtr: &logrus.JSONFormatter{},
			config: &Config{
				LogFormat: "json",
				LogLevel:  "trace",
			},
		},
		{
			name: "test_log_level_info",
			want: logrus.InfoLevel,
			fmtr: &logrus.JSONFormatter{},
			config: &Config{
				LogFormat: "json",
				LogLevel:  "info",
			},
		},
		{
			name: "test_log_level_error",
			want: logrus.ErrorLevel,
			fmtr: &logrus.JSONFormatter{},
			config: &Config{
				LogFormat: "json",
				LogLevel:  "error",
			},
		},
		{
			name: "test_log_level_fatal",
			want: logrus.FatalLevel,
			fmtr: &logrus.JSONFormatter{},
			config: &Config{
				LogFormat: "json",
				LogLevel:  "fatal",
			},
		},
		{
			name: "test_log_level_panic",
			want: logrus.PanicLevel,
			fmtr: &logrus.JSONFormatter{},
			config: &Config{
				LogFormat: "json",
				LogLevel:  "panic",
			},
		},
		{
			name: "test_log_level_default",
			want: logrus.WarnLevel,
			fmtr: &logrus.JSONFormatter{},
			config: &Config{
				LogFormat: "json",
				LogLevel:  "default",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config = tt.config
			if got := NewDefaultLogger(); !reflect.DeepEqual(got.Level, tt.want) ||
				reflect.TypeOf(got.Formatter) != reflect.TypeOf(tt.fmtr) {
				t.Errorf("NewDefaultLogger() = %v, want %v", got.Level, tt.want)
			}
		})
	}
}
