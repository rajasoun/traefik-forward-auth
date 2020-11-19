package tfa

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/gorilla/securecookie"
)

func TestMakeUserCookie(t *testing.T) {
	req, _ := http.NewRequest("GET", "http://domain.com", nil)
	fmt.Println(req)

	config = &Config{
		CookieHashKey:  cookieHashKey,
		CookieBlockKey: cookieBlockKey,
		UserInfoCookie: userInfoCookie,
	}

	cookie := &http.Cookie{
		Name:  config.UserInfoCookie,
		Value: "test_user_info",
	}

	type args struct {
		r        *http.Request
		userInfo string
	}
	tests := []struct {
		name string
		args args
		want *http.Cookie
	}{
		{
			name: "test_make_user_cookie_data",
			args: args{r: req, userInfo: "test_user_info"},
			want: cookie,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MakeUserCookie(tt.args.r, tt.args.userInfo); !compareCookie(got, tt.want) {
				t.Errorf("MakeUserCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}

func compareCookie(got, want *http.Cookie) bool {
	var s = securecookie.New([]byte(cookieHashKey), []byte(cookieBlockKey))
	if strings.Compare(got.Name, want.Name) != 0 {
		return false
	}
	value := ""
	if err := s.Decode(userInfoCookie, got.Value, &value); err == nil && !strings.Contains(value, want.Value) {
		return false
	}
	return true
}

var (
	cookieHashKey  string = "AMC7VVW06NF6NG1BN8WGQR4GGSHYHMKN"
	cookieBlockKey string = "R78IRDN6920MJPE2RD7MFQ9Y2GN5AKTJ"
	userInfoCookie string = "_user_info"
)
