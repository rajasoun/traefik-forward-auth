package tfa

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sync"

	"github.com/sirupsen/logrus"
)

var codeStore struct {
	code map[string]string
	sync.Mutex
}

func InitCodeStore() {
	codeStore.code = map[string]string{}
}

// GetUserInfoHandler Handles auth callback request
func (s *Server) GetUserInfoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Logging setup
		logger := s.logger(r, "GetUserInfoHandler", "default", "Handling callback")

		providerName := "oidc"

		// Get provider
		p, err := config.GetConfiguredProvider(providerName)
		if err != nil {
			logger.WithFields(logrus.Fields{
				"error": err,
				// "csrf_cookie": c,
				"provider": providerName,
			}).Warn("Invalid provider in csrf cookie")
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		// TODO: if code is not availible, redirect to login flow

		redirectURI := &url.URL{
			Scheme: r.Header.Get("X-Forwarded-Proto"),
			Host:   r.Host,
			Path:   config.Path,
		}

		cookie, err := r.Cookie(config.CookieName)
		if err != nil {
			logger.Errorf("get Cookie error: %v", err)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		code := getCode(cookie.Value)

		user, err := p.GetUserFromCode(code, redirectURI.String())
		if err != nil {
			logger.Errorf("GetUserFromCode error: %v", err)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		logger.Debug("User ID--------------------------------------------------->" + user.ID)
		logger.Debug("User Email--------------------------------------------------->" + user.Email)
		logger.Debug("User FirstName--------------------------------------------------->" + user.FirstName)
		logger.Debug("User LastName--------------------------------------------------->" + user.LastName)

		if err := json.NewEncoder(w).Encode(user); err != nil {
			logger.Errorf("GetUserFromCode: %v", err)
			http.Error(w, "failed to encode user information", http.StatusInternalServerError)
			return
		}

		logger.WithFields(logrus.Fields{
			"user_Email": user.Email,
			"user_ID":    user.ID,
		}).Infof("Generated auth cookie")
	}
}

func saveCode(cookie string, code string) {
	codeStore.Lock()
	codeStore.code[cookie] = code
	codeStore.Unlock()
}

func getCode(cookie string) string {
	codeStore.Lock()
	code := codeStore.code[cookie]
	codeStore.Unlock()
	return code
}
