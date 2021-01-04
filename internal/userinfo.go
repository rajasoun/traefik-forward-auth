package tfa

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/sirupsen/logrus"
)

var accessTokenStore struct {
	tokens map[string]string
	sync.Mutex
}

// InitCodeStore initialiazes tge code store
func InitCodeStore() {
	accessTokenStore.tokens = map[string]string{}
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

		cookie, err := r.Cookie(config.CookieName)
		if err != nil {
			logger.Errorf("get Cookie error: %v", err)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}
		accessToken := getAccessToken(cookie.Value)

		user, err := p.GetUserInfo(accessToken)
		if err != nil {
			logger.Errorf("GetUserFromCode error: %v", err)
			http.Error(w, "Not authorized", http.StatusUnauthorized)
			return
		}

		logger.Debugf("User : %+v",user)

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

func saveAccessToken(cookie string, code string) {
	accessTokenStore.Lock()
	accessTokenStore.tokens[cookie] = code
	accessTokenStore.Unlock()
}

func getAccessToken(cookie string) string {
	accessTokenStore.Lock()
	code := accessTokenStore.tokens[cookie]
	accessTokenStore.Unlock()
	return code
}
