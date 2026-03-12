package providers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/LCGant/role-auth/internal/config"
	"golang.org/x/oauth2"
)

type SpotifyProvider struct {
	Config *oauth2.Config
}

type SpotifyProfile struct {
	ID    string
	Email string
}

func NewSpotify(cfg config.OAuthProviderConfig) *SpotifyProvider {
	return &SpotifyProvider{
		Config: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURL,
			Endpoint: oauth2.Endpoint{
				AuthURL:  "https://accounts.spotify.com/authorize",
				TokenURL: "https://accounts.spotify.com/api/token",
			},
			Scopes: []string{"user-read-email"},
		},
	}
}

func (p *SpotifyProvider) AuthCodeURL(state, codeChallenge string) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	return p.Config.AuthCodeURL(state, opts...)
}

func (p *SpotifyProvider) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	return p.Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
}

func (p *SpotifyProvider) Profile(ctx context.Context, token *oauth2.Token) (*SpotifyProfile, error) {
	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(token))
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.spotify.com/v1/me", nil)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("spotify profile: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spotify profile status %d", resp.StatusCode)
	}
	var data struct {
		ID    string `json:"id"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("decode profile: %w", err)
	}
	return &SpotifyProfile{ID: data.ID, Email: data.Email}, nil
}
