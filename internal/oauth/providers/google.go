package providers

import (
	"context"
	"fmt"

	"github.com/LCGant/role-auth/internal/config"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type GoogleProvider struct {
	Config   *oauth2.Config
	Verifier *oidc.IDTokenVerifier
}

type GoogleProfile struct {
	Subject       string
	Email         string
	EmailVerified bool
}

func NewGoogle(ctx context.Context, cfg config.OAuthProviderConfig) (*GoogleProvider, error) {
	oidcProvider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("oidc provider: %w", err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     google.Endpoint,
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}

	verifier := oidcProvider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	return &GoogleProvider{Config: oauthConfig, Verifier: verifier}, nil
}

func (g *GoogleProvider) AuthCodeURL(state, codeChallenge, nonce string) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("response_type", "code"),
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oidc.Nonce(nonce),
	}
	return g.Config.AuthCodeURL(state, opts...)
}

func (g *GoogleProvider) Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error) {
	return g.Config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
}

func (g *GoogleProvider) VerifyIDToken(ctx context.Context, token *oauth2.Token, nonce string) (*GoogleProfile, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, fmt.Errorf("id_token missing in token response")
	}
	idToken, err := g.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if idToken.Nonce != nonce {
		return nil, fmt.Errorf("nonce mismatch")
	}
	var claims struct {
		Subject       string `json:"sub"`
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode claims: %w", err)
	}
	return &GoogleProfile{
		Subject:       claims.Subject,
		Email:         claims.Email,
		EmailVerified: claims.EmailVerified,
	}, nil
}
