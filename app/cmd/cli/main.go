package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
)

type RequestPayload struct {
	User     string `json:"user"`
	Role     string `json:"role"`
	Reason   string `json:"reason"`
	Duration string `json:"duration"`
}

type RequestResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "request":
		handleRequest()
	case "login":
		handleLogin()
	case "logout":
		handleLogout()
	case "whoami":
		handleWhoami()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown subcommand: %s\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

func handleRequest() {
	fs := flag.NewFlagSet("request", flag.ExitOnError)
	role := fs.String("role", "", "Role to request access for")
	duration := fs.String("duration", "", "Duration for the access (e.g., 1h, 30m)")
	reason := fs.String("reason", "", "Reason for the access request")

	fs.Parse(os.Args[2:])

	if *role == "" || *duration == "" {
		fmt.Fprintf(os.Stderr, "Error: --role and --duration are required\n")
		fs.PrintDefaults()
		os.Exit(1)
	}

	// Stored OIDC token takes priority over env var.
	rawToken, _ := loadStoredToken()
	if rawToken == "" {
		rawToken = os.Getenv("POLICY_ENGINE_TOKEN")
	}

	// Derive user identity from OIDC token sub when available.
	userIdentity := jwtSub(rawToken)

	// Fall back to kubeconfig identity (and kubeconfig token) when no OIDC token.
	if userIdentity == "" {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				log.Fatalf("Failed to get home directory: %v", err)
			}
			kubeconfig = filepath.Join(home, ".kube", "config")
		}

		cfg, err := clientcmd.LoadFromFile(kubeconfig)
		if err != nil {
			log.Fatalf("Failed to load kubeconfig: %v", err)
		}

		currentContext := cfg.CurrentContext
		if currentContext == "" {
			log.Fatal("No current context set in kubeconfig")
		}

		ctx := cfg.Contexts[currentContext]
		if ctx == nil {
			log.Fatalf("Context %s not found", currentContext)
		}

		authInfo := cfg.AuthInfos[ctx.AuthInfo]
		if authInfo == nil {
			log.Fatalf("AuthInfo for context %s not found", currentContext)
		}

		userIdentity = ctx.AuthInfo
		if rawToken == "" {
			rawToken = authInfo.Token
		}
	}

	if userIdentity == "" {
		userIdentity = "unknown-user"
	}

	backendURL := os.Getenv("POLICY_ENGINE_URL")
	if backendURL == "" {
		backendURL = "http://localhost:8080"
	}

	payload := RequestPayload{
		User:     userIdentity,
		Role:     *role,
		Reason:   *reason,
		Duration: *duration,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		log.Fatalf("Failed to marshal request: %v", err)
	}

	authHeader := ""
	if rawToken != "" {
		authHeader = fmt.Sprintf("Bearer %s", rawToken)
	}

	req, err := http.NewRequest("POST", backendURL+"/request", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Fatalf("Failed to create HTTP request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Failed to send request to policy engine: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode == http.StatusAccepted || resp.StatusCode == http.StatusOK {
		var response RequestResponse
		if err := json.Unmarshal(body, &response); err != nil {
			log.Fatalf("Failed to parse response: %v", err)
		}

		fmt.Printf("Request submitted (ID: %s).\n", response.ID)
		fmt.Printf("Status: %s.\n", response.Status)
		fmt.Println("Please wait for administrator approval.")
	} else {
		fmt.Fprintf(os.Stderr, "Error from policy engine (status %d): %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}
}

func jwtSub(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return ""
	}
	return claims.Sub
}

func handleLogin() {
	serverURL := os.Getenv("POLICY_ENGINE_URL")
	if serverURL == "" {
		serverURL = "http://localhost:8080"
	}
	if err := login(serverURL); err != nil {
		fmt.Fprintf(os.Stderr, "Login error: %v\n", err)
		os.Exit(1)
	}
}

func handleLogout() {
	if err := logout(); err != nil {
		fmt.Fprintf(os.Stderr, "Logout error: %v\n", err)
		os.Exit(1)
	}
}

func handleWhoami() {
	if err := whoami(); err != nil {
		fmt.Fprintf(os.Stderr, "Whoami error: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `kubectl-access - Just-In-Time Kubernetes Access Plugin

Usage:
  kubectl access <subcommand> [options]

Subcommands:
  login        Authenticate via Keycloak device flow (stores token in ~/.config/kubectl-access/token)
  logout       Remove the stored OIDC token
  whoami       Print the identity from the stored OIDC token
  request      Request temporary access to a Kubernetes role
  help         Show this help message

Options for request:
  --role       The Kubernetes role to request access for (required)
  --duration   How long to grant access (e.g., 1h, 30m, 5m) (required)
  --reason     Reason for the access request (optional)

Environment Variables:
  KUBECONFIG        Path to kubeconfig file (defaults to ~/.kube/config)
  POLICY_ENGINE_URL URL of the policy engine (defaults to http://localhost:8080)

Examples:
  kubectl access login
  kubectl access whoami
  kubectl access request --role=restricted-developer --duration=1h --reason="Debugging issue in prod"
  kubectl access request --role=admin --duration=30m
`)
}
