package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/google/go-github/v62/github"
)

type WebhookPayload struct {
	Action      string `json:"action"`
	PullRequest struct {
		Number  int    `json:"number"`
		DiffURL string `json:"diff_url"`
	} `json:"pull_request"`
	Repository struct {
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
		Name string `json:"name"`
	} `json:"repository"`
}

type DeepseekRequest struct {
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Model string `json:"model"`
}

type DeepseekResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
}

func main() {
	http.HandleFunc("/webhook", handleWebhook)
	fmt.Println("Server starting on :8080...")
	http.ListenAndServe(":8080", nil)
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	secret := []byte(os.Getenv("WEBHOOK_SECRET"))
	payload, err := verifyWebhookSignature(r, secret)
	if err != nil {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	eventType := r.Header.Get("X-GitHub-Event")
	switch eventType {
	case "ping":
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Ping received")
		return
	case "pull_request":
		var wp WebhookPayload
		if err := json.Unmarshal(payload, &wp); err != nil {
			http.Error(w, "Invalid payload", http.StatusBadRequest)
			return
		}

		if wp.Action != "opened" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Ignored non-opened action")
			return
		}

		diff, err := fetchPRDiff(wp.PullRequest.DiffURL)
		if err != nil {
			log.Printf("Error fetching diff: %v", err)
			http.Error(w, "Failed to fetch diff", http.StatusInternalServerError)
			return
		}

		review, err := getAIReview(diff)
		if err != nil {
			log.Printf("Error getting AI review: %v", err)
			http.Error(w, "AI review failed", http.StatusInternalServerError)
			return
		}

		if err := postGitHubComment(wp, review); err != nil {
			log.Printf("Error posting comment: %v", err)
			http.Error(w, "Failed to post comment", http.StatusInternalServerError)
			return
		}

		fmt.Fprint(w, "Review posted successfully")
	default:
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Ignored event type")
	}
}

func verifyWebhookSignature(r *http.Request, secret []byte) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	sig := r.Header.Get("X-Hub-Signature-256")
	if sig == "" {
		return nil, fmt.Errorf("missing signature")
	}

	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	expected := "sha256=" + fmt.Sprintf("%x", mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return nil, fmt.Errorf("signature mismatch")
	}

	return body, nil
}

func fetchPRDiff(diffURL string) (string, error) {
	resp, err := http.Get(diffURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return string(body), err
}

func getAIReview(diff string) (string, error) {
	prompt := fmt.Sprintf("Review the following Go code diff for errors, concurrency issues, and idiomatic practices. Provide specific suggestions for improvement:\n\n```diff\n%s\n```", diff)
	reqBody := DeepseekRequest{
		Messages: []struct {
			Role    string `json:"role"`
			Content string `json:"content"`
		}{
			{Role: "user", Content: prompt},
		},
		Model: "deepseek-r1",
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal failed: %w", err)
	}

	req, err := http.NewRequest("POST", "https://api.deepseek.com/v1/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("DEEPSEEK_API_KEY"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("API status %d: %s", resp.StatusCode, string(body))
	}

	var deepseekResp DeepseekResponse
	if err := json.NewDecoder(resp.Body).Decode(&deepseekResp); err != nil {
		return "", fmt.Errorf("decode failed: %w", err)
	}

	if len(deepseekResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in response")
	}

	return deepseekResp.Choices[0].Message.Content, nil
}

func postGitHubComment(wp WebhookPayload, comment string) error {
	client := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))
	_, _, err := client.PullRequests.CreateComment(
		context.Background(),
		wp.Repository.Owner.Login,
		wp.Repository.Name,
		wp.PullRequest.Number,
		&github.PullRequestComment{Body: github.String(comment)},
	)
	return err
}
