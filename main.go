package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"

	"crypto/hmac"
	"crypto/sha256"
	"github.com/google/go-github/v62/github"
)

// WebhookPayload represents the GitHub webhook payload (simplified)
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

// DeepseekRequest represents the request to Deepseek's API
type DeepseekRequest struct {
	Messages []struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	} `json:"messages"`
	Model string `json:"model"`
}

// DeepseekResponse represents the response from Deepseek
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
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Printf("Server error: %v\n", err)
	}
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	// Verify webhook signature
	secret := []byte(os.Getenv("WEBHOOK_SECRET"))
	payload, err := verifyWebhookSignature(r, secret)
	if err != nil {
		http.Error(w, "Invalid signature", http.StatusUnauthorized)
		return
	}

	// Parse webhook payload
	var wp WebhookPayload
	if err := json.Unmarshal(payload, &wp); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	// Handle only pull_request events
	if r.Header.Get("X-GitHub-Event") != "pull_request" || wp.Action != "opened" {
		http.Error(w, "Ignored event", http.StatusOK)
		return
	}

	// Fetch the PR diff
	diff, err := fetchPRDiff(wp.PullRequest.DiffURL)
	if err != nil {
		http.Error(w, "Failed to fetch diff", http.StatusInternalServerError)
		return
	}

	// Send diff to Deepseek for review
	review, err := getAIReview(diff)
	if err != nil {
		http.Error(w, "AI review failed", http.StatusInternalServerError)
		return
	}

	// Post review comment to GitHub
	err = postGitHubComment(wp, review)
	if err != nil {
		http.Error(w, "Failed to post comment", http.StatusInternalServerError)
		return
	}

	fmt.Fprint(w, "Review posted successfully")
}

// verifyWebhookSignature verifies the GitHub webhook signature
func verifyWebhookSignature(r *http.Request, secret []byte) ([]byte, error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body)) // Restore body for later use

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

// fetchPRDiff fetches the PR diff from the provided URL
func fetchPRDiff(diffURL string) (string, error) {
	resp, err := http.Get(diffURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// getAIReview sends the diff to Deepseek R1 and returns the review
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
		return "", fmt.Errorf("failed to marshal request: %v", err)
	}

	req, err := http.NewRequest("POST", "https://api.deepseek.com/v1/chat/completions", bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("DEEPSEEK_API_KEY"))
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to call Deepseek API: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("Deepseek API returned %d: %s", resp.StatusCode, string(body))
	}

	var deepseekResp DeepseekResponse
	if err := json.NewDecoder(resp.Body).Decode(&deepseekResp); err != nil {
		return "", fmt.Errorf("failed to decode response: %v", err)
	}

	if len(deepseekResp.Choices) == 0 {
		return "", fmt.Errorf("no choices in Deepseek response")
	}

	return deepseekResp.Choices[0].Message.Content, nil
}

// postGitHubComment posts a review comment to the GitHub PR
func postGitHubComment(wp WebhookPayload, comment string) error {
	client := github.NewClient(nil).WithAuthToken(os.Getenv("GITHUB_TOKEN"))
	reviewComment := &github.PullRequestComment{
		Body: github.String(comment),
	}

	_, _, err := client.PullRequests.CreateComment(
		context.Background(),
		wp.Repository.Owner.Login,
		wp.Repository.Name,
		wp.PullRequest.Number,
		reviewComment,
	)
	return err
}
