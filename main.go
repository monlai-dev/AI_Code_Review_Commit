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

func main() {
	http.HandleFunc("/webhook", handleWebhook)
	fmt.Println("Server starting on :8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
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

		review, err := getAIReviewFromOpenAI(diff)
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

// ✅ Hugging Face inference with deepseek-coder
func getAIReviewFromOpenAI(diff string) (string, error) {
	prompt := fmt.Sprintf(
		"Review the following Go code diff for errors, concurrency issues, and idiomatic practices. Provide specific suggestions for improvement:\n\n```diff\n%s\n```",
		diff,
	)

	reqBody := map[string]interface{}{
		"model": "gpt-3.5-turbo",
		"messages": []map[string]string{
			{
				"role":    "system",
				"content": "You are a code review assistant that provides helpful, concise feedback on code diffs.",
			},
			{
				"role":    "user",
				"content": prompt,
			},
		},
		"temperature": 0.7,
		"max_tokens":  512,
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal failed: %w", err)
	}

	apiURL := "https://api.openai.com/v1/chat/completions"
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonBody))
	if err != nil {
		return "", fmt.Errorf("create request failed: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+os.Getenv("OPENAI_API_KEY"))
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("OpenAI API error %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("decode failed: %w", err)
	}

	if len(result.Choices) == 0 {
		return "", fmt.Errorf("no response content")
	}

	return result.Choices[0].Message.Content, nil
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
