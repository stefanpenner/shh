package cli

import (
	"strings"

	"github.com/charmbracelet/lipgloss"
)

var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	errorStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true)
	headerStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("14")).Bold(true).Underline(true)
	keyStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("12"))
	nameStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	youStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true)
	hintStyle    = lipgloss.NewStyle().Foreground(lipgloss.Color("8")).Italic(true)
)

// RecipientDisplayName returns a short display name for a recipient.
func RecipientDisplayName(name string) string {
	if strings.HasPrefix(name, "https://github.com/") {
		return strings.TrimPrefix(name, "https://github.com/")
	}
	return name
}
