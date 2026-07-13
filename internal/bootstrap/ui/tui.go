package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"charm.land/bubbles/v2/textarea"
	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
)

var errWizardAborted = errors.New("wizard aborted")

type choiceOption struct {
	Label string
	Value string
}

type toggleOption struct {
	Label    string
	Value    string
	Selected bool
	Locked   bool
}

type promptSession struct {
	ctx        context.Context
	input      io.Reader
	output     io.Writer
	accessible bool
	lines      *bufio.Reader
}

func newPromptSession(ctx context.Context, input io.Reader, output io.Writer, accessible bool) *promptSession {
	return &promptSession{ctx: ctx, input: input, output: output, accessible: accessible, lines: bufio.NewReader(input)}
}

func (s *promptSession) choose(title, description, step string, options []choiceOption, initial string) (string, error) {
	if s.accessible {
		return s.chooseAccessible(title, description, options, initial)
	}
	model := newChoiceModel(title, description, step, options, initial)
	final, err := tea.NewProgram(model, tea.WithContext(s.ctx), tea.WithInput(s.input), tea.WithOutput(s.output)).Run()
	if err != nil {
		return "", normalizeProgramError(err)
	}
	result := final.(*choiceModel)
	if result.aborted {
		return "", errWizardAborted
	}
	return result.options[result.cursor].Value, nil
}

func (s *promptSession) configure(options []toggleOption, systemText, pipText string, validateComponents func([]string) error) ([]string, string, string, error) {
	if s.accessible {
		selected, err := s.multiAccessible("Components", "Required and flag-locked choices cannot be changed.", options, validateComponents)
		if err != nil {
			return nil, "", "", err
		}
		systemText, err = s.listAccessible("Extra system packages", systemText, validateSystemList)
		if err != nil {
			return nil, "", "", err
		}
		pipText, err = s.listAccessible("Extra pip requirements", pipText, validatePipList)
		return selected, systemText, pipText, err
	}
	model := newConfigureModel(options, systemText, pipText, validateComponents)
	final, err := tea.NewProgram(model, tea.WithContext(s.ctx), tea.WithInput(s.input), tea.WithOutput(s.output)).Run()
	if err != nil {
		return nil, "", "", normalizeProgramError(err)
	}
	result := final.(*configureModel)
	if result.aborted {
		return nil, "", "", errWizardAborted
	}
	return result.values(), result.system.Value(), result.pip.Value(), nil
}

func (s *promptSession) decision(title, description, affirmative, negative string) (bool, error) {
	value, err := s.choose(title, description, "Confirm", []choiceOption{{Label: affirmative, Value: "yes"}, {Label: negative, Value: "no"}}, "no")
	return value == "yes", err
}

func (s *promptSession) finalize(validateName func(string) error) (string, bool, bool, error) {
	if s.accessible {
		name, err := s.inputAccessible("Save as named recipe (optional)", "Leave blank not to save. Built-in names are reserved.", "", validateName)
		if err != nil {
			return "", false, false, err
		}
		bind := false
		if name != "" {
			bind, err = s.confirmAccessible("Bind the saved recipe to this host?", false)
			if err != nil {
				return "", false, false, err
			}
		}
		confirmed, err := s.confirmAccessible("Apply this exact plan?", false)
		return name, bind, confirmed, err
	}
	model := newFinalizeModel(validateName)
	final, err := tea.NewProgram(model, tea.WithContext(s.ctx), tea.WithInput(s.input), tea.WithOutput(s.output)).Run()
	if err != nil {
		return "", false, false, normalizeProgramError(err)
	}
	result := final.(*finalizeModel)
	if result.aborted {
		return "", false, false, errWizardAborted
	}
	return result.name.Value(), result.bind, result.confirmed, nil
}

func normalizeProgramError(err error) error {
	if errors.Is(err, tea.ErrInterrupted) || errors.Is(err, context.Canceled) {
		return errWizardAborted
	}
	return err
}

type uiStyles struct {
	brand, step, title, description, selected, marker, locked, help, danger, success lipgloss.Style
}

func makeStyles() uiStyles {
	plain := os.Getenv("NO_COLOR") != ""
	styles := uiStyles{}
	if plain {
		return styles
	}
	styles.brand = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7C6CFF"))
	styles.step = lipgloss.NewStyle().Foreground(lipgloss.Color("#5FD7FF"))
	styles.title = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#F5F5F7"))
	styles.description = lipgloss.NewStyle().Foreground(lipgloss.Color("#9A9AA3"))
	styles.selected = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#FFFFFF"))
	styles.marker = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("#7CFFB2"))
	styles.locked = lipgloss.NewStyle().Foreground(lipgloss.Color("#777781"))
	styles.help = lipgloss.NewStyle().Foreground(lipgloss.Color("#777781"))
	styles.danger = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF6B81"))
	styles.success = lipgloss.NewStyle().Foreground(lipgloss.Color("#7CFFB2"))
	return styles
}

func terminalView(content string) tea.View {
	view := tea.NewView(content)
	view.AltScreen = false
	return view
}

func frame(styles uiStyles, width int, step, title, description, body, help, message string) string {
	width = max(20, min(88, width-4))
	var b strings.Builder
	brand, progress := styles.brand.Render("◆ PWNBRIDGE"), styles.step.Render(step)
	if ansi.StringWidth(brand)+2+ansi.StringWidth(progress) > width {
		fmt.Fprintf(&b, "%s\n%s\n\n", brand, styles.step.Render(ansi.Wordwrap(step, width, "")))
	} else {
		fmt.Fprintf(&b, "%s  %s\n\n", brand, progress)
	}
	b.WriteString(styles.title.Render(ansi.Wordwrap(title, width, "")))
	b.WriteByte('\n')
	if description != "" {
		b.WriteString(styles.description.Render(ansi.Wordwrap(description, width, "")))
		b.WriteString("\n\n")
	} else {
		b.WriteByte('\n')
	}
	b.WriteString(body)
	if message != "" {
		b.WriteString("\n\n")
		b.WriteString(styles.danger.Render(ansi.Wordwrap("! "+message, width, "")))
	}
	b.WriteString("\n\n")
	b.WriteString(styles.help.Render(ansi.Wordwrap(help, width, "")))
	return b.String()
}

type choiceModel struct {
	title, description, step string
	options                  []choiceOption
	cursor, width, height    int
	done, aborted            bool
	styles                   uiStyles
}

func newChoiceModel(title, description, step string, options []choiceOption, initial string) *choiceModel {
	model := &choiceModel{title: title, description: description, step: step, options: options, width: 80, height: 24, styles: makeStyles()}
	for index, option := range options {
		if option.Value == initial {
			model.cursor = index
			break
		}
	}
	return model
}

func (m *choiceModel) Init() tea.Cmd { return nil }

func (m *choiceModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
	case tea.InterruptMsg:
		m.aborted = true
		return m, tea.Quit
	case tea.KeyPressMsg:
		switch message.String() {
		case "ctrl+c", "esc":
			m.aborted = true
			return m, tea.Quit
		case "up", "k", "left", "shift+tab":
			m.cursor = (m.cursor - 1 + len(m.options)) % len(m.options)
		case "down", "j", "right", "tab":
			m.cursor = (m.cursor + 1) % len(m.options)
		case "enter":
			m.done = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func (m *choiceModel) View() tea.View {
	if m.done {
		return terminalView(m.styles.success.Render("✓ " + m.title + ": " + m.options[m.cursor].Label))
	}
	if m.aborted {
		return terminalView(m.styles.danger.Render("× Cancelled"))
	}
	var body strings.Builder
	labelWidth := max(10, min(84, m.width-8))
	for index, option := range m.options {
		marker := "  "
		label := ansi.Truncate(option.Label, labelWidth, "…")
		if index == m.cursor {
			marker = m.styles.marker.Render("› ")
			label = m.styles.selected.Render(label)
		}
		fmt.Fprintf(&body, "%s%s\n", marker, label)
	}
	return terminalView(frame(m.styles, m.width, m.step, m.title, m.description, strings.TrimSuffix(body.String(), "\n"), "↑/↓ move  •  enter select  •  esc cancel", ""))
}

type configureModel struct {
	page, cursor, width, height int
	options                     []toggleOption
	system, pip                 textarea.Model
	validateComponents          func([]string) error
	message                     string
	done, aborted               bool
	styles                      uiStyles
}

func newConfigureModel(options []toggleOption, systemText, pipText string, validateComponents func([]string) error) *configureModel {
	system := textarea.New()
	system.Prompt, system.Placeholder, system.ShowLineNumbers = "│ ", "One package per line", false
	system.SetHeight(7)
	system.SetValue(systemText)
	pip := textarea.New()
	pip.Prompt, pip.Placeholder, pip.ShowLineNumbers = "│ ", "One requirement per line", false
	pip.SetHeight(7)
	pip.SetValue(pipText)
	return &configureModel{options: options, system: system, pip: pip, validateComponents: validateComponents, width: 80, height: 24, styles: makeStyles()}
}

func (m *configureModel) Init() tea.Cmd { return nil }

func (m *configureModel) values() []string {
	values := make([]string, 0, len(m.options))
	for _, option := range m.options {
		if option.Selected {
			values = append(values, option.Value)
		}
	}
	return values
}

func (m *configureModel) sizeInputs() {
	width := max(16, min(82, m.width-8))
	m.system.SetWidth(width)
	m.pip.SetWidth(width)
}

func (m *configureModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = message.Width, message.Height
		m.sizeInputs()
		return m, nil
	case tea.InterruptMsg:
		m.aborted = true
		return m, tea.Quit
	case tea.KeyPressMsg:
		key := message.String()
		if key == "ctrl+c" {
			m.aborted = true
			return m, tea.Quit
		}
		m.message = ""
		if m.page == 0 {
			switch key {
			case "esc":
				m.aborted = true
				return m, tea.Quit
			case "up", "k":
				m.cursor = (m.cursor - 1 + len(m.options)) % len(m.options)
			case "down", "j":
				m.cursor = (m.cursor + 1) % len(m.options)
			case "space", " ":
				if !m.options[m.cursor].Locked {
					m.options[m.cursor].Selected = !m.options[m.cursor].Selected
				}
			case "enter":
				if err := m.validateComponents(m.values()); err != nil {
					m.message = err.Error()
					return m, nil
				}
				m.page = 1
				return m, m.system.Focus()
			}
			return m, nil
		}
		if key == "esc" {
			if m.page == 1 {
				m.system.Blur()
				m.page = 0
				return m, nil
			}
			m.pip.Blur()
			m.page = 1
			return m, m.system.Focus()
		}
		if key == "ctrl+d" {
			if m.page == 1 {
				if err := validateSystemList(m.system.Value()); err != nil {
					m.message = err.Error()
					return m, nil
				}
				m.system.Blur()
				m.page = 2
				return m, m.pip.Focus()
			}
			if err := validatePipList(m.pip.Value()); err != nil {
				m.message = err.Error()
				return m, nil
			}
			m.done = true
			return m, tea.Quit
		}
	}
	var command tea.Cmd
	if m.page == 1 {
		m.system, command = m.system.Update(message)
	} else if m.page == 2 {
		m.pip, command = m.pip.Update(message)
	}
	return m, command
}

func (m *configureModel) View() tea.View {
	if m.done {
		return terminalView(m.styles.success.Render("✓ Bootstrap components configured"))
	}
	if m.aborted {
		return terminalView(m.styles.danger.Render("× Cancelled"))
	}
	if m.page == 0 {
		visible := max(4, min(len(m.options), m.height-12))
		start := max(0, min(m.cursor-visible/2, len(m.options)-visible))
		var body strings.Builder
		for index := start; index < min(len(m.options), start+visible); index++ {
			option := m.options[index]
			cursor, mark := "  ", "○"
			if option.Selected {
				mark = "●"
			}
			if index == m.cursor {
				cursor = m.styles.marker.Render("› ")
			}
			label := ansi.Truncate(option.Label, max(8, min(80, m.width-12)), "…")
			if option.Locked {
				label = m.styles.locked.Render(label)
			} else if index == m.cursor {
				label = m.styles.selected.Render(label)
			}
			fmt.Fprintf(&body, "%s%s  %s\n", cursor, mark, label)
		}
		return terminalView(frame(m.styles, m.width, "2 / 4  Components", "Choose capabilities", "Dependencies are resolved automatically. Locked choices are shown but cannot be changed.", strings.TrimSuffix(body.String(), "\n"), "↑/↓ move  •  space toggle  •  enter continue  •  esc cancel", m.message))
	}
	if m.page == 1 {
		return terminalView(frame(m.styles, m.width, "3 / 4  Packages", "Extra system packages", "Optional. Enter one validated package name per line.", m.system.View(), "ctrl+d continue  •  esc back  •  ctrl+c cancel", m.message))
	}
	return terminalView(frame(m.styles, m.width, "4 / 4  Python", "Extra pip requirements", "Optional. Requirements are installed only inside the managed environment.", m.pip.View(), "ctrl+d continue  •  esc back  •  ctrl+c cancel", m.message))
}

type finalizeModel struct {
	page, cursor, width int
	name                textinput.Model
	bind, confirmed     bool
	validateName        func(string) error
	message             string
	done, aborted       bool
	styles              uiStyles
}

func newFinalizeModel(validateName func(string) error) *finalizeModel {
	name := textinput.New()
	name.Prompt = "› "
	name.Placeholder = "leave blank"
	name.SetWidth(48)
	name.Focus()
	return &finalizeModel{name: name, validateName: validateName, width: 80, styles: makeStyles()}
}

func (m *finalizeModel) Init() tea.Cmd { return m.name.Focus() }

func (m *finalizeModel) setDecision(value bool) {
	if m.page == 1 {
		m.bind = value
	} else {
		m.confirmed = value
	}
}

func (m *finalizeModel) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		m.width = message.Width
		m.name.SetWidth(max(16, min(60, m.width-8)))
		return m, nil
	case tea.InterruptMsg:
		m.aborted = true
		return m, tea.Quit
	case tea.KeyPressMsg:
		key := message.String()
		if key == "ctrl+c" {
			m.aborted = true
			return m, tea.Quit
		}
		m.message = ""
		if m.page == 0 {
			if key == "esc" {
				m.aborted = true
				return m, tea.Quit
			}
			if key == "enter" {
				if err := m.validateName(m.name.Value()); err != nil {
					m.message = err.Error()
					return m, nil
				}
				m.name.Blur()
				if m.name.Value() == "" {
					m.page = 2
				} else {
					m.page = 1
				}
				m.cursor = 1
				return m, nil
			}
			var command tea.Cmd
			m.name, command = m.name.Update(message)
			return m, command
		}
		if key == "esc" {
			if m.page == 2 && m.name.Value() != "" {
				m.page = 1
			} else {
				m.page = 0
				return m, m.name.Focus()
			}
			m.cursor = 1
			return m, nil
		}
		switch key {
		case "up", "down", "left", "right", "h", "j", "k", "l", "tab", "shift+tab":
			m.cursor = 1 - m.cursor
		case "y":
			m.cursor = 0
			m.setDecision(true)
			if m.page == 1 {
				m.page, m.cursor = 2, 1
			} else {
				m.done = true
				return m, tea.Quit
			}
		case "n":
			m.cursor = 1
			m.setDecision(false)
			if m.page == 1 {
				m.page, m.cursor = 2, 1
			} else {
				m.done = true
				return m, tea.Quit
			}
		case "enter":
			m.setDecision(m.cursor == 0)
			if m.page == 1 {
				m.page, m.cursor = 2, 1
			} else {
				m.done = true
				return m, tea.Quit
			}
		}
	}
	return m, nil
}

func (m *finalizeModel) decisionBody(affirmative, negative string) string {
	labels := []string{affirmative, negative}
	var body strings.Builder
	for index, label := range labels {
		marker := "  "
		if index == m.cursor {
			marker = m.styles.marker.Render("› ")
			label = m.styles.selected.Render(label)
		}
		fmt.Fprintf(&body, "%s%s\n", marker, label)
	}
	return strings.TrimSuffix(body.String(), "\n")
}

func (m *finalizeModel) View() tea.View {
	if m.done {
		if m.confirmed {
			return terminalView(m.styles.success.Render("✓ Plan approved"))
		}
		return terminalView(m.styles.danger.Render("× Plan cancelled"))
	}
	if m.aborted {
		return terminalView(m.styles.danger.Render("× Cancelled"))
	}
	if m.page == 0 {
		return terminalView(frame(m.styles, m.width, "Review  •  1 / 3", "Save as named recipe", "Optional. Leave blank not to save; built-in names are reserved.", m.name.View(), "enter continue  •  esc cancel", m.message))
	}
	if m.page == 1 {
		return terminalView(frame(m.styles, m.width, "Review  •  2 / 3", "Bind recipe to this host?", "Future bootstraps will use this recipe by default.", m.decisionBody("Yes", "No"), "↑/↓ choose  •  enter continue  •  esc back", m.message))
	}
	return terminalView(frame(m.styles, m.width, "Review  •  3 / 3", "Apply this exact plan?", "No changes happen until you choose Apply.", m.decisionBody("Apply", "Cancel"), "↑/↓ choose  •  enter confirm  •  esc back", m.message))
}

func (s *promptSession) readLine() (string, error) {
	type result struct {
		line string
		err  error
	}
	completed := make(chan result, 1)
	go func() {
		line, err := s.lines.ReadString('\n')
		completed <- result{line: line, err: err}
	}()
	var line string
	var err error
	select {
	case <-s.ctx.Done():
		return "", errWizardAborted
	case value := <-completed:
		line, err = value.line, value.err
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if strings.ContainsRune(line, '\x03') {
		return "", errWizardAborted
	}
	if errors.Is(err, io.EOF) && line == "" {
		return "", errWizardAborted
	}
	return strings.TrimSpace(line), nil
}

func (s *promptSession) chooseAccessible(title, description string, options []choiceOption, initial string) (string, error) {
	fmt.Fprintf(s.output, "\n%s\n", title)
	if description != "" {
		fmt.Fprintln(s.output, description)
	}
	defaultIndex := 0
	for index, option := range options {
		fmt.Fprintf(s.output, "  %d) %s\n", index+1, option.Label)
		if option.Value == initial {
			defaultIndex = index
		}
	}
	for {
		fmt.Fprintf(s.output, "Choose [%d]: ", defaultIndex+1)
		line, err := s.readLine()
		if err != nil {
			return "", err
		}
		if line == "" {
			return options[defaultIndex].Value, nil
		}
		index, err := strconv.Atoi(line)
		if err == nil && index >= 1 && index <= len(options) {
			return options[index-1].Value, nil
		}
		fmt.Fprintln(s.output, "Enter one of the listed numbers.")
	}
}

func (s *promptSession) multiAccessible(title, description string, options []toggleOption, validate func([]string) error) ([]string, error) {
	fmt.Fprintf(s.output, "\n%s\n%s\n", title, description)
	for index, option := range options {
		mark := " "
		if option.Selected {
			mark = "x"
		}
		lock := ""
		if option.Locked {
			lock = " (locked)"
		}
		fmt.Fprintf(s.output, "  %d) [%s] %s%s\n", index+1, mark, option.Label, lock)
	}
	for {
		fmt.Fprint(s.output, "Toggle comma-separated numbers, or press Enter to keep defaults: ")
		line, err := s.readLine()
		if err != nil {
			return nil, err
		}
		copyOptions := append([]toggleOption(nil), options...)
		if line != "" {
			for _, token := range strings.Split(line, ",") {
				index, err := strconv.Atoi(strings.TrimSpace(token))
				if err != nil || index < 1 || index > len(copyOptions) {
					fmt.Fprintln(s.output, "Enter only listed numbers separated by commas.")
					copyOptions = nil
					break
				}
				if !copyOptions[index-1].Locked {
					copyOptions[index-1].Selected = !copyOptions[index-1].Selected
				}
			}
			if copyOptions == nil {
				continue
			}
		}
		var values []string
		for _, option := range copyOptions {
			if option.Selected {
				values = append(values, option.Value)
			}
		}
		if err := validate(values); err != nil {
			fmt.Fprintln(s.output, err)
			continue
		}
		return values, nil
	}
}

func (s *promptSession) listAccessible(title, current string, validate func(string) error) (string, error) {
	fmt.Fprintf(s.output, "\n%s\n", title)
	if current != "" {
		fmt.Fprintf(s.output, "Current: %s\n", strings.Join(nonemptyLines(current), "; "))
	}
	for {
		fmt.Fprint(s.output, "Semicolon-separated replacement; blank keeps current; '-' clears: ")
		line, err := s.readLine()
		if err != nil {
			return "", err
		}
		value := current
		if line == "-" {
			value = ""
		} else if line != "" {
			value = strings.Join(strings.Split(line, ";"), "\n")
		}
		if err := validate(value); err != nil {
			fmt.Fprintln(s.output, err)
			continue
		}
		return value, nil
	}
}

func (s *promptSession) inputAccessible(title, description, current string, validate func(string) error) (string, error) {
	for {
		fmt.Fprintf(s.output, "\n%s\n%s\n> ", title, description)
		line, err := s.readLine()
		if err != nil {
			return "", err
		}
		if line == "" {
			line = current
		}
		if err := validate(line); err != nil {
			fmt.Fprintln(s.output, err)
			continue
		}
		return line, nil
	}
}

func (s *promptSession) confirmAccessible(title string, defaultValue bool) (bool, error) {
	prompt := "[y/N]"
	if defaultValue {
		prompt = "[Y/n]"
	}
	for {
		fmt.Fprintf(s.output, "\n%s %s ", title, prompt)
		line, err := s.readLine()
		if err != nil {
			return false, err
		}
		switch strings.ToLower(line) {
		case "":
			return defaultValue, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		default:
			fmt.Fprintln(s.output, "Enter y or n.")
		}
	}
}
