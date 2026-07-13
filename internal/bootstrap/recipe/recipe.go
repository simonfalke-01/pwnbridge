// Package recipe defines the portable, persisted part of a bootstrap plan.
package recipe

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"unicode"

	"github.com/pelletier/go-toml/v2"
)

const Schema = 1
const maxRecipeBytes = 1 << 20

// Recipe deliberately excludes execution choices such as sudo, confirmation,
// dry-run, and output mode. It is safe to move between hosts.
type Recipe struct {
	Schema         int      `toml:"schema" json:"schema"`
	Name           string   `toml:"name" json:"name"`
	Components     []string `toml:"components" json:"components"`
	SystemPackages []string `toml:"system_packages,omitempty" json:"system_packages,omitempty"`
	PipPackages    []string `toml:"pip_packages,omitempty" json:"pip_packages,omitempty"`
}

func New(name string, components ...string) Recipe {
	return Recipe{Schema: Schema, Name: name, Components: append([]string(nil), components...)}
}

func Parse(data []byte) (Recipe, error) {
	if len(data) > maxRecipeBytes {
		return Recipe{}, fmt.Errorf("bootstrap recipe exceeds %d bytes", maxRecipeBytes)
	}
	var value Recipe
	decoder := toml.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return Recipe{}, fmt.Errorf("decode bootstrap recipe: %w", err)
	}
	if err := ValidatePortable(value); err != nil {
		return Recipe{}, err
	}
	return Normalize(value), nil
}

func Load(path string) (Recipe, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Recipe{}, fmt.Errorf("read bootstrap recipe: %w", err)
	}
	return Parse(data)
}

func Marshal(value Recipe) ([]byte, error) {
	value = Normalize(value)
	if err := ValidatePortable(value); err != nil {
		return nil, err
	}
	data, err := toml.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode bootstrap recipe: %w", err)
	}
	return data, nil
}

func Normalize(value Recipe) Recipe {
	value.Schema = Schema
	value.Components = stableUnique(value.Components)
	value.SystemPackages = stableUnique(value.SystemPackages)
	value.PipPackages = stableUnique(value.PipPackages)
	return value
}

func ValidatePortable(value Recipe) error {
	var problems []string
	if value.Schema != Schema {
		problems = append(problems, fmt.Sprintf("recipe schema must be %d", Schema))
	}
	if !ValidName(value.Name) {
		problems = append(problems, "recipe name must contain only letters, digits, '.', '_', or '-'")
	}
	if len(value.Components) == 0 {
		problems = append(problems, "recipe must select at least one component")
	}
	if len(value.Components) > 32 {
		problems = append(problems, "recipe selects too many components")
	}
	if len(value.SystemPackages) > 256 {
		problems = append(problems, "recipe has too many system packages")
	}
	if len(value.PipPackages) > 256 {
		problems = append(problems, "recipe has too many pip requirements")
	}
	known := map[string]bool{"core": true, "gdb": true, "python": true, "pwntools": true, "patching": true, "tracing": true, "pane-network": true, "mosh": true, "pwndbg": true, "podman": true, "docker": true}
	for _, component := range value.Components {
		if !known[component] {
			problems = append(problems, fmt.Sprintf("unknown bootstrap component %q", component))
		}
	}
	for _, name := range value.SystemPackages {
		if !ValidSystemPackage(name) {
			problems = append(problems, fmt.Sprintf("invalid system package %q", name))
		}
	}
	for _, requirement := range value.PipPackages {
		if !ValidPipRequirement(requirement) {
			problems = append(problems, fmt.Sprintf("invalid pip requirement %q", requirement))
		}
	}
	if len(problems) != 0 {
		sort.Strings(problems)
		return errors.New(strings.Join(problems, "; "))
	}
	return nil
}

func ValidName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

// ValidSystemPackage accepts package atoms used by all supported adapters,
// while excluding option injection, whitespace, shell syntax, and controls.
func ValidSystemPackage(name string) bool {
	if name == "" || len(name) > 192 || strings.HasPrefix(name, "-") || strings.Contains(name, "..") {
		return false
	}
	for _, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || strings.ContainsRune("+._:@/-", r)) {
			return false
		}
	}
	return true
}

// ValidPipRequirement permits ordinary PEP 508 specifiers and markers, but
// rejects pip options, direct URLs, controls, and malformed lexical grammar.
// The requirement is always passed as one argv item to pip.
func ValidPipRequirement(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 512 || strings.HasPrefix(value, "-") ||
		strings.Contains(value, "://") || strings.Contains(value, "@") || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	requirement, marker, hasMarker := strings.Cut(value, ";")
	requirement = strings.TrimSpace(requirement)
	if hasMarker && strings.TrimSpace(marker) == "" {
		return false
	}
	i := 0
	for i < len(requirement) && isPipNameByte(requirement[i]) {
		i++
	}
	if i == 0 || !isASCIIAlnum(requirement[0]) || !isASCIIAlnum(requirement[i-1]) {
		return false
	}
	if i < len(requirement) && requirement[i] == '[' {
		end := strings.IndexByte(requirement[i:], ']')
		if end <= 1 {
			return false
		}
		for _, extra := range strings.Split(requirement[i+1:i+end], ",") {
			extra = strings.TrimSpace(extra)
			if extra == "" {
				return false
			}
			for j := range len(extra) {
				if !isPipNameByte(extra[j]) {
					return false
				}
			}
			if !isASCIIAlnum(extra[0]) || !isASCIIAlnum(extra[len(extra)-1]) {
				return false
			}
		}
		i += end + 1
	}
	rest := strings.TrimSpace(requirement[i:])
	if rest != "" {
		if !strings.ContainsRune("<>=!~(", rune(rest[0])) {
			return false
		}
		for _, r := range rest {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("<>=!~.,*+_-() ", r)) {
				return false
			}
		}
	}
	if hasMarker {
		for _, r := range marker {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(" _.'\"<>=!()-", r)) {
				return false
			}
		}
	}
	return true
}

func isASCIIAlnum(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
func isPipNameByte(value byte) bool {
	return isASCIIAlnum(value) || value == '-' || value == '_' || value == '.'
}

func stableUnique(values []string) []string {
	seen := make(map[string]bool, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
