package main

import (
	"fmt"
	"io/fs"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// DetectionRule represents a single detection rule from YAML
type DetectionRule struct {
	ID          string            `yaml:"id"`
	Info        RuleInfo          `yaml:"info"`
	Detection   Detection         `yaml:"detection"`
	Confidence  int               `yaml:"confidence"`
	Version     string            `yaml:"version"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
}

// RuleInfo contains basic information about the rule
type RuleInfo struct {
	Name        string   `yaml:"name"`
	Author      string   `yaml:"author"`
	Severity    string   `yaml:"severity"`
	Description string   `yaml:"description"`
	Tags        []string `yaml:"tags"`
}

// Detection contains all detection methods
type Detection struct {
	Files       []FileRule       `yaml:"files,omitempty"`
	Directories []DirectoryRule  `yaml:"directories,omitempty"`
	Extensions  []ExtensionRule  `yaml:"extensions,omitempty"`
	Content     []ContentRule    `yaml:"content,omitempty"`
	Registry    []RegistryRule   `yaml:"registry,omitempty"`
	Process     []ProcessRule    `yaml:"process,omitempty"`
}

// FileRule represents file-based detection
type FileRule struct {
	Path     string `yaml:"path"`
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Required bool   `yaml:"required"`
	Weight   int    `yaml:"weight"`
}

// DirectoryRule represents directory-based detection
type DirectoryRule struct {
	Path     string `yaml:"path"`
	Name     string `yaml:"name"`
	Pattern  string `yaml:"pattern"`
	Required bool   `yaml:"required"`
	Weight   int    `yaml:"weight"`
}

// ExtensionRule represents file extension detection
type ExtensionRule struct {
	Extension string `yaml:"extension"`
	MinCount  int    `yaml:"min_count"`
	Required  bool   `yaml:"required"`
	Weight    int    `yaml:"weight"`
}

// ContentRule represents content-based detection
type ContentRule struct {
	File      string `yaml:"file"`
	Pattern   string `yaml:"pattern"`
	Contains  string `yaml:"contains"`
	Required  bool   `yaml:"required"`
	Weight    int    `yaml:"weight"`
}

// RegistryRule represents Windows registry detection
type RegistryRule struct {
	Key      string `yaml:"key"`
	Value    string `yaml:"value"`
	Data     string `yaml:"data"`
	Required bool   `yaml:"required"`
	Weight   int    `yaml:"weight"`
}

// ProcessRule represents running process detection
type ProcessRule struct {
	Name     string `yaml:"name"`
	Path     string `yaml:"path"`
	Required bool   `yaml:"required"`
	Weight   int    `yaml:"weight"`
}

// DetectionResult represents the result of detection
type DetectionResult struct {
	Engine      string            `yaml:"engine"`
	Confidence  int               `yaml:"confidence"`
	Matched     []string          `yaml:"matched"`
	Evidence    map[string]string `yaml:"evidence"`
	Possible    []string          `yaml:"possible,omitempty"`
	RuleVersion string            `yaml:"rule_version"`
}

// GameDetector is the main detector class
type GameDetector struct {
	rules         []DetectionRule
	supportedVersion string
}

// NewGameDetector creates a new detector instance
func NewGameDetector() *GameDetector {
	return &GameDetector{
		rules:         []DetectionRule{},
		supportedVersion: "1.0",
	}
}

// LoadRules loads detection rules from YAML files
func (gd *GameDetector) LoadRules(rulesPath string) error {
	return filepath.Walk(rulesPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !strings.HasSuffix(strings.ToLower(path), ".yaml") && 
		   !strings.HasSuffix(strings.ToLower(path), ".yml") {
			return nil
		}

		data, err := ioutil.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read rule file %s: %v", path, err)
		}

		var rule DetectionRule
		if err := yaml.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("failed to parse rule file %s: %v", path, err)
		}

		// Check version compatibility
		if rule.Version != "" && rule.Version != gd.supportedVersion {
			log.Printf("Warning: Rule %s version %s may not be compatible with detector version %s", 
				rule.ID, rule.Version, gd.supportedVersion)
		}

		gd.rules = append(gd.rules, rule)
		return nil
	})
}

// DetectEngine detects game engine from given path
func (gd *GameDetector) DetectEngine(gamePath string) (*DetectionResult, error) {
	results := make(map[string]*DetectionResult)

	for _, rule := range gd.rules {
		score := 0
		matched := []string{}
		evidence := make(map[string]string)

		// Check file rules
		for _, fileRule := range rule.Detection.Files {
			if gd.checkFileRule(gamePath, fileRule) {
				score += fileRule.Weight
				matched = append(matched, fmt.Sprintf("file:%s", fileRule.Name))
				evidence[fmt.Sprintf("file_%s", fileRule.Name)] = "found"
			} else if fileRule.Required {
				score = 0
				break
			}
		}

		// Check directory rules
		for _, dirRule := range rule.Detection.Directories {
			if gd.checkDirectoryRule(gamePath, dirRule) {
				score += dirRule.Weight
				matched = append(matched, fmt.Sprintf("directory:%s", dirRule.Name))
				evidence[fmt.Sprintf("dir_%s", dirRule.Name)] = "found"
			} else if dirRule.Required {
				score = 0
				break
			}
		}

		// Check extension rules
		for _, extRule := range rule.Detection.Extensions {
			count := gd.countExtensions(gamePath, extRule.Extension)
			if count >= extRule.MinCount {
				score += extRule.Weight
				matched = append(matched, fmt.Sprintf("extension:%s", extRule.Extension))
				evidence[fmt.Sprintf("ext_%s", extRule.Extension)] = fmt.Sprintf("count:%d", count)
			} else if extRule.Required {
				score = 0
				break
			}
		}

		// Check content rules
		for _, contentRule := range rule.Detection.Content {
			if gd.checkContentRule(gamePath, contentRule) {
				score += contentRule.Weight
				matched = append(matched, fmt.Sprintf("content:%s", contentRule.File))
				evidence[fmt.Sprintf("content_%s", contentRule.File)] = "matched"
			} else if contentRule.Required {
				score = 0
				break
			}
		}

		if score > 0 {
			confidence := min(100, (score*100)/rule.Confidence)
			results[rule.Info.Name] = &DetectionResult{
				Engine:      rule.Info.Name,
				Confidence:  confidence,
				Matched:     matched,
				Evidence:    evidence,
				RuleVersion: rule.Version,
			}
		}
	}

	return gd.consolidateResults(results), nil
}

// Helper functions for checking rules
func (gd *GameDetector) checkFileRule(basePath string, rule FileRule) bool {
	var searchPath string
	if rule.Path != "" {
		searchPath = filepath.Join(basePath, rule.Path)
	} else {
		searchPath = basePath
	}

	if rule.Name != "" {
		fullPath := filepath.Join(searchPath, rule.Name)
		if _, err := os.Stat(fullPath); err == nil {
			return true
		}
	}

	if rule.Pattern != "" {
		matches, _ := filepath.Glob(filepath.Join(searchPath, rule.Pattern))
		return len(matches) > 0
	}

	return false
}

func (gd *GameDetector) checkDirectoryRule(basePath string, rule DirectoryRule) bool {
	var searchPath string
	if rule.Path != "" {
		searchPath = filepath.Join(basePath, rule.Path)
	} else {
		searchPath = basePath
	}

	if rule.Name != "" {
		fullPath := filepath.Join(searchPath, rule.Name)
		if info, err := os.Stat(fullPath); err == nil && info.IsDir() {
			return true
		}
	}

	if rule.Pattern != "" {
		matches, _ := filepath.Glob(filepath.Join(searchPath, rule.Pattern))
		for _, match := range matches {
			if info, err := os.Stat(match); err == nil && info.IsDir() {
				return true
			}
		}
	}

	return false
}

func (gd *GameDetector) countExtensions(basePath, extension string) int {
	count := 0
	filepath.Walk(basePath, func(path string, info fs.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(info.Name()), strings.ToLower(extension)) {
			count++
		}
		return nil
	})
	return count
}

func (gd *GameDetector) checkContentRule(basePath string, rule ContentRule) bool {
	filePath := filepath.Join(basePath, rule.File)
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return false
	}

	contentStr := string(content)
	if rule.Contains != "" {
		return strings.Contains(contentStr, rule.Contains)
	}

	// Pattern matching can be implemented here with regex
	return false
}

func (gd *GameDetector) consolidateResults(results map[string]*DetectionResult) *DetectionResult {
	if len(results) == 0 {
		return &DetectionResult{
			Engine:     "Unknown",
			Confidence: 0,
			Matched:    []string{},
			Evidence:   make(map[string]string),
		}
	}

	// Sort by confidence
	type engineResult struct {
		name   string
		result *DetectionResult
	}

	var sortedResults []engineResult
	for name, result := range results {
		sortedResults = append(sortedResults, engineResult{name, result})
	}

	sort.Slice(sortedResults, func(i, j int) bool {
		return sortedResults[i].result.Confidence > sortedResults[j].result.Confidence
	})

	best := sortedResults[0].result
	
	// Add possible engines if confidence is not high enough
	if best.Confidence < 80 {
		for i := 1; i < len(sortedResults) && i < 3; i++ {
			if sortedResults[i].result.Confidence > 30 {
				best.Possible = append(best.Possible, sortedResults[i].name)
			}
		}
	}

	return best
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ListAvailableRules lists all loaded detection rules
func (gd *GameDetector) ListAvailableRules() {
	fmt.Println("Available Detection Rules:")
	fmt.Println("=" + strings.Repeat("=", 50))
	
	for _, rule := range gd.rules {
		fmt.Printf("ID: %s\n", rule.ID)
		fmt.Printf("Name: %s\n", rule.Info.Name)
		fmt.Printf("Author: %s\n", rule.Info.Author)
		fmt.Printf("Description: %s\n", rule.Info.Description)
		fmt.Printf("Version: %s\n", rule.Version)
		fmt.Printf("Tags: %v\n", rule.Info.Tags)
		fmt.Println("-" + strings.Repeat("-", 50))
	}
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  game-detector <game_path> [rules_path]")
		fmt.Println("  game-detector --list-rules [rules_path]")
		os.Exit(1)
	}

	detector := NewGameDetector()
	rulesPath := "./rules"
	
	if len(os.Args) > 2 {
		rulesPath = os.Args[2]
	}

	// Load detection rules
	if err := detector.LoadRules(rulesPath); err != nil {
		log.Fatalf("Failed to load rules: %v", err)
	}

	if os.Args[1] == "--list-rules" {
		detector.ListAvailableRules()
		return
	}

	gamePath := os.Args[1]
	result, err := detector.DetectEngine(gamePath)
	if err != nil {
		log.Fatalf("Detection failed: %v", err)
	}

	// Output result as YAML
	output, err := yaml.Marshal(result)
	if err != nil {
		log.Fatalf("Failed to marshal result: %v", err)
	}

	fmt.Println(string(output))
}