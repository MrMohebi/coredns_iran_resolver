package iran_resolver

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func removeNonCommentLines(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("error opening file: %w", err)
	}
	defer file.Close()

	var validLines []string

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			validLines = append(validLines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	tempFile, err := os.CreateTemp("", "tempfile-")
	if err != nil {
		return fmt.Errorf("error creating temp file: %w", err)
	}
	defer os.Remove(tempFile.Name()) // Clean up the temporary file

	for _, line := range validLines {
		_, err := tempFile.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("error writing to temp file: %w", err)
		}
	}

	if err := tempFile.Close(); err != nil {
		return err
	}

	err = os.Rename(tempFile.Name(), filePath)
	if err != nil {
		return fmt.Errorf("error renaming temp file to original file: %w", err)
	}

	return nil
}

func removeDuplicates(s []string) []string {
	var result []string
	seen := make(map[string]bool)
	for _, val := range s {
		if !seen[val] {
			result = append(result, val)
			seen[val] = true
		}
	}
	return result
}
