package iran_resolver

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

func removeNonCommentLines(filePath string) error {
	allLines, err := readLines(filePath)
	if err != nil {
		return fmt.Errorf("error reading file: %w", err)
	}

	var validLines []string

	for _, line := range allLines {
		l := strings.TrimSpace(line) // Trim whitespace

		if l == "" || strings.HasPrefix(l, "#") {
			validLines = append(validLines, l)
		}
	}

	err = writeLines(validLines, filePath)
	if err != nil {
		return fmt.Errorf("error writing file: %w", err)
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

func writeLines(lines []string, path string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(w, line)
	}
	return w.Flush()
}

func readLines(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}
