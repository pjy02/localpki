package server

import (
	"embed"
	"encoding/json"
	"html/template"
	"path"
	"strings"
	"time"
)

//go:embed templates/*.html templates/partials/*.html
var templateFS embed.FS

func LoadTemplates() (*template.Template, error) {
	funcs := template.FuncMap{
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.UTC().Format("2006-01-02 15:04:05")
		},
		"stringify": func(v interface{}) string {
			switch val := v.(type) {
			case string:
				return val
			default:
				b, _ := jsonMarshalIndent(val)
				return string(b)
			}
		},
	}
	root := template.New("root").Funcs(funcs)
	entries, err := templateFS.ReadDir("templates")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".html") {
			continue
		}
		content, err := templateFS.ReadFile(path.Join("templates", name))
		if err != nil {
			return nil, err
		}
		if _, err := root.New(strings.TrimSuffix(name, ".html")).Parse(string(content)); err != nil {
			return nil, err
		}
	}
	partials, err := templateFS.ReadDir("templates/partials")
	if err == nil {
		for _, entry := range partials {
			if entry.IsDir() {
				continue
			}
			name := entry.Name()
			if !strings.HasSuffix(name, ".html") {
				continue
			}
			content, err := templateFS.ReadFile(path.Join("templates/partials", name))
			if err != nil {
				return nil, err
			}
			if _, err := root.New(strings.TrimSuffix(name, ".html")).Parse(string(content)); err != nil {
				return nil, err
			}
		}
	}
	return root, nil
}

func jsonMarshalIndent(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
