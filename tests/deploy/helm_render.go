// Renders a Helm chart's templates with Go's text/template, Helm's template engine, for the chart tests
// (tests/deploy/chart_render.py). Standard library only: it runs with `go run` and no module download.
//
// It gives the templates the functions Helm adds that the demo-shop chart uses, `required` only, with Helm's
// semantics, so any other function is a parse error: the chart stays within what this render proves. Values
// arrive already merged, as JSON on stdin ({"values": ..., "release": ..., "chart": ...}), as Helm itself
// turns YAML values into JSON before rendering. Like `helm template --strict`, a missing key is an error.
//
//	go run tests/deploy/helm_render.go deploy/helm/demo-shop < input.json
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

type input struct {
	Values  map[string]any `json:"values"`
	Release map[string]any `json:"release"`
	Chart   map[string]any `json:"chart"`
}

// required is Helm's: an error for nil or the empty string, the value otherwise.
func required(message string, value any) (any, error) {
	if value == nil {
		return nil, errors.New(message)
	}
	if text, ok := value.(string); ok && text == "" {
		return nil, errors.New(message)
	}
	return value, nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: helm_render <chart directory> < input.json")
		os.Exit(2)
	}
	chart := os.Args[1]
	var in input
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		fmt.Fprintln(os.Stderr, "input:", err)
		os.Exit(2)
	}
	paths, err := filepath.Glob(filepath.Join(chart, "templates", "*"))
	if err != nil || len(paths) == 0 {
		fmt.Fprintln(os.Stderr, "no templates in", chart)
		os.Exit(2)
	}
	sort.Strings(paths)
	name := filepath.Base(chart)
	root := template.New(name).Option("missingkey=error").Funcs(template.FuncMap{"required": required})
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if _, err := root.New(name + "/templates/" + filepath.Base(path)).Parse(string(data)); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	scope := map[string]any{"Values": in.Values, "Release": in.Release, "Chart": in.Chart}
	for _, path := range paths {
		base := filepath.Base(path)
		if strings.HasPrefix(base, "_") || !strings.HasSuffix(base, ".yaml") {
			continue // partials and NOTES.txt render nothing, as in Helm
		}
		var out strings.Builder
		if err := root.ExecuteTemplate(&out, name+"/templates/"+base, scope); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Printf("---\n# Source: %s/templates/%s\n%s", name, base, out.String())
	}
}
