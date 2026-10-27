package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"text/template"

	batchv1 "k8s.io/api/batch/v1"
	"sigs.k8s.io/yaml"
)

//go:embed deploy/scanjob-template.yaml
var defaultJobTemplate []byte

// JobData is the set of values substituted into the Job template.
type JobData struct {
	ScanID     string
	JobName    string
	SecretName string
	Namespace  string
	Image      string
	Framework  string
	Timeout    string
}

// RenderJob fills the template and decodes it into a typed Job.
func RenderJob(tmpl []byte, d JobData) (*batchv1.Job, error) {
	t, err := template.New("scanjob").Option("missingkey=error").Parse(string(tmpl))
	if err != nil {
		return nil, fmt.Errorf("parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return nil, fmt.Errorf("render template: %w", err)
	}

	var job batchv1.Job
	if err := yaml.Unmarshal(buf.Bytes(), &job); err != nil {
		return nil, fmt.Errorf("decode rendered job: %w", err)
	}
	if job.Name == "" {
		return nil, fmt.Errorf("rendered job has no name")
	}
	return &job, nil
}
