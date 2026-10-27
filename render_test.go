package main

import (
	"strings"
	"testing"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
)

func sampleJobData() JobData {
	return JobData{
		ScanID:     "abcd1234",
		JobName:    "xscan-abcd1234",
		SecretName: "xscan-abcd1234-target",
		Namespace:  "kubescape",
		Image:      "kubescape-scanner:local",
		Framework:  "NSA",
		Timeout:    "20m",
	}
}

func TestRenderJob(t *testing.T) {
	job, err := RenderJob(defaultJobTemplate, sampleJobData())
	if err != nil {
		t.Fatalf("RenderJob: %v", err)
	}

	if job.Name != "xscan-abcd1234" {
		t.Errorf("name = %q", job.Name)
	}
	if job.Namespace != "kubescape" {
		t.Errorf("namespace = %q", job.Namespace)
	}
	if job.Labels["scan-id"] != "abcd1234" {
		t.Errorf("label scan-id = %q", job.Labels["scan-id"])
	}
	if job.Spec.BackoffLimit == nil || *job.Spec.BackoffLimit != 1 {
		t.Errorf("backoffLimit = %v", job.Spec.BackoffLimit)
	}
	if job.Spec.TTLSecondsAfterFinished == nil || *job.Spec.TTLSecondsAfterFinished != 3600 {
		t.Errorf("ttlSecondsAfterFinished = %v", job.Spec.TTLSecondsAfterFinished)
	}

	pod := job.Spec.Template.Spec
	if pod.RestartPolicy != corev1.RestartPolicyNever {
		t.Errorf("restartPolicy = %q", pod.RestartPolicy)
	}
	if len(pod.Containers) != 1 {
		t.Fatalf("got %d containers, want 1", len(pod.Containers))
	}

	c := pod.Containers[0]
	if c.Image != "kubescape-scanner:local" {
		t.Errorf("image = %q", c.Image)
	}
	if !hasEnv(c.Env, "KUBECONFIG", "/target/kubeconfig.yaml") {
		t.Error("KUBECONFIG env missing")
	}
	if !hasEnv(c.Env, "SCAN_FRAMEWORK", "NSA") {
		t.Error("SCAN_FRAMEWORK env missing")
	}
	script := strings.Join(c.Args, "\n")
	for _, want := range []string{"kubescape scan framework", "--format json", "SCAN_EXIT=", "cat /tmp/report.json", "20m"} {
		if !strings.Contains(script, want) {
			t.Errorf("script missing %q", want)
		}
	}

	if len(pod.Volumes) != 1 || pod.Volumes[0].Secret == nil {
		t.Fatalf("expected one secret volume, got %+v", pod.Volumes)
	}
	if pod.Volumes[0].Secret.SecretName != "xscan-abcd1234-target" {
		t.Errorf("secretName = %q", pod.Volumes[0].Secret.SecretName)
	}
	if len(c.VolumeMounts) != 1 || c.VolumeMounts[0].MountPath != "/target" || !c.VolumeMounts[0].ReadOnly {
		t.Errorf("target volume mount = %+v", c.VolumeMounts)
	}
}

func TestRenderJobRequiresName(t *testing.T) {
	data := sampleJobData()
	data.JobName = ""
	if _, err := RenderJob(defaultJobTemplate, data); err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestRenderJobUnknownPlaceholder(t *testing.T) {
	_, err := RenderJob([]byte("kind: Job\nmetadata:\n  name: {{.Nope}}\n"), sampleJobData())
	if err == nil {
		t.Fatal("expected error for unknown placeholder")
	}
}

func hasEnv(env []corev1.EnvVar, name, value string) bool {
	for _, e := range env {
		if e.Name == name && e.Value == value {
			return true
		}
	}
	return false
}

var _ = batchv1.Job{}
