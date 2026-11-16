package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

const sampleReport = `{"clusterName":"target","summaryDetails":{"score":42.5,"controls":{"C-1":{"status":"failed"},"C-2":{"status":"passed"},"C-3":{"status":"failed"}}}}`

func testCluster() Cluster {
	return Cluster{
		Name:       "target",
		Server:     "https://target.example",
		Source:     "target.kubeconfig",
		kubeconfig: []byte("apiVersion: v1\nkind: Config\nclusters:\n- name: target\n"),
	}
}

func newTestService() (*ScanService, *fake.Clientset) {
	cs := fake.NewSimpleClientset()
	return NewScanService(cs, "kubescape", "kubescape-scanner:local", "NSA"), cs
}

func TestCreateCreatesSecretAndJob(t *testing.T) {
	svc, cs := newTestService()
	ctx := context.Background()

	scan, err := svc.Create(ctx, testCluster(), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if scan.ID == "" || scan.JobName != "xscan-"+scan.ID {
		t.Errorf("unexpected scan identity: %+v", scan)
	}
	if scan.Framework != "NSA" {
		t.Errorf("framework = %q, want default NSA", scan.Framework)
	}
	if scan.Status != StatusPending {
		t.Errorf("status = %q, want %q", scan.Status, StatusPending)
	}

	secret, err := cs.CoreV1().Secrets("kubescape").Get(ctx, scan.SecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(secret.Data[kubeconfigKey]) != string(testCluster().Kubeconfig()) {
		t.Error("secret does not carry the cluster kubeconfig")
	}

	job, err := cs.BatchV1().Jobs("kubescape").Get(ctx, scan.JobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.Labels["scan-id"] != scan.ID {
		t.Errorf("job label scan-id = %q, want %q", job.Labels["scan-id"], scan.ID)
	}
	if job.Spec.Template.Spec.Containers[0].Image != "kubescape-scanner:local" {
		t.Errorf("image = %q", job.Spec.Template.Spec.Containers[0].Image)
	}
}

func TestCreateHonoursFrameworkOverride(t *testing.T) {
	svc, _ := newTestService()
	scan, err := svc.Create(context.Background(), testCluster(), "FSP-BASELINE")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if scan.Framework != "FSP-BASELINE" {
		t.Errorf("framework = %q", scan.Framework)
	}
}

func TestCreateRejectsEmptyKubeconfig(t *testing.T) {
	svc, cs := newTestService()
	if _, err := svc.Create(context.Background(), Cluster{Name: "empty"}, ""); err == nil {
		t.Fatal("expected error for empty kubeconfig")
	}
	if len(cs.Actions()) != 0 {
		t.Errorf("no cluster calls expected, got %d", len(cs.Actions()))
	}
}

func TestCreateCleansUpSecretWhenJobFails(t *testing.T) {
	svc, cs := newTestService()
	cs.PrependReactor("create", "jobs", func(k8stesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("boom")
	})

	_, err := svc.Create(context.Background(), testCluster(), "")
	if err == nil {
		t.Fatal("expected Create to fail")
	}
	secrets, err := cs.CoreV1().Secrets("kubescape").List(context.Background(), metav1.ListOptions{})
	if err != nil {
		t.Fatalf("list secrets: %v", err)
	}
	if len(secrets.Items) != 0 {
		t.Errorf("secret not cleaned up: %d remain", len(secrets.Items))
	}
}

func TestStatusPendingThenRunning(t *testing.T) {
	svc, cs := newTestService()
	ctx := context.Background()
	scan, err := svc.Create(ctx, testCluster(), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := svc.Status(ctx, scan.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Status != StatusPending {
		t.Errorf("status = %q, want %q", got.Status, StatusPending)
	}

	job, _ := cs.BatchV1().Jobs("kubescape").Get(ctx, scan.JobName, metav1.GetOptions{})
	job.Status.Active = 1
	if _, err := cs.BatchV1().Jobs("kubescape").UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update status: %v", err)
	}

	got, err = svc.Status(ctx, scan.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Status != StatusRunning {
		t.Errorf("status = %q, want %q", got.Status, StatusRunning)
	}
}

func TestStatusSucceededParsesReport(t *testing.T) {
	svc, cs := newTestService()
	ctx := context.Background()
	scan, err := svc.Create(ctx, testCluster(), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	svc.logs = func(context.Context, string, string) (string, error) {
		return "SCAN_EXIT=0\n" + sampleReport, nil
	}
	createPodWithScanLabel(t, cs, scan.ID)

	job, _ := cs.BatchV1().Jobs("kubescape").Get(ctx, scan.JobName, metav1.GetOptions{})
	job.Status.Succeeded = 1
	if _, err := cs.BatchV1().Jobs("kubescape").UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update status: %v", err)
	}

	got, err := svc.Status(ctx, scan.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Status != StatusSucceeded {
		t.Fatalf("status = %q, want %q", got.Status, StatusSucceeded)
	}
	if got.Report == nil {
		t.Fatal("report not parsed")
	}
	if got.Report.ClusterName != "target" {
		t.Errorf("report cluster = %q", got.Report.ClusterName)
	}
	if got.Report.Score != 42.5 {
		t.Errorf("score = %v", got.Report.Score)
	}
	if got.Report.Controls != 3 || got.Report.Failed != 2 {
		t.Errorf("controls/failed = %d/%d, want 3/2", got.Report.Controls, got.Report.Failed)
	}
}

func TestStatusSucceededButScanFailed(t *testing.T) {
	svc, cs := newTestService()
	ctx := context.Background()
	scan, err := svc.Create(ctx, testCluster(), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	svc.logs = func(context.Context, string, string) (string, error) {
		return `{"level":"fatal","msg":"failed to get resource: connection refused"}` + "\n" +
			"SCAN_EXIT=1\n", nil
	}
	createPodWithScanLabel(t, cs, scan.ID)

	job, _ := cs.BatchV1().Jobs("kubescape").Get(ctx, scan.JobName, metav1.GetOptions{})
	job.Status.Succeeded = 1
	if _, err := cs.BatchV1().Jobs("kubescape").UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update status: %v", err)
	}

	got, err := svc.Status(ctx, scan.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Status != StatusFailed {
		t.Fatalf("status = %q, want %q", got.Status, StatusFailed)
	}
	if want := "kubescape exited with code 1: failed to get resource: connection refused"; got.Error != want {
		t.Errorf("error = %q, want %q", got.Error, want)
	}
}

func TestScanExitCode(t *testing.T) {
	if got := scanExitCode("SCAN_EXIT=0\n"); got != "0" {
		t.Errorf("got %q", got)
	}
	if got := scanExitCode("SCAN_EXIT=1\n"); got != "1" {
		t.Errorf("got %q", got)
	}
	if got := scanExitCode("no marker"); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestFatalMessage(t *testing.T) {
	logs := `{"level":"info","msg":"start"}` + "\n" + `{"level":"fatal","msg":"boom` + strings.Repeat("x", 400) + `"}` + "\n"
	got := fatalMessage(logs)
	if !strings.HasPrefix(got, "boom") {
		t.Errorf("msg = %q", got)
	}
	if len(got) > 303 {
		t.Errorf("msg not truncated: %d chars", len(got))
	}
	if fatalMessage("SCAN_EXIT=1\n") != "" {
		t.Error("expected empty msg when no fatal line")
	}
}

func TestStatusNotFound(t *testing.T) {	svc, _ := newTestService()
	if _, err := svc.Status(context.Background(), "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestDeleteRemovesJobAndSecret(t *testing.T) {
	svc, cs := newTestService()
	ctx := context.Background()
	scan, err := svc.Create(ctx, testCluster(), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if err := svc.Delete(ctx, scan.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := cs.BatchV1().Jobs("kubescape").Get(ctx, scan.JobName, metav1.GetOptions{}); err == nil {
		t.Error("job still present")
	}
	if _, err := cs.CoreV1().Secrets("kubescape").Get(ctx, scan.SecretName, metav1.GetOptions{}); err == nil {
		t.Error("secret still present")
	}
	if _, err := svc.Status(ctx, scan.ID); !errors.Is(err, ErrNotFound) {
		t.Error("scan still tracked")
	}
}

func TestResultsServiceNotReady(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()
	scan, err := svc.Create(ctx, testCluster(), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, err := svc.Results(ctx, scan.ID); !errors.Is(err, ErrNotReady) {
		t.Fatalf("err = %v, want ErrNotReady", err)
	}
}

func TestResultsReturnsFullReport(t *testing.T) {
	svc, cs := newTestService()
	ctx := context.Background()
	scan, err := svc.Create(ctx, testCluster(), "")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	svc.logs = func(context.Context, string, string) (string, error) {
		return "SCAN_EXIT=0\n" + sampleReport, nil
	}
	createPodWithScanLabel(t, cs, scan.ID)
	job, _ := cs.BatchV1().Jobs("kubescape").Get(ctx, scan.JobName, metav1.GetOptions{})
	job.Status.Succeeded = 1
	if _, err := cs.BatchV1().Jobs("kubescape").UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update status: %v", err)
	}

	got, raw, err := svc.Results(ctx, scan.ID)
	if err != nil {
		t.Fatalf("Results: %v", err)
	}
	if string(raw) != sampleReport {
		t.Errorf("raw report = %s", raw)
	}
	if got.Report == nil || got.Report.Failed != 2 {
		t.Errorf("summary not parsed: %+v", got.Report)
	}
}

func TestResultsNoReportWhenLogUnreadable(t *testing.T) {
	svc, cs := newTestService()
	ctx := context.Background()
	scan, _ := svc.Create(ctx, testCluster(), "")

	svc.logs = func(context.Context, string, string) (string, error) {
		return "syntax error", nil
	}
	createPodWithScanLabel(t, cs, scan.ID)
	job, _ := cs.BatchV1().Jobs("kubescape").Get(ctx, scan.JobName, metav1.GetOptions{})
	job.Status.Succeeded = 1
	_, _ = cs.BatchV1().Jobs("kubescape").UpdateStatus(ctx, job, metav1.UpdateOptions{})

	if _, _, err := svc.Results(ctx, scan.ID); !errors.Is(err, ErrNoReport) {
		t.Fatalf("err = %v, want ErrNoReport", err)
	}
}

func TestParseReport(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		rep, err := ParseReport("SCAN_EXIT=0\n" + sampleReport + "\n")
		if err != nil {
			t.Fatalf("ParseReport: %v", err)
		}
		if rep.Controls != 3 || rep.Failed != 2 || rep.Score != 42.5 {
			t.Errorf("unexpected report: %+v", rep)
		}
	})
	t.Run("no json", func(t *testing.T) {
		if _, err := ParseReport("SCAN_EXIT=1\nkubescape: boom\n"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("truncated json", func(t *testing.T) {
		if _, err := ParseReport(`{"clusterName":"x"`); err == nil {
			t.Fatal("expected error")
		}
	})
}

func createPodWithScanLabel(t *testing.T, cs *fake.Clientset, scanID string) {
	t.Helper()
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "xscan-" + scanID + "-pod",
			Namespace: "kubescape",
			Labels:    map[string]string{"scan-id": scanID},
		},
	}
	if _, err := cs.CoreV1().Pods("kubescape").Create(context.Background(), pod, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create pod: %v", err)
	}
}
