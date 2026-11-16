package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const (
	kubeconfigKey = "kubeconfig.yaml"
	scannerName   = "scanner"

	StatusPending   = "Pending"
	StatusRunning   = "Running"
	StatusSucceeded = "Succeeded"
	StatusFailed    = "Failed"
	StatusUnknown   = "Unknown"
)

// ErrNotFound is returned when a scan ID is unknown.
var ErrNotFound = errors.New("scan not found")

// ErrNotReady is returned when results are requested before the Job finishes.
var ErrNotReady = errors.New("scan results not ready")

// ErrNoReport is returned when a finished scan produced no readable report.
var ErrNoReport = errors.New("scan produced no report")

// Report is the subset of the Kubescape report surfaced to the UI.
type Report struct {
	ClusterName string  `json:"clusterName"`
	Score       float64 `json:"score"`
	Controls    int     `json:"controls"`
	Failed      int     `json:"failed"`
}

// Scan is one scan request and its state.
type Scan struct {
	ID         string    `json:"id"`
	Cluster    string    `json:"cluster"`
	Framework  string    `json:"framework"`
	Namespace  string    `json:"namespace"`
	JobName    string    `json:"jobName"`
	SecretName string    `json:"secretName"`
	StartedAt  time.Time `json:"startedAt"`
	Status     string    `json:"status"`
	Report     *Report   `json:"report,omitempty"`
	Error      string    `json:"error,omitempty"`

	// rawReport is the full Kubescape report, kept for the results endpoint.
	// It is unexported so the scan JSON stays small.
	rawReport []byte
}

// Store keeps scans in memory. The backend is a control plane, not a database.
type Store struct {
	mu sync.Mutex
	m  map[string]*Scan
}

// NewStore returns an empty Store.
func NewStore() *Store { return &Store{m: make(map[string]*Scan)} }

// Put inserts or replaces a scan.
func (s *Store) Put(sc *Scan) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[sc.ID] = sc
}

// Get returns a copy of a scan.
func (s *Store) Get(id string) (*Scan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sc, ok := s.m[id]
	if !ok {
		return nil, false
	}
	cp := *sc
	return &cp, true
}

// Delete forgets a scan.
func (s *Store) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// List returns all scans, newest first.
func (s *Store) List() []*Scan {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Scan, 0, len(s.m))
	for _, sc := range s.m {
		cp := *sc
		out = append(out, &cp)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].StartedAt.After(out[j-1].StartedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// ScanService creates scan Jobs and reports their status.
type ScanService struct {
	client    kubernetes.Interface
	logs      func(ctx context.Context, namespace, pod string) (string, error)
	store     *Store
	namespace string
	image     string
	framework string
	jobTmpl   []byte
	newID     func() string
	now       func() time.Time
}

// NewScanService wires a service against a runner cluster.
func NewScanService(client kubernetes.Interface, namespace, image, framework string) *ScanService {
	return &ScanService{
		client:    client,
		logs:      kubeLogs(client),
		store:     NewStore(),
		namespace: namespace,
		image:     image,
		framework: framework,
		jobTmpl:   defaultJobTemplate,
		newID:     randomID,
		now:       time.Now,
	}
}

// Create creates the target Secret and the scan Job. It returns immediately;
// use Status to follow progress.
func (s *ScanService) Create(ctx context.Context, c Cluster, framework string) (*Scan, error) {
	if framework == "" {
		framework = s.framework
	}
	if len(c.Kubeconfig()) == 0 {
		return nil, fmt.Errorf("cluster %q has no kubeconfig", c.Name)
	}

	id := s.newID()
	sc := &Scan{
		ID:         id,
		Cluster:    c.Name,
		Framework:  framework,
		Namespace:  s.namespace,
		JobName:    "xscan-" + id,
		SecretName: "xscan-" + id + "-target",
		StartedAt:  s.now(),
		Status:     StatusPending,
	}

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      sc.SecretName,
			Namespace: sc.Namespace,
			Labels:    scanLabels(id),
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{kubeconfigKey: c.Kubeconfig()},
	}
	if _, err := s.client.CoreV1().Secrets(sc.Namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("create target secret: %w", err)
	}

	job, err := RenderJob(s.jobTmpl, JobData{
		ScanID:     id,
		JobName:    sc.JobName,
		SecretName: sc.SecretName,
		Namespace:  sc.Namespace,
		Image:      s.image,
		Framework:  framework,
	})
	if err != nil {
		s.cleanup(ctx, sc)
		return nil, err
	}
	if _, err := s.client.BatchV1().Jobs(sc.Namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		s.cleanup(ctx, sc)
		return nil, fmt.Errorf("create scan job: %w", err)
	}

	s.store.Put(sc)
	return sc, nil
}

// Status refreshes a scan from the runner cluster, reading the report once the
// Job has finished.
func (s *ScanService) Status(ctx context.Context, id string) (*Scan, error) {
	sc, ok := s.store.Get(id)
	if !ok {
		return nil, ErrNotFound
	}

	job, err := s.client.BatchV1().Jobs(sc.Namespace).Get(ctx, sc.JobName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			sc.Status = StatusUnknown
			s.store.Put(sc)
			return sc, nil
		}
		return nil, fmt.Errorf("get scan job: %w", err)
	}

	switch {
	case job.Status.Succeeded > 0:
		sc.Status = StatusSucceeded
	case job.Status.Failed > 0:
		sc.Status = StatusFailed
	case job.Status.Active > 0:
		sc.Status = StatusRunning
	default:
		sc.Status = StatusPending
	}

	if (sc.Status == StatusSucceeded || sc.Status == StatusFailed) && sc.rawReport == nil {
		if text, err := s.scanLogs(ctx, sc); err == nil {
			if exit := scanExitCode(text); exit != "" && exit != "0" {
				// kubescape failed even if the Job completed: the script
				// prints SCAN_EXIT before the (empty or partial) report.
				sc.Status = StatusFailed
			}
			if raw, err := extractReportJSON(text); err == nil {
				sc.rawReport = raw
				if rep, err := parseReportJSON(raw); err == nil {
					sc.Report = rep
				}
			} else if sc.Status == StatusFailed {
				sc.Error = scanFailureMessage(text, err)
			}
		}
	}

	s.store.Put(sc)
	return sc, nil
}

// Results refreshes the scan and returns the full report. It returns
// ErrNotReady while the Job is still running.
func (s *ScanService) Results(ctx context.Context, id string) (*Scan, []byte, error) {
	sc, err := s.Status(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if sc.rawReport == nil {
		switch sc.Status {
		case StatusSucceeded, StatusFailed:
			return sc, nil, ErrNoReport
		default:
			return sc, nil, ErrNotReady
		}
	}
	return sc, sc.rawReport, nil
}

// List returns all known scans.
func (s *ScanService) List() []*Scan { return s.store.List() }

// Delete removes a scan's Job and Secret and forgets it.
func (s *ScanService) Delete(ctx context.Context, id string) error {
	sc, ok := s.store.Get(id)
	if !ok {
		return ErrNotFound
	}
	s.cleanup(ctx, sc)
	s.store.Delete(id)
	return nil
}

func (s *ScanService) cleanup(ctx context.Context, sc *Scan) {
	_ = s.client.BatchV1().Jobs(sc.Namespace).Delete(ctx, sc.JobName, metav1.DeleteOptions{})
	_ = s.client.CoreV1().Secrets(sc.Namespace).Delete(ctx, sc.SecretName, metav1.DeleteOptions{})
}

func (s *ScanService) scanLogs(ctx context.Context, sc *Scan) (string, error) {
	pods, err := s.client.CoreV1().Pods(sc.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "scan-id=" + sc.ID,
	})
	if err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pod for scan %s", sc.ID)
	}
	return s.logs(ctx, sc.Namespace, pods.Items[0].Name)
}

func kubeLogs(client kubernetes.Interface) func(context.Context, string, string) (string, error) {
	return kubeLogsFor(client, scannerName)
}

func kubeLogsFor(client kubernetes.Interface, container string) func(context.Context, string, string) (string, error) {
	return func(ctx context.Context, namespace, pod string) (string, error) {
		req := client.CoreV1().Pods(namespace).GetLogs(pod, &corev1.PodLogOptions{Container: container})
		raw, err := req.Do(ctx).Raw()
		if err != nil {
			return "", err
		}
		return string(raw), nil
	}
}

func scanLabels(id string) map[string]string {
	return map[string]string{"app": "kubescape-xscan", "scan-id": id}
}

func randomID() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%08x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}

// kubescapeReport mirrors only the fields we expose. Unlisted fields are
// ignored, so this keeps working as the report grows.
type kubescapeReport struct {
	ClusterName    string `json:"clusterName"`
	SummaryDetails struct {
		Score    float64 `json:"score"`
		Controls map[string]struct {
			Status string `json:"status"`
		} `json:"controls"`
	} `json:"summaryDetails"`
	Metadata struct {
		TargetMetadata struct {
			ClusterContextMetadata struct {
				ContextName string `json:"contextName"`
			} `json:"clusterContextMetadata"`
		} `json:"targetMetadata"`
	} `json:"metadata"`
}

// extractReportJSON pulls the JSON report out of the scanner pod log. The
// report is printed after the SCAN_EXIT marker, so extraction is scoped to
// that part of the log; anything before it (kubescape's own log lines, which
// can be JSON) is not a report.
func extractReportJSON(logs string) ([]byte, error) {
	logs = afterScanExit(logs)
	start := strings.Index(logs, "{")
	end := strings.LastIndex(logs, "}")
	if start < 0 || end <= start {
		return nil, fmt.Errorf("no JSON report in pod log")
	}
	raw := []byte(logs[start : end+1])
	if !json.Valid(raw) {
		return nil, fmt.Errorf("report is not valid JSON (possibly truncated)")
	}
	return raw, nil
}

// afterScanExit returns everything after the scanner's "SCAN_EXIT=<n>" line,
// or the log unchanged when the marker is missing.
func afterScanExit(logs string) string {
	i := strings.LastIndex(logs, "SCAN_EXIT=")
	if i < 0 {
		return logs
	}
	rest := logs[i:]
	if nl := strings.Index(rest, "\n"); nl >= 0 {
		return rest[nl+1:]
	}
	return ""
}

// scanExitCode returns the value printed by the scanner's "SCAN_EXIT=<n>"
// line, or "" when the line is missing.
func scanExitCode(logs string) string {
	for _, line := range strings.Split(logs, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "SCAN_EXIT="); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// scanFailureMessage builds a short human-readable error for a failed scan,
// preferring kubescape's own fatal message over the generic extraction error.
func scanFailureMessage(logs string, extractErr error) string {
	if exit := scanExitCode(logs); exit != "" && exit != "0" {
		if msg := fatalMessage(logs); msg != "" {
			return fmt.Sprintf("kubescape exited with code %s: %s", exit, msg)
		}
		return fmt.Sprintf("kubescape exited with code %s", exit)
	}
	return extractErr.Error()
}

// fatalMessage returns the "msg" of the first kubescape fatal log line,
// truncated for display.
func fatalMessage(logs string) string {
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, `{"level":"fatal"`) {
			continue
		}
		var entry struct {
			Msg string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(line), &entry); err == nil && entry.Msg != "" {
			if len(entry.Msg) > 300 {
				entry.Msg = entry.Msg[:300] + "..."
			}
			return entry.Msg
		}
	}
	return ""
}

// ParseReport extracts a summary from the scanner pod log.
func ParseReport(logs string) (*Report, error) {
	raw, err := extractReportJSON(logs)
	if err != nil {
		return nil, err
	}
	return parseReportJSON(raw)
}

func parseReportJSON(raw []byte) (*Report, error) {
	var kr kubescapeReport
	if err := json.Unmarshal(raw, &kr); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}

	name := kr.ClusterName
	if name == "" {
		// Kubescape v3 reports the context under metadata instead.
		name = kr.Metadata.TargetMetadata.ClusterContextMetadata.ContextName
	}

	rep := &Report{
		ClusterName: name,
		Score:       kr.SummaryDetails.Score,
		Controls:    len(kr.SummaryDetails.Controls),
	}
	for _, c := range kr.SummaryDetails.Controls {
		if strings.EqualFold(c.Status, "failed") {
			rep.Failed++
		}
	}
	return rep, nil
}
