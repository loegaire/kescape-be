package main

import (
	"bytes"
	"compress/gzip"
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"text/template"
	"time"

	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

//go:embed deploy/sbomjob-template.yaml
var defaultSBOMJobTemplate []byte

const sbomContainerName = "sbom"

// ImageRef is one container image discovered in the target cluster.
type ImageRef struct {
	Image     string `json:"image"`
	Registry  string `json:"registry"`
	Namespace string `json:"namespace,omitempty"`
	Pod       string `json:"pod,omitempty"`
	Count     int    `json:"count"`
}

// SBOMProgress is one line of progress emitted by the scanner pod.
type SBOMProgress struct {
	Time     time.Time `json:"time"`
	Stage    string    `json:"stage"` // pull, syft, sbom, error, done
	Image    string    `json:"image,omitempty"`
	Registry string    `json:"registry,omitempty"`
	Message  string    `json:"message,omitempty"`
	Bytes    int       `json:"bytes,omitempty"`
}

// SBOMResult is the final state for one image.
type SBOMResult struct {
	Image    string `json:"image"`
	Registry string `json:"registry"`
	Status   string `json:"status"`
	Packages int    `json:"packages"`
	Bytes    int    `json:"bytes"`
	Error    string `json:"error,omitempty"`
}

// SBOMRun is one SBOM generation request and its state.
type SBOMRun struct {
	ID         string         `json:"id"`
	Cluster    string         `json:"cluster"`
	Namespace  string         `json:"namespace"`
	JobName    string         `json:"jobName"`
	SecretName string         `json:"secretName,omitempty"`
	Status     string         `json:"status"`
	Error      string         `json:"error,omitempty"`
	StartedAt  time.Time      `json:"startedAt"`
	Images     []ImageRef     `json:"images"`
	Progress   []SBOMProgress `json:"progress"`
	Results    []SBOMResult   `json:"results"`

	raw map[string][]byte
}

// SBOMStore keeps SBOM runs in memory.
type SBOMStore struct {
	mu sync.Mutex
	m  map[string]*SBOMRun
}

// NewSBOMStore returns an empty store.
func NewSBOMStore() *SBOMStore { return &SBOMStore{m: make(map[string]*SBOMRun)} }

// Put inserts or replaces a run.
func (s *SBOMStore) Put(run *SBOMRun) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[run.ID] = run
}

// Get returns a copy of a run.
func (s *SBOMStore) Get(id string) (*SBOMRun, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.m[id]
	if !ok {
		return nil, false
	}
	cp := *run
	return &cp, true
}

// Delete forgets a run.
func (s *SBOMStore) Delete(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, id)
}

// List returns all runs, newest first.
func (s *SBOMStore) List() []*SBOMRun {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*SBOMRun, 0, len(s.m))
	for _, run := range s.m {
		cp := *run
		out = append(out, &cp)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].StartedAt.After(out[j-1].StartedAt); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// SBOMService creates SBOM Jobs and reports their progress.
type SBOMService struct {
	client      kubernetes.Interface
	logs        func(ctx context.Context, namespace, pod string) (string, error)
	store       *SBOMStore
	namespace   string
	image       string
	jobTmpl     []byte
	maxImages   int
	registryCfg []byte
	listImages  func(ctx context.Context, kubeconfig []byte) ([]ImageRef, error)
	newID       func() string
	now         func() time.Time
}

// NewSBOMService wires a service against a runner cluster.
func NewSBOMService(client kubernetes.Interface, namespace, image string) *SBOMService {
	return &SBOMService{
		client:     client,
		logs:       kubeLogsFor(client, sbomContainerName),
		store:      NewSBOMStore(),
		namespace:  namespace,
		image:      image,
		jobTmpl:    defaultSBOMJobTemplate,
		listImages: ListTargetImages,
		newID:      randomID,
		now:        time.Now,
	}
}

// ListTargetImages returns the unique images referenced by pods in the target.
func ListTargetImages(ctx context.Context, kubeconfig []byte) ([]ImageRef, error) {
	rc, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("parse kubeconfig: %w", err)
	}
	cs, err := kubernetes.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("build target client: %w", err)
	}
	pods, err := cs.CoreV1().Pods("").List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("list pods: %w", err)
	}
	return imagesFromPods(pods.Items), nil
}

func imagesFromPods(pods []corev1.Pod) []ImageRef {
	byImage := map[string]*ImageRef{}
	for i := range pods {
		p := &pods[i]
		images := make([]string, 0, len(p.Spec.InitContainers)+len(p.Spec.Containers)+len(p.Spec.EphemeralContainers))
		for _, c := range p.Spec.InitContainers {
			images = append(images, c.Image)
		}
		for _, c := range p.Spec.Containers {
			images = append(images, c.Image)
		}
		for _, c := range p.Spec.EphemeralContainers {
			images = append(images, c.Image)
		}
		for _, img := range images {
			img = strings.TrimSpace(img)
			if img == "" {
				continue
			}
			if r, ok := byImage[img]; ok {
				r.Count++
				continue
			}
			byImage[img] = &ImageRef{
				Image:     img,
				Registry:  imageRegistry(img),
				Namespace: p.Namespace,
				Pod:       p.Name,
				Count:     1,
			}
		}
	}
	out := make([]ImageRef, 0, len(byImage))
	for _, r := range byImage {
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Image < out[j].Image })
	return out
}

func imageRegistry(img string) string {
	first, _, ok := strings.Cut(img, "/")
	if !ok {
		return "docker.io"
	}
	if strings.ContainsAny(first, ".:") || first == "localhost" {
		return first
	}
	return "docker.io"
}

// Create enumerates images in the target and creates an SBOM Job in the runner.
func (s *SBOMService) Create(ctx context.Context, c Cluster) (*SBOMRun, error) {
	if len(c.Kubeconfig()) == 0 {
		return nil, fmt.Errorf("cluster %q has no kubeconfig", c.Name)
	}
	images, err := s.listImages(ctx, c.Kubeconfig())
	if err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}
	if s.maxImages > 0 && len(images) > s.maxImages {
		images = images[:s.maxImages]
	}
	if len(images) == 0 {
		return nil, fmt.Errorf("cluster %q exposes no images", c.Name)
	}

	id := s.newID()
	run := &SBOMRun{
		ID:        id,
		Cluster:   c.Name,
		Namespace: s.namespace,
		JobName:   "sbom-" + id,
		Status:    StatusPending,
		StartedAt: s.now(),
		Images:    images,
		Progress:  []SBOMProgress{},
		Results:   []SBOMResult{},
		raw:       map[string][]byte{},
	}

	if len(s.registryCfg) > 0 {
		run.SecretName = "sbom-" + id + "-registry"
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      run.SecretName,
				Namespace: s.namespace,
				Labels:    sbomLabels(id),
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{"config.json": s.registryCfg},
		}
		if _, err := s.client.CoreV1().Secrets(s.namespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return nil, fmt.Errorf("create registry secret: %w", err)
		}
	}

	refs := make([]string, 0, len(images))
	for _, im := range images {
		refs = append(refs, im.Image)
	}
	job, err := RenderSBOMJob(s.jobTmpl, SBOMJobData{
		SBOMID:         id,
		JobName:        run.JobName,
		Namespace:      s.namespace,
		Image:          s.image,
		Images:         strings.Join(refs, " "),
		RegistrySecret: run.SecretName,
		HTTPSProxy:     os.Getenv("HTTPS_PROXY"),
		HTTPProxy:      os.Getenv("HTTP_PROXY"),
		NoProxy:        os.Getenv("NO_PROXY"),
	})
	if err != nil {
		s.cleanup(ctx, run)
		return nil, err
	}
	if _, err := s.client.BatchV1().Jobs(s.namespace).Create(ctx, job, metav1.CreateOptions{}); err != nil {
		s.cleanup(ctx, run)
		return nil, fmt.Errorf("create sbom job: %w", err)
	}

	s.store.Put(run)
	return run, nil
}

// Status refreshes a run from the runner cluster and parses pod progress.
func (s *SBOMService) Status(ctx context.Context, id string) (*SBOMRun, error) {
	run, ok := s.store.Get(id)
	if !ok {
		return nil, ErrNotFound
	}

	job, err := s.client.BatchV1().Jobs(run.Namespace).Get(ctx, run.JobName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			run.Status = StatusUnknown
			s.store.Put(run)
			return run, nil
		}
		return nil, fmt.Errorf("get sbom job: %w", err)
	}

	switch {
	case job.Status.Succeeded > 0:
		run.Status = StatusSucceeded
	case job.Status.Failed > 0:
		run.Status = StatusFailed
	case job.Status.Active > 0:
		run.Status = StatusRunning
	default:
		run.Status = StatusPending
	}

	if text, err := s.readLogs(ctx, run); err == nil {
		progress, sboms := parseSBOMLogs(text)
		run.Progress = progress
		if len(sboms) > 0 {
			run.raw = sboms
		}
		run.Results = buildSBOMResults(run.Images, progress, run.raw)
		if run.Status == StatusFailed && run.Error == "" {
			for i := len(progress) - 1; i >= 0; i-- {
				if progress[i].Stage == "error" {
					run.Error = progress[i].Message
					break
				}
			}
		}
	}

	s.store.Put(run)
	return run, nil
}

// Results returns the run and the full SBOM bytes keyed by image.
func (s *SBOMService) Results(ctx context.Context, id string) (*SBOMRun, map[string][]byte, error) {
	run, err := s.Status(ctx, id)
	if err != nil {
		return nil, nil, err
	}
	if len(run.raw) == 0 {
		switch run.Status {
		case StatusSucceeded, StatusFailed:
			return run, nil, ErrNoReport
		default:
			return run, nil, ErrNotReady
		}
	}
	out := make(map[string][]byte, len(run.raw))
	for k, v := range run.raw {
		out[k] = v
	}
	return run, out, nil
}

// List returns all known runs.
func (s *SBOMService) List() []*SBOMRun { return s.store.List() }

// Delete removes a run's Job and registry Secret and forgets it.
func (s *SBOMService) Delete(ctx context.Context, id string) error {
	run, ok := s.store.Get(id)
	if !ok {
		return ErrNotFound
	}
	s.cleanup(ctx, run)
	s.store.Delete(id)
	return nil
}

func (s *SBOMService) cleanup(ctx context.Context, run *SBOMRun) {
	_ = s.client.BatchV1().Jobs(run.Namespace).Delete(ctx, run.JobName, metav1.DeleteOptions{})
	if run.SecretName != "" {
		_ = s.client.CoreV1().Secrets(run.Namespace).Delete(ctx, run.SecretName, metav1.DeleteOptions{})
	}
}

func (s *SBOMService) readLogs(ctx context.Context, run *SBOMRun) (string, error) {
	pods, err := s.client.CoreV1().Pods(run.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "sbom-id=" + run.ID,
	})
	if err != nil {
		return "", err
	}
	if len(pods.Items) == 0 {
		return "", fmt.Errorf("no pod for sbom run %s", run.ID)
	}
	return s.logs(ctx, run.Namespace, pods.Items[0].Name)
}

func sbomLabels(id string) map[string]string {
	return map[string]string{"app": "kubescape-sbom", "sbom-id": id}
}

type sbomProgressLine struct {
	TS       int64  `json:"ts"`
	Stage    string `json:"stage"`
	Image    string `json:"image"`
	Registry string `json:"registry"`
	Message  string `json:"message"`
	Bytes    int    `json:"bytes"`
}

func parseSBOMLogs(logs string) ([]SBOMProgress, map[string][]byte) {
	progress := []SBOMProgress{}
	sboms := map[string][]byte{}
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "PROGRESS "):
			var l sbomProgressLine
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "PROGRESS ")), &l); err != nil {
				continue
			}
			p := SBOMProgress{
				Stage:    l.Stage,
				Image:    l.Image,
				Registry: l.Registry,
				Message:  l.Message,
				Bytes:    l.Bytes,
			}
			if l.TS > 0 {
				p.Time = time.Unix(l.TS, 0).UTC()
			}
			progress = append(progress, p)
		case strings.HasPrefix(line, "SBOM "):
			parts := strings.SplitN(line, " ", 3)
			if len(parts) != 3 {
				continue
			}
			raw, err := decodeSBOM(parts[2])
			if err != nil {
				continue
			}
			sboms[parts[1]] = raw
		}
	}
	return progress, sboms
}

func decodeSBOM(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(zr)
}

func buildSBOMResults(images []ImageRef, progress []SBOMProgress, sboms map[string][]byte) []SBOMResult {
	last := map[string]SBOMProgress{}
	errs := map[string]string{}
	for _, p := range progress {
		if p.Image == "" {
			continue
		}
		last[p.Image] = p
		if p.Stage == "error" {
			errs[p.Image] = p.Message
		}
	}

	out := make([]SBOMResult, 0, len(images))
	for _, im := range images {
		res := SBOMResult{Image: im.Image, Registry: im.Registry, Status: StatusPending}
		if p, ok := last[im.Image]; ok {
			switch p.Stage {
			case "pull", "syft":
				res.Status = StatusRunning
			case "sbom":
				res.Status = StatusSucceeded
				res.Bytes = p.Bytes
			case "error":
				res.Status = StatusFailed
				res.Error = errs[im.Image]
			}
		}
		if raw, ok := sboms[im.Image]; ok {
			res.Status = StatusSucceeded
			res.Bytes = len(raw)
			res.Packages = countSBOMSPackages(raw)
		}
		out = append(out, res)
	}
	return out
}

func countSBOMSPackages(raw []byte) int {
	var doc struct {
		Packages []json.RawMessage `json:"packages"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0
	}
	return len(doc.Packages)
}

// SBOMJobData is substituted into the SBOM Job template.
type SBOMJobData struct {
	SBOMID         string
	JobName        string
	Namespace      string
	Image          string
	Images         string
	RegistrySecret string
	HTTPSProxy     string
	HTTPProxy      string
	NoProxy        string
}

// RenderSBOMJob fills the template and decodes it into a typed Job.
func RenderSBOMJob(tmpl []byte, d SBOMJobData) (*batchv1.Job, error) {
	t, err := template.New("sbomjob").Option("missingkey=error").Parse(string(tmpl))
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
