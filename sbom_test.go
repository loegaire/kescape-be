package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const sampleSPDX = `{"spdxVersion":"SPDX-2.3","name":"alpine","packages":[{"name":"busybox"},{"name":"alpine-baselayout"}]}`

func newTestSBOMService() (*SBOMService, *fake.Clientset) {
	cs := fake.NewSimpleClientset()
	svc := NewSBOMService(cs, "kubescape", "sbom-scanner:local")
	svc.listImages = func(context.Context, []byte) ([]ImageRef, error) {
		return []ImageRef{
			{Image: "docker.io/library/alpine:3.20", Registry: "docker.io", Count: 1},
			{Image: "gcr.io/demo/api:1.2", Registry: "gcr.io", Count: 2},
		}, nil
	}
	return svc, cs
}

func envValue(c corev1.Container, name string) string {
	for _, e := range c.Env {
		if e.Name == name {
			return e.Value
		}
	}
	return ""
}

func encodeSBOMForTest(t *testing.T, raw string) string {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(raw)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestImageRegistry(t *testing.T) {
	cases := map[string]string{
		"alpine:3.20":                    "docker.io",
		"library/alpine":                 "docker.io",
		"docker.io/library/alpine:3.20":  "docker.io",
		"gcr.io/demo/api:1.2":            "gcr.io",
		"localhost:5000/app:dev":         "localhost:5000",
		"registry.example.com/team/app":  "registry.example.com",
		"quay.io/kubescape/kubescape:v4": "quay.io",
	}
	for in, want := range cases {
		if got := imageRegistry(in); got != want {
			t.Errorf("imageRegistry(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestImagesFromPodsDeduplicates(t *testing.T) {
	pods := []corev1.Pod{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "ns1"},
			Spec: corev1.PodSpec{
				InitContainers: []corev1.Container{{Name: "init", Image: "busybox:1.36"}},
				Containers:     []corev1.Container{{Name: "app", Image: "nginx:1.27"}},
			},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "ns2"},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{{Name: "app", Image: "nginx:1.27"}, {Name: "side", Image: "redis:7"}},
			},
		},
	}

	got := imagesFromPods(pods)
	if len(got) != 3 {
		t.Fatalf("got %d images, want 3: %+v", len(got), got)
	}
	byImage := map[string]ImageRef{}
	for _, im := range got {
		byImage[im.Image] = im
	}
	if byImage["nginx:1.27"].Count != 2 {
		t.Errorf("nginx count = %d, want 2", byImage["nginx:1.27"].Count)
	}
	if byImage["busybox:1.36"].Namespace != "ns1" {
		t.Errorf("busybox namespace = %q", byImage["busybox:1.36"].Namespace)
	}
	if got[0].Image != "busybox:1.36" {
		t.Errorf("images not sorted: %+v", got)
	}
}

func TestSBOMCreateCreatesJob(t *testing.T) {
	svc, cs := newTestSBOMService()
	ctx := context.Background()

	run, err := svc.Create(ctx, testCluster())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if run.ID == "" || run.JobName != "sbom-"+run.ID {
		t.Errorf("unexpected identity: %+v", run)
	}
	if run.Status != StatusPending {
		t.Errorf("status = %q", run.Status)
	}
	if len(run.Images) != 2 {
		t.Errorf("images = %d", len(run.Images))
	}

	job, err := cs.BatchV1().Jobs("kubescape").Get(ctx, run.JobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if job.Labels["sbom-id"] != run.ID {
		t.Errorf("job label sbom-id = %q", job.Labels["sbom-id"])
	}
	c := job.Spec.Template.Spec.Containers[0]
	if c.Image != "sbom-scanner:local" {
		t.Errorf("image = %q", c.Image)
	}
	want := "docker.io/library/alpine:3.20 gcr.io/demo/api:1.2"
	if got := envValue(c, "SBOM_IMAGES"); got != want {
		t.Errorf("SBOM_IMAGES = %q, want %q", got, want)
	}
}

func TestSBOMCreateRejectsEmptyKubeconfig(t *testing.T) {
	svc, cs := newTestSBOMService()
	if _, err := svc.Create(context.Background(), Cluster{Name: "empty"}); err == nil {
		t.Fatal("expected error for empty kubeconfig")
	}
	if len(cs.Actions()) != 0 {
		t.Errorf("no cluster calls expected, got %d", len(cs.Actions()))
	}
}

func TestSBOMCreateRejectsNoImages(t *testing.T) {
	svc, _ := newTestSBOMService()
	svc.listImages = func(context.Context, []byte) ([]ImageRef, error) { return nil, nil }
	if _, err := svc.Create(context.Background(), testCluster()); err == nil {
		t.Fatal("expected error when no images are found")
	}
}

func TestSBOMCreateWithRegistrySecret(t *testing.T) {
	svc, cs := newTestSBOMService()
	svc.registryCfg = []byte(`{"auths":{"registry.example.com":{}}}`)
	ctx := context.Background()

	run, err := svc.Create(ctx, testCluster())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if run.SecretName == "" {
		t.Fatal("expected a registry secret name")
	}
	secret, err := cs.CoreV1().Secrets("kubescape").Get(ctx, run.SecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get secret: %v", err)
	}
	if string(secret.Data["config.json"]) != string(svc.registryCfg) {
		t.Error("registry secret does not carry the docker config")
	}

	job, err := cs.BatchV1().Jobs("kubescape").Get(ctx, run.JobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	if len(job.Spec.Template.Spec.Volumes) != 1 {
		t.Errorf("volumes = %d, want 1", len(job.Spec.Template.Spec.Volumes))
	}
	if len(job.Spec.Template.Spec.Containers[0].VolumeMounts) != 1 {
		t.Errorf("volume mounts = %d, want 1", len(job.Spec.Template.Spec.Containers[0].VolumeMounts))
	}
}

func TestSBOMStatusParsesProgressAndResults(t *testing.T) {
	svc, cs := newTestSBOMService()
	ctx := context.Background()

	run, err := svc.Create(ctx, testCluster())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = cs.CoreV1().Pods("kubescape").Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "sbom-pod",
			Namespace: "kubescape",
			Labels:    map[string]string{"sbom-id": run.ID},
		},
		Spec: corev1.PodSpec{Containers: []corev1.Container{{Name: "sbom", Image: "sbom-scanner:local"}}},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create pod: %v", err)
	}

	job, err := cs.BatchV1().Jobs("kubescape").Get(ctx, run.JobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	job.Status.Succeeded = 1
	if _, err := cs.BatchV1().Jobs("kubescape").UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update job: %v", err)
	}

	encoded := encodeSBOMForTest(t, sampleSPDX)
	logs := `PROGRESS {"ts":1700000000,"stage":"pull","image":"docker.io/library/alpine:3.20","registry":"docker.io"}
PROGRESS {"ts":1700000001,"stage":"syft","image":"docker.io/library/alpine:3.20","registry":"docker.io"}
PROGRESS {"ts":1700000002,"stage":"sbom","image":"docker.io/library/alpine:3.20","registry":"docker.io","bytes":74}
SBOM docker.io/library/alpine:3.20 ` + encoded + `
PROGRESS {"ts":1700000003,"stage":"error","image":"gcr.io/demo/api:1.2","registry":"gcr.io","message":"pull access denied"}
PROGRESS {"ts":1700000004,"stage":"done"}`
	svc.logs = func(context.Context, string, string) (string, error) { return logs, nil }

	got, err := svc.Status(ctx, run.ID)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if got.Status != StatusSucceeded {
		t.Errorf("status = %q", got.Status)
	}
	if len(got.Progress) != 5 {
		t.Errorf("progress events = %d, want 5", len(got.Progress))
	}
	if len(got.Results) != 2 {
		t.Fatalf("results = %d, want 2", len(got.Results))
	}
	if got.Results[0].Image != "docker.io/library/alpine:3.20" {
		t.Errorf("first result = %q", got.Results[0].Image)
	}
	if got.Results[0].Status != StatusSucceeded {
		t.Errorf("alpine status = %q", got.Results[0].Status)
	}
	if got.Results[0].Packages != 2 {
		t.Errorf("alpine packages = %d, want 2", got.Results[0].Packages)
	}
	if got.Results[0].Bytes != len(sampleSPDX) {
		t.Errorf("alpine bytes = %d, want %d", got.Results[0].Bytes, len(sampleSPDX))
	}
	if got.Results[1].Status != StatusFailed || got.Results[1].Error != "pull access denied" {
		t.Errorf("api result = %+v", got.Results[1])
	}
}

func TestSBOMResultsNotReady(t *testing.T) {
	svc, _ := newTestSBOMService()
	ctx := context.Background()
	run, err := svc.Create(ctx, testCluster())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, _, err := svc.Results(ctx, run.ID); err != ErrNotReady {
		t.Errorf("err = %v, want ErrNotReady", err)
	}
}

func TestSBOMResultsNotFound(t *testing.T) {
	svc, _ := newTestSBOMService()
	if _, _, err := svc.Results(context.Background(), "nope"); err != ErrNotFound {
		t.Errorf("err = %v, want ErrNotFound", err)
	}
}

func TestParseSBOMLogsSkipsBadLines(t *testing.T) {
	encoded := encodeSBOMForTest(t, sampleSPDX)
	logs := "PROGRESS {bad json}\nSBOM image-without-payload\nSBOM alpine " + encoded + "\nnoise\n"
	progress, sboms := parseSBOMLogs(logs)
	if len(progress) != 0 {
		t.Errorf("progress = %d, want 0", len(progress))
	}
	if string(sboms["alpine"]) != sampleSPDX {
		t.Errorf("decoded sbom = %q", string(sboms["alpine"]))
	}
}

func TestRenderSBOMJob(t *testing.T) {
	job, err := RenderSBOMJob(defaultSBOMJobTemplate, SBOMJobData{
		SBOMID:     "abc123",
		JobName:    "sbom-abc123",
		Namespace:  "kubescape",
		Image:      "sbom-scanner:local",
		Images:     "alpine:3.20 busybox:latest",
		HTTPSProxy: "http://proxy:8080",
	})
	if err != nil {
		t.Fatalf("RenderSBOMJob: %v", err)
	}
	if job.Name != "sbom-abc123" || job.Labels["sbom-id"] != "abc123" {
		t.Errorf("job metadata = %+v", job.ObjectMeta)
	}
	c := job.Spec.Template.Spec.Containers[0]
	if got := envValue(c, "SBOM_IMAGES"); got != "alpine:3.20 busybox:latest" {
		t.Errorf("SBOM_IMAGES = %q", got)
	}
	if got := envValue(c, "HTTPS_PROXY"); got != "http://proxy:8080" {
		t.Errorf("HTTPS_PROXY = %q", got)
	}
	if len(job.Spec.Template.Spec.Volumes) != 0 {
		t.Errorf("unexpected volumes: %d", len(job.Spec.Template.Spec.Volumes))
	}
}

func TestSBOMContainerNameMatchesLogReader(t *testing.T) {
	job, err := RenderSBOMJob(defaultSBOMJobTemplate, SBOMJobData{
		SBOMID:    "abc123",
		JobName:   "sbom-abc123",
		Namespace: "kubescape",
		Image:     "sbom-scanner:local",
		Images:    "alpine:3.20",
	})
	if err != nil {
		t.Fatalf("RenderSBOMJob: %v", err)
	}
	if got := job.Spec.Template.Spec.Containers[0].Name; got != sbomContainerName {
		t.Fatalf("container name = %q, log reader reads %q", got, sbomContainerName)
	}
}

func TestRenderSBOMJobWithRegistrySecret(t *testing.T) {
	job, err := RenderSBOMJob(defaultSBOMJobTemplate, SBOMJobData{
		SBOMID:         "abc123",
		JobName:        "sbom-abc123",
		Namespace:      "kubescape",
		Image:          "sbom-scanner:local",
		Images:         "alpine:3.20",
		RegistrySecret: "sbom-abc123-registry",
	})
	if err != nil {
		t.Fatalf("RenderSBOMJob: %v", err)
	}
	if len(job.Spec.Template.Spec.Volumes) != 1 {
		t.Fatalf("volumes = %d, want 1", len(job.Spec.Template.Spec.Volumes))
	}
	if job.Spec.Template.Spec.Volumes[0].Secret.SecretName != "sbom-abc123-registry" {
		t.Errorf("volume secret = %q", job.Spec.Template.Spec.Volumes[0].Secret.SecretName)
	}
}

func TestAPICreateSBOM(t *testing.T) {
	h, _, _ := newTestAPI()
	w := do(t, h, http.MethodPost, "/api/sboms", `{"cluster":"target"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	var run SBOMRun
	if err := json.Unmarshal(w.Body.Bytes(), &run); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(run.Images) != 1 || run.Images[0].Image != "nginx:1.27" {
		t.Errorf("images = %+v", run.Images)
	}

	got := do(t, h, http.MethodGet, "/api/sboms/"+run.ID, "")
	if got.Code != http.StatusOK {
		t.Errorf("get status = %d", got.Code)
	}

	res := do(t, h, http.MethodGet, "/api/sboms/"+run.ID+"/results", "")
	if res.Code != http.StatusConflict {
		t.Errorf("results status = %d, want 409", res.Code)
	}
}

func TestAPICreateSBOMUnknownCluster(t *testing.T) {
	h, _, _ := newTestAPI()
	w := do(t, h, http.MethodPost, "/api/sboms", `{"cluster":"missing"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Code)
	}
}

func TestAPISBOMNotFound(t *testing.T) {
	h, _, _ := newTestAPI()
	if w := do(t, h, http.MethodGet, "/api/sboms/nope", ""); w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}

func TestAPISBOMPage(t *testing.T) {
	h, _, _ := newTestAPI()
	w := do(t, h, http.MethodGet, "/sbom", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("SBOM generation")) {
		t.Error("page does not contain the title")
	}
}
