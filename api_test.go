package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func newTestAPI() (http.Handler, *fake.Clientset, *ScanService) {
	svc, cs := newTestService()
	sbom := NewSBOMService(cs, "kubescape", "sbom-scanner:local")
	sbom.listImages = func(context.Context, []byte) ([]ImageRef, error) {
		return []ImageRef{{Image: "nginx:1.27", Registry: "docker.io", Count: 1}}, nil
	}
	handler := NewAPI(svc, sbom, []Cluster{
		{Name: "target", Server: "https://target.example", Source: "target.kubeconfig", kubeconfig: []byte("kubeconfig: yes\n")},
		{Name: "other", Server: "https://other.example", Source: "other.kubeconfig", kubeconfig: []byte("kubeconfig: yes\n")},
	})
	return handler, cs, svc
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, path, nil)
	} else {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func createScan(t *testing.T, h http.Handler) Scan {
	t.Helper()
	w := do(t, h, http.MethodPost, "/api/scans", `{"cluster":"target"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("create scan: status = %d, body = %s", w.Code, w.Body.String())
	}
	var scan Scan
	if err := json.Unmarshal(w.Body.Bytes(), &scan); err != nil {
		t.Fatalf("decode scan: %v", err)
	}
	return scan
}

func finishJob(t *testing.T, cs *fake.Clientset, scan Scan) {
	t.Helper()
	ctx := context.Background()
	createPodWithScanLabel(t, cs, scan.ID)
	job, err := cs.BatchV1().Jobs(scan.Namespace).Get(ctx, scan.JobName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("get job: %v", err)
	}
	job.Status.Succeeded = 1
	if _, err := cs.BatchV1().Jobs(scan.Namespace).UpdateStatus(ctx, job, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update job: %v", err)
	}
}

func TestListClusters(t *testing.T) {
	h, _, _ := newTestAPI()
	w := do(t, h, http.MethodGet, "/api/clusters", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}

	var got []Cluster
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(got) != 2 || got[0].Name != "target" || got[1].Name != "other" {
		t.Errorf("unexpected clusters: %+v", got)
	}
	if strings.Contains(w.Body.String(), "kubeconfig: yes") {
		t.Error("response leaked kubeconfig bytes")
	}
}

func TestHealth(t *testing.T) {
	h, _, _ := newTestAPI()
	if w := do(t, h, http.MethodGet, "/healthz", ""); w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestIndexServesHTML(t *testing.T) {
	h, _, _ := newTestAPI()
	w := do(t, h, http.MethodGet, "/", "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Target cluster") {
		t.Error("index HTML missing drop-down")
	}
}

func TestCreateScan(t *testing.T) {
	h, cs, _ := newTestAPI()
	w := do(t, h, http.MethodPost, "/api/scans", `{"cluster":"target"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}

	var scan Scan
	if err := json.Unmarshal(w.Body.Bytes(), &scan); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if scan.ID == "" || scan.Cluster != "target" || scan.Status != StatusPending {
		t.Errorf("unexpected scan: %+v", scan)
	}
	if len(cs.Actions()) != 2 {
		t.Fatalf("expected secret+job creation, got %d actions", len(cs.Actions()))
	}
}

func TestCreateScanRejectsUnknownCluster(t *testing.T) {
	h, cs, _ := newTestAPI()
	w := do(t, h, http.MethodPost, "/api/scans", `{"cluster":"nope"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
	if len(cs.Actions()) != 0 {
		t.Error("cluster was touched for an unknown target")
	}
}

func TestCreateScanRejectsBadJSON(t *testing.T) {
	h, _, _ := newTestAPI()
	if w := do(t, h, http.MethodPost, "/api/scans", `{`); w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestGetScan(t *testing.T) {
	h, _, _ := newTestAPI()
	scan := createScan(t, h)

	w := do(t, h, http.MethodGet, "/api/scans/"+scan.ID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d", w.Code)
	}
	var got Scan
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != scan.ID || got.Status != StatusPending {
		t.Errorf("unexpected scan: %+v", got)
	}
}

func TestGetScanNotFound(t *testing.T) {
	h, _, _ := newTestAPI()
	if w := do(t, h, http.MethodGet, "/api/scans/missing", ""); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestDeleteScan(t *testing.T) {
	h, _, _ := newTestAPI()
	scan := createScan(t, h)

	if w := do(t, h, http.MethodDelete, "/api/scans/"+scan.ID, ""); w.Code != http.StatusNoContent {
		t.Fatalf("status = %d", w.Code)
	}
	if w := do(t, h, http.MethodGet, "/api/scans/"+scan.ID, ""); w.Code != http.StatusNotFound {
		t.Fatalf("status after delete = %d", w.Code)
	}
}

func TestResultsNotReady(t *testing.T) {
	h, _, _ := newTestAPI()
	scan := createScan(t, h)
	if w := do(t, h, http.MethodGet, "/api/scans/"+scan.ID+"/results", ""); w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}
}

func TestResultsNotFound(t *testing.T) {
	h, _, _ := newTestAPI()
	if w := do(t, h, http.MethodGet, "/api/scans/missing/results", ""); w.Code != http.StatusNotFound {
		t.Fatalf("status = %d", w.Code)
	}
}

func TestResultsReady(t *testing.T) {
	h, cs, svc := newTestAPI()
	scan := createScan(t, h)

	svc.logs = func(context.Context, string, string) (string, error) {
		return "SCAN_EXIT=0\n" + sampleReport, nil
	}
	finishJob(t, cs, scan)

	for _, path := range []string{"/api/scans/" + scan.ID + "/results", "/api/results/" + scan.ID} {
		w := do(t, h, http.MethodGet, path, "")
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, body = %s", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), `"clusterName":"target"`) {
			t.Errorf("%s: full report missing", path)
		}
		var resp resultsResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: decode: %v", path, err)
		}
		if resp.Scan == nil || resp.Scan.ID != scan.ID {
			t.Errorf("%s: scan metadata missing", path)
		}
		if len(resp.Results) == 0 {
			t.Errorf("%s: results payload empty", path)
		}
	}
}
