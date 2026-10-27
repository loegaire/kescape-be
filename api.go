package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
)

// API serves the drop-down UI and the scan endpoints.
type API struct {
	svc      *ScanService
	sbom     *SBOMService
	clusters []Cluster
}

// NewAPI builds the HTTP handler.
func NewAPI(svc *ScanService, sbom *SBOMService, clusters []Cluster) http.Handler {
	a := &API{svc: svc, sbom: sbom, clusters: clusters}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", a.handleIndex)
	mux.HandleFunc("GET /healthz", a.handleHealth)
	mux.HandleFunc("GET /api/clusters", a.handleClusters)
	mux.HandleFunc("GET /api/scans", a.handleListScans)
	mux.HandleFunc("POST /api/scans", a.handleCreateScan)
	mux.HandleFunc("GET /api/scans/{id}", a.handleGetScan)
	mux.HandleFunc("GET /api/scans/{id}/results", a.handleResults)
	mux.HandleFunc("GET /api/results/{id}", a.handleResults)
	mux.HandleFunc("DELETE /api/scans/{id}", a.handleDeleteScan)

	mux.HandleFunc("GET /sbom", a.handleSBOMIndex)
	mux.HandleFunc("GET /api/sboms", a.handleListSBOMs)
	mux.HandleFunc("POST /api/sboms", a.handleCreateSBOM)
	mux.HandleFunc("GET /api/sboms/{id}", a.handleGetSBOM)
	mux.HandleFunc("GET /api/sboms/{id}/results", a.handleSBOMResults)
	mux.HandleFunc("GET /api/sboms/{id}/results/{image...}", a.handleSBOMResultOne)
	mux.HandleFunc("DELETE /api/sboms/{id}", a.handleDeleteSBOM)
	return mux
}

type resultsResponse struct {
	Scan    *Scan           `json:"scan"`
	Results json.RawMessage `json:"results"`
}

func (a *API) handleResults(w http.ResponseWriter, r *http.Request) {
	scan, raw, err := a.svc.Results(r.Context(), r.PathValue("id"))
	if err != nil {
		switch {
		case errors.Is(err, ErrNotFound):
			writeError(w, http.StatusNotFound, "scan not found")
		case errors.Is(err, ErrNotReady):
			writeError(w, http.StatusConflict, "scan still running")
		case errors.Is(err, ErrNoReport):
			writeError(w, http.StatusNotFound, "scan produced no report")
		default:
			writeError(w, http.StatusInternalServerError, err.Error())
		}
		return
	}
	writeJSON(w, http.StatusOK, resultsResponse{Scan: scan, Results: json.RawMessage(raw)})
}

type createScanRequest struct {
	Cluster   string `json:"cluster"`
	Framework string `json:"framework"`
}

func (a *API) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

func (a *API) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) handleClusters(w http.ResponseWriter, r *http.Request) {
	list := append([]Cluster(nil), a.clusters...)
	if list == nil {
		list = []Cluster{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) handleListScans(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.svc.List())
}

func (a *API) handleCreateScan(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	cluster, ok := a.findCluster(req.Cluster)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown cluster: "+req.Cluster)
		return
	}

	scan, err := a.svc.Create(r.Context(), cluster, req.Framework)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, scan)
}

func (a *API) handleGetScan(w http.ResponseWriter, r *http.Request) {
	scan, err := a.svc.Status(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, scan)
}

func (a *API) handleDeleteScan(w http.ResponseWriter, r *http.Request) {
	if err := a.svc.Delete(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "scan not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) handleSBOMIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(sbomHTML))
}

func (a *API) handleListSBOMs(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.sbom.List())
}

func (a *API) handleCreateSBOM(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}

	cluster, ok := a.findCluster(req.Cluster)
	if !ok {
		writeError(w, http.StatusBadRequest, "unknown cluster: "+req.Cluster)
		return
	}

	run, err := a.sbom.Create(r.Context(), cluster)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusAccepted, run)
}

func (a *API) handleGetSBOM(w http.ResponseWriter, r *http.Request) {
	run, err := a.sbom.Status(r.Context(), r.PathValue("id"))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "sbom run not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, run)
}

type sbomDoc struct {
	Image string          `json:"image"`
	SBOM  json.RawMessage `json:"sbom"`
}

type sbomResultsResponse struct {
	Run   *SBOMRun  `json:"run"`
	SBOMs []sbomDoc `json:"sboms"`
}

func (a *API) handleSBOMResults(w http.ResponseWriter, r *http.Request) {
	run, sboms, err := a.sbom.Results(r.Context(), r.PathValue("id"))
	if err != nil {
		writeSBOMServiceError(w, err)
		return
	}
	docs := make([]sbomDoc, 0, len(sboms))
	for image, raw := range sboms {
		docs = append(docs, sbomDoc{Image: image, SBOM: json.RawMessage(raw)})
	}
	sort.Slice(docs, func(i, j int) bool { return docs[i].Image < docs[j].Image })
	writeJSON(w, http.StatusOK, sbomResultsResponse{Run: run, SBOMs: docs})
}

func (a *API) handleSBOMResultOne(w http.ResponseWriter, r *http.Request) {
	_, sboms, err := a.sbom.Results(r.Context(), r.PathValue("id"))
	if err != nil {
		writeSBOMServiceError(w, err)
		return
	}
	image := r.PathValue("image")
	raw, ok := sboms[image]
	if !ok {
		writeError(w, http.StatusNotFound, "no SBOM for image: "+image)
		return
	}
	w.Header().Set("Content-Type", "application/spdx+json")
	w.Header().Set("Content-Disposition", `inline; filename="sbom.spdx.json"`)
	_, _ = w.Write(raw)
}

func (a *API) handleDeleteSBOM(w http.ResponseWriter, r *http.Request) {
	if err := a.sbom.Delete(r.Context(), r.PathValue("id")); err != nil {
		if errors.Is(err, ErrNotFound) {
			writeError(w, http.StatusNotFound, "sbom run not found")
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeSBOMServiceError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		writeError(w, http.StatusNotFound, "sbom run not found")
	case errors.Is(err, ErrNotReady):
		writeError(w, http.StatusConflict, "sbom run still running")
	case errors.Is(err, ErrNoReport):
		writeError(w, http.StatusNotFound, "sbom run produced no reports")
	default:
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func (a *API) findCluster(name string) (Cluster, bool) {
	for _, c := range a.clusters {
		if c.Name == name {
			return c, true
		}
	}
	return Cluster{}, false
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
