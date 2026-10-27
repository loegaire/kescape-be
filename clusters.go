package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

// Cluster is a scannable target cluster, as offered in the UI drop-down.
type Cluster struct {
	Name   string `json:"name"`   // context name - what the user picks
	Server string `json:"server"` // API server URL, shown as a hint
	Source string `json:"source"` // kubeconfig file it came from

	// kubeconfig is a self-contained config for exactly this context. It is
	// mounted into the scan Job and never leaves the runner cluster.
	kubeconfig []byte
}

// Kubeconfig returns the per-context kubeconfig bytes.
func (c Cluster) Kubeconfig() []byte { return c.kubeconfig }

// DiscoverClusters reads every kubeconfig-looking file in dir and returns one
// Cluster per context found. Files that cannot be parsed are skipped rather
// than aborting discovery, so one broken kubeconfig cannot take the drop-down
// down.
func DiscoverClusters(dir string) ([]Cluster, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read targets dir %q: %w", dir, err)
	}

	var out []Cluster
	for _, e := range entries {
		if e.IsDir() || !looksLikeKubeconfig(e.Name()) {
			continue
		}
		clusters, err := loadClusters(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, clusters...)
	}

	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func looksLikeKubeconfig(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, "kubeconfig") {
		return true
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".yaml", ".yml", ".conf":
		return true
	}
	return false
}

func loadClusters(path string) ([]Cluster, error) {
	cfg, err := clientcmd.LoadFromFile(path)
	if err != nil {
		return nil, err
	}
	if len(cfg.Contexts) == 0 {
		return nil, fmt.Errorf("%s: no contexts", path)
	}

	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)

	var out []Cluster
	for _, name := range names {
		raw, err := kubeconfigForContext(cfg, name)
		if err != nil {
			continue
		}
		var server string
		if ctx := cfg.Contexts[name]; ctx != nil {
			if cl := cfg.Clusters[ctx.Cluster]; cl != nil {
				server = cl.Server
			}
		}
		out = append(out, Cluster{
			Name:       name,
			Server:     server,
			Source:     filepath.Base(path),
			kubeconfig: raw,
		})
	}
	return out, nil
}

// kubeconfigForContext builds a minimal kubeconfig holding only ctxName and
// the cluster/auth objects it references.
func kubeconfigForContext(cfg *clientcmdapi.Config, ctxName string) ([]byte, error) {
	ctx, ok := cfg.Contexts[ctxName]
	if !ok || ctx == nil {
		return nil, fmt.Errorf("context %q not found", ctxName)
	}

	out := clientcmdapi.NewConfig()
	out.Contexts[ctxName] = ctx.DeepCopy()
	out.CurrentContext = ctxName
	if cl, ok := cfg.Clusters[ctx.Cluster]; ok && cl != nil {
		out.Clusters[ctx.Cluster] = cl.DeepCopy()
	}
	if au, ok := cfg.AuthInfos[ctx.AuthInfo]; ok && au != nil {
		out.AuthInfos[ctx.AuthInfo] = au.DeepCopy()
	}
	return clientcmd.Write(*out)
}
