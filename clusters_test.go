package main

import (
	"os"
	"path/filepath"
	"testing"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func writeKubeconfig(t *testing.T, dir, file string, contexts ...[2]string) {
	t.Helper()
	cfg := clientcmdapi.NewConfig()
	for _, c := range contexts {
		cfg.Clusters[c[0]] = &clientcmdapi.Cluster{Server: c[1]}
		cfg.AuthInfos[c[0]] = &clientcmdapi.AuthInfo{Token: "test-token"}
		cfg.Contexts[c[0]] = &clientcmdapi.Context{Cluster: c[0], AuthInfo: c[0]}
	}
	if len(contexts) > 0 {
		cfg.CurrentContext = contexts[0][0]
	}
	data, err := clientcmd.Write(*cfg)
	if err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, file), data, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
}

func TestDiscoverClusters(t *testing.T) {
	dir := t.TempDir()
	writeKubeconfig(t, dir, "a.kubeconfig", [2]string{"cluster-a", "https://a.example"})
	writeKubeconfig(t, dir, "b.yaml",
		[2]string{"cluster-b-2", "https://b2.example"},
		[2]string{"cluster-b-1", "https://b1.example"},
	)
	// The oddly named company download: no extension, contains "kubeconfig".
	writeKubeconfig(t, dir, "llm-demo-kubeconfig 4", [2]string{"cluster-c", "https://c.example"})

	// Files that must be ignored.
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("hello"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "broken.kubeconfig"), []byte("not: [valid"), 0o600)

	got, err := DiscoverClusters(dir)
	if err != nil {
		t.Fatalf("DiscoverClusters: %v", err)
	}

	want := []string{"cluster-a", "cluster-b-1", "cluster-b-2", "cluster-c"}
	if len(got) != len(want) {
		t.Fatalf("got %d clusters, want %d: %+v", len(got), len(want), got)
	}
	for i, name := range want {
		if got[i].Name != name {
			t.Errorf("cluster %d = %q, want %q", i, got[i].Name, name)
		}
		if got[i].Server == "" {
			t.Errorf("cluster %q has no server", name)
		}
		if len(got[i].Kubeconfig()) == 0 {
			t.Errorf("cluster %q has no kubeconfig", name)
		}
	}
}

func TestDiscoverClustersMissingDir(t *testing.T) {
	if _, err := DiscoverClusters(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("expected error for missing directory")
	}
}

func TestKubeconfigForContextIsolation(t *testing.T) {
	dir := t.TempDir()
	writeKubeconfig(t, dir, "multi.kubeconfig",
		[2]string{"ctx-1", "https://one.example"},
		[2]string{"ctx-2", "https://two.example"},
	)

	clusters, err := DiscoverClusters(dir)
	if err != nil {
		t.Fatalf("DiscoverClusters: %v", err)
	}
	if len(clusters) != 2 {
		t.Fatalf("got %d clusters, want 2", len(clusters))
	}

	for _, c := range clusters {
		cfg, err := clientcmd.Load(c.Kubeconfig())
		if err != nil {
			t.Fatalf("reload %q: %v", c.Name, err)
		}
		if len(cfg.Contexts) != 1 {
			t.Errorf("%q: got %d contexts, want 1", c.Name, len(cfg.Contexts))
		}
		if cfg.CurrentContext != c.Name {
			t.Errorf("%q: current context = %q", c.Name, cfg.CurrentContext)
		}
		if len(cfg.Clusters) != 1 || len(cfg.AuthInfos) != 1 {
			t.Errorf("%q: cluster/auth not isolated: %d/%d", c.Name, len(cfg.Clusters), len(cfg.AuthInfos))
		}
	}
}

func TestLooksLikeKubeconfig(t *testing.T) {
	cases := map[string]bool{
		"config":                     false,
		"readonly-fsp-api.kubeconfig": true,
		"cluster.yaml":               true,
		"weird.conf":                 true,
		"llm-demo-kubeconfig 4":      true,
		"notes.txt":                  false,
	}
	for name, want := range cases {
		if got := looksLikeKubeconfig(name); got != want {
			t.Errorf("looksLikeKubeconfig(%q) = %v, want %v", name, got, want)
		}
	}
}
