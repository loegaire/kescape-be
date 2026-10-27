package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

func main() {
	var (
		targetsDir  = flag.String("targets-dir", "./kubeconfigs", "directory of kubeconfigs for scannable target clusters")
		runnerKC    = flag.String("runner-kubeconfig", "", "kubeconfig for the cluster that runs scan Jobs (default: $KUBECONFIG or ~/.kube/config)")
		runnerCtx   = flag.String("runner-context", "", "context to use in the runner kubeconfig")
		namespace   = flag.String("namespace", "kubescape", "namespace for scan Jobs and Secrets")
		image       = flag.String("scanner-image", "kubescape-scanner:local", "scanner image (must contain the kubescape CLI)")
		framework   = flag.String("framework", "NSA", "default framework when the request does not set one")
		jobTmpl     = flag.String("job-template", "", "optional path to a scan Job template (default: built-in)")
		sbomImage   = flag.String("sbom-image", "sbom-scanner:local", "scanner image for SBOM Jobs (must contain syft)")
		registryCfg = flag.String("registry-config", "", "optional docker config.json for pulling private images")
		sbomMax     = flag.Int("sbom-max-images", 0, "limit images per SBOM run (0 = all)")
		addr        = flag.String("addr", ":8080", "HTTP listen address")
	)
	flag.Parse()

	clusters, err := DiscoverClusters(*targetsDir)
	if err != nil {
		log.Fatalf("discover clusters: %v", err)
	}
	if len(clusters) == 0 {
		log.Printf("warning: no target clusters found in %q", *targetsDir)
	} else {
		log.Printf("found %d target cluster(s) in %q", len(clusters), *targetsDir)
		for _, c := range clusters {
			log.Printf("  - %s (%s) from %s", c.Name, c.Server, c.Source)
		}
	}

	client, err := newRunnerClient(*runnerKC, *runnerCtx)
	if err != nil {
		log.Fatalf("runner cluster: %v", err)
	}

	svc := NewScanService(client, *namespace, *image, *framework)
	if *jobTmpl != "" {
		tmpl, err := os.ReadFile(*jobTmpl)
		if err != nil {
			log.Fatalf("read job template: %v", err)
		}
		svc.jobTmpl = tmpl
	}

	sbomSvc := NewSBOMService(client, *namespace, *sbomImage)
	sbomSvc.maxImages = *sbomMax
	if *registryCfg != "" {
		cfg, err := os.ReadFile(*registryCfg)
		if err != nil {
			log.Fatalf("read registry config: %v", err)
		}
		sbomSvc.registryCfg = cfg
	}

	server := &http.Server{
		Handler:           NewAPI(svc, sbomSvc, clusters),
		ReadHeaderTimeout: 10 * time.Second,
	}
	ln, err := listenWithFallback(*addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("listening on http://%s", ln.Addr())
	log.Printf("open http://localhost:%d in a browser", ln.Addr().(*net.TCPAddr).Port)
	if err := server.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

// listenWithFallback binds addr, and if the port is taken it tries the next
// free ports. Docker Desktop and WSL commonly hold 8080, so a busy port should
// not stop the server from starting.
func listenWithFallback(addr string) (net.Listener, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid addr %q: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if port == 0 {
		return net.Listen("tcp", addr)
	}

	var lastErr error
	for candidate := port; candidate <= port+20 && candidate <= 65535; candidate++ {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(candidate)))
		if err == nil {
			return ln, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("no free port near %d: %w", port, lastErr)
}

func newRunnerClient(kubeconfigPath, contextName string) (kubernetes.Interface, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubeconfigPath != "" {
		rules.ExplicitPath = kubeconfigPath
	}
	overrides := &clientcmd.ConfigOverrides{}
	if contextName != "" {
		overrides.CurrentContext = contextName
	}

	cfg, err := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}
