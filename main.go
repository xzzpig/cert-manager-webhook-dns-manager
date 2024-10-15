package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	dnsv1 "github.com/xzzpig/kube-dns-manager/api/dns/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	client client.Client
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	Labels map[string]string `json:"labels"`
	Extra  map[string]string `json:"extra"`
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "kube-dns-manager"
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (c *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.InfoS("Presenting DNS01 challenge", "fqdn", ch.ResolvedFQDN, "uid", ch.UID, "namespace", ch.ResourceNamespace)

	cfg, err := loadConfig(ch.Config)
	if err != nil {
		klog.ErrorS(err, "Failed to load solver configuration")
		return err
	}

	ctx := context.Background()
	dnsRecord := dnsv1.Record{}
	dnsRecord.Name = getRecordName(ch.ResolvedFQDN)
	if err := c.client.Get(ctx, client.ObjectKey{Namespace: ch.ResourceNamespace, Name: dnsRecord.Name}, &dnsRecord); client.IgnoreNotFound(err) != nil {
		klog.ErrorS(err, "Failed to get DNS record", "fqdn", ch.ResolvedFQDN, "uid", ch.UID, "namespace", ch.ResourceNamespace)
		return err
	}

	dnsRecord.Namespace = ch.ResourceNamespace
	dnsRecord.Labels = cfg.Labels
	dnsRecord.Spec.Name = ch.ResolvedFQDN
	dnsRecord.Spec.Type = "TXT"
	dnsRecord.Spec.Value = ch.Key
	dnsRecord.Spec.Extra = cfg.Extra

	// remove trailing dot
	if strings.HasSuffix(ch.ResolvedFQDN, ".") {
		dnsRecord.Spec.Name = ch.ResolvedFQDN[:len(ch.ResolvedFQDN)-1]
	}

	if dnsRecord.UID == "" {
		if err := c.client.Create(ctx, &dnsRecord); err != nil {
			klog.ErrorS(err, "Failed to create DNS record", "fqdn", ch.ResolvedFQDN, "uid", ch.UID, "namespace", ch.ResourceNamespace)
			return err
		}
	} else {
		if err := c.client.Update(ctx, &dnsRecord); err != nil {
			klog.ErrorS(err, "Failed to update DNS record", "fqdn", ch.ResolvedFQDN, "uid", ch.UID, "namespace", ch.ResourceNamespace)
			return err
		}
	}
	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (c *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) (e error) {
	klog.InfoS("Cleaning up DNS01 challenge", "fqdn", ch.ResolvedFQDN, "uid", ch.UID, "namespace", ch.ResourceNamespace)
	defer func() {
		if e != nil {
			klog.ErrorS(e, "Failed to clean up DNS record", "fqdn", ch.ResolvedFQDN, "uid", ch.UID, "namespace", ch.ResourceNamespace)
		}
	}()

	ctx := context.Background()

	dnsRecord := dnsv1.Record{}
	dnsRecord.Name = getRecordName(ch.ResolvedFQDN)
	if err := c.client.Get(ctx, client.ObjectKey{Namespace: ch.ResourceNamespace, Name: dnsRecord.Name}, &dnsRecord); err != nil {
		return client.IgnoreNotFound(err)
	}
	return c.client.Delete(ctx, &dnsRecord)
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	schema := runtime.NewScheme()
	if err := dnsv1.AddToScheme(schema); err != nil {
		return err
	}
	cl, err := client.New(kubeClientConfig, client.Options{Scheme: schema})
	if err != nil {
		return err
	}
	c.client = cl

	klog.Info("Initialized DNS provider solver")
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}

func getRecordName(fqdn string) string {
	fqdn = strings.ToLower(fqdn)
	fqdn = regexp.MustCompile(`[^a-z0-9-]`).ReplaceAllString(fqdn, "-")
	fqdn = strings.TrimRight(fqdn, "-")
	return "acme-" + fqdn
}
