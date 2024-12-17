package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/nrdcg/desec"

	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
)

const desecTTL = 3600 // Minimum defined by DeSEC

// https://github.com/kubernetes/community/blob/31a7798d2ec54093364c47d6819e7bc353b57f70/contributors/devel/sig-instrumentation/logging.md
const (
	logLevelError    = 0
	logLevelWarn     = 1
	logLevelStandard = 2
	logLevelExtended = 3
	logLevelDebug    = 4
	logLevelTrace    = 5
)

type (
	desecDNSProviderSolver struct {
		client *kubernetes.Clientset
	}

	desecDNSProviderConfig struct {
		APIKeySecretRef v1.SecretKeySelector `json:"apiKeySecretRef"`
	}
)

var groupName = os.Getenv("GROUP_NAME")

func loadConfig(cfgJSON *extapi.JSON) (cfg desecDNSProviderConfig, err error) {
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}

	if err = json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("decoding solver config: %w", err)
	}

	return cfg, nil
}

func main() {
	if groupName == "" {
		panic("GROUP_NAME must be specified")
	}

	cmd.RunWebhookServer(groupName, &desecDNSProviderSolver{})
}

// CleanUp is responsible for deleting the challenge record after the
// ACME challenge is completed
func (c *desecDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	klog.V(logLevelStandard).Infof("cleanup record %q", ch.ResolvedFQDN)

	klog.V(logLevelTrace).Info("creating desec client")
	api, err := c.getAuthorizedClient(ch)
	if err != nil {
		return fmt.Errorf("getting desec client: %w", err)
	}

	domain, subName, err := c.getRecordInfo(api, ch)
	if err != nil {
		return fmt.Errorf("getting record info: %w", err)
	}

	if err = api.Records.Delete(context.Background(), domain.Name, subName, "TXT"); err != nil {
		return fmt.Errorf("deleting record: %w", err)
	}

	klog.V(1).Infof("record %s in zone %s deleted", subName, domain.Name)
	return nil
}

// Initialize configures the Kubernetes ClientSet for accessing the
// secret containing the API-Key
func (c *desecDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, _ <-chan struct{}) (err error) {
	if c.client, err = kubernetes.NewForConfig(kubeClientConfig); err != nil {
		return fmt.Errorf("creating kubernetes ClientSet: %w", err)
	}

	return nil
}

// Name returns the solver name to be registered in the given group
func (*desecDNSProviderSolver) Name() string { return "desec" }

// Present is responsible for creating the record requested in the ACME
// challenge for the given domain
func (c *desecDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	klog.V(logLevelStandard).Infof("preset record %q", ch.ResolvedFQDN)

	klog.V(logLevelTrace).Info("creating desec client")
	api, err := c.getAuthorizedClient(ch)
	if err != nil {
		return fmt.Errorf("getting desec client: %w", err)
	}

	klog.V(logLevelStandard).Infof("retrieving domain %s", util.UnFqdn(ch.ResolvedZone))
	domain, subName, err := c.getRecordInfo(api, ch)
	if err != nil {
		return err
	}

	recordSet := desec.RRSet{
		Domain:  domain.Name,
		SubName: subName,
		Type:    "TXT",
		Records: []string{fmt.Sprintf("%q", ch.Key)},
		TTL:     desecTTL,
	}

	klog.V(logLevelTrace).Info(recordSet)

	record, err := api.Records.Create(context.Background(), recordSet)
	if err != nil {
		return fmt.Errorf("creating record: %w", err)
	}

	klog.V(logLevelTrace).Infof("record %#v", record)
	return nil
}

func (c *desecDNSProviderSolver) getAuthorizedClient(ch *v1alpha1.ChallengeRequest) (*desec.Client, error) {
	cfg, err := loadConfig(ch.Config)
	if err != nil {
		return nil, fmt.Errorf("loading config: %w", err)
	}

	klog.V(logLevelTrace).Info("retrieving secret")
	apiToken, err := c.getSecretKey(cfg.APIKeySecretRef, ch.ResourceNamespace)
	if err != nil {
		return nil, fmt.Errorf("retrieving secret: %w", err)
	}

	klog.V(logLevelTrace).Info("creating desec client")
	return desec.New(apiToken, desec.NewDefaultClientOptions()), nil
}

func (*desecDNSProviderSolver) getDomain(client *desec.Client, subname string) (*desec.Domain, error) {
	domains, err := client.Domains.GetAll(context.Background())
	if err != nil {
		return nil, fmt.Errorf("getting all domains: %w", err)
	}

	for _, v := range domains {
		if strings.HasSuffix(subname, v.Name) {
			return &v, nil
		}
	}

	return nil, fmt.Errorf("domain not found")
}

func (c *desecDNSProviderSolver) getRecordInfo(api *desec.Client, ch *v1alpha1.ChallengeRequest) (*desec.Domain, string, error) {
	klog.V(logLevelTrace).Infof("%s record", ch.ResolvedFQDN)

	// Remove trailing dots from zone and fqdn
	zone := util.UnFqdn(ch.ResolvedZone)
	fqdn := util.UnFqdn(ch.ResolvedFQDN)

	domain, err := c.getDomain(api, zone)
	if err != nil {
		return nil, "", fmt.Errorf("getting domain: %w", err)
	}

	// Get the subdomain portion of fqdn
	subName := fqdn[:len(fqdn)-len(domain.Name)-1]

	return domain, subName, nil
}

// getSecretKey fetch a secret key based on a selector and a namespace
func (c *desecDNSProviderSolver) getSecretKey(secret v1.SecretKeySelector, namespace string) (string, error) {
	klog.V(logLevelTrace).Infof("retrieving key `%s` in secret `%s/%s`", secret.Key, namespace, secret.Name)

	sec, err := c.client.CoreV1().Secrets(namespace).Get(context.Background(), secret.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("getting secret: %w", err)
	}

	data, ok := sec.Data[secret.Key]
	if !ok {
		return "", fmt.Errorf("key %q not found in secret %s/%s", secret.Key, namespace, secret.Name)
	}

	return string(data), nil
}
