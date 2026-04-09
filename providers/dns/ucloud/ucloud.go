// Package ucloud implements a DNS provider for solving the DNS-01 challenge using UCloud UDNR.
package ucloud

import (
	"errors"
	"fmt"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/platform/config/env"
	"github.com/go-acme/lego/v4/providers/dns/ucloud/internal"
)

// Environment variables names.
const (
	envNamespace = "UCLOUD_"

	EnvPublicKey = envNamespace + "PUBLIC_KEY"
	EnvSecretKey = envNamespace + "SECRET_KEY"

	EnvProjectId = envNamespace + "PROJECT_ID"
	EnvRegion    = envNamespace + "REGION"

	EnvTTL                = envNamespace + "TTL"
	EnvPropagationTimeout = envNamespace + "PROPAGATION_TIMEOUT"
	EnvPollingInterval    = envNamespace + "POLLING_INTERVAL"
)

const (
	defaultTTL = 600
)

// Config is used to configure the creation of the DNSProvider.
type Config struct {
	PublicKey string
	SecretKey string

	ProjectId string
	Region    string

	PropagationTimeout time.Duration
	PollingInterval    time.Duration
	TTL                int
}

// NewDefaultConfig returns a default configuration for the DNSProvider.
func NewDefaultConfig() *Config {
	return &Config{
		TTL:                env.GetOrDefaultInt(EnvTTL, defaultTTL),
		PropagationTimeout: env.GetOrDefaultSecond(EnvPropagationTimeout, 5*time.Minute),
		PollingInterval:    env.GetOrDefaultSecond(EnvPollingInterval, dns01.DefaultPollingInterval),
	}
}

// DNSProvider implements the challenge.Provider interface.
type DNSProvider struct {
	config *Config
	client *internal.Client
}

// NewDNSProvider returns a DNSProvider instance configured for UCloud UDNR.
func NewDNSProvider() (*DNSProvider, error) {
	values, err := env.Get(EnvPublicKey, EnvSecretKey)
	if err != nil {
		return nil, fmt.Errorf("ucloud: %w", err)
	}

	config := NewDefaultConfig()
	config.PublicKey = values[EnvPublicKey]
	config.SecretKey = values[EnvSecretKey]
	config.ProjectId = values[EnvProjectId]
	config.Region = values[EnvRegion]

	return NewDNSProviderConfig(config)
}

// NewDNSProviderConfig returns a DNSProvider instance configured for UCloud UDNR.
func NewDNSProviderConfig(config *Config) (*DNSProvider, error) {
	if config == nil {
		return nil, errors.New("ucloud: the configuration of the DNS provider is nil")
	}

	if config.PublicKey == "" && config.SecretKey == "" {
		return nil, errors.New("ucloud: credentials missing")
	}

	client := internal.NewClient(config.PublicKey, config.SecretKey, config.ProjectId, config.Region)

	return &DNSProvider{
		config: config,
		client: client,
	}, nil
}

// Present creates a TXT record using the specified parameters.
func (d *DNSProvider) Present(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zone, err := d.getHostedZone(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("ucloud: %w", err)
	}

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, zone)
	if err != nil {
		return fmt.Errorf("ucloud: %w", err)
	}

	// Dn must be the parent domain, RecordName must be the fully qualified domain name
	record := internal.Record{
		Dn:         zone,
		RecordName: subDomain + "." + zone,
		DnsType:    "TXT",
		Content:    info.Value,
		TTL:        fmt.Sprintf("%d", d.config.TTL),
	}

	err = d.client.AddRecord(record)
	if err != nil {
		return fmt.Errorf("ucloud: add record: %w", err)
	}

	return nil
}

// CleanUp removes the TXT record matching the specified parameters.
func (d *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)

	zone, err := d.getHostedZone(info.EffectiveFQDN)
	if err != nil {
		return fmt.Errorf("ucloud: %w", err)
	}

	subDomain, err := dns01.ExtractSubDomain(info.EffectiveFQDN, zone)
	if err != nil {
		return fmt.Errorf("ucloud: %w", err)
	}

	// Delete record directly using Dn, RecordName, DnsType, Content
	// RecordName must be in fully qualified domain name format
	err = d.client.DeleteRecord(zone, subDomain+"."+zone, "TXT", info.Value)
	if err != nil {
		return fmt.Errorf("ucloud: delete record: %w", err)
	}

	return nil
}

// Timeout returns the timeout and interval to use when checking for DNS propagation.
func (d *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return d.config.PropagationTimeout, d.config.PollingInterval
}

func (d *DNSProvider) getHostedZone(fqdn string) (string, error) {
	// Get the root domain from the FQDN
	zoneName := dns01.UnFqdn(fqdn)

	// Try to find parent zone by splitting domain
	parts := splitDomain(zoneName)
	if len(parts) > 2 {
		// Return the last 2 parts as the zone (parent domain)
		return joinDomain(parts[len(parts)-2:]), nil
	}

	return zoneName, nil
}

func splitDomain(domain string) []string {
	var result []string
	var current []rune

	for _, r := range domain {
		if r == '.' {
			if len(current) > 0 {
				result = append(result, string(current))
				current = nil
			}
		} else {
			current = append(current, r)
		}
	}

	if len(current) > 0 {
		result = append(result, string(current))
	}

	return result
}

func joinDomain(parts []string) string {
	result := ""
	for i, part := range parts {
		if i > 0 {
			result += "."
		}
		result += part
	}
	return result
}
