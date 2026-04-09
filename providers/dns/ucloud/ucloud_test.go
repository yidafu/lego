package ucloud

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/go-acme/lego/v4/platform/tester"
	"github.com/go-acme/lego/v4/providers/dns/ucloud/internal"
	"github.com/stretchr/testify/require"
)

const envDomain = envNamespace + "DOMAIN"

var envTest = tester.NewEnvTest(EnvPublicKey, EnvSecretKey).WithDomain(envDomain)

func TestNewDNSProvider(t *testing.T) {
	testCases := []struct {
		desc     string
		envVars  map[string]string
		expected string
	}{
		{
			desc: "success",
			envVars: map[string]string{
				EnvPublicKey: "key",
				EnvSecretKey: "secret",
			},
		},
		{
			desc: "missing public key",
			envVars: map[string]string{
				EnvPublicKey: "key",
			},
			expected: "ucloud: some credentials information are missing: UCLOUD_SECRET_KEY",
		},
		{
			desc: "missing secret key",
			envVars: map[string]string{
				EnvSecretKey: "secret",
			},
			expected: "ucloud: some credentials information are missing: UCLOUD_PUBLIC_KEY",
		},
		{
			desc:     "missing credentials",
			envVars:  map[string]string{},
			expected: "ucloud: some credentials information are missing: UCLOUD_PUBLIC_KEY,UCLOUD_SECRET_KEY",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			defer envTest.RestoreEnv()

			envTest.ClearEnv()

			envTest.Apply(test.envVars)

			p, err := NewDNSProvider()

			if test.expected == "" {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestNewDNSProviderConfig(t *testing.T) {
	testCases := []struct {
		desc      string
		publicKey string
		secretKey string
		expected  string
	}{
		{
			desc:      "success",
			publicKey: "key",
			secretKey: "secret",
		},
		{
			desc:      "missing credentials",
			publicKey: "",
			secretKey: "",
			expected:  "ucloud: credentials missing",
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			config := NewDefaultConfig()
			config.PublicKey = test.publicKey
			config.SecretKey = test.secretKey

			p, err := NewDNSProviderConfig(config)

			if test.expected == "" {
				require.NoError(t, err)
				require.NotNil(t, p)
				require.NotNil(t, p.config)
				require.NotNil(t, p.client)
			} else {
				require.EqualError(t, err, test.expected)
			}
		})
	}
}

func TestLivePresent(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.Present(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}

func TestLiveCleanUp(t *testing.T) {
	if !envTest.IsLiveTest() {
		t.Skip("skipping live test")
	}

	envTest.RestoreEnv()

	provider, err := NewDNSProvider()
	require.NoError(t, err)

	err = provider.CleanUp(envTest.GetDomain(), "", "123d==")
	require.NoError(t, err)
}

// TestInternalClientAddRecord tests the internal client's AddRecord method
// against a mock server.
func TestInternalClientAddRecord(t *testing.T) {
	var receivedBody map[string]interface{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		err := json.NewDecoder(req.Body).Decode(&receivedBody)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		json.NewEncoder(rw).Encode(map[string]interface{}{
			"RetCode": 0,
			"Action":  "UdnrDomainDNSAdd",
			"Message": "Success",
			"Data":    map[string]interface{}{},
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := internal.NewClient("test-public-key", "test-secret-key", "", "")
	serverURL, _ := url.Parse(server.URL)
	client.BaseURL = serverURL
	client.HTTPClient = server.Client()

	record := internal.Record{
		Dn:         "example.com.",
		RecordName: "_acme-challenge.example.com.",
		DnsType:    "TXT",
		Content:   "test-value",
		TTL:       "600",
	}

	err := client.AddRecord(record)
	require.NoError(t, err)
	require.Equal(t, "UdnrDomainDNSAdd", receivedBody["Action"])
	require.Equal(t, "test-public-key", receivedBody["PublicKey"])
	require.Equal(t, "example.com.", receivedBody["Dn"])
	require.Equal(t, "_acme-challenge.example.com.", receivedBody["RecordName"])
	require.Equal(t, "TXT", receivedBody["DnsType"])
	require.Equal(t, "test-value", receivedBody["Content"])
	require.Equal(t, "600", receivedBody["TTL"])
}

// TestInternalClientDeleteRecord tests the internal client's DeleteRecord method
// against a mock server.
func TestInternalClientDeleteRecord(t *testing.T) {
	var receivedBody map[string]interface{}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(rw http.ResponseWriter, req *http.Request) {
		err := json.NewDecoder(req.Body).Decode(&receivedBody)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusBadRequest)
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		rw.WriteHeader(http.StatusOK)
		json.NewEncoder(rw).Encode(map[string]interface{}{
			"RetCode": 0,
			"Action":  "UdnrDeleteDnsRecord",
			"Message": "Success",
			"Data":    map[string]interface{}{},
		})
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := internal.NewClient("test-public-key", "test-secret-key", "", "")
	serverURL, _ := url.Parse(server.URL)
	client.BaseURL = serverURL
	client.HTTPClient = server.Client()

	err := client.DeleteRecord("example.com.", "_acme-challenge.example.com.", "TXT", "test-value")
	require.NoError(t, err)
	require.Equal(t, "UdnrDeleteDnsRecord", receivedBody["Action"])
	require.Equal(t, "test-public-key", receivedBody["PublicKey"])
	require.Equal(t, "example.com.", receivedBody["Dn"])
	require.Equal(t, "_acme-challenge.example.com.", receivedBody["RecordName"])
	require.Equal(t, "TXT", receivedBody["DnsType"])
	require.Equal(t, "test-value", receivedBody["Content"])
}
