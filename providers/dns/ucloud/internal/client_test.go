package internal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

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

	client := NewClient("test-public-key", "test-secret-key", "", "")
	serverURL, _ := url.Parse(server.URL)
	client.BaseURL = serverURL
	client.HTTPClient = server.Client()

	record := Record{
		Dn:         "example.com.",
		RecordName: "_acme-challenge.example.com.",
		DnsType:    "TXT",
		Content:    "test-value",
		TTL:        "600",
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

	client := NewClient("test-public-key", "test-secret-key", "", "")
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

func TestNewClient(t *testing.T) {
	client := NewClient("test-public-key", "test-secret-key", "test-project-id", "hk")

	require.Equal(t, "test-public-key", client.publicKey)
	require.Equal(t, "test-secret-key", client.secretKey)
	require.Equal(t, "test-project-id", client.projectId)
	require.Equal(t, "hk", client.region)
	require.NotNil(t, client.HTTPClient)
}

func TestClient_generateSignature(t *testing.T) {
	client := NewClient("test-public-key", "test-secret-key", "", "cn-bj2")

	params := map[string]interface{}{
		"Action":    "UdnrAddDnsRecord",
		"Domain":    "example.com",
		"Name":      "@",
		"Type":      "TXT",
		"Value":     "test-value",
		"TTL":       300,
		"PublicKey": "test-public-key",
		"ProjectId": "",
		"Region":    "cn-bj2",
	}

	signature := client.generateSignature("UdnrAddDnsRecord", params)

	// Verify signature is not empty and is valid lowercase hex
	require.NotEmpty(t, signature)
	require.Len(t, signature, 40) // SHA1 hex encoded is always 40 chars
}

// TestClient_generateSignature_OfficialExample tests against UCloud official documentation example.
// Reference: https://docs.ucloud.cn/uapi/ucloud-apis/sign
func TestClient_generateSignature_OfficialExample(t *testing.T) {
	// Official example keys from UCloud docs
	publicKey := "ucloudsomeone@example.com1296235120854146120"
	privateKey := "46f09bb9fab4f12dfc160dae12273d5332b5debe"

	client := NewClient(publicKey, privateKey, "", "")

	// Request parameters from official example
	params := map[string]interface{}{
		"Action":    "DescribeUHostInstance",
		"Region":    "cn-bj2",
		"Limit":     10,
		"PublicKey": publicKey,
	}

	signature := client.generateSignature("DescribeUHostInstance", params)

	// Expected signature from official documentation
	expected := "cba5cf5ec4d4233d206b1b54951e3787350a642f"
	require.Equal(t, expected, signature, "signature should match UCloud official example")
}

func TestRecord(t *testing.T) {
	record := Record{
		Dn:         "example.com",
		RecordName: "@",
		DnsType:    "TXT",
		Content:    "test-value",
		TTL:        "300",
	}

	require.Equal(t, "example.com", record.Dn)
	require.Equal(t, "@", record.RecordName)
	require.Equal(t, "TXT", record.DnsType)
	require.Equal(t, "test-value", record.Content)
	require.Equal(t, "300", record.TTL)
}
