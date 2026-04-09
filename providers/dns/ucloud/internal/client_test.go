package internal

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	client := NewClient("test-public-key", "test-secret-key", "test-project-id", "hk")

	require.Equal(t, "test-public-key", client.publicKey)
	require.Equal(t, "test-secret-key", client.secretKey)
	require.Equal(t, "test-project-id", client.projectId)
	require.Equal(t, "hk", client.region)
	require.NotNil(t, client.client)
}

func TestClient_generateSignature(t *testing.T) {
	client := NewClient("test-public-key", "test-secret-key", "", "cn-bj2")

	params := map[string]interface{}{
		"Action":          "UdnrAddDnsRecord",
		"Domain":          "example.com",
		"Name":            "@",
		"Type":            "TXT",
		"Value":           "test-value",
		"TTL":             300,
		"PublicKey":       "test-public-key",
		"ProjectId":       "",
		"Region":          "cn-bj2",
		"SignatureMethod": "HMAC-SHA256",
		"Timestamp":      "2024-01-01T00:00:00Z",
		"Token":          "",
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
		"Action":     "DescribeUHostInstance",
		"Region":     "cn-bj2",
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
		Dn:        "example.com",
		RecordName: "@",
		DnsType:   "TXT",
		Content:  "test-value",
		TTL:      "300",
	}

	require.Equal(t, "example.com", record.Dn)
	require.Equal(t, "@", record.RecordName)
	require.Equal(t, "TXT", record.DnsType)
	require.Equal(t, "test-value", record.Content)
	require.Equal(t, "300", record.TTL)
}

func TestRecordID(t *testing.T) {
	recordID := RecordID{
		RecordID: "123456",
	}

	require.Equal(t, "123456", recordID.RecordID)
}