package internal

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/go-acme/lego/v4/log"
)

// Client is a UCloud API client.
type Client struct {
	publicKey string
	secretKey string
	projectId string
	region    string
	client    *http.Client
}

// NewClient creates a new UCloud API client.
func NewClient(publicKey, secretKey, projectId, region string) *Client {
	return &Client{
		publicKey: publicKey,
		secretKey: secretKey,
		projectId: projectId,
		region:    region,
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// AddRecord adds a DNS record.
func (c *Client) AddRecord(record Record) error {
	params := map[string]interface{}{
		"Dn":         record.Dn,
		"RecordName": record.RecordName,
		"DnsType":    record.DnsType,
		"Content":    record.Content,
		"TTL":       record.TTL,
	}

	if record.Prio != "" {
		params["Prio"] = record.Prio
	}

	_, err := c.doRequest("UdnrDomainDNSAdd", params)
	if err != nil {
		return fmt.Errorf("add record: %w", err)
	}

	return nil
}

// DeleteRecord deletes a DNS record.
func (c *Client) DeleteRecord(domain, name, recordType, content string) error {
	params := map[string]interface{}{
		"Dn":         domain,
		"RecordName": name,
		"DnsType":    recordType,
		"Content":    content,
	}

	_, err := c.doRequest("UdnrDeleteDnsRecord", params)
	if err != nil {
		return fmt.Errorf("delete record: %w", err)
	}

	return nil
}

// FindRecordID finds a DNS record ID by domain, name, type and value.
// Deprecated: This method is not used.
func (c *Client) FindRecordID(domain, name, recordType, value string) (string, error) {
	params := map[string]interface{}{
		"Dn": domain,
	}

	response, err := c.doRequest("UdnrDomainDNSQuery", params)
	if err != nil {
		return "", fmt.Errorf("describe record: %w", err)
	}

	data, ok := response["Data"].([]interface{})
	if !ok {
		return "", errors.New("record not found")
	}

	for _, item := range data {
		record, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		recordName, _ := record["RecordName"].(string)
		dnsType, _ := record["DnsType"].(string)

		if recordName == name && dnsType == recordType {
			content, _ := record["Content"].(string)
			if content == value {
				return recordName + "|" + dnsType + "|" + content, nil
			}
		}
	}

	return "", errors.New("record not found")
}

func (c *Client) FindZone(domain string) (string, error) {
	// Domain validation is now done via UdnrDomainDNSAdd API
	// This method kept for compatibility but doesn't make API call
	return domain, nil
}

func (c *Client) doRequest(action string, params map[string]interface{}) (map[string]interface{}, error) {
	baseURL := "https://api.ucloud.cn"

	reqParams := make(map[string]interface{})
	for k, v := range params {
		reqParams[k] = v
	}

	// Add common parameters
	reqParams["Action"] = action
	reqParams["PublicKey"] = c.publicKey

	// Add optional parameters if provided
	if c.projectId != "" {
		reqParams["ProjectId"] = c.projectId
	}
	if c.region != "" {
		reqParams["Region"] = c.region
	}

	// Generate signature
	signature := c.generateSignature(action, reqParams)
	reqParams["Signature"] = signature

	// Build JSON body
	jsonBody, err := json.Marshal(reqParams)
	if err != nil {
		return nil, err
	}

	log.Infof("[UCloud] action=%s params=%v json=%v", action, params, reqParams)

	req, err := http.NewRequest(http.MethodPost, baseURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	err = json.Unmarshal(body, &result)
	if err != nil {
		log.Infof("[UCloud] action=%s error: %v", action, err)
		return nil, err
	}

	// Check for errors - UCloud API returns error info in response body even with 200 status
	if errCode, ok := result["RetCode"].(float64); ok && errCode != 0 {
		if errMsg, ok := result["Message"].(string); ok {
			log.Infof("[UCloud] action=%s error: code %.0f, message: %s", action, errCode, errMsg)
			return nil, fmt.Errorf("ucloud API error (code %.0f): %s", errCode, errMsg)
		}
		log.Infof("[UCloud] action=%s error: code %.0f", action, errCode)
		return nil, fmt.Errorf("ucloud API error: code %.0f", errCode)
	}

	log.Infof("[UCloud] action=%s success", action)

	return result, nil
}

func (c *Client) generateSignature(action string, params map[string]interface{}) string {
	// Sort parameters by key name (ascending)
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build signature string: concatenate key + value (no delimiters)
	var signed bytes.Buffer
	for _, k := range keys {
		if k == "Signature" {
			continue
		}
		signed.WriteString(k)
		if v, ok := params[k].(string); ok {
			signed.WriteString(v)
		} else if v, ok := params[k].(int); ok {
			signed.WriteString(fmt.Sprintf("%d", v))
		}
	}

	// Append PrivateKey at the end
	signed.WriteString(c.secretKey)

	// Hash with SHA1
	h := sha1.New()
	h.Write(signed.Bytes())

	// Return lowercase hex string
	return hex.EncodeToString(h.Sum(nil))
}
