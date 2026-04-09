package internal

// Record represents a DNS record.
type Record struct {
	Dn         string `json:"Dn,omitempty"`         // Domain name
	RecordName string `json:"RecordName,omitempty"` // Record name
	DnsType   string `json:"DnsType,omitempty"` // Record type
	Content   string `json:"Content,omitempty"` // Record content
	TTL       string `json:"TTL,omitempty"`       // Time to live
	Prio      string `json:"Prio,omitempty"`      // Priority (optional)
}