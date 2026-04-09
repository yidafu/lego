package internal

// Record represents a DNS record.
type Record struct {
	Dn    string `json:"Dn,omitempty"`     // 域名
	RecordName string `json:"RecordName,omitempty"` // 解析记录名
	DnsType string `json:"DnsType,omitempty"` // 记录类型
	Content string `json:"Content,omitempty"` // 解析内容
	TTL    string `json:"TTL,omitempty"`    // 生存时间
	Prio   string `json:"Prio,omitempty"`   // 优先级 (可选)
}

// RecordID represents a DNS record ID.
type RecordID struct {
	RecordID string `json:"RecordId,omitempty"`
}