package adguard

type ServerStatus struct {
	DNSAddresses               []string `json:"dns_addresses"`
	DNSPort                    int      `json:"dns_port"`
	HTTPPort                   int      `json:"http_port"`
	ProtectionEnabled          bool     `json:"protection_enabled"`
	ProtectionDisabledDuration int64    `json:"protection_disabled_duration"`
	DHCPAvailable              bool     `json:"dhcp_available"`
	Running                    bool     `json:"running"`
	Version                    string   `json:"version"`
	Language                   string   `json:"language"`
}

type Filter struct {
	ID          int64  `json:"id"`
	Enabled     bool   `json:"enabled"`
	URL         string `json:"url"`
	Name        string `json:"name"`
	RulesCount  int    `json:"rules_count"`
	LastUpdated string `json:"last_updated"`
}

type FilterStatus struct {
	Enabled          bool     `json:"enabled"`
	Interval         int      `json:"interval"`
	Filters          []Filter `json:"filters"`
	WhitelistFilters []Filter `json:"whitelist_filters"`
	UserRules        []string `json:"user_rules"`
}

type AddUrlRequest struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Whitelist bool   `json:"whitelist"`
}

type RemoveUrlRequest struct {
	URL       string `json:"url"`
	Whitelist bool   `json:"whitelist"`
}

type FilterSetUrlData struct {
	Enabled bool   `json:"enabled"`
	Name    string `json:"name"`
	URL     string `json:"url"`
}

type FilterSetUrl struct {
	Data      FilterSetUrlData `json:"data"`
	URL       string           `json:"url"`
	Whitelist bool             `json:"whitelist"`
}

type SetRulesRequest struct {
	Rules []string `json:"rules"`
}

type BlockedServicesAll struct {
	BlockedServices []BlockedService `json:"blocked_services"`
	Groups          []ServiceGroup   `json:"groups"`
}

type BlockedService struct {
	ID      string   `json:"id"`
	Name    string   `json:"name"`
	GroupID string   `json:"group_id"`
	Rules   []string `json:"rules"`
}

type ServiceGroup struct {
	ID string `json:"id"`
}

type BlockedServicesSchedule struct {
	Schedule interface{} `json:"schedule"`
	IDs      []string    `json:"ids"`
}

type QueryLogResponse struct {
	Data   []QueryLogItem `json:"data"`
	Oldest string         `json:"oldest"`
	Total  int            `json:"total"`
}

type QueryLogItem struct {
	Time       int64            `json:"time"`
	Question   QueryLogQuestion `json:"question"`
	Client     string           `json:"client"`
	ClientIP   string           `json:"client_ip"`
	ClientName string           `json:"client_name"`
	ClientID   string           `json:"client_id"`
	Reason     string           `json:"reason"`
	Rule       string           `json:"rule"`
	Rules      []QueryLogRule   `json:"rules"`
}

type QueryLogQuestion struct {
	Name string `json:"name"`
	Type int    `json:"type"`
}

type QueryLogRule struct {
	FilterListID int64  `json:"filter_list_id"`
	Text         string `json:"text"`
}
