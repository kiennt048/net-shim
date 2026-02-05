package webfilter

type Category struct {
	ID          string
	Name        string
	Description string
	URL         string
	Tag         string
}

func DefaultCategories() []Category {
	return []Category{
		{
			ID:          "ads_tracking",
			Name:        "Ads & Trackers",
			Description: "Blocks common ad and tracking domains using the AdGuard DNS filter.",
			URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt",
			Tag:         "Recommended",
		},
		{
			ID:          "malware_phishing",
			Name:        "Malware & Phishing",
			Description: "Blocks known phishing and malware distribution domains.",
			URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_30.txt",
			Tag:         "Security",
		},
		{
			ID:          "security_balanced",
			Name:        "Balanced Security",
			Description: "Balanced protection list for broader security coverage.",
			URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_34.txt",
			Tag:         "Optional",
		},
		{
			ID:          "gambling",
			Name:        "Gambling",
			Description: "Blocks gambling-related domains.",
			URL:         "https://adguardteam.github.io/HostlistsRegistry/assets/filter_47.txt",
			Tag:         "Policy",
		},
	}
}

func DefaultDoHHosts() []string {
	return []string{
		"dns.google",
		"dns.cloudflare.com",
		"cloudflare-dns.com",
		"dns.quad9.net",
		"doh.opendns.com",
		"doh.cleanbrowsing.org",
		"family.cloudflare-dns.com",
		"security.cloudflare-dns.com",
		"dns.nextdns.io",
		"anycast.dns.nextdns.io",
		"adguard-dns.com",
		"dns.adguard.com",
	}
}
