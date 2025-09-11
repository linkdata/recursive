package recursive

// dnsPort is the standard DNS port (can be overridden for testing)
var dnsPort uint16 = 53
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return (r.config.useIPv4 && addr.Is4()) || (r.config.useIPv6 && addr.Is6())
}
