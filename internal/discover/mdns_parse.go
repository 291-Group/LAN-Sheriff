package discover

import (
	"net/netip"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// Attributing a DNS-SD record to the right device.
//
// The obvious approach, credit whatever the packet says to the address it came
// from, is wrong, and wrong in a way that is visible to the user. DNS-SD lets
// one host advertise services on behalf of another: a Mac with a printer
// installed republishes that printer's records, and a Bonjour sleep proxy
// answers for devices that are asleep. Crediting the sender labelled this
// machine "Samsung M2020 Series" on the development network.
//
// What actually identifies the device is the SRV record's *target hostname*, and
// the A record that binds that hostname to an address. So a message is parsed as
// a whole, and each service instance is attributed to its target rather than to
// the sender.

// mdnsMessage is everything one packet said, indexed for attribution.
type mdnsMessage struct {
	// addrs maps a hostname to the address it claims.
	addrs map[string]netip.Addr
	// srv maps a service instance to the hostname that actually provides it.
	srv map[string]string
	// txt maps a service instance to its key/value records.
	txt map[string][]string
	// instances maps a service instance to its service type.
	instances map[string]string
	// senderServices are service types the sender offered for itself, from a
	// response to the enumeration query.
	senderServices []string
}

func newMDNSMessage() *mdnsMessage {
	return &mdnsMessage{
		addrs:     map[string]netip.Addr{},
		srv:       map[string]string{},
		txt:       map[string][]string{},
		instances: map[string]string{},
	}
}

// parseMDNSMessage reads every record in a packet without attributing anything.
func parseMDNSMessage(data []byte) (*mdnsMessage, bool) {
	var p dnsmessage.Parser
	if _, err := p.Start(data); err != nil {
		return nil, false
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil, false
	}

	m := newMDNSMessage()
	for section := 0; section < 3; section++ {
		for {
			h, err := nextHeader(&p, section)
			if err == dnsmessage.ErrSectionDone {
				break
			}
			if err != nil {
				// A malformed record ends parsing; what was read stays usable.
				return m, true
			}
			if err := m.absorb(&p, h); err != nil {
				return m, true
			}
		}
	}
	return m, true
}

func (m *mdnsMessage) absorb(p *dnsmessage.Parser, h dnsmessage.ResourceHeader) error {
	name := trimLocal(h.Name.String())

	switch h.Type {
	case dnsmessage.TypeA:
		r, err := p.AResource()
		if err != nil {
			return err
		}
		m.addrs[strings.ToLower(name)] = netip.AddrFrom4(r.A)

	case dnsmessage.TypeAAAA:
		r, err := p.AAAAResource()
		if err != nil {
			return err
		}
		addr := netip.AddrFrom16(r.AAAA)
		// Only record a v6 address if no v4 one is known: the rest of the
		// pipeline keys on the address the neighbour table reports, which is v4.
		if _, ok := m.addrs[strings.ToLower(name)]; !ok {
			m.addrs[strings.ToLower(name)] = addr
		}

	case dnsmessage.TypePTR:
		r, err := p.PTRResource()
		if err != nil {
			return err
		}
		target := trimLocal(r.PTR.String())
		if isMetaQueryName(name) {
			// The sender listing its own service types (RFC 6763 §9).
			if svc := serviceType(target); svc != "" {
				m.senderServices = appendUnique(m.senderServices, svc)
			}
			return nil
		}
		if svc := serviceType(name); svc != "" && target != "" {
			m.instances[target] = svc
		}

	case dnsmessage.TypeSRV:
		r, err := p.SRVResource()
		if err != nil {
			return err
		}
		if target := trimLocal(r.Target.String()); target != "" {
			m.srv[name] = target
		}
		if svc := serviceType(name); svc != "" {
			m.instances[name] = svc
		}

	case dnsmessage.TypeTXT:
		r, err := p.TXTResource()
		if err != nil {
			return err
		}
		m.txt[name] = append(m.txt[name], r.TXT...)
		if svc := serviceType(name); svc != "" {
			if _, ok := m.instances[name]; !ok {
				m.instances[name] = svc
			}
		}

	default:
		return p.SkipAnswer()
	}
	return nil
}

// adverts turns one parsed message into a claim about each device it describes.
//
// from is the packet's source, used only where the message gives no better
// answer. Anything with an SRV target is attributed to that target's address.
func (m *mdnsMessage) adverts(from netip.AddrPort, iface string, now time.Time) []Advert {
	byHost := map[string]*Advert{}

	// get returns the advert being built for a hostname, creating it against the
	// address that hostname claims, or the sender if it claims none.
	get := func(host string) *Advert {
		// A UUID-named record is Apple's sleep-proxy and AirPlay plumbing, not a
		// device name. Left alone these become identity keys, and one run
		// produced dozens of them against a single machine.
		if looksLikeIdentifier(host) {
			return senderAdvert(byHost, from, iface, now)
		}
		key := strings.ToLower(host)
		if ad, ok := byHost[key]; ok {
			return ad
		}
		addr := from
		if a, ok := m.addrs[key]; ok {
			addr = netip.AddrPortFrom(a, from.Port())
		}
		ad := &Advert{
			Addr: addr, Source: "mdns", Interface: iface,
			Hostname: cleanLabel(host), SeenAt: now,
		}
		byHost[key] = ad
		return ad
	}

	for instance, svc := range m.instances {
		// The target hostname is the device that actually provides the service.
		// Without one there is nothing to attribute to but the sender.
		host, known := m.srv[instance]
		if !known {
			host = ""
		}

		var ad *Advert
		if host != "" {
			ad = get(host)
		} else {
			ad = senderAdvert(byHost, from, iface, now)
		}

		ad.Services = appendUnique(ad.Services, svc)
		if name := instanceName(instance); name != "" && ad.Name == "" {
			ad.Name = name
		}
		absorbTXT(m.txt[instance], ad)
	}

	// A hostname with an address but no services is still worth reporting: it
	// names a device.
	for host := range m.addrs {
		if looksLikeIdentifier(host) {
			continue
		}
		get(host)
	}

	if len(m.senderServices) > 0 {
		ad := senderAdvert(byHost, from, iface, now)
		for _, svc := range m.senderServices {
			ad.Services = appendUnique(ad.Services, svc)
		}
	}

	out := make([]Advert, 0, len(byHost))
	for _, ad := range byHost {
		if ad.Hostname == "" && ad.Name == "" && ad.Model == "" && len(ad.Services) == 0 {
			continue
		}
		out = append(out, *ad)
	}
	return out
}

// senderAdvert is the record for the sending host itself, used when a message
// gives no target hostname to attribute something to.
func senderAdvert(byHost map[string]*Advert, from netip.AddrPort, iface string, now time.Time) *Advert {
	const key = "\x00sender"
	if ad, ok := byHost[key]; ok {
		return ad
	}
	ad := &Advert{Addr: from, Source: "mdns", Interface: iface, SeenAt: now}
	byHost[key] = ad
	return ad
}

func appendUnique(list []string, v string) []string {
	for _, e := range list {
		if e == v {
			return list
		}
	}
	return append(list, v)
}
