package discover

import (
	"strings"

	"github.com/291-Group/LAN-Sheriff/internal/types"
)

// Working out what a device actually is.
//
// A Roster row reading "Samsung Electronics Co.,Ltd" is barely more useful than
// an IP address: Samsung makes phones, televisions, printers, fridges and
// memory. What makes the row readable is the *type*, and the evidence for it is
// spread across three weak signals that are strong in combination:
//
//   - Advertised services say what a device does. A thing offering _ipp._tcp
//     accepts print jobs, whatever its badge says.
//   - The model string often names the product outright.
//   - The vendor narrows the field, and for single-product manufacturers settles
//     it.
//
// Each rule carries a confidence, and the strongest match wins. Ties are broken
// by rule order, so the more specific rule is written first.
//
// The result is a stable code, never a phrase: the dashboard translates it, and
// an English string stored in the database would be untranslatable afterwards.

// Device type codes. Stable identifiers, changing one changes stored data and
// every translation key that refers to it.
const (
	TypeThisMachine = "this-machine"
	TypeRouter      = "router"
	TypePrinter     = "printer"
	TypeTV          = "tv"
	TypeSpeaker     = "speaker"
	TypePhone       = "phone"
	TypeTablet      = "tablet"
	TypeComputer    = "computer"
	TypeSBC         = "single-board-computer"
	TypeNAS         = "nas"
	TypeCamera      = "camera"
	TypeConsole     = "games-console"
	TypeSmartHome   = "smart-home"
	TypeUnknown     = ""
)

// Inference is a conclusion about what a device is, with the reason for it.
//
// The reason is carried so the UI can explain itself. "Printer, because it
// advertises IPP" is a claim a user can check; "Printer" alone is something they
// have to take on faith, and being wrong without explanation is worse than being
// vague.
type Inference struct {
	Type string
	// Because names the evidence, as a stable code the dashboard translates.
	Because string
	// Confidence ranks competing conclusions. Not shown to the user.
	Confidence int
}

// Evidence codes for Inference.Because.
const (
	ByService = "service"
	ByModel   = "model"
	ByVendor  = "vendor"
	ByGateway = "gateway"
	BySelf    = "self"
)

// InferType decides what a device is from everything known about it.
//
// isGateway is whether this device is the network's default route, which is the
// single most reliable signal available: whatever else it does, that device is
// the router.
func InferType(d types.Device, services []string, isGateway bool) Inference {
	if d.IsSelf {
		return Inference{Type: TypeThisMachine, Because: BySelf, Confidence: 100}
	}
	if isGateway {
		return Inference{Type: TypeRouter, Because: ByGateway, Confidence: 95}
	}

	best := Inference{Type: TypeUnknown}
	consider := func(in Inference) {
		if in.Type != TypeUnknown && in.Confidence > best.Confidence {
			best = in
		}
	}

	consider(typeFromServices(services))
	consider(typeFromModel(d.Model, d.Name, d.Hostname))
	consider(typeFromVendor(d.Vendor))
	return best
}

// serviceRules map an advertised service to what offers it.
//
// Ordered most specific first. A service is evidence about function, which is
// usually what a person means when they ask what something is.
var serviceRules = []struct {
	service    string
	deviceType string
	confidence int
}{
	{"_ipp._tcp", TypePrinter, 90},
	{"_ipps._tcp", TypePrinter, 90},
	{"_printer._tcp", TypePrinter, 90},
	{"_pdl-datastream._tcp", TypePrinter, 85},
	{"_scanner._tcp", TypePrinter, 80},
	{"_uscan._tcp", TypePrinter, 80},

	{"_googlecast._tcp", TypeTV, 75},
	{"_androidtvremote2._tcp", TypeTV, 85},
	{"_airplay._tcp", TypeTV, 60},

	{"_raop._tcp", TypeSpeaker, 65},
	{"_spotify-connect._tcp", TypeSpeaker, 70},
	{"_sonos._tcp", TypeSpeaker, 90},

	{"_hap._tcp", TypeSmartHome, 70},
	{"_homekit._tcp", TypeSmartHome, 70},
	{"_matter._tcp", TypeSmartHome, 75},
	{"_matterc._udp", TypeSmartHome, 75},

	{"_nvstream._tcp", TypeConsole, 80},
	{"_xbox._tcp", TypeConsole, 90},

	{"_adisk._tcp", TypeNAS, 75},
	{"_afpovertcp._tcp", TypeNAS, 60},
	{"_smb._tcp", TypeComputer, 40},

	{"_rtsp._tcp", TypeCamera, 50},
	{"_axis-video._tcp", TypeCamera, 90},

	{"_workstation._tcp", TypeComputer, 55},
	{"_sftp-ssh._tcp", TypeComputer, 45},
	{"_ssh._tcp", TypeComputer, 40},
	{"_companion-link._tcp", TypePhone, 35},
}

func typeFromServices(services []string) Inference {
	best := Inference{Type: TypeUnknown}
	for _, svc := range services {
		s := strings.ToLower(strings.TrimSuffix(svc, "."))
		for _, rule := range serviceRules {
			if s != rule.service {
				continue
			}
			if rule.confidence > best.Confidence {
				best = Inference{Type: rule.deviceType, Because: ByService, Confidence: rule.confidence}
			}
		}
	}
	return best
}

// modelRules match words that appear in a published model or name.
//
// A device that calls itself a printer is a printer. This is the strongest
// signal after the gateway, because it is the manufacturer's own description
// rather than an inference from behaviour.
var modelRules = []struct {
	needle     string
	deviceType string
	confidence int
}{
	{"printer", TypePrinter, 92},
	{"laserjet", TypePrinter, 95},
	{"officejet", TypePrinter, 95},
	{"deskjet", TypePrinter, 95},
	{"envy", TypePrinter, 70},
	{"pixma", TypePrinter, 95},
	{"workforce", TypePrinter, 90},
	{"ecotank", TypePrinter, 95},
	{"scanner", TypePrinter, 85},

	{"appletv", TypeTV, 95},
	{"apple tv", TypeTV, 95},
	{"chromecast", TypeTV, 95},
	{"firetv", TypeTV, 95},
	{"fire tv", TypeTV, 95},
	{"roku", TypeTV, 95},
	{"shield", TypeTV, 80},
	{"bravia", TypeTV, 95},
	{"smart tv", TypeTV, 95},
	{"televi", TypeTV, 90},

	{"homepod", TypeSpeaker, 95},
	{"sonos", TypeSpeaker, 95},
	{"echo", TypeSpeaker, 80},
	{"soundbar", TypeSpeaker, 90},

	{"iphone", TypePhone, 95},
	{"pixel", TypePhone, 85},
	{"galaxy s", TypePhone, 85},

	{"ipad", TypeTablet, 95},
	{"galaxy tab", TypeTablet, 90},

	{"macbook", TypeComputer, 95},
	{"imac", TypeComputer, 95},
	{"mac mini", TypeComputer, 95},
	{"macmini", TypeComputer, 95},
	{"macpro", TypeComputer, 90},
	{"thinkpad", TypeComputer, 90},
	{"surface", TypeComputer, 80},

	{"raspberrypi", TypeSBC, 95},
	{"raspberry pi", TypeSBC, 95},

	{"synology", TypeNAS, 95},
	{"diskstation", TypeNAS, 95},
	{"truenas", TypeNAS, 95},
	{"freenas", TypeNAS, 95},

	{"playstation", TypeConsole, 95},
	{"xbox", TypeConsole, 95},
	{"nintendo", TypeConsole, 95},
	{"switch", TypeConsole, 60},

	{"camera", TypeCamera, 85},
	{"doorbell", TypeCamera, 90},
	{"nestcam", TypeCamera, 95},

	{"thermostat", TypeSmartHome, 90},
	{"lightstrip", TypeSmartHome, 85},
	{"hue bridge", TypeSmartHome, 90},

	{"router", TypeRouter, 90},
	{"gateway", TypeRouter, 70},
	{"access point", TypeRouter, 80},
}

func typeFromModel(fields ...string) Inference {
	best := Inference{Type: TypeUnknown}
	for _, field := range fields {
		f := strings.ToLower(field)
		if f == "" {
			continue
		}
		for _, rule := range modelRules {
			if !strings.Contains(f, rule.needle) {
				continue
			}
			if rule.confidence > best.Confidence {
				best = Inference{Type: rule.deviceType, Because: ByModel, Confidence: rule.confidence}
			}
		}
	}
	return best
}

// vendorRules apply where a manufacturer makes essentially one kind of thing.
//
// Deliberately short. Samsung, Apple, LG and Sony are excluded no matter how
// common they are, because each makes several categories and guessing from the
// badge alone would be wrong often enough to make the whole column untrustworthy.
var vendorRules = []struct {
	needle     string
	deviceType string
	confidence int
}{
	{"raspberry pi", TypeSBC, 70},
	{"espressif", TypeSmartHome, 55},
	{"tuya", TypeSmartHome, 60},
	{"sonos", TypeSpeaker, 85},
	{"roku", TypeTV, 85},
	{"nintendo", TypeConsole, 85},
	{"synology", TypeNAS, 85},
	{"qnap", TypeNAS, 85},
	{"axis communications", TypeCamera, 80},
	{"hikvision", TypeCamera, 80},
	{"dahua", TypeCamera, 80},
	{"ubiquiti", TypeRouter, 50},
	{"tp-link", TypeRouter, 45},
	{"netgear", TypeRouter, 45},
	{"arris", TypeRouter, 55},
	{"eero", TypeRouter, 70},
	{"brother", TypePrinter, 65},
	{"lexmark", TypePrinter, 75},
	{"zebra tech", TypePrinter, 70},
}

func typeFromVendor(vendor string) Inference {
	if vendor == "" {
		return Inference{Type: TypeUnknown}
	}
	v := strings.ToLower(vendor)
	best := Inference{Type: TypeUnknown}
	for _, rule := range vendorRules {
		if !strings.Contains(v, rule.needle) {
			continue
		}
		if rule.confidence > best.Confidence {
			best = Inference{Type: rule.deviceType, Because: ByVendor, Confidence: rule.confidence}
		}
	}
	return best
}
