package main

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

//main structure of XML
type Ip struct {
	IP          string       `xml:"number"`
	Count       string       `xml:"count"`
	Attacks     string       `xml:"attacks"`
	FirstReport string       `xml:"mindate"`
	LastReport  string       `xml:"maxdate"`
	Country     string       `xml:"ascountry"`
	Threatfeeds *Threatfeeds `xml:"threatfeeds"`
}

//list of threatfeeds from DShield
type Threatfeeds struct {
	BEBLOH                        bebloh                        `xml:"bebloh,omitempty"`
	BlindFerret                   blindferret                   `xml:"blindferret,omitempty"`
	BlockListDePort110            blocklistde110                `xml:"blocklistde110,omitempty"`
	BlockListDePort143            blocklistde143                `xml:"blocklistde143,omitempty"`
	BlockListDePort21             blocklistde21                 `xml:"blocklistde21,omitempty"`
	BlockListDePort22             blocklistde22                 `xml:"blocklistde22,omitempty"`
	BlockListDePort25             blocklistde25                 `xml:"blocklistde25,omitempty"`
	BlockListDePort443            blocklistde443                `xml:"blocklistde443,omitempty"`
	BlockListDePort80             blocklistde80                 `xml:"blocklistde80,omitempty"`
	BlockListDePort993            blocklistde993                `xml:"blocklistde993,omitempty"`
	BlockListDeApache             blocklistdeapache             `xml:"blocklistdeapache,omitempty"`
	BlockListDeAsterisk           blocklistdeasterisk           `xml:"blocklistdeasterisk,omitempty"`
	BlockListDeBots               blocklistdebots               `xml:"blocklistdebots,omitempty"`
	BlockListDeBFL                blocklistdebruteforcelogin    `xml:"blocklistdebruteforcelogin,omitempty"`
	BlockListDeCourierIMAP        blocklistdecourierimap        `xml:"blocklistdecourierimap,omitempty"`
	BlockListDeCourierPOP3        blocklistdecourierpop3        `xml:"blocklistdecourierpop3,omitempty"`
	CIArmy                        ciarmy                        `xml:"ciarmy,omitempty"`
	CryptoWall                    cryptowall                    `xml:"cryptowall,omitempty"`
	CyberGreen                    cybergreen                    `xml:"cybergreen,omitempty"`
	Dyreza                        dyreza                        `xml:"dyreza,omitempty"`
	EmergingThreats               emergincompromised            `xml:"emergincompromised,omitempty"`
	ErrataSec                     erratasec                     `xml:"erratasec,omitempty"`
	ForumSpam                     forumspam                     `xml:"forumspam,omitempty"`
	HesperBot                     hesperbot                     `xml:"hesperbot,omitempty"`
	MalC0de                       malc0de                       `xml:"malc0de,omitempty"`
	MalwareDomainList             malwaredomainlist             `xml:"malwaredomainlist,omitempty"`
	MalwareDomains                malwaredomains                `xml:"malwaredomains,omitempty"`
	MalwareTrafficAnalysis        malwaretrafficanalysis        `xml:"malwaretrafficanalysis,omitempty"`
	MalwareTrafficAnalysisDomains malwaretrafficanalysisdomains `xml:"malwaretrafficanalysisdomains,omitempty"`
	Matsnu                        matsnu                        `xml:"matsnu,omitempty"`
	Miner                         miner                         `xml:"miner,omitempty"`
	OpenblFTP                     openbl_ftp                    `xml:"openbl_ftp,omitempty"`
	OpenblHTTP                    openbl_http                   `xml:"openbl_http,omitempty"`
	OpenblMAIL                    openbl_mail                   `xml:"openbl_mail,omitempty"`
	OpenblSMTP                    openbl_smtp                   `xml:"openbl_smtp,omitempty"`
	OpenblSSH                     openbl_ssh                    `xml:"openbl_ssh,omitempty"`
	PalevoDomains                 palevodomains                 `xml:"palevodomains,omitempty"`
	PalevoIPs                     palevoips                     `xml:"palevoips,omitempty"`
	QakBot                        qakbot                        `xml:"qakbot,omitempty"`
	Ramnit                        ramnit                        `xml:"ramnit,omitempty"`
	Ransomware                    ransomware                    `xml:"ransomware,omitempty"`
	RansomwareIPs                 ransomwareips                 `xml:"ransomwareips,omitempty"`
	Rapid7Sonar                   rapid7sonar                   `xml:"rapid7sonar,omitempty"`
	ShadowServer                  shadowserver                  `xml:"shadowserver,omitempty"`
	Shodan                        shodan                        `xml:"shodan,omitempty"`
	SpyEye                        spyeye                        `xml:"spyeye,omitempty"`
	SpyEyeDomains                 spyeyedomains                 `xml:"spyeyedomains,omitempty"`
	Symmi                         symmi                         `xml:"symmi,omitempty"`
	ThreatExpert                  threatexpert                  `xml:"threatexpert,omitempty"`
	TinBa                         tinba                         `xml:"tinba,omitempty"`
	TLDns                         tldns                         `xml:"tldns,omitempty"`
	TorExit                       torexit                       `xml:"torexit,omitempty"`
	UnivMichigan                  univmichigan                  `xml:"univmichigan,omitempty"`
	Upatre                        upatre                        `xml:"upatre,omitempty"`
	VirusTotal                    virustotal                    `xml:"virustotal,omitempty"`
	WebIron                       webiron                       `xml:"webiron,omitempty"`
	ZeusCC                        zeuscc                        `xml:"zeuscc,omitempty"`
	ZeusDomains                   zeusdomains                   `xml:"zeusdomains,omitempty"`
}

type bebloh struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blindferret struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistde110 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistde143 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistde21 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistde22 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistde25 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistde443 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistde80 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistde993 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistdeapache struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistdeasterisk struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistdebots struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistdebruteforcelogin struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistdecourierimap struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type blocklistdecourierpop3 struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type ciarmy struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type cryptowall struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type cybergreen struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type dyreza struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type emergincompromised struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type erratasec struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type forumspam struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type hesperbot struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type malc0de struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type malwaredomainlist struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type malwaredomains struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type malwaretrafficanalysis struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type malwaretrafficanalysisdomains struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type matsnu struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type miner struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type openbl_ftp struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type openbl_http struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type openbl_mail struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type openbl_smtp struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type openbl_ssh struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type palevodomains struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type palevoips struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type qakbot struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type ramnit struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type ransomware struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type ransomwareips struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type rapid7sonar struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type shadowserver struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type shodan struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type spyeye struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type spyeyedomains struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type symmi struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type threatexpert struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type tinba struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type tldns struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type torexit struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type univmichigan struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type upatre struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type virustotal struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type webiron struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type zeuscc struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

type zeusdomains struct {
	LastSeen  string `xml:"lastseen"`
	FirstSeen string `xml:"firstseen"`
}

//function to GET file from the SANS API and unmarshal into XML structure as above.
func getIP(ip string) Ip {

	resp, err := http.Get("http://isc.sans.edu/api/ip/" + ip)

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	defer resp.Body.Close()

	respData, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal(err)
	}

	var IP Ip

	xml.Unmarshal([]byte(respData), &IP)

	return IP
}
