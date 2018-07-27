package main

import (
	"fmt"
	"os"
	"regexp"

	flag "github.com/ogier/pflag"
)

// flags
var (
	ip   string
	port string
)

func main() {

	//parse flags
	flag.Parse()

	//if user does not supply flags, print usage
	if flag.NFlag() == 0 {
		fmt.Printf("Usage: %s [options]\n", os.Args[0])
		fmt.Println("Options:")
		flag.PrintDefaults()
		os.Exit(1)
	}
	//check that user has inputed a valid IP
	match, _ := regexp.MatchString(`^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$`, ip)
	if match == true {
		fmt.Printf("Searching DShield for %s...\n", ip)

		//calls function of ip.go
		result := getIP(ip)

		//checks whether IP has been reported to DShield, then prints results to the console.
		if result.Count != "" {

			fmt.Println("Country:", result.Country)

			fmt.Println("Reports:", result.Count)

			fmt.Println("Targets:", result.Attacks)

			fmt.Println("First reported:", result.FirstReport)

			fmt.Println("Most recent report:", result.LastReport)

			if result.Threatfeeds != nil {
				fmt.Println("\n**** Threatfeeds ***** \n")
				if result.Threatfeeds.BEBLOH.FirstSeen != "" {
					fmt.Println("BEBLOH: \n", "First seen =>", result.Threatfeeds.BEBLOH.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BEBLOH.LastSeen, "\n")
				}
				if result.Threatfeeds.BlindFerret.FirstSeen != "" {
					fmt.Println("BlindFerret: \n", "First seen =>", result.Threatfeeds.BlindFerret.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlindFerret.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDePort110.FirstSeen != "" {
					fmt.Println("Blocklist.de Port 110 Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDePort110.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDePort110.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDePort143.FirstSeen != "" {
					fmt.Println("Blocklist.de Port 143 Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDePort143.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDePort143.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDePort21.FirstSeen != "" {
					fmt.Println("Blocklist.de Port 21 Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDePort21.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDePort21.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDePort22.FirstSeen != "" {
					fmt.Println("Blocklist.de Port 22 Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDePort22.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDePort22.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDePort25.FirstSeen != "" {
					fmt.Println("Blocklist.de Port 25 Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDePort25.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDePort25.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDePort443.FirstSeen != "" {
					fmt.Println("Blocklist.de Port 443 Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDePort443.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDePort443.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDePort80.FirstSeen != "" {
					fmt.Println("Blocklist.de Port 80 Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDePort80.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDePort80.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDePort993.FirstSeen != "" {
					fmt.Println("Blocklist.de Port 993 Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDePort993.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDePort993.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDeApache.FirstSeen != "" {
					fmt.Println("Blocklist.de Apache Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDeApache.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDeApache.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDeAsterisk.FirstSeen != "" {
					fmt.Println("Blocklist.de Asterisk VoIP Scanner: \n", "First seen =>", result.Threatfeeds.BlockListDeAsterisk.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDeAsterisk.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDeBots.FirstSeen != "" {
					fmt.Println("Blocklist.de Bots: \n", "First seen =>", result.Threatfeeds.BlockListDeBots.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDeBots.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDeBFL.FirstSeen != "" {
					fmt.Println("Blocklist.de Bruteforce Login: \n", "First seen =>", result.Threatfeeds.BlockListDeBFL.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDeBFL.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDeCourierIMAP.FirstSeen != "" {
					fmt.Println("Blocklist.de Courier IMAP: \n", "First seen =>", result.Threatfeeds.BlockListDeCourierIMAP.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDeCourierIMAP.LastSeen, "\n")
				}
				if result.Threatfeeds.BlockListDeCourierPOP3.FirstSeen != "" {
					fmt.Println("Blocklist.de Courier POP3: \n", "First seen =>", result.Threatfeeds.BlockListDeCourierPOP3.FirstSeen, "\n Last seen  =>", result.Threatfeeds.BlockListDeCourierPOP3.LastSeen, "\n")
				}
				if result.Threatfeeds.CIArmy.FirstSeen != "" {
					fmt.Println("CI Army List. Combined CINS Threat Intelligence Feed: \n", "First seen =>", result.Threatfeeds.CIArmy.FirstSeen, "\n Last seen  =>", result.Threatfeeds.CIArmy.LastSeen, "\n")
				}
				if result.Threatfeeds.CryptoWall.FirstSeen != "" {
					fmt.Println("CryptoWall C&C servers from John Bambenek: \n", "First seen =>", result.Threatfeeds.CryptoWall.FirstSeen, "\n Last seen  =>", result.Threatfeeds.CryptoWall.LastSeen, "\n")
				}
				if result.Threatfeeds.CyberGreen.FirstSeen != "" {
					fmt.Println("Cybergreen Network Security Research Project: \n", "First seen =>", result.Threatfeeds.CyberGreen.FirstSeen, "\n Last seen  =>", result.Threatfeeds.CyberGreen.LastSeen, "\n")
				}
				if result.Threatfeeds.Dyreza.FirstSeen != "" {
					fmt.Println("Dyreza List from techhelplist.com: \n", "First seen =>", result.Threatfeeds.Dyreza.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Dyreza.LastSeen, "\n")
				}
				if result.Threatfeeds.EmergingThreats.FirstSeen != "" {
					fmt.Println("Emerging Threats Compromised IPs: \n", "First seen =>", result.Threatfeeds.EmergingThreats.FirstSeen, "\n Last seen  =>", result.Threatfeeds.EmergingThreats.LastSeen, "\n")
				}
				if result.Threatfeeds.ErrataSec.FirstSeen != "" {
					fmt.Println("Errata Security Masscan: \n", "First seen =>", result.Threatfeeds.ErrataSec.FirstSeen, "\n Last seen  =>", result.Threatfeeds.ErrataSec.LastSeen, "\n")
				}
				if result.Threatfeeds.ForumSpam.FirstSeen != "" {
					fmt.Println("Forumspam.com List of forum spammers: \n", "First seen =>", result.Threatfeeds.ForumSpam.FirstSeen, "\n Last seen  =>", result.Threatfeeds.ForumSpam.LastSeen, "\n")
				}
				if result.Threatfeeds.HesperBot.FirstSeen != "" {
					fmt.Println("HesperBot C&C servers from John Bambenek: \n", "First seen =>", result.Threatfeeds.HesperBot.FirstSeen, "\n Last seen  =>", result.Threatfeeds.HesperBot.LastSeen, "\n")
				}
				if result.Threatfeeds.MalC0de.FirstSeen != "" {
					fmt.Println("Malc0de.com IP Blacklist: \n", "First seen =>", result.Threatfeeds.MalC0de.FirstSeen, "\n Last seen  =>", result.Threatfeeds.MalC0de.LastSeen, "\n")
				}
				if result.Threatfeeds.MalwareDomainList.FirstSeen != "" {
					fmt.Println("Malware Domain List.com: \n", "First seen =>", result.Threatfeeds.MalwareDomainList.FirstSeen, "\n Last seen  =>", result.Threatfeeds.MalwareDomainList.LastSeen, "\n")
				}
				if result.Threatfeeds.MalwareDomains.FirstSeen != "" {
					fmt.Println("Domain Blocklist From Malwaredomains: \n", "First seen =>", result.Threatfeeds.MalwareDomains.FirstSeen, "\n Last seen  =>", result.Threatfeeds.MalwareDomains.LastSeen, "\n")
				}
				if result.Threatfeeds.MalwareTrafficAnalysis.FirstSeen != "" {
					fmt.Println("Suspicious IPs and Domains from Malware Traffic Analysis: \n", "First seen =>", result.Threatfeeds.MalwareTrafficAnalysis.FirstSeen, "\n Last seen  =>", result.Threatfeeds.MalwareTrafficAnalysis.LastSeen, "\n")
				}
				if result.Threatfeeds.MalwareTrafficAnalysisDomains.FirstSeen != "" {
					fmt.Println("Suspicious IPs and Domains from Malware Traffic Analysis: \n", "First seen =>", result.Threatfeeds.MalwareTrafficAnalysisDomains.FirstSeen, "\n Last seen  =>", result.Threatfeeds.MalwareTrafficAnalysisDomains.LastSeen, "\n")
				}
				if result.Threatfeeds.Matsnu.FirstSeen != "" {
					fmt.Println("Matsnu C&C servers from John Bambenek: \n", "First seen =>", result.Threatfeeds.Matsnu.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Matsnu.LastSeen, "\n")
				}
				if result.Threatfeeds.Miner.FirstSeen != "" {
					fmt.Println("Cryptocoin Miner Pool Addresses: \n", "First seen =>", result.Threatfeeds.Miner.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Miner.LastSeen, "\n")
				}
				if result.Threatfeeds.OpenblFTP.FirstSeen != "" {
					fmt.Println("OpenBL.org FTP Scanners: \n", "First seen =>", result.Threatfeeds.OpenblFTP.FirstSeen, "\n Last seen  =>", result.Threatfeeds.OpenblFTP.LastSeen, "\n")
				}
				if result.Threatfeeds.OpenblHTTP.FirstSeen != "" {
					fmt.Println("OpenBL.org HTTP Scanners: \n", "First seen =>", result.Threatfeeds.OpenblHTTP.FirstSeen, "\n Last seen  =>", result.Threatfeeds.OpenblHTTP.LastSeen, "\n")
				}
				if result.Threatfeeds.OpenblMAIL.FirstSeen != "" {
					fmt.Println("OpenBL.org MAIL Scanners: \n", "First seen =>", result.Threatfeeds.OpenblMAIL.FirstSeen, "\n Last seen  =>", result.Threatfeeds.OpenblMAIL.LastSeen, "\n")
				}
				if result.Threatfeeds.OpenblSMTP.FirstSeen != "" {
					fmt.Println("OpenBL.org SMTP Scanners: \n", "First seen =>", result.Threatfeeds.OpenblSMTP.FirstSeen, "\n Last seen  =>", result.Threatfeeds.OpenblSMTP.LastSeen, "\n")
				}
				if result.Threatfeeds.OpenblSSH.FirstSeen != "" {
					fmt.Println("OpenBL.org SSH Scanners: \n", "First seen =>", result.Threatfeeds.OpenblSSH.FirstSeen, "\n Last seen  =>", result.Threatfeeds.OpenblSSH.LastSeen, "\n")
				}
				if result.Threatfeeds.PalevoDomains.FirstSeen != "" {
					fmt.Println("Palevo C&C Server Domains from Abuse.ch: \n", "First seen =>", result.Threatfeeds.PalevoDomains.FirstSeen, "\n Last seen  =>", result.Threatfeeds.PalevoDomains.LastSeen, "\n")
				}
				if result.Threatfeeds.PalevoIPs.FirstSeen != "" {
					fmt.Println("Palevo C&C Server IPs from Abuse.ch: \n", "First seen =>", result.Threatfeeds.PalevoIPs.FirstSeen, "\n Last seen  =>", result.Threatfeeds.PalevoIPs.LastSeen, "\n")
				}
				if result.Threatfeeds.QakBot.FirstSeen != "" {
					fmt.Println("Qakbot C&C servers from John Bambenek: \n", "First seen =>", result.Threatfeeds.QakBot.FirstSeen, "\n Last seen  =>", result.Threatfeeds.QakBot.LastSeen, "\n")
				}
				if result.Threatfeeds.Ramnit.FirstSeen != "" {
					fmt.Println("Ramnit C&C servers from John Bambenek: \n", "First seen =>", result.Threatfeeds.Ramnit.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Ramnit.LastSeen, "\n")
				}
				if result.Threatfeeds.Ransomware.FirstSeen != "" {
					fmt.Println("Abuse.ch Ransomware Domain Blocklist: \n", "First seen =>", result.Threatfeeds.Ransomware.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Ransomware.LastSeen, "\n")
				}
				if result.Threatfeeds.RansomwareIPs.FirstSeen != "" {
					fmt.Println("Abuse.ch Ransomware IPs Blocklist: \n", "First seen =>", result.Threatfeeds.RansomwareIPs.FirstSeen, "\n Last seen  =>", result.Threatfeeds.RansomwareIPs.LastSeen, "\n")
				}
				if result.Threatfeeds.Rapid7Sonar.FirstSeen != "" {
					fmt.Println("Rapid 7 Project Sonar: \n", "First seen =>", result.Threatfeeds.Rapid7Sonar.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Rapid7Sonar.LastSeen, "\n")
				}
				if result.Threatfeeds.ShadowServer.FirstSeen != "" {
					fmt.Println("Shadowserver Scanners. Consider them &quot;false positives&quot: \n", "First seen =>", result.Threatfeeds.ShadowServer.FirstSeen, "\n Last seen  =>", result.Threatfeeds.ShadowServer.LastSeen, "\n")
				}
				if result.Threatfeeds.Shodan.FirstSeen != "" {
					fmt.Println("Scanners Operated by the ShodanHQ Project: \n", "First seen =>", result.Threatfeeds.Shodan.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Shodan.LastSeen, "\n")
				}
				if result.Threatfeeds.SpyEye.FirstSeen != "" {
					fmt.Println("Spyeye C&C Server from Abuse.ch: \n", "First seen =>", result.Threatfeeds.SpyEye.FirstSeen, "\n Last seen  =>", result.Threatfeeds.SpyEye.LastSeen, "\n")
				}
				if result.Threatfeeds.SpyEyeDomains.FirstSeen != "" {
					fmt.Println("Spyeye C&C Server from Abuse.ch: \n", "First seen =>", result.Threatfeeds.SpyEyeDomains.FirstSeen, "\n Last seen  =>", result.Threatfeeds.SpyEyeDomains.LastSeen, "\n")
				}
				if result.Threatfeeds.Symmi.FirstSeen != "" {
					fmt.Println("Symmi C&C Server from John Bambenek: \n", "First seen =>", result.Threatfeeds.Symmi.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Symmi.LastSeen, "\n")
				}
				if result.Threatfeeds.ThreatExpert.FirstSeen != "" {
					fmt.Println("Threatexpert.com Malicious URLs: \n", "First seen =>", result.Threatfeeds.ThreatExpert.FirstSeen, "\n Last seen  =>", result.Threatfeeds.ThreatExpert.LastSeen, "\n")
				}
				if result.Threatfeeds.TinBa.FirstSeen != "" {
					fmt.Println("Tiny Banker C&C servers from John Bambenek: \n", "First seen =>", result.Threatfeeds.TinBa.FirstSeen, "\n Last seen  =>", result.Threatfeeds.TinBa.LastSeen, "\n")
				}
				if result.Threatfeeds.TLDns.FirstSeen != "" {
					fmt.Println("Root and Top Level Domain Name Servers: \n", "First seen =>", result.Threatfeeds.TLDns.FirstSeen, "\n Last seen  =>", result.Threatfeeds.TLDns.LastSeen, "\n")
				}
				if result.Threatfeeds.TorExit.FirstSeen != "" {
					fmt.Println("Tor Exit Nodes from Tor Project: \n", "First seen =>", result.Threatfeeds.TorExit.FirstSeen, "\n Last seen  =>", result.Threatfeeds.TorExit.LastSeen, "\n")
				}
				if result.Threatfeeds.UnivMichigan.FirstSeen != "" {
					fmt.Println("University of Michigan scans.io zmap scans: \n", "First seen =>", result.Threatfeeds.UnivMichigan.FirstSeen, "\n Last seen  =>", result.Threatfeeds.UnivMichigan.LastSeen, "\n")
				}
				if result.Threatfeeds.Upatre.FirstSeen != "" {
					fmt.Println("Upatre List from techhelplist.com: \n", "First seen =>", result.Threatfeeds.Upatre.FirstSeen, "\n Last seen  =>", result.Threatfeeds.Upatre.LastSeen, "\n")
				}
				if result.Threatfeeds.VirusTotal.FirstSeen != "" {
					fmt.Println("Virustotal Domains: \n", "First seen =>", result.Threatfeeds.VirusTotal.FirstSeen, "\n Last seen  =>", result.Threatfeeds.VirusTotal.LastSeen, "\n")
				}
				if result.Threatfeeds.ZeusCC.FirstSeen != "" {
					fmt.Println("Zeus C&C Server from Abuse.ch: \n", "First seen =>", result.Threatfeeds.ZeusCC.FirstSeen, "\n Last seen  =>", result.Threatfeeds.ZeusCC.LastSeen, "\n")
				}
				if result.Threatfeeds.ZeusDomains.FirstSeen != "" {
					fmt.Println("Zeus C&C Server from Abuse.ch: \n", "First seen =>", result.Threatfeeds.ZeusDomains.FirstSeen, "\n Last seen  =>", result.Threatfeeds.ZeusDomains.LastSeen, "\n")
				}
			} else {
				print("No Threatfeeds found for this IP. \n")
			}
		} else {
			fmt.Println("IP has not been reported to DShield.")
		}
	} else {
		fmt.Println(ip, "is not a valid IP.")
	}
}

//Specify flags and usage
func init() {
	flag.StringVarP(&ip, "ip", "i", "", "Search IP")
}
