package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/Ullaakut/nmap"
	_ "github.com/Ullaakut/nmap"
	"log"
	"net"
	"os"
	"time"
)

func getlocalIP() string{
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	fmt.Printf("local IP: %v \n", localAddr.IP.String())
	return localAddr.IP.String()
}
func main() {
	// Subcommands
	listUpCommand := flag.NewFlagSet("listup", flag.ExitOnError)
	scanupCommand := flag.NewFlagSet("scanup", flag.ExitOnError)

	// list Subcommands flag pointers
	listHostPtr := listUpCommand.String("host", "", "Host to scan incl subnet (default= current ip/24)")

	// scan Subcommand flag pointers
	scanHostPtr := scanupCommand.String("host", "", "Host to scan incl subnet (default= current ip/24)")
	scanIntensityPtr := scanupCommand.Int("I", 0, "Scan Intensity: 0-Low 1-Medium 2-High")

	// exit if no option is given


	if len(os.Args) < 2 {
		fmt.Println("listup or scanup subcommand is required")
		flag.PrintDefaults()
		os.Exit(1)
	}


	switch os.Args[1] {
	case "listup":
		listUpCommand.Parse(os.Args[2:])
	case "scanup":
		scanupCommand.Parse(os.Args[2:])
	default:
		flag.PrintDefaults()
		os.Exit(1)
	}

	if listUpCommand.Parsed() {
		listup(*listHostPtr)
	}
	if scanupCommand.Parsed() {
		intensityChoice := map[int]bool{0:true, 1:true, 2:true }
		if _, validChoice := intensityChoice[*scanIntensityPtr]; !validChoice {
			scanupCommand.PrintDefaults()
			os.Exit(1)
		}
		intensity := *scanIntensityPtr + 7
		fmt.Println("using intensity:", intensity)
		scanup(*scanHostPtr,intensity)

	}
}
func listup(hostnetwork string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var networktoscan string
	if hostnetwork == "" {
		networktoscan = getlocalIP()+"/24"
	}else {
		networktoscan = hostnetwork
	}
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(networktoscan),
		nmap.WithPingScan(),
		nmap.WithContext(ctx),
		nmap.WithFilterHost(func(h nmap.Host) bool {
			if h.Status.String() == "up" {
				return true
			}

			return false
		}),
	)
	if err != nil {
		log.Fatalf("unable to create berendmap scanner: %v", err)
	}
	progress := make(chan float32, 1)

	go func(){
		for p := range progress {
			fmt.Printf("Progress: %v %%\n", p)
		}
	}()
	result, warnings, err := scanner.RunWithProgress(progress)
	if err!= nil {
		log.Fatalf(" Unable to run berendmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf(" Warnings: \n %v", warnings)
	}

	//print results
	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		fmt.Printf("Host %q is up\n", host.Addresses[0])
	}

	fmt.Printf("Berendmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}

func scanup(hostnetwork string, intensity int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var networktoscan string
	if hostnetwork == "" {
		networktoscan = getlocalIP()+"/24"
	}else {
		networktoscan = hostnetwork
	}
	scanner, err := nmap.NewScanner(
		nmap.WithTargets(networktoscan),
		//nmap.WithMostCommonPorts(25),
		nmap.WithContext(ctx),
		nmap.WithConsecutivePortScanning(),
		nmap.WithFilterHost(func(h nmap.Host) bool {
			if h.Status.String() == "up" {
				return true
			}

			return false
		}),
	)
	if err != nil {
		log.Fatalf("unable to create berendmap scanner: %v", err)
	}
	progress := make(chan float32, 1)

	go func(){
		for p := range progress {
			fmt.Printf("Progress: %v %%\n", p)
		}
	}()
	result, warnings, err := scanner.RunWithProgress(progress)
	if err!= nil {
		log.Fatalf(" Unable to run berendmap scan: %v", err)
	}

	if warnings != nil {
		log.Printf(" Warnings: \n %v", warnings)
	}

	//print results
	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}
		fmt.Printf("Host %q is up\t| known as: %s\n", host.Addresses[0], host.Hostnames)
		for _, port := range host.Ports {
			if port.State.String() == "open" {
			fmt.Printf("\tPort %d/%s %s %s\n", port.ID, port.Protocol, port.State, port.Service.Name)
		}
		}
	}

	fmt.Printf("Berendmap done: %d hosts up scanned in %3f seconds\n", len(result.Hosts), result.Stats.Finished.Elapsed)
}
//
//func (p *Person) SayHi() {
//	fmt.Println("Your name is", p.Name)
//	fmt.Println("Your age is", p.Age)
//	if p.DrivingLicense{
//		fmt.Println("You're able to drive a car")
//	} else {
//		fmt.Println("You're unable to drive a car")
//	}
//	fmt.Println("-------------------\n")
//}
//
//type Person struct {
//	Name           string
//	Age            int
//	DrivingLicense bool
//}
