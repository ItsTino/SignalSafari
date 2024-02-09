package main

import (
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	const device = "wlx00c0cab03e26" // Ensure this is your device's correct interface name
	snapshotLen := int32(1024)
	promiscuous := false
	timeout := pcap.BlockForever

	// Maps to keep track of SSID counts
	beaconSSIDs := make(map[string]int)
	probeSSIDs := make(map[string]int)

	// Open the device for capturing
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		dot11Layer := packet.Layer(layers.LayerTypeDot11)
		if dot11Layer == nil {
			continue // Not a Dot11 packet
		}

		dot11, _ := dot11Layer.(*layers.Dot11)

		// Process SSID based on frame type
		if dot11.Type == layers.Dot11TypeMgmtBeacon || dot11.Type == layers.Dot11TypeMgmtProbeReq {
			ssid, found := extractSSID(packet)
			if found {
				if dot11.Type == layers.Dot11TypeMgmtBeacon {
					beaconSSIDs[ssid]++
				} else if dot11.Type == layers.Dot11TypeMgmtProbeReq {
					probeSSIDs[ssid]++
				}
			}
		}
	}

	// Print the SSIDs and their counts
	fmt.Println("Beacon SSID:")
	for ssid, count := range beaconSSIDs {
		fmt.Printf("%s (%d)\n", ssid, count)
	}

	fmt.Println("\nProbe SSID:")
	for ssid, count := range probeSSIDs {
		fmt.Printf("%s (%d)\n", ssid, count)
	}
}

func extractSSID(packet gopacket.Packet) (string, bool) {
	for _, layer := range packet.Layers() {
		if infoElement, ok := layer.(*layers.Dot11InformationElement); ok && infoElement.ID == layers.Dot11InformationElementIDSSID {
			return string(infoElement.Info), true
		}
	}
	return "", false // SSID not found
}
