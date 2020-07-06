package main

import (
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type FiveTuple struct {
	SrcIP    string
	DstIP    string
	SrcPort  uint16
	DstPort  uint16
	Protocol uint8
}

func (f FiveTuple) GetReverse() FiveTuple {
	return FiveTuple{
		SrcIP:    f.DstIP,
		SrcPort:  f.DstPort,
		DstIP:    f.SrcIP,
		DstPort:  f.SrcPort,
		Protocol: f.Protocol,
	}
}

type PacketData struct {
	Timestamp  time.Time
	Header     FiveTuple
	Length uint32
	IsOutbound bool
	TCP layers.TCP
}

func (p *PacketData) GetKey() FiveTuple {
	if p.IsOutbound {
		return p.Header
	} else {
		return p.Header.GetReverse()
	}
}

type FlowEntry struct {
	Key FiveTuple
	Created time.Time
	Updated time.Time

	DownPackets int
	UpPackets int
}

func NewFlowEntry(key FiveTuple, pktTime time.Time) *FlowEntry {
	return &FlowEntry{
		Key: key,
		Created: pktTime,
		Updated: pktTime,
		DownPackets: 0,
		UpPackets: 0,
	}
}

func (e *FlowEntry) OnPacket(pd PacketData) {
	e.Updated = pd.Timestamp

	fmt.Printf("%v,%v,%v,%v,%v,%v\n", pd.Timestamp.Format("2006-01-02 15:04:05.999999999"), pd.GetKey(), pd.IsOutbound, pd.TCP.Seq, pd.TCP.Ack, pd.TCP.Window)

	if pd.IsOutbound {
		e.UpPackets += 1
	} else {
		e.DownPackets += 1
	}

}

var packets chan PacketData

func main() {
	pcapFile := flag.String("pcap", "", "Path to PCAP File")
	filter := flag.String("filter", "", "TCPDUMP like filter")
	clientMac := flag.String("mac", "", "Client MAC to figure out direction")
	flag.Parse()

	if *pcapFile == "" {
		log.Fatal("Please enter a valid pcap path.")
	}

	if *clientMac == "" {
		log.Fatal("Please enter a valid clientMac.")
	}

	packets = make(chan PacketData, 1000)

	go PacketParser(pcapFile, filter, clientMac)
	PacketHandler()
}

func PacketHandler() {
	m := make(map[FiveTuple]*FlowEntry)
	for pkt := range packets {
		k := pkt.GetKey()
		entry, exists := m[k]
		if !exists {
			entry = NewFlowEntry(k, pkt.Timestamp)
			m[k] = entry
		}
		entry.OnPacket(pkt)
	}
}

func PacketParser(pcapFile *string, filter *string, clientMac *string) {
	// Open file instead of device
	handle, err := pcap.OpenOffline(*pcapFile)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(*filter)
	if err != nil {
		log.Fatal(err)
	}

	var (
		ethLayer layers.Ethernet
		ip4Layer layers.IPv4
		tcpLayer layers.TCP
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ip4Layer,
		&tcpLayer,
	)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	for packet := range packetSource.Packets() {
		foundLayerTypes := []gopacket.LayerType{}
		_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		var pd PacketData
		pd.Length, pd.Timestamp = uint32(packet.Metadata().Length), packet.Metadata().Timestamp
		for _, layerType := range foundLayerTypes {
			switch layerType {
			case layers.LayerTypeEthernet:
				if ethLayer.SrcMAC.String() == *clientMac {
					pd.IsOutbound = true
				}
			case layers.LayerTypeIPv4:
				pd.Header.SrcIP = ip4Layer.SrcIP.String()
				pd.Header.DstIP = ip4Layer.DstIP.String()
				pd.Header.Protocol = uint8(ip4Layer.Protocol)
			case layers.LayerTypeTCP:
				pd.Header.SrcPort = uint16(tcpLayer.SrcPort)
				pd.Header.DstPort = uint16(tcpLayer.DstPort)
				pd.TCP = tcpLayer
				packets <- pd
			}
		}
	}
	close(packets)
}
