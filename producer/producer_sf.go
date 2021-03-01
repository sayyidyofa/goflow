package producer

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/cloudflare/goflow/v3/decoders/sflow"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
)

func GetSFlowFlowSamples(packet *sflow.Packet) []interface{} {
	flowSamples := make([]interface{}, 0)
	for _, sample := range packet.Samples {
		switch sample.(type) {
		case sflow.FlowSample:
			flowSamples = append(flowSamples, sample)
		case sflow.ExpandedFlowSample:
			flowSamples = append(flowSamples, sample)
		}
	}
	return flowSamples
}

type SFlowProducerConfig struct {
	DecodeGRE bool
}

func ParseSampledHeader(flowMessage *flowmessage.FlowMessage, sampledHeader *sflow.SampledHeader) error {
	return ParseSampledHeaderConfig(flowMessage, sampledHeader, nil)
}

func ParseSampledHeaderConfig(flowMessage *flowmessage.FlowMessage, sampledHeader *sflow.SampledHeader, config *SFlowProducerConfig) error {
	var decodeGRE bool
	if config != nil {
		decodeGRE = config.DecodeGRE
	}

	data := (*sampledHeader).HeaderData
	switch (*sampledHeader).Protocol {
	case 1: // Ethernet

		var hasEncap bool
		var nextHeader byte
		var nextHeaderEncap byte
		srcIP := net.IP{}
		dstIP := net.IP{}
		srcIPEncap := net.IP{}
		dstIPEncap := net.IP{}
		offset := 14

		var tos byte
		var ttl byte
		var identification uint16
		var fragOffset uint16
		var flowLabel uint32

		var tosEncap byte
		var ttlEncap byte
		var identificationEncap uint16
		var fragOffsetEncap uint16
		var flowLabelEncap uint32

		var srcPort uint16
		var dstPort uint16

		etherType := data[12:14]
		etherTypeEncap := []byte{0, 0}

		encap := true
		iterations := 0
		for encap && iterations <= 1 {
			encap = false

			if etherType[0] == 0x8 && etherType[1] == 0x0 { // IPv4
				if len(data) >= offset+20 {
					nextHeader = data[offset+9]
					srcIP = data[offset+12 : offset+16]
					dstIP = data[offset+16 : offset+20]
					tos = data[offset+1]
					ttl = data[offset+8]

					identification = binary.BigEndian.Uint16(data[offset+4 : offset+6])
					fragOffset = binary.BigEndian.Uint16(data[offset+6 : offset+8])

					offset += 20
				}
			} else if etherType[0] == 0x86 && etherType[1] == 0xdd { // IPv6
				if len(data) >= offset+40 {
					nextHeader = data[offset+6]
					srcIP = data[offset+8 : offset+24]
					dstIP = data[offset+24 : offset+40]

					tostmp := uint32(binary.BigEndian.Uint16(data[offset : offset+2]))
					tos = uint8(tostmp & 0x0ff0 >> 4)
					ttl = data[offset+7]

					flowLabel = binary.BigEndian.Uint32(data[offset : offset+4])

					offset += 40

				}
			} else if etherType[0] == 0x8 && etherType[1] == 0x6 { // ARP
			} /*else {
				return errors.New(fmt.Sprintf("Unknown EtherType: %v\n", etherType))
			} */

			if len(data) >= offset+4 && (nextHeader == 17 || nextHeader == 6) {
				srcPort = binary.BigEndian.Uint16(data[offset+0 : offset+2])
				dstPort = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			}

			// GRE
			if len(data) >= offset+4 && nextHeader == 47 {
				etherTypeEncap = data[offset+2 : offset+4]
				offset += 4
				if (etherTypeEncap[0] == 0x8 && etherTypeEncap[1] == 0x0) ||
					(etherTypeEncap[0] == 0x86 && etherTypeEncap[1] == 0xdd) {
					encap = true
					hasEncap = true
				}
				if etherTypeEncap[0] == 0x88 && etherTypeEncap[1] == 0x0b && len(data) >= offset+12 {
					offset += 8
					encap = true
					pppEtherType := data[offset+2 : offset+4]
					if pppEtherType[0] == 0x0 && pppEtherType[1] == 0x21 {
						etherTypeEncap = []byte{0x8, 0x00}
						hasEncap = true
					} else if pppEtherType[0] == 0x0 && pppEtherType[1] == 0x57 {
						etherTypeEncap = []byte{0x86, 0xdd}
						hasEncap = true
					}
					offset += 4

				}

				if hasEncap {
					srcIPEncap = srcIP
					dstIPEncap = dstIP

					nextHeaderEncap = nextHeader
					tosEncap = tos
					ttlEncap = ttl
					identificationEncap = identification
					fragOffsetEncap = fragOffset
					flowLabelEncap = flowLabel

					etherTypeEncapTmp := etherTypeEncap
					etherTypeEncap = etherType
					etherType = etherTypeEncapTmp
				}

			}
			iterations++
		}

		if !decodeGRE && hasEncap {
			//fmt.Printf("DEOCDE %v -> %v || %v -> %v\n", net.IP(srcIPEncap), net.IP(dstIPEncap), net.IP(srcIP), net.IP(dstIP))
			tmpSrc := srcIPEncap
			tmpDst := dstIPEncap
			srcIPEncap = srcIP
			dstIPEncap = dstIP
			srcIP = tmpSrc
			dstIP = tmpDst

			tmpNextHeader := nextHeaderEncap
			nextHeaderEncap = nextHeader
			nextHeader = tmpNextHeader

			tosTmp := tosEncap
			tosEncap = tos
			tos = tosTmp

			ttlTmp := ttlEncap
			ttlEncap = ttl
			ttl = ttlTmp

			identificationTmp := identificationEncap
			identificationEncap = identification
			identification = identificationTmp

			fragOffsetTmp := fragOffsetEncap
			fragOffsetEncap = fragOffset
			fragOffset = fragOffsetTmp

			flowLabelTmp := flowLabelEncap
			flowLabelEncap = flowLabel
			flowLabel = flowLabelTmp
		}

		(*flowMessage).Etype = uint32(binary.BigEndian.Uint16(etherType[0:2]))

		(*flowMessage).SrcPort = uint32(srcPort)
		(*flowMessage).DstPort = uint32(dstPort)

		(*flowMessage).SrcAddr = srcIP
		(*flowMessage).DstAddr = dstIP
		(*flowMessage).Proto = uint32(nextHeader)
		(*flowMessage).IPTos = uint32(tos)
	}
	return nil
}

func SearchSFlowSamples(samples []interface{}) []*flowmessage.FlowMessage {
	return SearchSFlowSamples(samples)
}

func SearchSFlowSamplesConfig(samples []interface{}, config *SFlowProducerConfig) []*flowmessage.FlowMessage {
	flowMessageSet := make([]*flowmessage.FlowMessage, 0)

	for _, flowSample := range samples {
		var records []sflow.FlowRecord

		flowMessage := &flowmessage.FlowMessage{}
		flowMessage.Type = flowmessage.FlowMessage_SFLOW_5

		switch flowSample := flowSample.(type) {
		case sflow.FlowSample:
			records = flowSample.Records
		case sflow.ExpandedFlowSample:
			records = flowSample.Records
		}

		ipSrc := net.IP{}
		ipDst := net.IP{}
		flowMessage.Packets = 1
		for _, record := range records {
			switch recordData := record.Data.(type) {
			case sflow.SampledHeader:
				ParseSampledHeaderConfig(flowMessage, &recordData, config)
			case sflow.SampledIPv4:
				ipSrc = recordData.Base.SrcIP
				ipDst = recordData.Base.DstIP
				flowMessage.SrcAddr = ipSrc
				flowMessage.DstAddr = ipDst
				flowMessage.Proto = recordData.Base.Protocol
				flowMessage.SrcPort = recordData.Base.SrcPort
				flowMessage.DstPort = recordData.Base.DstPort
				flowMessage.IPTos = recordData.Tos
				flowMessage.Etype = 0x800
			case sflow.SampledIPv6:
				ipSrc = recordData.Base.SrcIP
				ipDst = recordData.Base.DstIP
				flowMessage.SrcAddr = ipSrc
				flowMessage.DstAddr = ipDst
				flowMessage.Proto = recordData.Base.Protocol
				flowMessage.SrcPort = recordData.Base.SrcPort
				flowMessage.DstPort = recordData.Base.DstPort
				flowMessage.IPTos = recordData.Priority
				flowMessage.Etype = 0x86dd
			case sflow.ExtendedRouter:

			case sflow.ExtendedGateway:

			}
		}
		flowMessageSet = append(flowMessageSet, flowMessage)
	}
	return flowMessageSet
}

func ProcessMessageSFlow(msgDec interface{}) ([]*flowmessage.FlowMessage, error) {
	return ProcessMessageSFlowConfig(msgDec, nil)
}

func ProcessMessageSFlowConfig(msgDec interface{}, config *SFlowProducerConfig) ([]*flowmessage.FlowMessage, error) {
	switch packet := msgDec.(type) {
	case sflow.Packet:
		seqnum := packet.SequenceNumber
		var agent net.IP
		agent = packet.AgentIP

		flowSamples := GetSFlowFlowSamples(&packet)
		flowMessageSet := SearchSFlowSamplesConfig(flowSamples, config)
		for _, fmsg := range flowMessageSet {
			fmsg.SamplerAddress = agent
			fmsg.SequenceNum = seqnum
		}

		return flowMessageSet, nil
	default:
		return []*flowmessage.FlowMessage{}, errors.New("Bad sFlow version")
	}
}
