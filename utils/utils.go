package utils

import (
	"errors"
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	decoder "github.com/cloudflare/goflow/v3/decoders"
	"github.com/cloudflare/goflow/v3/decoders/netflow"
	flowmessage "github.com/cloudflare/goflow/v3/pb"
	reuseport "github.com/libp2p/go-reuseport"
	"github.com/prometheus/client_golang/prometheus"
)

const defaultFields = "Type,TimeReceived,SequenceNum,SamplerAddress,TimeFlowStart,TimeFlowEnd,Packets,SrcAddr,DstAddr,Etype,Proto,SrcPort,DstPort,IPTos"

var (
	MessageFields = flag.String("message.fields", defaultFields, "The list of fields to include in flow messages")
)

func GetServiceAddresses(srv string) (addrs []string, err error) {
	_, srvs, err := net.LookupSRV("", "", srv)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Service discovery: %v\n", err))
	}
	for _, srv := range srvs {
		addrs = append(addrs, net.JoinHostPort(srv.Target, strconv.Itoa(int(srv.Port))))
	}
	return addrs, nil
}

type Logger interface {
	Printf(string, ...interface{})
	Errorf(string, ...interface{})
	Warnf(string, ...interface{})
	Warn(...interface{})
	Error(...interface{})
	Debug(...interface{})
	Debugf(string, ...interface{})
	Infof(string, ...interface{})
	Fatalf(string, ...interface{})
}

type BaseMessage struct {
	Src     net.IP
	Port    int
	Payload []byte

	SetTime  bool
	RecvTime time.Time
}

type Transport interface {
	Publish([]*flowmessage.FlowMessage)
}

type DefaultLogTransport struct {
}

func (s *DefaultLogTransport) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		fmt.Printf("%v\n", FlowMessageToString(msg))
	}
}

type DefaultJSONTransport struct {
}

func (s *DefaultJSONTransport) Publish(msgs []*flowmessage.FlowMessage) {
	for _, msg := range msgs {
		fmt.Printf("%v\n", FlowMessageToJSON(msg))
	}
}

type DefaultErrorCallback struct {
	Logger Logger
}

func (cb *DefaultErrorCallback) Callback(name string, id int, start, end time.Time, err error) {
	if _, ok := err.(*netflow.ErrorTemplateNotFound); ok {
		return
	}
	if cb.Logger != nil {
		cb.Logger.Errorf("Error from: %v (%v) duration: %v. %v", name, id, end.Sub(start), err)
	}
}

type flowMessageItem struct {
	Name, Value string
}

func flowMessageFiltered(fmsg *flowmessage.FlowMessage) []flowMessageItem {
	srcmac := make([]byte, 8)
	dstmac := make([]byte, 8)
	srcmac = srcmac[2:8]
	dstmac = dstmac[2:8]
	var message []flowMessageItem

	for _, field := range strings.Split(*MessageFields, ",") {
		switch field {
		case "Type":
			message = append(message, flowMessageItem{"Type", fmsg.Type.String()})
		case "TimeReceived":
			message = append(message, flowMessageItem{"TimeReceived", fmt.Sprintf("%v", fmsg.TimeReceived)})
		case "SequenceNum":
			message = append(message, flowMessageItem{"SequenceNum", fmt.Sprintf("%v", fmsg.SequenceNum)})
		case "SamplerAddress":
			message = append(message, flowMessageItem{"SamplerAddress", net.IP(fmsg.SamplerAddress).String()})
		case "TimeFlowStart":
			message = append(message, flowMessageItem{"TimeFlowStart", fmt.Sprintf("%v", fmsg.TimeFlowStart)})
		case "TimeFlowEnd":
			message = append(message, flowMessageItem{"TimeFlowEnd", fmt.Sprintf("%v", fmsg.TimeFlowEnd)})
		case "Packets":
			message = append(message, flowMessageItem{"Packets", fmt.Sprintf("%v", fmsg.Packets)})
		case "SrcAddr":
			message = append(message, flowMessageItem{"SrcAddr", net.IP(fmsg.SrcAddr).String()})
		case "DstAddr":
			message = append(message, flowMessageItem{"DstAddr", net.IP(fmsg.DstAddr).String()})
		case "Etype":
			message = append(message, flowMessageItem{"Etype", fmt.Sprintf("%v", fmsg.Etype)})
		case "Proto":
			message = append(message, flowMessageItem{"Proto", fmt.Sprintf("%v", fmsg.Proto)})
		case "SrcPort":
			message = append(message, flowMessageItem{"SrcPort", fmt.Sprintf("%v", fmsg.SrcPort)})
		case "DstPort":
			message = append(message, flowMessageItem{"DstPort", fmt.Sprintf("%v", fmsg.DstPort)})
		case "SrcMac":
			message = append(message, flowMessageItem{"SrcMac", net.HardwareAddr(srcmac).String()})
		case "DstMac":
			message = append(message, flowMessageItem{"DstMac", net.HardwareAddr(dstmac).String()})
		case "IPTos":
			message = append(message, flowMessageItem{"IPTos", fmt.Sprintf("%v", fmsg.IPTos)})
		}
	}

	return message
}

func FlowMessageToString(fmsg *flowmessage.FlowMessage) string {
	filteredMessage := flowMessageFiltered(fmsg)
	message := make([]string, len(filteredMessage))
	for i, m := range filteredMessage {
		message[i] = m.Name + ":" + m.Value
	}
	return strings.Join(message, " ")
}

func FlowMessageToJSON(fmsg *flowmessage.FlowMessage) string {
	filteredMessage := flowMessageFiltered(fmsg)
	message := make([]string, len(filteredMessage))
	for i, m := range filteredMessage {
		message[i] = fmt.Sprintf("\"%s\":\"%s\"", m.Name, m.Value)
	}
	return "{" + strings.Join(message, ",") + "}"
}

func UDPRoutine(name string, decodeFunc decoder.DecoderFunc, workers int, addr string, port int, sockReuse bool, logger Logger) error {
	ecb := DefaultErrorCallback{
		Logger: logger,
	}

	decoderParams := decoder.DecoderParams{
		DecoderFunc:   decodeFunc,
		DoneCallback:  DefaultAccountCallback,
		ErrorCallback: ecb.Callback,
	}

	processor := decoder.CreateProcessor(workers, decoderParams, name)
	processor.Start()

	addrUDP := net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: port,
	}

	var udpconn *net.UDPConn
	var err error

	if sockReuse {
		pconn, err := reuseport.ListenPacket("udp", addrUDP.String())
		defer pconn.Close()
		if err != nil {
			return err
		}
		var ok bool
		udpconn, ok = pconn.(*net.UDPConn)
		if !ok {
			return err
		}
	} else {
		udpconn, err = net.ListenUDP("udp", &addrUDP)
		defer udpconn.Close()
		if err != nil {
			return err
		}
	}

	payload := make([]byte, 9000)

	localIP := addrUDP.IP.String()
	if addrUDP.IP == nil {
		localIP = ""
	}

	for {
		size, pktAddr, _ := udpconn.ReadFromUDP(payload)
		payloadCut := make([]byte, size)
		copy(payloadCut, payload[0:size])

		baseMessage := BaseMessage{
			Src:     pktAddr.IP,
			Port:    pktAddr.Port,
			Payload: payloadCut,
		}
		processor.ProcessMessage(baseMessage)

		MetricTrafficBytes.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Add(float64(size))
		MetricTrafficPackets.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Inc()
		MetricPacketSizeSum.With(
			prometheus.Labels{
				"remote_ip":   pktAddr.IP.String(),
				"remote_port": strconv.Itoa(pktAddr.Port),
				"local_ip":    localIP,
				"local_port":  strconv.Itoa(addrUDP.Port),
				"type":        name,
			}).
			Observe(float64(size))
	}
}
