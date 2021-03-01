// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.15.3
// source: pb/flow.proto

package flowprotob

import (
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

type FlowMessage_FlowType int32

const (
	FlowMessage_FLOWUNKNOWN FlowMessage_FlowType = 0
	FlowMessage_SFLOW_5     FlowMessage_FlowType = 1
	FlowMessage_NETFLOW_V5  FlowMessage_FlowType = 2
	FlowMessage_NETFLOW_V9  FlowMessage_FlowType = 3
	FlowMessage_IPFIX       FlowMessage_FlowType = 4
)

// Enum value maps for FlowMessage_FlowType.
var (
	FlowMessage_FlowType_name = map[int32]string{
		0: "FLOWUNKNOWN",
		1: "SFLOW_5",
		2: "NETFLOW_V5",
		3: "NETFLOW_V9",
		4: "IPFIX",
	}
	FlowMessage_FlowType_value = map[string]int32{
		"FLOWUNKNOWN": 0,
		"SFLOW_5":     1,
		"NETFLOW_V5":  2,
		"NETFLOW_V9":  3,
		"IPFIX":       4,
	}
)

func (x FlowMessage_FlowType) Enum() *FlowMessage_FlowType {
	p := new(FlowMessage_FlowType)
	*p = x
	return p
}

func (x FlowMessage_FlowType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (FlowMessage_FlowType) Descriptor() protoreflect.EnumDescriptor {
	return file_pb_flow_proto_enumTypes[0].Descriptor()
}

func (FlowMessage_FlowType) Type() protoreflect.EnumType {
	return &file_pb_flow_proto_enumTypes[0]
}

func (x FlowMessage_FlowType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use FlowMessage_FlowType.Descriptor instead.
func (FlowMessage_FlowType) EnumDescriptor() ([]byte, []int) {
	return file_pb_flow_proto_rawDescGZIP(), []int{0, 0}
}

type FlowMessage struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Type          FlowMessage_FlowType `protobuf:"varint,1,opt,name=Type,proto3,enum=flowprotob.FlowMessage_FlowType" json:"Type,omitempty"`
	TimeReceived  uint64               `protobuf:"varint,2,opt,name=TimeReceived,proto3" json:"TimeReceived,omitempty"`
	SequenceNum   uint32               `protobuf:"varint,4,opt,name=SequenceNum,proto3" json:"SequenceNum,omitempty"` //uint64 SamplingRate = 3;
	FlowDirection uint32               `protobuf:"varint,42,opt,name=FlowDirection,proto3" json:"FlowDirection,omitempty"`
	// Sampler information
	SamplerAddress []byte `protobuf:"bytes,11,opt,name=SamplerAddress,proto3" json:"SamplerAddress,omitempty"`
	// Found inside packet
	TimeFlowStart uint64 `protobuf:"varint,38,opt,name=TimeFlowStart,proto3" json:"TimeFlowStart,omitempty"`
	TimeFlowEnd   uint64 `protobuf:"varint,5,opt,name=TimeFlowEnd,proto3" json:"TimeFlowEnd,omitempty"`
	// Size of the sampled packet
	// uint64 Bytes = 9;
	Packets uint64 `protobuf:"varint,10,opt,name=Packets,proto3" json:"Packets,omitempty"`
	// Source/destination addresses
	SrcAddr []byte `protobuf:"bytes,6,opt,name=SrcAddr,proto3" json:"SrcAddr,omitempty"`
	DstAddr []byte `protobuf:"bytes,7,opt,name=DstAddr,proto3" json:"DstAddr,omitempty"`
	// Layer 3 protocol (IPv4/IPv6/ARP/MPLS...)
	Etype uint32 `protobuf:"varint,30,opt,name=Etype,proto3" json:"Etype,omitempty"`
	// Layer 4 protocol
	Proto uint32 `protobuf:"varint,20,opt,name=Proto,proto3" json:"Proto,omitempty"`
	// Ports for UDP and TCP
	SrcPort uint32 `protobuf:"varint,21,opt,name=SrcPort,proto3" json:"SrcPort,omitempty"`
	DstPort uint32 `protobuf:"varint,22,opt,name=DstPort,proto3" json:"DstPort,omitempty"`
	// IP and TCP special flags
	IPTos uint32 `protobuf:"varint,23,opt,name=IPTos,proto3" json:"IPTos,omitempty"`
}

func (x *FlowMessage) Reset() {
	*x = FlowMessage{}
	if protoimpl.UnsafeEnabled {
		mi := &file_pb_flow_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *FlowMessage) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*FlowMessage) ProtoMessage() {}

func (x *FlowMessage) ProtoReflect() protoreflect.Message {
	mi := &file_pb_flow_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use FlowMessage.ProtoReflect.Descriptor instead.
func (*FlowMessage) Descriptor() ([]byte, []int) {
	return file_pb_flow_proto_rawDescGZIP(), []int{0}
}

func (x *FlowMessage) GetType() FlowMessage_FlowType {
	if x != nil {
		return x.Type
	}
	return FlowMessage_FLOWUNKNOWN
}

func (x *FlowMessage) GetTimeReceived() uint64 {
	if x != nil {
		return x.TimeReceived
	}
	return 0
}

func (x *FlowMessage) GetSequenceNum() uint32 {
	if x != nil {
		return x.SequenceNum
	}
	return 0
}

func (x *FlowMessage) GetFlowDirection() uint32 {
	if x != nil {
		return x.FlowDirection
	}
	return 0
}

func (x *FlowMessage) GetSamplerAddress() []byte {
	if x != nil {
		return x.SamplerAddress
	}
	return nil
}

func (x *FlowMessage) GetTimeFlowStart() uint64 {
	if x != nil {
		return x.TimeFlowStart
	}
	return 0
}

func (x *FlowMessage) GetTimeFlowEnd() uint64 {
	if x != nil {
		return x.TimeFlowEnd
	}
	return 0
}

func (x *FlowMessage) GetPackets() uint64 {
	if x != nil {
		return x.Packets
	}
	return 0
}

func (x *FlowMessage) GetSrcAddr() []byte {
	if x != nil {
		return x.SrcAddr
	}
	return nil
}

func (x *FlowMessage) GetDstAddr() []byte {
	if x != nil {
		return x.DstAddr
	}
	return nil
}

func (x *FlowMessage) GetEtype() uint32 {
	if x != nil {
		return x.Etype
	}
	return 0
}

func (x *FlowMessage) GetProto() uint32 {
	if x != nil {
		return x.Proto
	}
	return 0
}

func (x *FlowMessage) GetSrcPort() uint32 {
	if x != nil {
		return x.SrcPort
	}
	return 0
}

func (x *FlowMessage) GetDstPort() uint32 {
	if x != nil {
		return x.DstPort
	}
	return 0
}

func (x *FlowMessage) GetIPTos() uint32 {
	if x != nil {
		return x.IPTos
	}
	return 0
}

var File_pb_flow_proto protoreflect.FileDescriptor

var file_pb_flow_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x70, 0x62, 0x2f, 0x66, 0x6c, 0x6f, 0x77, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x0a, 0x66, 0x6c, 0x6f, 0x77, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x22, 0xb8, 0x04, 0x0a, 0x0b,
	0x46, 0x6c, 0x6f, 0x77, 0x4d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x12, 0x34, 0x0a, 0x04, 0x54,
	0x79, 0x70, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x20, 0x2e, 0x66, 0x6c, 0x6f, 0x77,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2e, 0x46, 0x6c, 0x6f, 0x77, 0x4d, 0x65, 0x73, 0x73, 0x61,
	0x67, 0x65, 0x2e, 0x46, 0x6c, 0x6f, 0x77, 0x54, 0x79, 0x70, 0x65, 0x52, 0x04, 0x54, 0x79, 0x70,
	0x65, 0x12, 0x22, 0x0a, 0x0c, 0x54, 0x69, 0x6d, 0x65, 0x52, 0x65, 0x63, 0x65, 0x69, 0x76, 0x65,
	0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0c, 0x54, 0x69, 0x6d, 0x65, 0x52, 0x65, 0x63,
	0x65, 0x69, 0x76, 0x65, 0x64, 0x12, 0x20, 0x0a, 0x0b, 0x53, 0x65, 0x71, 0x75, 0x65, 0x6e, 0x63,
	0x65, 0x4e, 0x75, 0x6d, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0b, 0x53, 0x65, 0x71, 0x75,
	0x65, 0x6e, 0x63, 0x65, 0x4e, 0x75, 0x6d, 0x12, 0x24, 0x0a, 0x0d, 0x46, 0x6c, 0x6f, 0x77, 0x44,
	0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x2a, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x0d,
	0x46, 0x6c, 0x6f, 0x77, 0x44, 0x69, 0x72, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x26, 0x0a,
	0x0e, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x41, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x0b, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x0e, 0x53, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x72, 0x41, 0x64,
	0x64, 0x72, 0x65, 0x73, 0x73, 0x12, 0x24, 0x0a, 0x0d, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f,
	0x77, 0x53, 0x74, 0x61, 0x72, 0x74, 0x18, 0x26, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0d, 0x54, 0x69,
	0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x53, 0x74, 0x61, 0x72, 0x74, 0x12, 0x20, 0x0a, 0x0b, 0x54,
	0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64, 0x18, 0x05, 0x20, 0x01, 0x28, 0x04,
	0x52, 0x0b, 0x54, 0x69, 0x6d, 0x65, 0x46, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x64, 0x12, 0x18, 0x0a,
	0x07, 0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x18, 0x0a, 0x20, 0x01, 0x28, 0x04, 0x52, 0x07,
	0x50, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x12, 0x18, 0x0a, 0x07, 0x53, 0x72, 0x63, 0x41, 0x64,
	0x64, 0x72, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x07, 0x53, 0x72, 0x63, 0x41, 0x64, 0x64,
	0x72, 0x12, 0x18, 0x0a, 0x07, 0x44, 0x73, 0x74, 0x41, 0x64, 0x64, 0x72, 0x18, 0x07, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x07, 0x44, 0x73, 0x74, 0x41, 0x64, 0x64, 0x72, 0x12, 0x14, 0x0a, 0x05, 0x45,
	0x74, 0x79, 0x70, 0x65, 0x18, 0x1e, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x45, 0x74, 0x79, 0x70,
	0x65, 0x12, 0x14, 0x0a, 0x05, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x18, 0x14, 0x20, 0x01, 0x28, 0x0d,
	0x52, 0x05, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x18, 0x0a, 0x07, 0x53, 0x72, 0x63, 0x50, 0x6f,
	0x72, 0x74, 0x18, 0x15, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x07, 0x53, 0x72, 0x63, 0x50, 0x6f, 0x72,
	0x74, 0x12, 0x18, 0x0a, 0x07, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x18, 0x16, 0x20, 0x01,
	0x28, 0x0d, 0x52, 0x07, 0x44, 0x73, 0x74, 0x50, 0x6f, 0x72, 0x74, 0x12, 0x14, 0x0a, 0x05, 0x49,
	0x50, 0x54, 0x6f, 0x73, 0x18, 0x17, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x05, 0x49, 0x50, 0x54, 0x6f,
	0x73, 0x22, 0x53, 0x0a, 0x08, 0x46, 0x6c, 0x6f, 0x77, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0f, 0x0a,
	0x0b, 0x46, 0x4c, 0x4f, 0x57, 0x55, 0x4e, 0x4b, 0x4e, 0x4f, 0x57, 0x4e, 0x10, 0x00, 0x12, 0x0b,
	0x0a, 0x07, 0x53, 0x46, 0x4c, 0x4f, 0x57, 0x5f, 0x35, 0x10, 0x01, 0x12, 0x0e, 0x0a, 0x0a, 0x4e,
	0x45, 0x54, 0x46, 0x4c, 0x4f, 0x57, 0x5f, 0x56, 0x35, 0x10, 0x02, 0x12, 0x0e, 0x0a, 0x0a, 0x4e,
	0x45, 0x54, 0x46, 0x4c, 0x4f, 0x57, 0x5f, 0x56, 0x39, 0x10, 0x03, 0x12, 0x09, 0x0a, 0x05, 0x49,
	0x50, 0x46, 0x49, 0x58, 0x10, 0x04, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_pb_flow_proto_rawDescOnce sync.Once
	file_pb_flow_proto_rawDescData = file_pb_flow_proto_rawDesc
)

func file_pb_flow_proto_rawDescGZIP() []byte {
	file_pb_flow_proto_rawDescOnce.Do(func() {
		file_pb_flow_proto_rawDescData = protoimpl.X.CompressGZIP(file_pb_flow_proto_rawDescData)
	})
	return file_pb_flow_proto_rawDescData
}

var file_pb_flow_proto_enumTypes = make([]protoimpl.EnumInfo, 1)
var file_pb_flow_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_pb_flow_proto_goTypes = []interface{}{
	(FlowMessage_FlowType)(0), // 0: flowprotob.FlowMessage.FlowType
	(*FlowMessage)(nil),       // 1: flowprotob.FlowMessage
}
var file_pb_flow_proto_depIdxs = []int32{
	0, // 0: flowprotob.FlowMessage.Type:type_name -> flowprotob.FlowMessage.FlowType
	1, // [1:1] is the sub-list for method output_type
	1, // [1:1] is the sub-list for method input_type
	1, // [1:1] is the sub-list for extension type_name
	1, // [1:1] is the sub-list for extension extendee
	0, // [0:1] is the sub-list for field type_name
}

func init() { file_pb_flow_proto_init() }
func file_pb_flow_proto_init() {
	if File_pb_flow_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_pb_flow_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*FlowMessage); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_pb_flow_proto_rawDesc,
			NumEnums:      1,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_pb_flow_proto_goTypes,
		DependencyIndexes: file_pb_flow_proto_depIdxs,
		EnumInfos:         file_pb_flow_proto_enumTypes,
		MessageInfos:      file_pb_flow_proto_msgTypes,
	}.Build()
	File_pb_flow_proto = out.File
	file_pb_flow_proto_rawDesc = nil
	file_pb_flow_proto_goTypes = nil
	file_pb_flow_proto_depIdxs = nil
}
