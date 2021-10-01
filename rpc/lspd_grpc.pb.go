// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package lspd

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ChannelOpenerClient is the client API for ChannelOpener service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ChannelOpenerClient interface {
	ChannelInformation(ctx context.Context, in *ChannelInformationRequest, opts ...grpc.CallOption) (*ChannelInformationReply, error)
	OpenChannel(ctx context.Context, in *OpenChannelRequest, opts ...grpc.CallOption) (*OpenChannelReply, error)
	RegisterPayment(ctx context.Context, in *RegisterPaymentRequest, opts ...grpc.CallOption) (*RegisterPaymentReply, error)
	CheckChannels(ctx context.Context, in *Encrypted, opts ...grpc.CallOption) (*Encrypted, error)
}

type channelOpenerClient struct {
	cc grpc.ClientConnInterface
}

func NewChannelOpenerClient(cc grpc.ClientConnInterface) ChannelOpenerClient {
	return &channelOpenerClient{cc}
}

func (c *channelOpenerClient) ChannelInformation(ctx context.Context, in *ChannelInformationRequest, opts ...grpc.CallOption) (*ChannelInformationReply, error) {
	out := new(ChannelInformationReply)
	err := c.cc.Invoke(ctx, "/lspd.ChannelOpener/ChannelInformation", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *channelOpenerClient) OpenChannel(ctx context.Context, in *OpenChannelRequest, opts ...grpc.CallOption) (*OpenChannelReply, error) {
	out := new(OpenChannelReply)
	err := c.cc.Invoke(ctx, "/lspd.ChannelOpener/OpenChannel", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *channelOpenerClient) RegisterPayment(ctx context.Context, in *RegisterPaymentRequest, opts ...grpc.CallOption) (*RegisterPaymentReply, error) {
	out := new(RegisterPaymentReply)
	err := c.cc.Invoke(ctx, "/lspd.ChannelOpener/RegisterPayment", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *channelOpenerClient) CheckChannels(ctx context.Context, in *Encrypted, opts ...grpc.CallOption) (*Encrypted, error) {
	out := new(Encrypted)
	err := c.cc.Invoke(ctx, "/lspd.ChannelOpener/CheckChannels", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ChannelOpenerServer is the server API for ChannelOpener service.
// All implementations must embed UnimplementedChannelOpenerServer
// for forward compatibility
type ChannelOpenerServer interface {
	ChannelInformation(context.Context, *ChannelInformationRequest) (*ChannelInformationReply, error)
	OpenChannel(context.Context, *OpenChannelRequest) (*OpenChannelReply, error)
	RegisterPayment(context.Context, *RegisterPaymentRequest) (*RegisterPaymentReply, error)
	CheckChannels(context.Context, *Encrypted) (*Encrypted, error)
	mustEmbedUnimplementedChannelOpenerServer()
}

// UnimplementedChannelOpenerServer must be embedded to have forward compatible implementations.
type UnimplementedChannelOpenerServer struct {
}

func (UnimplementedChannelOpenerServer) ChannelInformation(context.Context, *ChannelInformationRequest) (*ChannelInformationReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ChannelInformation not implemented")
}
func (UnimplementedChannelOpenerServer) OpenChannel(context.Context, *OpenChannelRequest) (*OpenChannelReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method OpenChannel not implemented")
}
func (UnimplementedChannelOpenerServer) RegisterPayment(context.Context, *RegisterPaymentRequest) (*RegisterPaymentReply, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RegisterPayment not implemented")
}
func (UnimplementedChannelOpenerServer) CheckChannels(context.Context, *Encrypted) (*Encrypted, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CheckChannels not implemented")
}
func (UnimplementedChannelOpenerServer) mustEmbedUnimplementedChannelOpenerServer() {}

// UnsafeChannelOpenerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ChannelOpenerServer will
// result in compilation errors.
type UnsafeChannelOpenerServer interface {
	mustEmbedUnimplementedChannelOpenerServer()
}

func RegisterChannelOpenerServer(s grpc.ServiceRegistrar, srv ChannelOpenerServer) {
	s.RegisterService(&ChannelOpener_ServiceDesc, srv)
}

func _ChannelOpener_ChannelInformation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ChannelInformationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChannelOpenerServer).ChannelInformation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/lspd.ChannelOpener/ChannelInformation",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChannelOpenerServer).ChannelInformation(ctx, req.(*ChannelInformationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChannelOpener_OpenChannel_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(OpenChannelRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChannelOpenerServer).OpenChannel(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/lspd.ChannelOpener/OpenChannel",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChannelOpenerServer).OpenChannel(ctx, req.(*OpenChannelRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChannelOpener_RegisterPayment_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RegisterPaymentRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChannelOpenerServer).RegisterPayment(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/lspd.ChannelOpener/RegisterPayment",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChannelOpenerServer).RegisterPayment(ctx, req.(*RegisterPaymentRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _ChannelOpener_CheckChannels_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(Encrypted)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(ChannelOpenerServer).CheckChannels(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/lspd.ChannelOpener/CheckChannels",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(ChannelOpenerServer).CheckChannels(ctx, req.(*Encrypted))
	}
	return interceptor(ctx, in, info, handler)
}

// ChannelOpener_ServiceDesc is the grpc.ServiceDesc for ChannelOpener service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var ChannelOpener_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "lspd.ChannelOpener",
	HandlerType: (*ChannelOpenerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ChannelInformation",
			Handler:    _ChannelOpener_ChannelInformation_Handler,
		},
		{
			MethodName: "OpenChannel",
			Handler:    _ChannelOpener_OpenChannel_Handler,
		},
		{
			MethodName: "RegisterPayment",
			Handler:    _ChannelOpener_RegisterPayment_Handler,
		},
		{
			MethodName: "CheckChannels",
			Handler:    _ChannelOpener_CheckChannels_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "lspd.proto",
}
