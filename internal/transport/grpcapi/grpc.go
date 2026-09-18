package grpcapi

import (
	"context"
	"encoding/json"
	"os"

	"github.com/endl/sso_go/internal/service"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/structpb"
)

type rpcFn func(context.Context, *structpb.Struct) (*structpb.Struct, error)

type Server struct{ management service.Management }

func New(management service.Management) *Server { return &Server{management: management} }

func grpcMethod(name string, fn rpcFn) grpc.MethodDesc {
	return grpc.MethodDesc{MethodName: name, Handler: func(_ any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
		req := new(structpb.Struct)
		if err := dec(req); err != nil {
			return nil, err
		}
		if interceptor == nil {
			return fn(ctx, req)
		}
		info := &grpc.UnaryServerInfo{FullMethod: "/sso.Management/" + name}
		return interceptor(ctx, req, info, func(ctx context.Context, v any) (any, error) { return fn(ctx, v.(*structpb.Struct)) })
	}}
}
func (s *Server) GRPCServer() (*grpc.Server, error) {
	opts := []grpc.ServerOption{}
	cert, key := os.Getenv("SSO_GRPC_TLS_CERT"), os.Getenv("SSO_GRPC_TLS_KEY")
	if cert != "" || key != "" {
		creds, err := credentials.NewServerTLSFromFile(cert, key)
		if err != nil {
			return nil, err
		}
		opts = append(opts, grpc.Creds(creds))
	}
	g := grpc.NewServer(opts...)
	g.RegisterService(&grpc.ServiceDesc{ServiceName: "sso.Management", HandlerType: (*management)(nil), Methods: []grpc.MethodDesc{grpcMethod("GetUser", s.getUser), grpcMethod("UpdateProfile", s.updateProfile), grpcMethod("ListRequests", s.listRequests), grpcMethod("ApproveRequest", s.approve), grpcMethod("SetRoles", s.setRoles), grpcMethod("RevokeAccess", s.revoke)}}, s)
	return g, nil
}

type management interface{}

func field(v *structpb.Struct, k string) string { return v.GetFields()[k].GetStringValue() }
func stringsField(v *structpb.Struct, k string) []string {
	out := []string{}
	for _, x := range v.GetFields()[k].GetListValue().GetValues() {
		if x.GetStringValue() != "" {
			out = append(out, x.GetStringValue())
		}
	}
	return out
}
func response(m map[string]any) (*structpb.Struct, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var normalized map[string]any
	if err = json.Unmarshal(b, &normalized); err != nil {
		return nil, err
	}
	return structpb.NewStruct(normalized)
}
