package grpcapi

import (
	"context"
	"errors"
	"strings"

	"github.com/endl/sso_go/internal/service"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
)

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func managementError(err error) error {
	switch {
	case errors.Is(err, service.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, "invalid credentials")
	case errors.Is(err, service.ErrForbidden):
		return status.Error(codes.PermissionDenied, "permission denied")
	case errors.Is(err, service.ErrInvalidInput):
		return status.Error(codes.InvalidArgument, "invalid request")
	case errors.Is(err, service.ErrNotFound):
		return status.Error(codes.NotFound, "not found")
	default:
		return err
	}
}

func (s *Server) actor(ctx context.Context, project string, admin bool) (service.Actor, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	actor, err := s.management.Authenticate(ctx, project, first(md.Get("x-client-id")), first(md.Get("x-client-secret")), strings.TrimPrefix(first(md.Get("authorization")), "Bearer "), admin)
	return actor, managementError(err)
}

func (s *Server) getUser(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	actor, err := s.actor(ctx, field(v, "project_id"), false)
	if err != nil {
		return nil, err
	}
	user, err := s.management.GetUser(ctx, actor, field(v, "user_id"))
	if err != nil {
		return nil, managementError(err)
	}
	return response(user)
}

func (s *Server) updateProfile(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	actor, err := s.actor(ctx, field(v, "project_id"), false)
	if err != nil {
		return nil, err
	}
	user, err := s.management.UpdateProfile(ctx, actor, field(v, "user_id"), field(v, "name"), field(v, "avatar_url"))
	if err != nil {
		return nil, managementError(err)
	}
	return response(user)
}

func (s *Server) listRequests(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	actor, err := s.actor(ctx, field(v, "project_id"), true)
	if err != nil {
		return nil, err
	}
	requests, err := s.management.ListRequests(ctx, actor)
	if err != nil {
		return nil, managementError(err)
	}
	items := make([]any, 0, len(requests))
	for _, x := range requests {
		items = append(items, map[string]any{"request_id": x.ID, "user_id": x.UserID, "email": x.Email, "name": x.Name})
	}
	return response(map[string]any{"requests": items})
}

func (s *Server) approve(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	actor, err := s.actor(ctx, field(v, "project_id"), true)
	if err != nil {
		return nil, err
	}
	result, err := s.management.Approve(ctx, actor, field(v, "request_id"), stringsField(v, "roles"))
	if err != nil {
		return nil, managementError(err)
	}
	return response(result)
}

func (s *Server) setRoles(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	actor, err := s.actor(ctx, field(v, "project_id"), true)
	if err != nil {
		return nil, err
	}
	result, err := s.management.SetRoles(ctx, actor, field(v, "user_id"), stringsField(v, "roles"))
	if err != nil {
		return nil, managementError(err)
	}
	return response(result)
}

func (s *Server) revoke(ctx context.Context, v *structpb.Struct) (*structpb.Struct, error) {
	actor, err := s.actor(ctx, field(v, "project_id"), true)
	if err != nil {
		return nil, err
	}
	err = s.management.Revoke(ctx, actor, field(v, "user_id"))
	if err != nil {
		return nil, managementError(err)
	}
	return response(map[string]any{"user_id": field(v, "user_id")})
}
