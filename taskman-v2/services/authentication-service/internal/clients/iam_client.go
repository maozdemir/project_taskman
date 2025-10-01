package clients

import (
	"context"

	iamPb "github.com/taskman/v2/services/iam-admin-service/pkg/api/api"
	"github.com/taskman/v2/shared/pkg/grpcclient"
	"google.golang.org/grpc"
)

// IAMClient wraps the IAM admin service gRPC client
type IAMClient struct {
	conn   *grpc.ClientConn
	Client iamPb.IAMAdminServiceClient
}

// NewIAMClient creates a new IAM admin service client
func NewIAMClient(addr string) (*IAMClient, error) {
	conn, err := grpcclient.Connect(grpcclient.DefaultConfig(addr))
	if err != nil {
		return nil, err
	}

	return &IAMClient{
		conn:   conn,
		Client: iamPb.NewIAMAdminServiceClient(conn),
	}, nil
}

// GetUserRoles retrieves all roles for a user
func (c *IAMClient) GetUserRoles(ctx context.Context, userID, companyID string) (*iamPb.GetUserRolesResponse, error) {
	resp, err := c.Client.GetUserRoles(ctx, &iamPb.GetUserRolesRequest{
		UserId:    userID,
		CompanyId: companyID,
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetUserPermissions retrieves all permissions for a user
func (c *IAMClient) GetUserPermissions(ctx context.Context, userID, companyID string) (*iamPb.GetUserPermissionsResponse, error) {
	resp, err := c.Client.GetUserPermissions(ctx, &iamPb.GetUserPermissionsRequest{
		UserId:    userID,
		CompanyId: companyID,
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// AssignRole assigns a role to a user
func (c *IAMClient) AssignRole(ctx context.Context, req *iamPb.AssignRoleRequest) error {
	_, err := c.Client.AssignRole(ctx, req)
	return err
}

// Close closes the connection
func (c *IAMClient) Close() error {
	return c.conn.Close()
}
