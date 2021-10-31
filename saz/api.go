package saz

import (
	"context"

	ajt "github.com/myfantasy/api_json_types"
	"github.com/myfantasy/mft"
)

func (spc *SimplePermissionChecker) AllowedCommands() []ajt.CommandDescription {
	return []ajt.CommandDescription{
		{
			ObjectName:  string(ObjectTypeName),
			Name:        string(AddUserAction),
			Description: "creates new user (saz.AddUserRequest -> AddUserResponce)",
		},
	}
}
func (spc *SimplePermissionChecker) DoRequest(ctx context.Context, req *ajt.CommandRequest) *ajt.CommandResponce {

	if req.CommandName == string(AddUserAction) {
		var aReq *AddUserRequest

		err := req.Unmarshal(&aReq)
		if err != nil {
			return &ajt.CommandResponce{
				Error: mft.GenerateErrorE(20200301, err),
			}
		}

		err = spc.AddUser(ctx, req, aReq)

		return &ajt.CommandResponce{
			Error: err,
		}
	}
	return &ajt.CommandResponce{
		Error: mft.GenerateError(20200300, req.ObjectName, req.CommandName),
	}
}

func AddUser(ctx context.Context, api ajt.Api, req *AddUserRequest,
) (err *mft.Error) {
	if api == nil {
		return mft.GenerateError(20200200)
	}

	reqA, err := ajt.CreateRequest(string(ObjectTypeName), string(AddUserAction), req)
	if err != nil {
		return mft.GenerateError(20200201, err)
	}

	respA := api.DoRequest(ctx, reqA)

	if respA.Error != nil {
		return mft.GenerateError(20200202, respA.Error)
	}

	return nil
}
