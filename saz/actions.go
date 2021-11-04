package saz

import (
	"context"

	ajt "github.com/myfantasy/api_json_types"
	az "github.com/myfantasy/authorization"
	"github.com/myfantasy/mft"
)

type AddUserRequest struct {
	Name       string `json:"name"`
	IsAdmin    bool   `json:"is_admin"`
	IsDisabled bool   `json:"is_disabled"`
}

func (spc *SimplePermissionChecker) AddUser(ctx context.Context, user az.User, req *AddUserRequest,
) (err *mft.Error) {
	if spc == nil {
		return mft.GenerateError(20200100)
	}

	if req == nil {
		return mft.GenerateError(20200101)
	}

	allowed, err := spc.CheckPermission(ctx, user, ObjectTypeName, AddUserAction, req.Name)
	if err != nil {
		return mft.GenerateError(20200104)
	}

	if !allowed {
		return mft.GenerateError(20200105)
	}

	if spc.DataLock(ctx) {
		return mft.GenerateError(20200102)
	}
	defer spc.DataUnlock()

	if spc.Users == nil {
		spc.Users = make(map[string]User)
	}

	_, ok := spc.Users[req.Name]

	if ok {
		return mft.GenerateError(20200103, req.Name)
	}

	u := User{
		Name:       req.Name,
		IsAdmin:    req.IsAdmin,
		IsDisabled: req.IsDisabled,
	}
	spc.Users[req.Name] = u

	return nil
}

func (spc *SimplePermissionChecker) UpdateUser(ctx context.Context, user az.User, req *AddUserRequest,
) (err *mft.Error) {
	if spc == nil {
		return mft.GenerateError(20200120)
	}

	if req == nil {
		return mft.GenerateError(20200121)
	}

	allowed, err := spc.CheckPermission(ctx, user, ObjectTypeName, UpdateUserAction, req.Name)
	if err != nil {
		return mft.GenerateError(20200124)
	}

	if !allowed {
		return mft.GenerateError(20200125)
	}

	if spc.DataLock(ctx) {
		return mft.GenerateError(20200122)
	}
	defer spc.DataUnlock()

	if spc.Users == nil {
		spc.Users = make(map[string]User)
	}

	u, ok := spc.Users[req.Name]

	if !ok {
		return mft.GenerateError(20200123, req.Name)
	}

	u.IsAdmin = req.IsAdmin
	u.IsDisabled = req.IsDisabled
	spc.Users[req.Name] = u

	return nil
}

type DropUserRequest struct {
	Name string
}

func (spc *SimplePermissionChecker) DropUser(ctx context.Context, user az.User, req *DropUserRequest,
) (err *mft.Error) {
	if spc == nil {
		return mft.GenerateError(20200110)
	}

	if req == nil {
		return mft.GenerateError(20200111)
	}

	allowed, err := spc.CheckPermission(ctx, user, ObjectTypeName, DropUserAction, req.Name)
	if err != nil {
		return mft.GenerateError(20200114)
	}

	if !allowed {
		return mft.GenerateError(20200115)
	}

	if spc.DataLock(ctx) {
		return mft.GenerateError(20200112)
	}
	defer spc.DataUnlock()

	if spc.Users == nil {
		spc.Users = make(map[string]User)
	}

	delete(spc.Users, req.Name)

	return nil
}

type RenameUserRequest struct {
	OldName string
	NewName string
}

func (spc *SimplePermissionChecker) RenameUser(ctx context.Context, user az.User, req *RenameUserRequest,
) (err *mft.Error) {
	if spc == nil {
		return mft.GenerateError(20200130)
	}

	if req == nil {
		return mft.GenerateError(20200131)
	}

	allowed, err := spc.CheckPermission(ctx, user, ObjectTypeName, DropUserAction, req.OldName)
	if err != nil {
		return mft.GenerateError(20200134)
	}

	if !allowed {
		return mft.GenerateError(20200135)
	}

	allowed, err = spc.CheckPermission(ctx, user, ObjectTypeName, AddUserAction, req.NewName)
	if err != nil {
		return mft.GenerateError(20200136)
	}

	if !allowed {
		return mft.GenerateError(20200137)
	}

	if spc.DataLock(ctx) {
		return mft.GenerateError(20200132)
	}
	defer spc.DataUnlock()

	if spc.Users == nil {
		spc.Users = make(map[string]User)
	}

	u, ok := spc.Users[req.OldName]

	if !ok {
		return mft.GenerateError(20200133, req.OldName)
	}

	_, ok = spc.Users[req.NewName]

	if ok {
		return mft.GenerateError(20200138, req.OldName)
	}

	delete(spc.Users, req.OldName)
	spc.Users[req.NewName] = u

	return nil
}

type SetPermissionRequest struct {
	Name       string
	ObjectType ajt.ObjectType
	Action     ajt.Action
	ObjectName string
	Value      Permission
}

func (spc *SimplePermissionChecker) SetPermission(ctx context.Context, user az.User, req *SetPermissionRequest,
) (err *mft.Error) {
	if spc == nil {
		return mft.GenerateError(20200140)
	}

	if req == nil {
		return mft.GenerateError(20200141)
	}

	allowed, err := spc.CheckPermission(ctx, user, ObjectTypeName, SetPermissionAction, req.Name)
	if err != nil {
		return mft.GenerateError(20200144)
	}

	if !allowed {
		return mft.GenerateError(20200145)
	}

	if spc.DataLock(ctx) {
		return mft.GenerateError(20200142)
	}
	defer spc.DataUnlock()

	if spc.Users == nil {
		spc.Users = make(map[string]User)
	}

	u, ok := spc.Users[req.Name]

	if !ok {
		return mft.GenerateError(20200143, req.Name)
	}

	u.Set(req.ObjectType, req.Action, req.ObjectName, req.Value)
	spc.Users[req.Name] = u

	return nil
}

type DropPermissionRequest struct {
	Name       string
	ObjectType ajt.ObjectType
	Action     ajt.Action
	ObjectName string
}

func (spc *SimplePermissionChecker) DropPermission(ctx context.Context, user az.User, req *DropPermissionRequest,
) (err *mft.Error) {
	if spc == nil {
		return mft.GenerateError(20200150)
	}

	if req == nil {
		return mft.GenerateError(20200151)
	}

	allowed, err := spc.CheckPermission(ctx, user, ObjectTypeName, DropPermissionAction, req.Name)
	if err != nil {
		return mft.GenerateError(20200154)
	}

	if !allowed {
		return mft.GenerateError(20200155)
	}

	if spc.DataLock(ctx) {
		return mft.GenerateError(20200152)
	}
	defer spc.DataUnlock()

	if spc.Users == nil {
		spc.Users = make(map[string]User)
	}

	u, ok := spc.Users[req.Name]

	if !ok {
		return mft.GenerateError(20200153, req.Name)
	}

	u.Drop(req.ObjectType, req.Action, req.ObjectName)
	spc.Users[req.Name] = u

	return nil
}

type GetUserInfoRequest struct {
	Name string
}

type GetUserInfoResponce struct {
	User User
}

func (spc *SimplePermissionChecker) GetUserInfo(ctx context.Context, user az.User, req *GetUserInfoRequest,
) (resp *GetUserInfoResponce, err *mft.Error) {
	if spc == nil {
		return nil, mft.GenerateError(20200160)
	}

	if req == nil {
		return nil, mft.GenerateError(20200161)
	}

	allowed, err := spc.CheckPermission(ctx, user, ObjectTypeName, GetUserInfoAction, req.Name)
	if err != nil {
		return nil, mft.GenerateError(20200164)
	}

	if !allowed {
		return nil, mft.GenerateError(20200165)
	}

	if !spc.DataRLock(ctx) {
		return nil, mft.GenerateError(20200162)
	}
	defer spc.DataRUnlock()

	if spc.Users == nil {
		return nil, mft.GenerateError(20200166, req.Name)
	}

	u, ok := spc.Users[req.Name]

	if !ok {
		return nil, mft.GenerateError(20200163, req.Name)
	}

	return &GetUserInfoResponce{
		User: u,
	}, nil
}

type GetUsersInfoRequest struct {
}

type GetUsersInfoResponce struct {
	Users []User
}

func (spc *SimplePermissionChecker) GetUsersInfo(ctx context.Context, user az.User, req *GetUsersInfoRequest,
) (resp *GetUsersInfoResponce, err *mft.Error) {
	if spc == nil {
		return nil, mft.GenerateError(20200170)
	}

	if req == nil {
		return nil, mft.GenerateError(20200171)
	}

	allowed, err := spc.CheckPermission(ctx, user, ObjectTypeName, GetUsersInfoAction, "")
	if err != nil {
		return nil, mft.GenerateError(20200174)
	}

	if !allowed {
		return nil, mft.GenerateError(20200175)
	}

	if !spc.DataRLock(ctx) {
		return nil, mft.GenerateError(20200172)
	}
	defer spc.DataRUnlock()

	if spc.Users == nil {
		return nil, mft.GenerateError(20200176)
	}

	resp = &GetUsersInfoResponce{
		Users: make([]User, 0),
	}

	for _, v := range spc.Users {
		resp.Users = append(resp.Users, v)
	}

	return resp, nil
}
