package authorization

import (
	"context"

	"github.com/myfantasy/mft"
)

// User - user for authentification
type User interface {
	UserName() string
}

type UserName string

func (un UserName) UserName() string {
	return string(un)
}

type ObjectType string
type Action string

const (
	AllObjectTypes ObjectType = "*"
	AllActions     Action     = "*"
	AllObjectNames ObjectType = "*"
)

type CheckPermission func(ctx context.Context, user User,
	objectType ObjectType, action Action, objectName string,
) (allowed bool, err *mft.Error)

type CheckedObject struct {
	User          User                   `json:"user,omitempty"`
	ObjectType    ObjectType             `json:"object_type,omitempty"`
	Action        Action                 `json:"action,omitempty"`
	ObjectName    string                 `json:"object_name,omitempty"`
	ItemIDsInt    []int64                `json:"item_ids_int,omitempty"`
	ItemIDsString []string               `json:"item_ids_string,omitempty"`
	Meta          map[string]interface{} `json:"meta,omitempty"`
}
type CheckPermissionWide func(ctx context.Context, co *CheckedObject) (allowed bool, err *mft.Error)

type PermissionChecker interface {
	CheckPermission(ctx context.Context, user User,
		objectType ObjectType, action Action, objectName string,
	) (allowed bool, err *mft.Error)
	CheckPermissionWide(ctx context.Context, co *CheckedObject) (allowed bool, err *mft.Error)
}
