package saz

import (
	"context"
	"encoding/json"

	ajt "github.com/myfantasy/api_json_types"
	az "github.com/myfantasy/authorization"
	"github.com/myfantasy/mft"
	"github.com/myfantasy/storage"
)

type Permission struct {
	Allow           bool                `json:"allow"`
	AllowIntKeys    map[int64]struct{}  `json:"aik,omitempty"`
	AllowStringKeys map[string]struct{} `json:"ask,omitempty"`

	Deny           bool                `json:"deny"`
	DenyIntKeys    map[int64]struct{}  `json:"dik,omitempty"`
	DenyStringKeys map[string]struct{} `json:"dsk,omitempty"`
}

func (p *Permission) AllowRaw(co *az.CheckedObject) bool {
	if p.Allow {
		return p.Allow
	}

	if len(co.ItemIDsInt) == 0 && len(co.ItemIDsString) == 0 {
		return false
	}

	for i := 0; i < len(co.ItemIDsInt); i++ {
		if _, ok := p.AllowIntKeys[co.ItemIDsInt[i]]; !ok {
			return false
		}
	}
	for i := 0; i < len(co.ItemIDsString); i++ {
		if _, ok := p.AllowStringKeys[co.ItemIDsString[i]]; !ok {
			return false
		}
	}

	return true
}

func (p *Permission) DenyRaw(co *az.CheckedObject) bool {
	if p.Deny {
		return p.Deny
	}

	if len(co.ItemIDsInt) == 0 && len(co.ItemIDsString) == 0 {
		return false
	}

	for i := 0; i < len(co.ItemIDsInt); i++ {
		if _, ok := p.DenyIntKeys[co.ItemIDsInt[i]]; ok {
			return true
		}
	}
	for i := 0; i < len(co.ItemIDsString); i++ {
		if _, ok := p.DenyStringKeys[co.ItemIDsString[i]]; ok {
			return true
		}
	}

	return false
}

type User struct {
	Name       string                                                  `json:"name"`
	IsAdmin    bool                                                    `json:"is_admin,omitempty"`
	IsDisabled bool                                                    `json:"is_disabled"`
	Rules      map[ajt.ObjectType]map[ajt.Action]map[string]Permission `json:"rule"`
}

func (u *User) Allow(objectType ajt.ObjectType, action ajt.Action, objectName string) bool {
	if u.IsDisabled {
		return false
	}

	if u.IsAdmin {
		return true
	}

	d0 := u.AllowRow(objectType, action, objectName)
	d1 := u.AllowRow(objectType, action, "*")
	d2 := u.AllowRow(objectType, "*", objectName)
	d3 := u.AllowRow(objectType, "*", "*")
	d4 := u.AllowRow("*", action, objectName)
	d5 := u.AllowRow("*", action, "*")
	d6 := u.AllowRow("*", "*", objectName)
	d7 := u.AllowRow("*", "*", "*")

	return (d0.Allow ||
		d1.Allow ||
		d2.Allow ||
		d3.Allow ||
		d4.Allow ||
		d5.Allow ||
		d6.Allow ||
		d7.Allow) && !(d0.Deny ||
		d1.Deny ||
		d2.Deny ||
		d3.Deny ||
		d4.Deny ||
		d5.Deny ||
		d6.Deny ||
		d7.Deny)
}

func (u *User) AllowWide(co *az.CheckedObject) bool {
	if u.IsDisabled {
		return false
	}

	if u.IsAdmin {
		return true
	}

	d0 := u.AllowRow(co.ObjectType, co.Action, co.ObjectName)
	d1 := u.AllowRow(co.ObjectType, co.Action, "*")
	d2 := u.AllowRow(co.ObjectType, "*", co.ObjectName)
	d3 := u.AllowRow(co.ObjectType, "*", "*")
	d4 := u.AllowRow("*", co.Action, co.ObjectName)
	d5 := u.AllowRow("*", co.Action, "*")
	d6 := u.AllowRow("*", "*", co.ObjectName)
	d7 := u.AllowRow("*", "*", "*")

	return (d0.AllowRaw(co) ||
		d1.AllowRaw(co) ||
		d2.AllowRaw(co) ||
		d3.AllowRaw(co) ||
		d4.AllowRaw(co) ||
		d5.AllowRaw(co) ||
		d6.AllowRaw(co) ||
		d7.AllowRaw(co)) && !(d0.DenyRaw(co) ||
		d1.DenyRaw(co) ||
		d2.DenyRaw(co) ||
		d3.DenyRaw(co) ||
		d4.DenyRaw(co) ||
		d5.DenyRaw(co) ||
		d6.DenyRaw(co) ||
		d7.DenyRaw(co))
}

func (u *User) AllowRow(objectType ajt.ObjectType, action ajt.Action, objectName string) Permission {
	if u.IsDisabled {
		return Permission{Allow: false}
	}

	if u.IsAdmin {
		return Permission{Allow: true}
	}

	if u.Rules == nil {
		return Permission{}
	}

	a, ok := u.Rules[objectType]
	if !ok {
		return Permission{}
	}

	o, ok := a[action]
	if !ok {
		return Permission{}
	}

	v, ok := o[objectName]
	if !ok {
		return Permission{}
	}

	return v
}

func (u *User) Set(objectType ajt.ObjectType, action ajt.Action, objectName string, value Permission) {

	if u.Rules == nil {
		u.Rules = make(map[ajt.ObjectType]map[ajt.Action]map[string]Permission)
	}

	a, ok := u.Rules[objectType]
	if !ok {
		a = make(map[ajt.Action]map[string]Permission)
		u.Rules[objectType] = a
	}

	o, ok := a[action]
	if !ok {
		o = make(map[string]Permission)
		a[action] = o
	}

	o[objectName] = value
}

func (u *User) Drop(objectType ajt.ObjectType, action ajt.Action, objectName string) {
	if u.Rules == nil {
		return
	}

	a, ok := u.Rules[objectType]
	if !ok {
		return
	}

	o, ok := a[action]
	if !ok {
		return
	}

	delete(o, objectName)
	if len(o) == 0 {
		delete(a, action)
	}

	if len(a) == 0 {
		delete(u.Rules, objectType)
	}
}

var _ az.PermissionChecker = &SimplePermissionChecker{}
var _ storage.Storable = &SimplePermissionChecker{}
var _ ajt.Api = &SimplePermissionChecker{}

type SimplePermissionChecker struct {
	storage.SaveObjectProto

	Users map[string]User `json:"users,omitempty"`
}

func (spc *SimplePermissionChecker) ToBytes() (data []byte, err *mft.Error) {
	b, er0 := json.Marshal(spc)
	if er0 != nil {
		return nil, mft.GenerateErrorE(10510000, er0)
	}
	return b, nil
}
func (spc *SimplePermissionChecker) FromBytes(data []byte) (err *mft.Error) {
	er0 := json.Unmarshal(data, &spc)
	if er0 != nil {
		return mft.GenerateErrorE(10510000, er0)
	}
	return nil
}

func (spc *SimplePermissionChecker) CheckPermission(ctx context.Context, user az.User,
	objectType ajt.ObjectType, action ajt.Action, objectName string,
) (allowed bool, err *mft.Error) {
	if spc == nil {
		return true, nil
	}
	if spc.DataRLock(ctx) {
		return false, mft.GenerateError(20200000)
	}
	defer spc.DataRUnlock()
	if len(spc.Users) == 0 {
		return true, nil
	}

	u, ok := spc.Users[user.UserName()]
	if !ok {
		return false, nil
	}

	allowed = u.Allow(objectType, action, objectName)

	return allowed, nil
}
func (spc *SimplePermissionChecker) CheckPermissionWide(ctx context.Context, co *az.CheckedObject) (allowed bool, err *mft.Error) {
	if spc == nil {
		return true, nil
	}
	if spc.DataRLock(ctx) {
		return false, mft.GenerateError(20200010)
	}
	defer spc.DataRUnlock()
	if len(spc.Users) == 0 {
		return true, nil
	}

	u, ok := spc.Users[co.User.UserName()]
	if !ok {
		return false, nil
	}

	allowed = u.AllowWide(co)

	return allowed, nil
}
