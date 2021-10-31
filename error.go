package authorization

import "github.com/myfantasy/mft"

// Errors codes and description
var Errors map[int]string = map[int]string{
	20200000: "authorization.saz.SimplePermissionChecker.CheckPermission: DataRLock fail",
	20200010: "authorization.saz.SimplePermissionChecker.CheckPermissionWide: DataRLock fail",

	20200100: "authorization.saz.SimplePermissionChecker.AddUser: object is nil",
	20200101: "authorization.saz.SimplePermissionChecker.AddUser: request is nil",
	20200102: "authorization.saz.SimplePermissionChecker.AddUser: DataLock fail",
	20200103: "authorization.saz.SimplePermissionChecker.AddUser: User `%v` already exists",
	20200104: "authorization.saz.SimplePermissionChecker.AddUser: Check permittion fail",
	20200105: "authorization.saz.SimplePermissionChecker.AddUser: Not allowed",

	20200110: "authorization.saz.SimplePermissionChecker.DropUser: object is nil",
	20200111: "authorization.saz.SimplePermissionChecker.DropUser: request is nil",
	20200112: "authorization.saz.SimplePermissionChecker.DropUser: DataLock fail",
	20200114: "authorization.saz.SimplePermissionChecker.DropUser: Check permittion fail",
	20200115: "authorization.saz.SimplePermissionChecker.DropUser: Not allowed",

	20200120: "authorization.saz.SimplePermissionChecker.UpdateUser: object is nil",
	20200121: "authorization.saz.SimplePermissionChecker.UpdateUser: request is nil",
	20200122: "authorization.saz.SimplePermissionChecker.UpdateUser: DataLock fail",
	20200123: "authorization.saz.SimplePermissionChecker.UpdateUser: User `%v` not exists",
	20200124: "authorization.saz.SimplePermissionChecker.UpdateUser: Check permittion fail",
	20200125: "authorization.saz.SimplePermissionChecker.UpdateUser: Not allowed",

	20200130: "authorization.saz.SimplePermissionChecker.RenameUser: object is nil",
	20200131: "authorization.saz.SimplePermissionChecker.RenameUser: request is nil",
	20200132: "authorization.saz.SimplePermissionChecker.RenameUser: DataLock fail",
	20200133: "authorization.saz.SimplePermissionChecker.RenameUser: User `%v` not exists",
	20200134: "authorization.saz.SimplePermissionChecker.RenameUser: Check permittion fail",
	20200135: "authorization.saz.SimplePermissionChecker.RenameUser: Not allowed",
	20200136: "authorization.saz.SimplePermissionChecker.RenameUser: Check permittion fail",
	20200137: "authorization.saz.SimplePermissionChecker.RenameUser: Not allowed",
	20200138: "authorization.saz.SimplePermissionChecker.RenameUser: User `%v` already exists",

	20200140: "authorization.saz.SimplePermissionChecker.SetPermission: object is nil",
	20200141: "authorization.saz.SimplePermissionChecker.SetPermission: request is nil",
	20200142: "authorization.saz.SimplePermissionChecker.SetPermission: DataLock fail",
	20200143: "authorization.saz.SimplePermissionChecker.SetPermission: User `%v` not exists",
	20200144: "authorization.saz.SimplePermissionChecker.SetPermission: Check permittion fail",
	20200145: "authorization.saz.SimplePermissionChecker.SetPermission: Not allowed",

	20200150: "authorization.saz.SimplePermissionChecker.DropPermission: object is nil",
	20200151: "authorization.saz.SimplePermissionChecker.DropPermission: request is nil",
	20200152: "authorization.saz.SimplePermissionChecker.DropPermission: DataLock fail",
	20200153: "authorization.saz.SimplePermissionChecker.DropPermission: User `%v` not exists",
	20200154: "authorization.saz.SimplePermissionChecker.DropPermission: Check permittion fail",
	20200155: "authorization.saz.SimplePermissionChecker.DropPermission: Not allowed",

	20200160: "authorization.saz.SimplePermissionChecker.GetUserInfo: object is nil",
	20200161: "authorization.saz.SimplePermissionChecker.GetUserInfo: request is nil",
	20200162: "authorization.saz.SimplePermissionChecker.GetUserInfo: DataLock fail",
	20200163: "authorization.saz.SimplePermissionChecker.GetUserInfo: User `%v` not exists",
	20200164: "authorization.saz.SimplePermissionChecker.GetUserInfo: Check permittion fail",
	20200165: "authorization.saz.SimplePermissionChecker.GetUserInfo: Not allowed",
	20200166: "authorization.saz.SimplePermissionChecker.GetUserInfo: User `%v` not exists",

	20200170: "authorization.saz.SimplePermissionChecker.GetUsersInfo: object is nil",
	20200171: "authorization.saz.SimplePermissionChecker.GetUsersInfo: request is nil",
	20200172: "authorization.saz.SimplePermissionChecker.GetUsersInfo: DataLock fail",
	20200174: "authorization.saz.SimplePermissionChecker.GetUsersInfo: Check permittion fail",
	20200175: "authorization.saz.SimplePermissionChecker.GetUsersInfo: Not allowed",
	20200176: "authorization.saz.SimplePermissionChecker.GetUsersInfo: Users not exists",

	20200200: "authorization.saz.AddUser: api is nil",
	20200201: "authorization.saz.AddUser: create request fail",
	20200202: "authorization.saz.AddUser: responce error",

	20200300: "authorization.saz.SimplePermissionChecker.DoRequest: No Action `%v`.`%v`",
	20200301: "authorization.saz.SimplePermissionChecker.DoRequest: Fail unmarchal to AddUserRequest",
}

func init() {
	mft.AddErrorsCodes(Errors)
}
