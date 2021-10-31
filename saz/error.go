package saz

import (
	"github.com/myfantasy/mft"
)

// Errors codes and description
var Errors map[int]string = map[int]string{
	10510000: "SimplePermissionChecker.ToBytes: fail to marshal",
	10510010: "SimplePermissionChecker.FromBytes: fail to unmarshal",
}

func init() {
	mft.AddErrorsCodes(Errors)
}
