package common

import (
	"fmt"
	"github.com/container-storage-interface/spec/lib/go/csi"
)

// common types and definitions for all driver types

type DriverMode uint

const (
	DriverModeInvalid = DriverMode(0)
	DriverModeSmb     = DriverMode(1)
	DriverModeIscsi   = DriverMode(2)
)

func (m DriverMode) String() string {
	switch m {
	case DriverModeSmb:
		return "smb"
	case DriverModeIscsi:
		return "iscsi"
	default:
		return "invalid"
	}
}

func ParseDriverMode(mode string) (DriverMode, error) {
	switch mode {
	case "iscsi":
		return DriverModeIscsi, nil
	case "smb":
		return DriverModeSmb, nil
	default:
		return DriverModeInvalid, fmt.Errorf("invalid mode %s", mode)
	}
}

type SmbDriverOptions struct {
	// this only applies to Windows node
	RemoveSMBMappingDuringUnmount bool
	WorkingMountDir               string
}

type IscsiDriverOptions struct {
	Endpoint string
}

// DriverOptions defines driver parameters specified in driver deployment
type DriverOptions struct {
	NodeID               string
	DriverName           string
	Mode                 DriverMode
	EnableGetVolumeStats bool

	SmbOpts   SmbDriverOptions
	IscsiOpts IscsiDriverOptions
}

type BaseDriver interface {
	ValidateControllerServiceRequest(c csi.ControllerServiceCapability_RPC_Type) error
	ValidateNodeServiceRequest(c csi.NodeServiceCapability_RPC_Type) error
	AddControllerServiceCapabilities(cl []csi.ControllerServiceCapability_RPC_Type)
	AddNodeServiceCapabilities(nl []csi.NodeServiceCapability_RPC_Type)
	AddVolumeCapabilityAccessModes(vc []csi.VolumeCapability_AccessMode_Mode) []*csi.VolumeCapability_AccessMode
	GetVolumeCapabilityAccessModes() []*csi.VolumeCapability_AccessMode

	Init()
	GetMode() DriverMode

	GetControllerServer() csi.ControllerServer
	GetIdentityServer() csi.IdentityServer
	GetNodeServer() csi.NodeServer
}
