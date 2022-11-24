//go:build windows
// +build windows

package main

import (
	"flag"
	"fmt"
	"strconv"

	"github.com/sulakshm/csi-driver/pkg/mounter"
	"k8s.io/klog/v2"
)

var (
	driverVersion = ""
	gitCommit     = ""
	buildDate     = ""
)

/// need targetportal addr, port, iqn, volume id

var (
	ver      = flag.Bool("version", false, "show version")
	tpAddr   = flag.String("tp_addr", "127.0.0.1", "iscsi target portal address")
	tpPort   = flag.Uint("tp_port", 3260, "iscsi target portal port")
	nodeAddr = flag.String("iqn", "", "iscsi target node address")
	volumeId = flag.String("id", "", "volume uuid")

	path    = flag.String("path", "", "[un]mount volume path")
	mount   = flag.Bool("mount", false, "perform mount")
	unmount = flag.Bool("unmount", false, "perform unmount")
)

func volHigh(id uint64) uint64 {
	return id >> 48
}

func volLow(id uint64) uint64 {
	return id & 0xffffffffffff
}

func GetVolumeWWN(volumeID string) (string, error) {
	// volumeID - pwx unique volume id ex. 425350735095133013
	const volIDFmt = "504f5258-0000-0002-%04x-%012x"

	id, err := strconv.ParseUint(volumeID, 10, 64)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf(volIDFmt, volHigh(id), volLow(id)), nil
}

func init() {
	klog.InitFlags(nil)
}

func main() {
	flag.Parse()

	if *ver {
		fmt.Println("driverVersion: ", driverVersion)
		fmt.Println("gitCommit: ", gitCommit)
		fmt.Println("buildDate: ", buildDate)
		return
	}

	m, err := mounter.NewSafeMounter(false)
	if err != nil {
		fmt.Printf("new mounter failed %v", err)
		return
	}

	px, ok := m.Interface.(mounter.IscsiMounter)
	if !ok {
		fmt.Printf("cannot assert to iscsi interface")
		return
	}

	// get disk
	fmt.Printf("1. get iscsi disk %v\n", *volumeId)
	wwn, err := GetVolumeWWN(*volumeId)
	if err != nil {
		fmt.Printf("volume %s parse for serial number failed %v", *volumeId, err)
		return
	}
	fmt.Printf("volume %s - parsed serial number %s\n", *volumeId, wwn)

	ok, err = px.IscsiDiskInitialized(wwn)
	if err == mounter.ErrNoSuchDisk {
		fmt.Printf("volume %s has no local disk available\n", *volumeId)
	} else if err != nil {
		fmt.Printf("volume %s finding local disk failed %v\n", *volumeId, err)
	} else {
		fmt.Printf("volume %s local disk state %t\n", *volumeId, ok)
	}

	// get mapped volume
	fmt.Printf("2. get mapped volume %v\n", *volumeId)
	exists, err := px.IscsiVolumeExists(*volumeId)
	if err != nil {
		fmt.Printf("px.IscsiVolumeExists failed %v", err)
		return
	}
	fmt.Printf("volume %s exists %t\n", *volumeId, exists)
	if exists {
		mp, err := px.IscsiGetVolumeMounts(*volumeId, false)
		if err != nil && err != mounter.ErrNoSuchVolume {
			fmt.Printf("px.IscsiGetVolumeMounts volume %s failed %v", *volumeId, err)
			return
		}

		if len(mp) != 0 {
			fmt.Printf("mountpoints...\n")
			for i, p := range mp {
				fmt.Printf("[%d]: %s\n", i, p)
			}
		}
	}

	if *mount {
		// 1. add target portal details
		fmt.Printf("1. add target portal %s:%d\n", *tpAddr, *tpPort)
		err = px.IscsiAddTargetPortal(*tpAddr, uint32(*tpPort))
		if err != nil {
			fmt.Printf("px.IscsiAddTargetPortal failed %v", err)
			return
		}

		// 2. connect to the target
		fmt.Printf("2. iscsi connect iqn %s\n", *nodeAddr)
		err = px.IscsiConnectTargetNoAuth(*tpAddr, uint32(*tpPort), *nodeAddr)
		if err != nil {
			fmt.Printf("px.IscsiConnectTargetNoAuth failed %v", err)
			return
		}

		fmt.Printf("m1. performing mount action - format volume %v\n", *volumeId)
		err = px.IscsiFormatVolume(wwn, *volumeId)
		if err != nil {
			fmt.Printf("px.IscsiFormatVolume failed %v", err)
			return
		}

		fmt.Printf("m2. performing mount action - mount volume %v to path %v\n", *volumeId, *path)
		err = px.IscsiVolumeMount(*volumeId, *path)
		if err != nil {
			fmt.Printf("px.IscsiVolumeMount failed %v", err)
			return
		}

		return
	}

	if *unmount {
		fmt.Printf("u1. performing unmount action - volume %v from path %s\n", *volumeId, *path)
		err := px.IscsiVolumeUnmount(*volumeId, *path)
		if err != nil {
			fmt.Printf("px.IscsiVolumeUnmount failed %v", err)
			return
		}

		fmt.Printf("u2. disconnect target volume %v, iqn %s\n", *volumeId, *nodeAddr)
		err = px.IscsiDisconnectTarget(*nodeAddr)
		if err != nil {
			fmt.Printf("px.IscsiDisconnectTarget failed %v", err)
			return
		}

		return
	}
}
