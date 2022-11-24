package main


import (
	"fmt"
	"flag"

	"github.com/sulakshm/csi-driver/pkg/mounter"
)

/// need targetportal addr, port, iqn, volume id

var (
	tpAddr = flag.String("tp_addr", "127.0.0.1", "iscsi target portal address")
	tpPort = flag.Uint("tp_port", 3260, "iscsi target portal port")
	nodeAddr = flag.String("iqn", "", "iscsi target node address")
	volumeId = flag.String("id", "", "volume uuid")

	path = flag.String("path", "", "[un]mount volume path")
	mount = flag.Bool("mount", false, "perform mount")
	unmount = flag.Bool("unmount", false, "perform mount")
)


func main() {
	flag.Parse()

	m, err:= mounter.NewSafeMounter(false)
	if err != nil {
		fmt.Printf("new mounter failed %v", err)
		return
	}

	px := m.(mounter.csiProxyMounter)

	// 1. add target portal details
	fmt.Printf("1. add target portal %s:%d\n", *tpAddr, *tpPort)
	err = px.IscsiAddTargetPortal(*tpAddr, *tpPort)
	if err != nil {
		fmt.Printf("px.IscsiAddTargetPortal failed %v", err)
		return
	}

	// 2. connect to the target
	fmt.Printf("2. iscsi connect iqn %s\n", *nodeAddr)
	err = px.IscsiConnectTargetNoAuth(*tpAddr, *tpPort, *nodeAddr)
	if err != nil {
		fmt.Printf("px.IscsiConnectTargetNoAuth failed %v", err)
		return
	}

	// 3. get mapped volume
	fmt.Printf("3. get mapped volume %v\n", *volumeId)
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

	if mount {
		if !exists {
			fmt.Printf("volume %s does not exist\n", *volumeId)
			return
		}
		fmt.Printf("m1. performing mount action - format volume %v\n", *volumeId)
		wwn, err := px.GetVolumeWWN(*volumeId)
		if err != nil {
			fmt.Printf("volume %s parse for serial number failed %v", *volumeId, err)
			return
		}

		fmt.Printf("volume %s - parsed serial number %s\n", *volumeId, *wwn)
		err := px.IscsiFormatVolume(wwn, *volumeId)
		if err != nil {
			fmt.Printf("px.IscsiFormatVolume failed %v", err)
			return
		}

		fmt.Printf("m2. performing mount action - mount volume %v to path %v\n", *volumeId, *path)
		err := px.IscsiVolumeMount(*volumeId, *path)
		if err != nil {
			fmt.Printf("px.IscsiVolumeMount failed %v", err)
			return
		}

		return
	}


	if unmount {
		fmt.Printf("u1. performing unmount action - volume %v from path %s\n", *volumeId, *path)

		fmt.Printf("u2. disconnect target volume %v, iqn %s\n", *volumeId, *nodeAddr)
		return
	}
}
