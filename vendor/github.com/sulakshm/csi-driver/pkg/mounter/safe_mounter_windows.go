//go:build windows
// +build windows

/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package mounter

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	filepath "path/filepath"
	"strconv"
	"strings"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"

	iscsi "github.com/kubernetes-csi/csi-proxy/client/api/iscsi/v1alpha2"

	fs "github.com/kubernetes-csi/csi-proxy/client/api/filesystem/v1"
	fsclient "github.com/kubernetes-csi/csi-proxy/client/groups/filesystem/v1"

	smb "github.com/kubernetes-csi/csi-proxy/client/api/smb/v1"
	smbclient "github.com/kubernetes-csi/csi-proxy/client/groups/smb/v1"

	"github.com/sulakshm/csi-driver/pkg/common"
	"k8s.io/klog/v2"
	mount "k8s.io/mount-utils"
	utilexec "k8s.io/utils/exec"
)

// CSIProxyMounter extends the mount.Interface interface with CSI Proxy methods.
type CSIProxyMounter interface {
	mount.Interface

	IscsiMounter

	SMBMount(source, target, fsType string, mountOptions, sensitiveMountOptions []string) error
	SMBUnmount(target string) error
	MakeDir(path string) error
	Rmdir(path string) error
	IsMountPointMatch(mp mount.MountPoint, dir string) bool
	ExistsPath(path string) (bool, error)
	GetAPIVersions() string
	EvalHostSymlinks(pathname string) (string, error)
}

var _ CSIProxyMounter = &csiProxyMounter{}

type csiProxyMounter struct {
	Mode                          common.DriverMode
	FsClient                      *fsclient.Client
	SMBClient                     *smbclient.Client
	RemoveSMBMappingDuringUnmount bool
}

func normalizeWindowsPath(path string) string {
	normalizedPath := strings.Replace(path, "/", "\\", -1)
	if strings.HasPrefix(normalizedPath, "\\") {
		normalizedPath = "c:" + normalizedPath
	}
	if !strings.HasSuffix(normalizedPath, "\\") {
		normalizedPath += "\\"
	}
	return normalizedPath
}

// / Iscsi specifics
func (mounter *csiProxyMounter) IscsiAddTargetPortal(addr string, port uint32) error {
	klog.V(2).Infof("IscsiAddTargetPortal: target addr: %v, target port: %d", addr, port)
	// Runs: New-IscsiTargetPortal -TargetPortalAddress 10.13.111.125 -TargetPortalPortNumber 3260
	cmdLine := fmt.Sprintf(
		`New-IscsiTargetPortal -TargetPortalAddress ${Env:iscsi_tp_address} ` +
			`-TargetPortalPortNumber ${Env:iscsi_tp_port}`)
	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("iscsi_tp_address=%s", addr),
		fmt.Sprintf("iscsi_tp_port=%d", port))
	if err != nil {
		return fmt.Errorf("error adding target portal. cmd %s, output: %s, err: %v", cmdLine, string(out), err)
	}

	return nil
}

func (mounter *csiProxyMounter) refreshTargets() error {
	cmdLine := "Update-IscsiTarget"
	_, out, err := RunPowershellCmd(cmdLine)
	if err != nil {
		return fmt.Errorf("error running target refresh. cmd %s, output: %s, err: %w", cmdLine, string(out), err)
	}

	return nil
}

func (mounter *csiProxyMounter) IscsiHasActiveSession(addr string, port uint32) (bool, error) {
	// Runs:  Get-IscsiTargetPortal -TargetPortalAddress 10.13.111.120 -TargetPortalPortNumber 3260 | Get-IscsiSession
	cmdLine := fmt.Sprintf(
		`Get-IscsiTargetPortal -TargetPortalAddress ${Env:iscsi_tp_address} ` +
			`-TargetPortalPortNumber ${Env:iscsi_tp_port} | Get-IscsiSession`)

	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("iscsi_tp_address=%s", addr),
		fmt.Sprintf("iscsi_tp_port=%d", port))
	if err != nil {
		return false, fmt.Errorf("error checking for active session. cmd %s, output: %s, err: %w", cmdLine, string(out), err)
	}

	// refresh target portal
	mounter.refreshTargets()
	return true, nil
}

func (mounter *csiProxyMounter) IscsiConnectTargetNoAuth(addr string, port uint32, iqn string) error {
	klog.V(2).Infof("IscsiConnectTarget: target addr: %v, target port: %d, iqn: %s, auth: none", addr, port, iqn)

	sessionOk, _ := mounter.IscsiHasActiveSession(addr, port)
	if sessionOk {
		klog.V(2).Infof("Using existing iscsi session for %s:%d\n", addr, port)
		return nil
	}

	authType := "NONE" // AuthenticationType.None
	chapUser := ""
	chapSecret := ""

	cmdLine := fmt.Sprintf(
		`Connect-IscsiTarget -TargetPortalAddress ${Env:iscsi_tp_address}` +
			` -TargetPortalPortNumber ${Env:iscsi_tp_port} -NodeAddress ${Env:iscsi_target_iqn}` +
			` -AuthenticationType ${Env:iscsi_auth_type}`)

	// not setting chapUser/chapSecrets
	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("iscsi_tp_address=%s", addr),
		fmt.Sprintf("iscsi_tp_port=%d", port),
		fmt.Sprintf("iscsi_target_iqn=%s", iqn),
		fmt.Sprintf("iscsi_auth_type=%s", authType),
		fmt.Sprintf("iscsi_chap_user=%s", chapUser),
		fmt.Sprintf("iscsi_chap_secret=%s", chapSecret))
	if err != nil {
		return fmt.Errorf("error connecting to target portal. cmd %s, output: %s, err: %w", cmdLine, string(out), err)
	}

	return nil
}

func (mounter *csiProxyMounter) IscsiDisconnectTarget(iqn string) error {
	// Runs: Disconnect-IscsiTarget -NodeAddress $Target.NodeAddress
	cmdLine := fmt.Sprintf(`Disconnect-IscsiTarget -NodeAddress ${Env:iscsi_target_iqn} -Confirm:$false`)
	var lastError error

	// need retry to get session cleared
	f := func() (bool, error) {
		klog.V(2).Infof("IscsiDisconnectTarget: target iqn: %s", iqn)
		_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("iscsi_target_iqn=%s", iqn))
		if err != nil {
			lastError = fmt.Errorf("error disconnecting target. cmd %s, output: %s, err: %w", cmdLine, string(out), err)
			return false, nil
		}
		lastError = nil
		return true, nil
	}

	err := wait.ExponentialBackoff(
		wait.Backoff{
			Duration: 200 * time.Millisecond,
			Factor:   1.2,
			Steps:    10,
			Cap:      1 * time.Second,
		}, f,
	)

	if err != nil {
		return err
	}

	return lastError
}

func (mounter *csiProxyMounter) IscsiDiscoverTargetPortal(addr string, port uint32) ([]string, error) {
	klog.V(2).Infof("IscsiDiscoverTargetPortal: target addr: %v, target port: %d", addr, port)
	// ConvertTo-Json is not part of the pipeline because powershell converts an
	// array with one element to a single element
	cmdLine := fmt.Sprintf(
		`ConvertTo-Json -InputObject @(Get-IscsiTargetPortal -TargetPortalAddress ` +
			`${Env:iscsi_tp_address} -TargetPortalPortNumber ${Env:iscsi_tp_port} | ` +
			`Get-IscsiTarget | Select-Object -ExpandProperty NodeAddress)`)
	out, stderr, err := RunPowershellCmd(cmdLine, fmt.Sprintf("iscsi_tp_address=%s", addr),
		fmt.Sprintf("iscsi_tp_port=%d", port))
	if err != nil {
		return nil, fmt.Errorf("error discovering target portal. cmd: %s, output: %s, err: %w", cmdLine, string(stderr), err)
	}

	var iqns []string
	err = json.Unmarshal(out, &iqns)
	if err != nil {
		return nil, fmt.Errorf("failed parsing iqn list. cmd: %s output: %s, err: %w", cmdLine, string(out), err)
	}

	return iqns, nil
}

func (mounter *csiProxyMounter) IscsiListTargetPortals() ([]iscsi.TargetPortal, error) {
	klog.V(2).Infof("IscsiListTargetPortals requested")
	cmdLine := fmt.Sprintf(
		`ConvertTo-Json -InputObject @(Get-IscsiTargetPortal | ` +
			`Select-Object TargetPortalAddress, TargetPortalPortNumber)`)

	out, stderr, err := RunPowershellCmd(cmdLine)
	if err != nil {
		return nil, fmt.Errorf("error listing target portals. cmd %s, output: %s, err: %w", cmdLine, string(stderr), err)
	}

	var portals []iscsi.TargetPortal
	err = json.Unmarshal(out, &portals)
	if err != nil {
		return nil, fmt.Errorf("failed parsing target portal list. cmd: %s output: %s, err: %w", cmdLine, string(out), err)
	}

	return portals, nil
}

func (mounter *csiProxyMounter) IscsiRemoveTargetPortal(addr string, port uint32) error {
	klog.V(2).Infof("IscsiRemoveTargetPortal: target addr: %v, target port: %d", addr, port)
	// Runs: Remove-IscsiTargetPortal -TargetPortalAddress 10.13.111.125 -TargetPortalPortNumber 3260 -Confirm:$false
	cmdLine := fmt.Sprintf(`Remove-IscsiTargetPortal -TargetPortalAddress ${Env:iscsi_tp_address} ` +
		`-TargetPortalPortNumber ${Env:iscsi_tp_port} -Confirm:$false`)

	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("iscsi_tp_address=%s", addr), fmt.Sprintf("iscsi_tp_port=%d", port))
	if err != nil {
		return fmt.Errorf("error connecting to target portal. cmd %s, output: %s, err: %w", cmdLine, string(out), err)
	}

	return nil
}

// /IscsiVolumeExists implies volume formatted and ready to use.
func (mounter *csiProxyMounter) IscsiVolumeExists(fsLabel string) (bool, error) {
	type VolumeInfo struct {
		OperationalStatus string
		HealthStatus      string
		FileSystemType    string
	}

	var volumes []VolumeInfo
	// Runs: Get-Volume -FilesystemLabel 398649739277880943
	cmdLine := fmt.Sprintf(`ConvertTo-Json -InputObject @(Get-Volume -FilesystemLabel ${Env:fs_label} | ` +
		`Select-Object OperationalStatus,HealthStatus,FilesystemType)`)

	out, stderr, err := RunPowershellCmd(cmdLine, fmt.Sprintf("fs_label=%s", fsLabel))
	if err != nil {
		return false, fmt.Errorf("error listing volumes. cmd %s, output: %s, err: %w", cmdLine, string(stderr), err)
	}

	klog.V(2).Infof("IscsiVolumeExists found volume with fs label %v - with properties %v", fsLabel, string(out))
	err = json.Unmarshal(out, &volumes)
	if err != nil {
		return false, err
	}

	if len(volumes) == 0 {
		klog.Warningf("IscsiVolumeExists did not find any volume for label %v", fsLabel)
		return false, nil
	}

	if len(volumes) != 1 {
		klog.Warningf("IscsiVolumeExists found multiple volumes(%v) - unexpected", volumes)
	}
	vol := volumes[0]
	if vol.OperationalStatus != "OK" || vol.HealthStatus != "Healthy" || vol.FileSystemType != "NTFS" {
		klog.Warningf("IscsiVolumeExists found volume state inconsistent - %+v", vol)
		return false, ErrVolumeInconsistent
	}

	return true, nil
}

func (mounter *csiProxyMounter) IscsiDiskInitialized(serialnum string) (bool, error) {
	// Runs:  Get-Disk -SerialNumber serialnum | select-object PartitionStyle
	// expected: GPT or RAW.
	cmdLine := fmt.Sprintf(`ConvertTo-Json -InputObject @(` +
		`Get-Disk -SerialNumber ${Env:disk_serial_number} | Select-Object PartitionStyle)`)

	out, stderr, err := RunPowershellCmd(cmdLine, fmt.Sprintf("disk_serial_number=%s", serialnum))
	if err != nil {
		klog.V(2).Infof("error checking disk status. cmd %s, output: %s, err: %w", cmdLine, string(stderr), err)
		return false, fmt.Errorf("error checking disk status. cmd %s, output: %s, err: %w", cmdLine, string(stderr), err)
	}

	type diskInfo struct {
		PartitionStyle string
	}

	var di []diskInfo
	if err := json.Unmarshal(out, &di); err != nil {
		klog.V(2).Infof("error parsing %v, error %v", string(out), err)
		return false, err
	}

	if len(di) == 0 {
		klog.V(2).Infof("disk with serialnum %v - not found", serialnum)
		return false, ErrNoSuchDisk
	}

	if len(di) != 1 {
		klog.Warningf("IscsiDiskInitialized found multiple disks(%v) - unexpected", di)
	}

	ps := di[0].PartitionStyle

	klog.V(2).Infof("partitionStyle found disk with serialnumber %v - with partitionstyle %v", serialnum, ps)
	raw := strings.Contains(ps, "RAW")
	return !raw, nil
}

func (mounter *csiProxyMounter) IscsiDiskInit(serialnum string) error {
	// Runs: Initialize-Disk -PartitionStyle GPT
	cmdLine := fmt.Sprintf(`Get-Disk -SerialNumber ${Env:disk_serial_number} | Initialize-Disk -PartitionStyle GPT`)

	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("disk_serial_number=%s", serialnum))
	if err != nil {
		return fmt.Errorf("error initializing disk: cmd %s, output: %s, err: %w", cmdLine, string(out), err)
	}

	return nil
}

func (mounter *csiProxyMounter) IscsiFormatVolume(serialnum, fslabel string) error {
	// Runs:  Initialize-Disk and creates a new data partition for use

	// retry loop until disk appears
	f := func() (bool, error) {
		klog.V(2).Infof("finding disk with serialnum %v\n", serialnum)
		ok, err := mounter.IscsiDiskInitialized(serialnum)
		if err == ErrNoSuchDisk {
			return false, nil
		}
		if err != nil {
			return false, err
		}

		if !ok {
			// Perform raw disk initialization
			if err := mounter.IscsiDiskInit(serialnum); err != nil {
				return false, err
			}
		}

		return true, nil
	}

	err := wait.ExponentialBackoff(
		wait.Backoff{
			Duration: 200 * time.Millisecond,
			Factor:   1.2,
			Steps:    10,
			Cap:      1 * time.Second,
		}, f,
	)

	if err != nil {
		return err
	}

	exists, err := mounter.IscsiVolumeExists(fslabel)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	// very longish operation
	cmdLine := fmt.Sprintf(`Get-Disk -SerialNumber ${Env:disk_serial_number} | ` +
		`New-Partition -UseMaximumSize | ` +
		`Format-Volume -FileSystem ntfs -AllocationUnitSize 4096 -NewFileSystemLabel ${Env:fs_label}`)

	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("disk_serial_number=%s", serialnum), fmt.Sprintf("fs_label=%s", fslabel))
	if err != nil {
		return fmt.Errorf("disk format fail, cmd:%s, output:%s, err: %w", cmdLine, string(out), err)
	}

	exists, err = mounter.IscsiVolumeExists(fslabel)
	if err != nil {
		return err
	}

	if !exists {
		return fmt.Errorf("disk format failure - unknown")
	}

	return nil
}

func (mounter *csiProxyMounter) IscsiVolumeReadOnly(fslabel string) (bool, error) {
	exists, err := mounter.IscsiVolumeExists(fslabel)
	if err != nil {
		return false, err
	}
	if !exists {
		return false, ErrNoSuchVolume
	}

	cmdLine := fmt.Sprintf(`(Get-Volume -FilesystemLabel ${Env:fs_label} | Get-Partition).IsReadOnly`)
	out, stderr, err := RunPowershellCmd(cmdLine, fmt.Sprintf("fs_label=%s", fslabel))
	if err != nil {
		return false, fmt.Errorf("IscsiVolumeReadOnly fail, cmd:%s, output:%s, err: %w", cmdLine, string(stderr), err)
	}

	return strconv.ParseBool(string(out))
}

func (mounter *csiProxyMounter) IscsiVolumeSetReadOnly(fslabel string, readonly bool) error {
	exists, err := mounter.IscsiVolumeExists(fslabel)
	if err != nil {
		return err
	}
	if !exists {
		return ErrNoSuchVolume
	}

	cmdLine := fmt.Sprintf(`Get-Volume -FilesystemLabel ${Env:fs_label} | Get-Partition | Set-Partition -IsReadOnly ${Env:readonly}`)
	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("fs_label=%s", fslabel), fmt.Sprintf("readonly=%t", readonly))
	if err != nil {
		return fmt.Errorf("IscsiVolumeSetReadOnly fail, cmd:%s, output:%s, err: %w", cmdLine, string(out), err)
	}

	return err
}

func (mounter *csiProxyMounter) IscsiSetMutualChapSecret(req *iscsi.SetMutualChapSecretRequest) (*iscsi.SetMutualChapSecretResponse, error) {
	klog.V(2).Infof("IscsiSetMutualChapSecret: chap secret %v", req.MutualChapSecret)
	// return mounter.ISCSIClient.SetMutualChapSecret(context.Background(), req)
	return nil, fmt.Errorf("not implemented")
}

func (mounter *csiProxyMounter) IscsiVolumeMount(fslabel string, path string) error {
	normalizedPath := normalizeWindowsPath(path)

	// check if path already mounted.
	if mounts, e := mounter.IscsiGetVolumeMounts(fslabel, false); e == nil {
		for _, p := range mounts {
			if strings.ToLower(p) == strings.ToLower(normalizedPath) {
				return nil
			}
		}
	}

	// NOTE: path has to be exist as a directory
	if err := os.MkdirAll(normalizedPath, 0755); err != nil && !os.IsExist(err) {
		return err
	}

	// Runs: Get-Volume -FilesystemLabel 398649739277880943 |Get-Partition |Add-PartitionAccessPath -AccessPath c:\temp\test
	cmdLine := fmt.Sprintf(`Get-Volume -FileSystemLabel ${Env:fs_label} | ` +
		`Get-Partition | ` +
		`Add-PartitionAccessPath -AccessPath ${Env:access_path}`)
	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("fs_label=%s", fslabel), fmt.Sprintf("access_path=%s", normalizedPath))
	if err != nil {
		return fmt.Errorf("volume mount fail cmd:%s, output:%s, err: %w", cmdLine, string(out), err)
	}
	return nil
}

func (mounter *csiProxyMounter) IscsiVolumeUnmount(fslabel string, path string) error {
	normalizedPath := normalizeWindowsPath(path)

	/// pre-check if volume exists
	exists, err := mounter.IscsiVolumeExists(fslabel)
	if err != nil {
		return err
	}
	if !exists {
		return nil
	}

	// Runs: Get-Volume -FilesystemLabel 398649739277880943 |Get-Partition |Remove-PartitionAccessPath -AccessPath c:\temp\test
	cmdLine := fmt.Sprintf(`Get-Volume -FileSystemLabel ${Env:fs_label} -ErrorAction Stop | ` +
		`Get-Partition | ` +
		`Remove-PartitionAccessPath -AccessPath ${Env:access_path}`)
	_, out, err := RunPowershellCmd(cmdLine, fmt.Sprintf("fs_label=%s", fslabel), fmt.Sprintf("access_path=%s", normalizedPath))
	if err != nil {
		// check if path already removed.
		if mounts, e := mounter.IscsiGetVolumeMounts(fslabel, false); e == nil {
			for _, p := range mounts {
				if p == normalizedPath {
					// hard failure - unmount really failed.
					return fmt.Errorf("volume unmount fail cmd:%s, output:%s, err: %w", cmdLine, string(out), err)
				}
			}
			return nil
		}

		return fmt.Errorf("volume unmount fail cmd:%s, output:%s, err: %w", cmdLine, string(out), err)
	}
	return nil
}

func (mounter *csiProxyMounter) IscsiGetVolumeMounts(fslabel string, filter bool) ([]string, error) {
	// Runs: ConvertTo-Json -InputObject @(Get-Volume -FilesystemLabel 398649739277880943 |Get-Partition | Select-Object AccessPaths)
	cmdLine := fmt.Sprintf(`ConvertTo-Json -InputObject @(Get-Volume -FileSystemLabel ${Env:fs_label} -ErrorAction Stop| ` +
		`Get-Partition | Select-Object AccessPaths)`)
	out, stderr, err := RunPowershellCmd(cmdLine, fmt.Sprintf("fs_label=%s", fslabel))
	if err != nil {
		return nil, fmt.Errorf("volume get mounts fail cmd:%s, output:%s, err: %w", cmdLine, string(stderr), err)
	}

	type Mounts struct {
		AccessPaths []string
	}
	var mounts []Mounts

	err = json.Unmarshal(out, &mounts)
	if err != nil {
		klog.V(2).Infof("unmarshal failed - output %v", string(out))
		return nil, ErrNoSuchVolume
	}

	if len(mounts) == 0 {
		return nil, nil
	}

	if len(mounts) != 1 {
		klog.V(2).Infof("IscsiGetVolumeMounts found multiple volumes(%v) - unexpected", mounts)
	}
	mount := mounts[0]

	// will hold default volume access path like:  "\\\\?\\Volume{8210f2d0-ed6d-47ca-8ba2-8040fa14af11}\\"
	if filter {
		var res []string
		for _, p := range mount.AccessPaths {
			if strings.HasPrefix(p, "\\\\?\\Volume{") {
				continue
			}
			res = append(res, p)
		}
		return res, nil
	}
	return mount.AccessPaths, nil
}

func (mounter *csiProxyMounter) IscsiGetTargetNodeAddress(fslabel string) (string, error) {
	// Runs: (Get-Volume -FilesystemLabel 398649739277880943 | Get-Partition | Get-Disk |Get-IscsiSession).TargetNodeAddress
	cmdLine := fmt.Sprintf(`ConvertTo-Json -InputObject @(Get-Volume -FileSystemLabel ${Env:fs_label} | ` +
		`Get-Partition | Get-Disk  | Get-IscsiSession | Select-Object -ExpandProperty TargetNodeAddress)`)
	out, stderr, err := RunPowershellCmd(cmdLine, fmt.Sprintf("fs_label=%s", fslabel))
	if err != nil {
		return "", fmt.Errorf("volume get mounts fail cmd:%s, output:%s, err: %w", cmdLine, string(stderr), err)
	}

	var iqns []string
	err = json.Unmarshal(out, &iqns)
	if err != nil {
		return "", err
	}

	if len(iqns) == 0 {
		return "", ErrNoSuchVolume
	}

	if len(iqns) != 1 {
		klog.Warningf("probed for volume %s and found many iqns %v", fslabel, iqns)
	}
	return iqns[0], nil
}

// Iscsi end

func (mounter *csiProxyMounter) SMBMount(source, target, fsType string, mountOptions, sensitiveMountOptions []string) error {
	klog.V(2).Infof("SMBMount: remote path: %s local path: %s", source, target)

	if len(mountOptions) == 0 || len(sensitiveMountOptions) == 0 {
		return fmt.Errorf("empty mountOptions(len: %d) or sensitiveMountOptions(len: %d) is not allowed", len(mountOptions), len(sensitiveMountOptions))
	}

	parentDir := filepath.Dir(target)
	parentExists, err := mounter.ExistsPath(parentDir)
	if err != nil {
		return fmt.Errorf("parent dir: %s exist check failed with err: %v", parentDir, err)
	}

	if !parentExists {
		klog.V(2).Infof("Parent directory %s does not exists. Creating the directory", parentDir)
		if err := mounter.MakeDir(parentDir); err != nil {
			return fmt.Errorf("create of parent dir: %s dailed with error: %v", parentDir, err)
		}
	}

	parts := strings.FieldsFunc(source, Split)
	if len(parts) > 0 && strings.HasSuffix(parts[0], "svc.cluster.local") {
		domainName := parts[0]
		klog.V(2).Infof("begin to replace hostname(%s) with IP for source(%s)", domainName, source)
		ip, err := net.ResolveIPAddr("ip4", domainName)
		if err != nil {
			klog.Warningf("could not resolve name to IPv4 address for host %s, failed with error: %v", domainName, err)
		} else {
			klog.V(2).Infof("resolve the name of host %s to IPv4 address: %s", domainName, ip.String())
			source = strings.Replace(source, domainName, ip.String(), 1)
		}
	}

	source = strings.Replace(source, "/", "\\", -1)
	source = strings.TrimSuffix(source, "\\")
	mappingPath, err := getRootMappingPath(source)
	if mounter.RemoveSMBMappingDuringUnmount && err != nil {
		return fmt.Errorf("getRootMappingPath(%s) failed with error: %v", source, err)
	}
	unlock := lock(mappingPath)
	defer unlock()

	normalizedTarget := normalizeWindowsPath(target)
	smbMountRequest := &smb.NewSmbGlobalMappingRequest{
		LocalPath:  normalizedTarget,
		RemotePath: source,
		Username:   mountOptions[0],
		Password:   sensitiveMountOptions[0],
	}
	klog.V(2).Infof("begin to NewSmbGlobalMapping %s on %s", source, normalizedTarget)
	if _, err := mounter.SMBClient.NewSmbGlobalMapping(context.Background(), smbMountRequest); err != nil {
		return fmt.Errorf("NewSmbGlobalMapping(%s, %s) failed with error: %v", source, normalizedTarget, err)
	}
	klog.V(2).Infof("NewSmbGlobalMapping %s on %s successfully", source, normalizedTarget)

	if mounter.RemoveSMBMappingDuringUnmount {
		if err := incementRemotePathReferencesCount(mappingPath, source); err != nil {
			return fmt.Errorf("incementMappingPathCount(%s, %s) failed with error: %v", mappingPath, source, err)
		}
	}
	return nil
}

func (mounter *csiProxyMounter) SMBUnmount(target string) error {
	klog.V(4).Infof("SMBUnmount: local path: %s", target)

	if remotePath, err := os.Readlink(target); err != nil {
		klog.Warningf("SMBUnmount: can't get remote path: %v", err)
	} else {
		remotePath = strings.TrimSuffix(remotePath, "\\")
		mappingPath, err := getRootMappingPath(remotePath)
		if mounter.RemoveSMBMappingDuringUnmount && err != nil {
			return fmt.Errorf("getRootMappingPath(%s) failed with error: %v", remotePath, err)
		}
		klog.V(4).Infof("SMBUnmount: remote path: %s, mapping path: %s", remotePath, mappingPath)

		unlock := lock(mappingPath)
		defer unlock()

		if mounter.RemoveSMBMappingDuringUnmount {
			if err := decrementRemotePathReferencesCount(mappingPath, remotePath); err != nil {
				return fmt.Errorf("decrementMappingPathCount(%s, %s) failed with error: %v", mappingPath, remotePath, err)
			}
			count := getRemotePathReferencesCount(mappingPath)
			if count == 0 {
				smbUnmountRequest := &smb.RemoveSmbGlobalMappingRequest{
					RemotePath: remotePath,
				}
				klog.V(2).Infof("begin to RemoveSmbGlobalMapping %s on %s", remotePath, target)
				if _, err := mounter.SMBClient.RemoveSmbGlobalMapping(context.Background(), smbUnmountRequest); err != nil {
					return fmt.Errorf("RemoveSmbGlobalMapping failed with error: %v", err)
				}
				klog.V(2).Infof("RemoveSmbGlobalMapping %s on %s successfully", remotePath, target)
			} else {
				klog.Infof("SMBUnmount: found %d links to %s", count, mappingPath)
			}
		}
	}

	return mounter.Rmdir(target)
}

// Mount just creates a soft link at target pointing to source.
func (mounter *csiProxyMounter) Mount(source string, target string, fstype string, options []string) error {
	klog.V(4).Infof("Mount: old name: %s. new name: %s", source, target)
	// Mount is called after the format is done.
	// TODO: Confirm that fstype is empty.
	linkRequest := &fs.CreateSymlinkRequest{
		SourcePath: normalizeWindowsPath(source),
		TargetPath: normalizeWindowsPath(target),
	}
	_, err := mounter.FsClient.CreateSymlink(context.Background(), linkRequest)
	if err != nil {
		return err
	}
	return nil
}

func Split(r rune) bool {
	return r == ' ' || r == '/'
}

// Rmdir - delete the given directory
// TODO: Call separate rmdir for pod context and plugin context. v1alpha1 for CSI
//
//	proxy does a relaxed check for prefix as c:\var\lib\kubelet, so we can do
//	rmdir with either pod or plugin context.
func (mounter *csiProxyMounter) Rmdir(path string) error {
	klog.V(4).Infof("Remove directory: %s", path)
	rmdirRequest := &fs.RmdirRequest{
		Path:  normalizeWindowsPath(path),
		Force: true,
	}
	_, err := mounter.FsClient.Rmdir(context.Background(), rmdirRequest)
	if err != nil {
		return err
	}
	return nil
}

// Unmount - Removes the directory - equivalent to unmount on Linux.
func (mounter *csiProxyMounter) Unmount(target string) error {
	klog.V(4).Infof("Unmount: %s", target)
	return mounter.Rmdir(target)
}

func (mounter *csiProxyMounter) List() ([]mount.MountPoint, error) {
	return []mount.MountPoint{}, fmt.Errorf("List not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) IsMountPointMatch(mp mount.MountPoint, dir string) bool {
	return mp.Path == dir
}

// IsLikelyMountPoint - If the directory does not exists, the function will return os.ErrNotExist error.
//
//	If the path exists, call to CSI proxy will check if its a link, if its a link then existence of target
//	path is checked.
func (mounter *csiProxyMounter) IsLikelyNotMountPoint(path string) (bool, error) {
	klog.V(4).Infof("IsLikelyNotMountPoint: %s", path)
	isExists, err := mounter.ExistsPath(path)
	if err != nil {
		return false, err
	}
	if !isExists {
		return true, os.ErrNotExist
	}

	response, err := mounter.FsClient.IsSymlink(context.Background(),
		&fs.IsSymlinkRequest{
			Path: normalizeWindowsPath(path),
		})
	if err != nil {
		return false, err
	}
	return !response.IsSymlink, nil
}

func (mounter *csiProxyMounter) PathIsDevice(pathname string) (bool, error) {
	return false, fmt.Errorf("PathIsDevice not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) DeviceOpened(pathname string) (bool, error) {
	return false, fmt.Errorf("DeviceOpened not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) GetDeviceNameFromMount(mountPath, pluginMountDir string) (string, error) {
	return "", fmt.Errorf("GetDeviceNameFromMount not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MakeRShared(path string) error {
	return fmt.Errorf("MakeRShared not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MakeFile(pathname string) error {
	return fmt.Errorf("MakeFile not implemented for CSIProxyMounter")
}

// MakeDir - Creates a directory. The CSI proxy takes in context information.
// Currently the make dir is only used from the staging code path, hence we call it
// with Plugin context..
func (mounter *csiProxyMounter) MakeDir(path string) error {
	klog.V(4).Infof("Make directory: %s", path)
	mkdirReq := &fs.MkdirRequest{
		Path: normalizeWindowsPath(path),
	}
	_, err := mounter.FsClient.Mkdir(context.Background(), mkdirReq)
	if err != nil {
		return err
	}

	return nil
}

// ExistsPath - Checks if a path exists. Unlike util ExistsPath, this call does not perform follow link.
func (mounter *csiProxyMounter) ExistsPath(path string) (bool, error) {
	klog.V(4).Infof("Exists path: %s", path)
	isExistsResponse, err := mounter.FsClient.PathExists(context.Background(),
		&fs.PathExistsRequest{
			Path: normalizeWindowsPath(path),
		})
	if err != nil {
		return false, err
	}
	return isExistsResponse.Exists, err
}

// GetAPIVersions returns the versions of the client APIs this mounter is using.
func (mounter *csiProxyMounter) GetAPIVersions() string {
	return fmt.Sprintf(
		"API Versions filesystem: %s, SMB: %s",
		fsclient.Version,
		smbclient.Version,
	)
}

func (mounter *csiProxyMounter) EvalHostSymlinks(pathname string) (string, error) {
	return "", fmt.Errorf("EvalHostSymlinks not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) GetMountRefs(pathname string) ([]string, error) {
	return []string{}, fmt.Errorf("GetMountRefs not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) GetFSGroup(pathname string) (int64, error) {
	return -1, fmt.Errorf("GetFSGroup not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) GetSELinuxSupport(pathname string) (bool, error) {
	return false, fmt.Errorf("GetSELinuxSupport not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) GetMode(pathname string) (os.FileMode, error) {
	return 0, fmt.Errorf("GetMode not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MountSensitive(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	return fmt.Errorf("MountSensitive not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MountSensitiveWithoutSystemd(source string, target string, fstype string, options []string, sensitiveOptions []string) error {
	return fmt.Errorf("MountSensitiveWithoutSystemd not implemented for CSIProxyMounter")
}

func (mounter *csiProxyMounter) MountSensitiveWithoutSystemdWithMountFlags(source string, target string, fstype string, options []string, sensitiveOptions []string, mountFlags []string) error {
	return mounter.MountSensitive(source, target, fstype, options, sensitiveOptions /* sensitiveOptions */)
}

// NewSmbCSIProxyMounter - creates a new CSI Proxy mounter struct which encompassed all the
// clients to the CSI proxy - filesystem, disk and volume clients.
func NewSmbCSIProxyMounter(removeSMBMappingDuringUnmount bool) (*csiProxyMounter, error) {
	fsClient, err := fsclient.NewClient()
	if err != nil {
		return nil, err
	}
	smbClient, err := smbclient.NewClient()
	if err != nil {
		return nil, err
	}

	return &csiProxyMounter{
		Mode:                          common.DriverModeSmb,
		FsClient:                      fsClient,
		SMBClient:                     smbClient,
		RemoveSMBMappingDuringUnmount: removeSMBMappingDuringUnmount,
	}, nil
}

// NewIscsiCSIProxyMounter - creates a new CSI Proxy mounter struct which provides the wrapper over
// needed iscsi operations.
func NewIscsiCSIProxyMounter() (*csiProxyMounter, error) {
	return &csiProxyMounter{Mode: common.DriverModeIscsi}, nil
}

func NewSafeMounter(mode common.DriverMode, removeSMBMappingDuringUnmount bool) (*mount.SafeFormatAndMount, error) {
	var csiProxyMounter *csiProxyMounter
	var err error

	if mode == common.DriverModeSmb {
		csiProxyMounter, err = NewSmbCSIProxyMounter(removeSMBMappingDuringUnmount)
		if err != nil {
			klog.V(2).Infof("failed to connect to csi-proxy with error: %v", err)
			return nil, err
		}
		klog.V(2).Infof("using SMB CSIProxyMounterV1, %s", csiProxyMounter.GetAPIVersions())
	} else if mode == common.DriverModeIscsi {
		csiProxyMounter, err = NewIscsiCSIProxyMounter()
		if err != nil {
			klog.V(2).Infof("failed to initialize iscsi mounter: %v", err)
			return nil, err
		}
		klog.V(2).Infof("using ISCSI CSIProxyMounter, %s", csiProxyMounter.GetAPIVersions())
	} else {
		return nil, fmt.Errorf("unsupported driver mode %v", mode.String())
	}

	return &mount.SafeFormatAndMount{
		Interface: csiProxyMounter,
		Exec:      utilexec.New(),
	}, nil
}
