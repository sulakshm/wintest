package mounter

import (
	"fmt"

	iscsi "github.com/kubernetes-csi/csi-proxy/client/api/iscsi/v1alpha2"
)

type IscsiMounter interface {
	///  Iscsi specifics
	IscsiAddTargetPortal(addr string, port uint32) error
	IscsiConnectTargetNoAuth(addr string, port uint32, iqn string) error
	IscsiDisconnectTarget(iqn string) error
	IscsiDiscoverTargetPortal(addr string, port uint32) ([]string, error)
	IscsiListTargetPortals() ([]iscsi.TargetPortal, error)
	IscsiRemoveTargetPortal(addr string, port uint32) error
	IscsiVolumeExists(fsLabel string) (bool, error)
	IscsiDiskInitialized(serialnum string) (bool, error)
	IscsiDiskInit(serialnum string) error
	IscsiFormatVolume(serialnum, fslabel string) error

	IscsiVolumeReadOnly(fslabel string) (bool, error)
	IscsiVolumeSetReadOnly(fslabel string, ro bool) error

	IscsiVolumeMount(fslabel string, path string) error
	IscsiVolumeUnmount(fslabel string, path string) error
	IscsiGetVolumeMounts(fslabel string, filter bool) ([]string, error)

	IscsiGetTargetNodeAddress(fslabel string) (string, error)
	IscsiSetMutualChapSecret(req *iscsi.SetMutualChapSecretRequest) (*iscsi.SetMutualChapSecretResponse, error)
}

var (
	ErrNoSuchVolume       = fmt.Errorf("no such volume")
	ErrVolumeInconsistent = fmt.Errorf("volume state inconsistent")

	ErrNoSuchDisk = fmt.Errorf("no such disk")
)

var errStubImpl = fmt.Errorf("stubhandler not implemented")

type stubIscsiMounter struct {
}

func (m *stubIscsiMounter) IscsiAddTargetPortal(addr string, port uint32) error {
	return errStubImpl
}
func (m *stubIscsiMounter) IscsiConnectTargetNoAuth(addr string, port uint32, iqn string) error {
	return errStubImpl
}
func (m *stubIscsiMounter) IscsiDisconnectTarget(iqn string) error {
	return errStubImpl
}
func (m *stubIscsiMounter) IscsiDiscoverTargetPortal(addr string, port uint32) ([]string, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiListTargetPortals() ([]iscsi.TargetPortal, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiRemoveTargetPortal(addr string, port uint32) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiVolumeExists(fsLabel string) (bool, error) {
	return false, errStubImpl
}

func (m *stubIscsiMounter) IscsiDiskInitialized(serialnum string) (bool, error) {
	return false, errStubImpl
}

func (m *stubIscsiMounter) IscsiDiskInit(serialnum string) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiFormatVolume(serialnum string, fslabel string) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiVolumeMount(fslabel string, path string) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiVolumeUnmount(fslabel string, path string) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiGetVolumeMounts(fslabel string, filter bool) ([]string, error) {
	return nil, errStubImpl
}
func (m *stubIscsiMounter) IscsiVolumeReadOnly(fslabel string) (bool, error) {
	return false, errStubImpl
}
func (m *stubIscsiMounter) IscsiVolumeSetReadOnly(fslabel string, ro bool) error {
	return errStubImpl
}

func (m *stubIscsiMounter) IscsiGetTargetNodeAddress(fslabel string) (string, error) {
	return "", errStubImpl
}

func (m *stubIscsiMounter) IscsiSetMutualChapSecret(req *iscsi.SetMutualChapSecretRequest) (*iscsi.SetMutualChapSecretResponse, error) {
	return nil, errStubImpl
}
