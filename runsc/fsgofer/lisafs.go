// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fsgofer

import (
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	rwfd "gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/sync"
)

// RPC Handlers that perfrom path traversal must lock the server's rename mutex
// for reading to insure that the file is not moved maliciously during
// traversal to incorrectly give access to files outside the mountpoint.
//
// Only the handlers performing rename operations must lock the server's rename
// mutex for writing.
//
// Control FD users must also lock FD.upgradeMu for reading before using the
// host file descriptor to ensure that it remains valid while being used.
//
// Lock ordering: Server's rename mutex -> FD.upgradeMu

// LisafsHandlers are fsgofer's RPC handlers for lisafs protocol messages.
var LisafsHandlers []lisafs.RPCHanlder = buildLisafsHandlers()

// MountHandler handles the Mount RPC for fsgofer.
func MountHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.MountReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	mountPath := c.MountPath()
	if gotMountPath := filepath.Clean(string(req.MountPath)); gotMountPath != mountPath {
		log.Warningf("incorrect mount path found in request: expected %q, got %q", mountPath, gotMountPath)
		return 0, nil, unix.EINVAL
	}

	rootFD, rootStat, err := tryOpen(c, "", nil, func(flags int) (int, error) {
		return unix.Open(mountPath, flags, 0)
	})
	if err != nil {
		return 0, nil, err
	}

	resp := &lisafs.MountResp{
		MaxM:          c.MaxMessage(),
		UnsupportedMs: c.UnsupportedMessages(),
	}
	rootFD.initInodeWithStat(&resp.Root, &rootStat)

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// StatHandler handles the Fstat request for fsgofer.
func StatHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.StatReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	var resp lisafs.StatX
	if err := connFD.(*FD).fstatTo(&resp); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// SetStatHandler handles the SetStat request for fsgofer.
func SetStatHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.SetStatReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	if req.Mask&^(unix.STATX_MODE|unix.STATX_UID|unix.STATX_GID|unix.STATX_SIZE|unix.STATX_ATIME|unix.STATX_MTIME) != 0 {
		return 0, nil, unix.EPERM
	}

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.isControlFD {
		// ftruncate(2) requires the FD to be open for writing.
		if err := fd.ensureWritable(); err != nil {
			return 0, nil, err
		}
	}
	// No need to lock upgradeMu as fd is already upgraded by now so it can't
	// change anymore. This also enables us to lock the rename mutex below.

	var resp lisafs.SetStatResp
	if req.Mask&unix.STATX_MODE != 0 {
		if err := unix.Fchmod(fd.no, req.Mode&07777); err != nil {
			log.Debugf("SetStat fchmod failed %q, err: %v", fd.hostPath(c), err)
			resp.FailureMask |= unix.STATX_MODE
		}
	}

	if req.Mask&unix.STATX_SIZE != 0 {
		if err := unix.Ftruncate(fd.no, int64(req.Size)); err != nil {
			log.Debugf("SetStat ftruncate failed %q, err: %v", fd.hostPath(c), err)
			resp.FailureMask |= unix.STATX_SIZE
		}
	}

	if req.Mask&(unix.STATX_ATIME|unix.STATX_MTIME) != 0 {
		utimes := [2]unix.Timespec{
			{Sec: 0, Nsec: unix.UTIME_OMIT},
			{Sec: 0, Nsec: unix.UTIME_OMIT},
		}
		if req.Mask&unix.STATX_ATIME != 0 {
			utimes[0].Sec = req.Atime.Sec
			utimes[0].Nsec = req.Atime.Nsec
		}
		if req.Mask&unix.STATX_MTIME != 0 {
			utimes[1].Sec = req.Mtime.Sec
			utimes[1].Nsec = req.Mtime.Nsec
		}

		if fd.ftype == unix.S_IFLNK {
			// utimensat operates different that other syscalls. To operate on a
			// symlink it *requires* AT_SYMLINK_NOFOLLOW with dirFD and a non-empty
			// name.
			c.WithRenameRLock(func() error {
				fd.node.parent.upgradeMu.RLock() // fd.node.parent is always a control FD.
				if err := utimensat(fd.node.parent.no, fd.node.name, utimes, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					log.Debugf("SetStat utimens failed %q, err: %v", fd.hostPathLocked(c), err)
					resp.FailureMask |= (req.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
				}
				fd.node.parent.upgradeMu.RUnlock()
				return nil
			})
		} else {
			// Directories and regular files can operate directly on the fd
			// using empty name.
			if err := utimensat(fd.no, "", utimes, 0); err != nil {
				log.Debugf("SetStat utimens failed %q, err: %v", fd.hostPath(c), err)
				resp.FailureMask |= (req.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
			}
		}
	}

	if req.Mask&(unix.STATX_UID|unix.STATX_GID) != 0 {
		// "If the owner or group is specified as -1, then that ID is not changed"
		// - chown(2)
		uid := -1
		if req.Mask&unix.STATX_UID != 0 {
			uid = int(req.UID)
		}
		gid := -1
		if req.Mask&unix.STATX_GID != 0 {
			gid = int(req.GID)
		}
		if err := unix.Fchown(fd.no, uid, gid); err != nil {
			log.Debugf("SetStat fchown failed %q, err: %v", fd.hostPath(c), err)
			resp.FailureMask |= req.Mask & (unix.STATX_UID | unix.STATX_GID)
		}
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// WalkHandler handles Walk for fsgofer.
func WalkHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.WalkReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFD := connFD.(*FD)
	if dirFD.ftype != unix.S_IFDIR {
		return 0, nil, unix.ENOTDIR
	}

	if !dirFD.isControlFD {
		// Walk is only allowed on control FDs.
		return 0, nil, unix.EINVAL
	}
	dirFD.upgradeMu.RLock()
	defer dirFD.upgradeMu.RUnlock()

	// We need to generate inodes for each component walked. We will manually
	// marshal the inodes into the payload buffer as they are generated to avoid
	// the slice allocation. The memory format should be lisafs.WalkResp's.
	curDirFD := dirFD
	var numInodes primitive.Uint32
	maxPayloadSize := numInodes.SizeBytes() + (len(req.Path) * (*lisafs.Inode)(nil).SizeBytes())
	if maxPayloadSize > int(^uint32(0)) {
		// Too much to walk, can't do.
		return 0, nil, unix.EIO
	}
	payloadBuf := comm.PayloadBuf(uint32(maxPayloadSize))
	payloadPos := numInodes.SizeBytes()

	cu := cleanup.Make(func() {
		// Destroy all newly created FDs until now. Walk upward from curDirFD to
		// dirFD. Do not destroy dirFD as the client still owns that.
		for curDirFD != dirFD {
			c.RemoveFD(curDirFD.id)
			curDirFD = curDirFD.node.parent
		}
	})
	defer cu.Clean()

	for _, name := range req.Path {
		if err := checkSafeName(name); err != nil {
			return 0, nil, err
		}

		child, childStat, err := tryOpen(c, name, curDirFD, func(flags int) (int, error) {
			return unix.Openat(curDirFD.no, name, flags, 0)
		})
		if err == unix.ENOENT {
			// No more path components exist on the filesystem. Return the partial
			// walk to the client.
			break
		}
		if err != nil {
			return 0, nil, err
		}

		// Write inode to payloadBuf and update state.
		var childInode lisafs.Inode
		child.initInodeWithStat(&childInode, &childStat)
		childInode.MarshalBytes(payloadBuf[payloadPos:])
		payloadPos += childInode.SizeBytes()
		numInodes++
		curDirFD = child

		// Symlinks are not cool. This client gets the symlink inode, but will have
		// to invoke Walk again with the new path.
		if child.ftype == unix.S_IFLNK {
			break
		}
	}
	cu.Release()

	// lisafs.WalkResp writes the number of inodes in the beginning.
	numInodes.MarshalBytes(payloadBuf)
	return uint32(payloadPos), nil, nil
}

// OpenAtHandler handles OpenAt for fsgofer.
func OpenAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.OpenAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// Only keep allowed open flags.
	if allowedFlags := req.Flags & (unix.O_ACCMODE | allowedOpenFlags); allowedFlags != req.Flags {
		log.Debugf("discarding open flags that are not allowed: old open flags = %d, new open flags = %d", req.Flags, allowedFlags)
		req.Flags = allowedFlags
	}

	accessMode := req.Flags & unix.O_ACCMODE
	trunc := req.Flags&unix.O_TRUNC != 0
	if accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR || trunc {
		if conf := c.Opts().(*Config); conf.ROMount {
			return 0, nil, unix.EROFS
		}
	}

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.ftype == unix.S_IFDIR {
		// Directory is not truncatable.
		if trunc {
			return 0, nil, unix.EISDIR
		}
		// Directory must be opened with O_RDONLY.
		if accessMode != unix.O_RDONLY {
			return 0, nil, unix.EISDIR
		}
	}

	var newFD *FD
	if err := c.WithRenameRLock(func() error {
		if fd.isControlFD {
			fd.upgradeMu.RLock()
			defer fd.upgradeMu.RUnlock()
		}

		newFDNo, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(fd.no), int(req.Flags)|openFlags, 0)
		if err != nil {
			return err
		}
		newFD = &FD{
			no:          newFDNo,
			node:        fd.node,
			isControlFD: false,
			ftype:       fd.ftype,
			readable:    accessMode == unix.O_RDONLY || accessMode == unix.O_RDWR,
			writable:    accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR,
		}
		newFD.initRefs(c)
		return nil
	}); err != nil {
		return 0, nil, err
	}

	var donatedFD []int
	if newFD.ftype == unix.S_IFREG {
		// Donate FD for regular files only. Since FD donation is a destructive
		// operation, we should duplicate the to-be-donated FD. Eat the error if
		// one occurs, it is better to have an FD without a host FD, than failing
		// the Open attempt.
		if dupFD, err := unix.Dup(newFD.no); err == nil {
			donatedFD = []int{dupFD}
		}
	}

	resp := lisafs.OpenAtResp{NewFD: newFD.id}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, donatedFD, nil
}

// OpenCreateAtHandler handles OpenCreateAt for fsgofer.
func OpenCreateAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.OpenCreateAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// Only keep allowed open flags.
	if allowedFlags := req.Flags & (unix.O_ACCMODE | allowedOpenFlags); allowedFlags != req.Flags {
		log.Debugf("discarding open flags that are not allowed: old open flags = %d, new open flags = %d", req.Flags, allowedFlags)
		req.Flags = allowedFlags
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connDirFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connDirFD.DecRef(nil)

	dirFD := connDirFD.(*FD)
	if dirFD.ftype != unix.S_IFDIR {
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.OpenCreateAtResp
	var newFD *FD
	if err := c.WithRenameRLock(func() error {
		if dirFD.isControlFD {
			dirFD.upgradeMu.RLock()
			defer dirFD.upgradeMu.RUnlock()
		}

		childFD, _, err := tryOpen(c, name, dirFD, func(flags int) (int, error) {
			return unix.Openat(dirFD.no, name, flags|unix.O_CREAT|unix.O_EXCL, uint32(req.Mode)&07777)
		})
		if err != nil {
			return err
		}

		cu := cleanup.Make(func() {
			c.RemoveFD(childFD.id)
			// Best effort attempt to remove the file in case of failure.
			if err := unix.Unlinkat(dirFD.no, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFD.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		// Set the owners as requested by the client.
		if err := unix.Fchown(childFD.no, int(req.UID), int(req.GID)); err != nil {
			return err
		}

		// Do not use the stat result from tryOpen because the owners might have
		// changed. initInode() will stat the FD again and use fresh results.
		if err := childFD.initInode(&resp.Child); err != nil {
			return err
		}

		// Now open an FD to the newly created file with the flags requested by the client.
		newFDNo, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(childFD.no), int(req.Flags)|openFlags, 0)
		if err != nil {
			return err
		}
		cu.Release()

		accessMode := req.Flags & unix.O_ACCMODE
		newFD = &FD{
			no:          newFDNo,
			node:        childFD.node,
			isControlFD: false,
			ftype:       childFD.ftype,
			readable:    accessMode == unix.O_RDONLY || accessMode == unix.O_RDWR,
			writable:    accessMode == unix.O_WRONLY || accessMode == unix.O_RDWR,
		}
		newFD.initRefs(c)
		resp.NewFD = newFD.id
		return nil
	}); err != nil {
		return 0, nil, err
	}

	var donatedFD []int
	// Donate FD because open(O_CREAT|O_EXCL) always creates a regular file.
	// Since FD donation is a destructive operation, we should duplicate the
	// to-be-donated FD. Eat the error if one occurs, it is better to have an FD
	// without a host FD, than failing the Open attempt.
	if dupFD, err := unix.Dup(newFD.no); err == nil {
		donatedFD = []int{dupFD}
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, donatedFD, nil
}

// CloseHandler handles the Close request for fsgofer.
func CloseHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.CloseReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))
	c.RemoveFDs(req.FDs)

	// There is no response message for this.
	return 0, nil, nil
}

// SyncHandler handles the Fsync request for fsgofer.
func SyncHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.FsyncReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// Return the first error we encounter, but sync everything we can
	// regardless.
	var retErr error
	for _, fdid := range req.FDs {
		if err := fsyncFD(c, fdid); err != nil && retErr == nil {
			retErr = err
		}
	}

	// There is no response message for this.
	return 0, nil, retErr
}

func fsyncFD(c *lisafs.Connection, id lisafs.FDID) error {
	connFD, err := c.LookupFD(id)
	if err != nil {
		log.Warningf("lisafs.Connection.LookupFD(%d): %v", id, err)
		return err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.isControlFD {
		log.Warningf("cannot fsync control FD %d", fd.id)
		return unix.EBADF
	}

	if err := unix.Fsync(fd.no); err != nil {
		log.Warningf("unix.Fsync(%d): %v", fd.no, err)
		return err
	}
	return nil
}

// WriteHandler handles PWrite for fsgofer.
func WriteHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.PWriteReq
	// Note that it is an optimized Unmarshal operation which avoids any buffer
	// allocation and copying. req.Buf just points to payload. This is safe to do
	// as the handler owns payload and req's lifetime is limited to the handler.
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.isControlFD {
		// Control FD should not be used for IO.
		return 0, nil, unix.EBADF
	}

	if !fd.writable {
		return 0, nil, unix.EPERM
	}

	rw := rwfd.NewReadWriter(fd.no)
	n, err := rw.WriteAt(req.Buf, int64(req.Offset))
	if err != nil {
		return 0, nil, err
	}

	resp := &lisafs.PWriteResp{Count: uint64(n)}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// ReadHandler handles PWrite for fsgofer.
func ReadHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.PReadReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.isControlFD {
		// Control FD should not be used for IO.
		return 0, nil, unix.EBADF
	}

	if !fd.readable {
		return 0, nil, unix.EPERM
	}

	// Beware of the marshalling gymnastics below. We manually marshal a part of
	// the response onto the payload buffer. The rest of the response is directly
	// written into via readat(2).
	var resp lisafs.PReadResp
	respMetaSize := uint32(resp.NumBytes.SizeBytes())
	maxRespLen := respMetaSize + req.Count

	// Read directly into the communicator's payload buffer to avoid allocations.
	payloadBuf := comm.PayloadBuf(maxRespLen)
	rw := rwfd.NewReadWriter(fd.no)
	n, err := rw.ReadAt(payloadBuf[respMetaSize:maxRespLen], int64(req.Offset))
	if err != nil {
		return 0, nil, err
	}

	// Write the response metadata onto the payload buffer. The response contents
	// already have been written immediately after it.
	resp.NumBytes = primitive.Uint32(n)
	resp.NumBytes.MarshalBytes(payloadBuf[:respMetaSize])
	return respMetaSize + uint32(n), nil, nil
}

// MkdirAtHandler handles MkdirAt for fsgofer.
func MkdirAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.MkdirAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFd := connFD.(*FD)
	if !dirFd.isControlFD {
		// MkdirAt can only be used on control FDs.
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.MkdirAtResp
	if err := c.WithRenameRLock(func() error {
		dirFd.upgradeMu.RLock()
		defer dirFd.upgradeMu.RUnlock()

		if err := unix.Mkdirat(dirFd.no, name, uint32(req.Mode)&07777); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the dir in case of failure.
			if err := unix.Unlinkat(dirFd.no, name, unix.AT_REMOVEDIR); err != nil {
				log.Warningf("error unlinking dir %q after failure: %v", path.Join(dirFd.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		// Open directory to change ownership.
		childDirFd, err := unix.Openat(dirFd.no, name, unix.O_DIRECTORY|unix.O_RDONLY|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchown(childDirFd, int(req.UID), int(req.GID)); err != nil {
			unix.Close(childDirFd)
			return err
		}

		childDir := &FD{
			no: childDirFd,
			node: &node{
				name:   name,
				parent: dirFd,
			},
			isControlFD: true,
			ftype:       unix.S_IFDIR,
			readable:    true,
		}
		childDir.initRefs(c)

		if err := childDir.initInode(&resp.ChildDir); err != nil {
			c.RemoveFD(childDir.id)
			return err
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// MknodAtHandler handles MknodAt for fsgofer.
func MknodAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.MknodAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// From mknod(2) man page:
	// "EPERM: [...] if the filesystem containing pathname does not support
	// the type of node requested."
	if req.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, nil, unix.EPERM
	}

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFd := connFD.(*FD)
	if !dirFd.isControlFD {
		// MknotAt can only be used on control FDs.
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.MknodAtResp
	if err := c.WithRenameRLock(func() error {
		dirFd.upgradeMu.RLock()
		defer dirFd.upgradeMu.RUnlock()

		if err := unix.Mknodat(dirFd.no, name, uint32(req.Mode), 0); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the file in case of failure.
			if err := unix.Unlinkat(dirFd.no, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFd.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		// Open file to change ownership.
		childFD, err := unix.Openat(dirFd.no, name, unix.O_PATH|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchown(childFD, int(req.UID), int(req.GID)); err != nil {
			unix.Close(childFD)
			return err
		}

		child := &FD{
			no: childFD,
			node: &node{
				name:   name,
				parent: dirFd,
			},
			isControlFD: true,
			ftype:       unix.S_IFREG,
			readable:    false,
		}
		child.initRefs(c)

		if err := child.initInode(&resp.Child); err != nil {
			c.RemoveFD(child.id)
			return err
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// SymlinkAtHandler handles SymlinkAt for fsgofer.
func SymlinkAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.SymlinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFd := connFD.(*FD)
	if !dirFd.isControlFD {
		// SymlinkAt can only be used on control FDs.
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.SymlinkAtResp
	if err := c.WithRenameRLock(func() error {
		dirFd.upgradeMu.RLock()
		defer dirFd.upgradeMu.RUnlock()

		if err := unix.Symlinkat(string(req.Target), dirFd.no, name); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the symlink in case of failure.
			if err := unix.Unlinkat(dirFd.no, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFd.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		// Open symlink to change ownership.
		symlinkFD, err := unix.Openat(dirFd.no, name, unix.O_PATH|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchown(symlinkFD, int(req.UID), int(req.GID)); err != nil {
			unix.Close(symlinkFD)
			return err
		}

		symlink := &FD{
			no: symlinkFD,
			node: &node{
				name:   name,
				parent: dirFd,
			},
			isControlFD: true,
			ftype:       unix.S_IFLNK,
			readable:    false,
		}
		symlink.initRefs(c)

		if err := symlink.initInode(&resp.Symlink); err != nil {
			c.RemoveFD(symlink.id)
			return err
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// LinkAtHandler handles LinkAt for fsgofer.
func LinkAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.LinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connDirFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connDirFD.DecRef(nil)

	connTargetFD, err := c.LookupFD(req.Target)
	if err != nil {
		return 0, nil, err
	}
	defer connTargetFD.DecRef(nil)

	dirFd := connDirFD.(*FD)
	targetFd := connTargetFD.(*FD)
	if !dirFd.isControlFD || !targetFd.isControlFD {
		// LinkAt can only be used on control FDs.
		return 0, nil, unix.EINVAL
	}

	var resp lisafs.LinkAtResp
	if err := c.WithRenameRLock(func() error {
		dirFd.upgradeMu.RLock()
		defer dirFd.upgradeMu.RUnlock()

		targetFd.upgradeMu.RLock()
		defer targetFd.upgradeMu.RUnlock()

		if err := unix.Linkat(targetFd.no, "", dirFd.no, name, unix.AT_EMPTY_PATH); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the hard link in case of failure.
			if err := unix.Unlinkat(dirFd.no, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFd.hostPathLocked(c), name), err)
			}
		})
		defer cu.Clean()

		linkFD, linkStat, err := tryOpen(c, name, dirFd, func(flags int) (int, error) {
			return unix.Openat(dirFd.no, name, flags, 0)
		})
		if err != nil {
			return err
		}
		cu.Release()

		linkFD.initInodeWithStat(&resp.Link, &linkStat)
		return nil
	}); err != nil {
		return 0, nil, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// StatFSHandler handles FStatFS for fsgofer.
func StatFSHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.FStatFSReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.isControlFD {
		fd.upgradeMu.RLock()
		defer fd.upgradeMu.RUnlock()
	}

	var s unix.Statfs_t
	if err := unix.Fstatfs(fd.no, &s); err != nil {
		return 0, nil, err
	}

	resp := lisafs.FStatFSResp{
		Type:            uint64(s.Type),
		BlockSize:       s.Bsize,
		Blocks:          s.Blocks,
		BlocksFree:      s.Bfree,
		BlocksAvailable: s.Bavail,
		Files:           s.Files,
		FilesFree:       s.Ffree,
		NameLength:      uint64(s.Namelen),
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// AllocateHandler handles FAllocate for fsgofer.
func AllocateHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.FAllocateReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.isControlFD {
		return 0, nil, unix.EINVAL
	}

	if !fd.writable {
		return 0, nil, unix.EBADF
	}
	return 0, nil, unix.Fallocate(fd.no, req.Mode, int64(req.Offset), int64(req.Length))
}

// ReadLinkAtHandler handles ReadLinkAt for fsgofer.
func ReadLinkAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.ReadLinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.ftype != unix.S_IFLNK {
		return 0, nil, unix.EINVAL
	}
	if fd.isControlFD {
		fd.upgradeMu.RLock()
		defer fd.upgradeMu.RUnlock()
	}

	// We will manually marshal lisafs.ReadLinkAtResp, which just contains a
	// lisafs.SizedString. Let unix.Readlinkat directly write into the payload
	// buffer and manually write the string size before it.

	// This is similar to what os.Readlink does.
	const limit = primitive.Uint32(1024 * 1024)
	for linkLen := primitive.Uint32(128); linkLen < limit; linkLen *= 2 {
		b := comm.PayloadBuf(uint32(linkLen) + uint32(linkLen.SizeBytes()))
		n, err := unix.Readlinkat(fd.no, "", b[linkLen.SizeBytes():])
		if err != nil {
			return 0, nil, err
		}
		if n < int(linkLen) {
			linkLen = primitive.Uint32(n)
			linkLen.MarshalBytes(b[:linkLen.SizeBytes()])
			return uint32(linkLen) + uint32(linkLen.SizeBytes()), nil, nil
		}
	}
	return 0, nil, unix.ENOMEM
}

// ConnectHandler handles Connect for fsgofer.
func ConnectHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if !c.Opts().(*Config).HostUDS {
		return 0, nil, unix.ECONNREFUSED
	}

	var req lisafs.ConnectReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	// Only SOCK_STREAM, SOCK_DGRAM and SOCK_SEQPACKET types are supported.
	if req.SockType != unix.SOCK_STREAM &&
		req.SockType != unix.SOCK_DGRAM &&
		req.SockType != unix.SOCK_SEQPACKET {
		return 0, nil, unix.ENXIO
	}

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.ftype != unix.S_IFSOCK {
		return 0, nil, unix.EINVAL
	}
	if fd.isControlFD {
		fd.upgradeMu.RLock()
		defer fd.upgradeMu.RUnlock()
	}

	var sock int
	if err := c.WithRenameRLock(func() error {
		hostPath := fd.hostPathLocked(c)

		// TODO(gvisor.dev/issue/1003): Due to different app vs replacement
		// mappings, the app path may have fit in the sockaddr, but we can't fit
		// hostPath in our sockaddr. We'd need to redirect through a shorter path
		// in order to actually connect to this socket.
		if len(hostPath) > 108 { // UNIX_PATH_MAX = 108 is defined in afunix.h.
			return unix.ECONNREFUSED
		}

		sock, err = unix.Socket(unix.AF_UNIX, int(req.SockType), 0)
		if err != nil {
			return err
		}
		if err := unix.SetNonblock(sock, true); err != nil {
			return err
		}
		sa := unix.SockaddrUnix{Name: hostPath}
		return unix.Connect(sock, &sa)
	}); err != nil {
		if sock > 0 {
			_ = unix.Close(sock)
		}
		return 0, nil, err
	}

	return 0, []int{sock}, nil
}

// UnlinkAtHandler handles UnlinkAt for fsgofer.
func UnlinkAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.UnlinkAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	name := string(req.Name)
	if err := checkSafeName(name); err != nil {
		return 0, nil, err
	}

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFD := connFD.(*FD)
	if dirFD.ftype != unix.S_IFDIR {
		return 0, nil, unix.EINVAL
	}

	if !dirFD.isControlFD {
		return 0, nil, unix.EINVAL
	}

	err = c.WithRenameRLock(func() error {
		dirFD.upgradeMu.RLock()
		defer dirFD.upgradeMu.RUnlock()

		return unix.Unlinkat(dirFD.no, name, int(req.Flags))
	})
	return 0, nil, err
}

// RenameAtHandler handles RenameAt for fsgofer.
func RenameAtHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if conf := c.Opts().(*Config); conf.ROMount {
		return 0, nil, unix.EROFS
	}

	var req lisafs.RenameAtReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	newName := string(req.NewName)
	if err := checkSafeName(newName); err != nil {
		return 0, nil, err
	}

	renamedConnFD, err := c.LookupFD(req.Renamed)
	if err != nil {
		return 0, nil, err
	}
	defer renamedConnFD.DecRef(nil)

	newDirConnFD, err := c.LookupFD(req.NewDir)
	if err != nil {
		return 0, nil, err
	}
	defer newDirConnFD.DecRef(nil)

	renamed := renamedConnFD.(*FD)
	newDir := newDirConnFD.(*FD)
	if newDir.ftype != unix.S_IFDIR {
		return 0, nil, unix.EINVAL
	}

	err = c.WithRenameLock(func() error {
		if renamed.isRoot() {
			return unix.EINVAL
		}

		if renamed.node.parent == newDir && newName == renamed.node.name {
			// Nothing to do.
			return nil
		}

		if err := renameat(renamed.node.parent.no, renamed.node.name, newDir.no, newName); err != nil {
			return err
		}
		// Update node info now that we know the rename was successful.
		renamed.node.name = newName
		renamed.node.parent = newDir
		return nil
	})
	return 0, nil, err
}

// Getdents64Handler handles Getdents64 for fsgofer.
func Getdents64Handler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	var req lisafs.Getdents64Req
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.DirFD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	dirFD := connFD.(*FD)
	// Getdents is only allowed on opened directory FDs.
	if dirFD.ftype != unix.S_IFDIR || dirFD.isControlFD {
		return 0, nil, unix.EINVAL
	}

	if !dirFD.readable {
		return 0, nil, unix.EBADF
	}

	// See if the client wants us to reset the FD offset.
	if req.Count < 0 {
		req.Count *= -1
		if _, err := unix.Seek(dirFD.no, 0, 0); err != nil {
			return 0, nil, err
		}
	}

	// We will manually marshal the response lisafs.Getdents64Resp. If its
	// memory format changes, the logic below should change too.

	// numDirents is the number of dirents marshalled into the payload.
	var numDirents primitive.Uint32
	// The payload starts with numDirents, dirents go right after that.
	// payloadBufPos represents the position at which to write the next dirent.
	payloadBufPos := uint32(numDirents.SizeBytes())
	// Request enough payloadBuf for 10 dirents, we will extend when needed.
	payloadBuf := comm.PayloadBuf(payloadBufPos + 10*unixDirentMaxSize)

	var direntsBuf [8192]byte
	count := int(req.Count)
	var bytesRead int
	for bytesRead < count {
		n, err := unix.Getdents(dirFD.no, direntsBuf[:])
		if err != nil {
			return 0, nil, err
		}
		if n <= 0 {
			break
		}
		bytesRead += n

		var statErr error
		parseDirents(direntsBuf[:n], func(ino uint64, off int64, ftype uint8, name string) bool {
			dirent := lisafs.Dirent64{
				Ino:  primitive.Uint64(ino),
				Off:  primitive.Uint64(off),
				Type: primitive.Uint8(ftype),
				Name: lisafs.SizedString(name),
			}

			// The client also wants the device ID, which annoyingly incurs an
			// additional syscall per dirent. Live with it.
			stat, err := statAt(dirFD.no, name)
			if err != nil {
				statErr = err
				return false
			}
			dirent.Dev = primitive.Uint64(stat.Dev)

			// Paste the dirent into the payload buffer without having the dirent
			// escape. Request a larger buffer if needed.
			if int(payloadBufPos)+dirent.SizeBytes() > len(payloadBuf) {
				// Ask for 10 large dirents worth of more space.
				payloadBuf = comm.PayloadBuf(payloadBufPos + 10*unixDirentMaxSize)
			}
			dirent.MarshalBytes(payloadBuf[payloadBufPos:])
			payloadBufPos += uint32(dirent.SizeBytes())
			numDirents++
			return true
		})
		if statErr != nil {
			return 0, nil, statErr
		}
	}

	// The number of dirents goes at the beginning of the payload.
	numDirents.MarshalBytes(payloadBuf)
	return payloadBufPos, nil, nil
}

// GetXattrHandler handles FGetXattr for fsgofer.
func GetXattrHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if !c.Opts().(*Config).EnableVerityXattr {
		return 0, nil, unix.EOPNOTSUPP
	}

	var req lisafs.FGetXattrReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.isControlFD {
		// fd must be atleast readable or writable to use fgetxattr(2). If not, it
		// was opened with O_PATH and the operation will fail with EBADF.
		shouldUpgradeLock, err := fd.ensureReadableOrWritable()
		if err != nil {
			return 0, nil, err
		}
		if shouldUpgradeLock {
			fd.upgradeMu.RLock()
			defer fd.upgradeMu.Unlock()
		}
	}

	// Note that this can be optimized further to avoid the 2 allocations below
	// at the cost of more complexity. You'd have to make unix.Fgetxattr write
	// directly into the payload buffer and manually write the string header
	// before it. I have chosen simplicity over efficiency here as this is not
	// a very frequently used method by applications.
	valueBuf := make([]byte, req.BufSize)
	valueLen, err := unix.Fgetxattr(fd.no, string(req.Name), valueBuf)
	if err != nil {
		return 0, nil, err
	}

	resp := &lisafs.FGetXattrResp{
		Value: lisafs.SizedString(valueBuf[:valueLen]),
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalBytes(comm.PayloadBuf(respLen))
	return respLen, nil, nil
}

// SetXattrHandler handles FSetXattr for fsgofer.
func SetXattrHandler(c *lisafs.Connection, comm lisafs.Communicator, payloadLen uint32) (uint32, []int, error) {
	if !c.Opts().(*Config).EnableVerityXattr {
		return 0, nil, unix.EOPNOTSUPP
	}

	var req lisafs.FSetXattrReq
	req.UnmarshalBytes(comm.PayloadBuf(payloadLen))

	connFD, err := c.LookupFD(req.FD)
	if err != nil {
		return 0, nil, err
	}
	defer connFD.DecRef(nil)

	fd := connFD.(*FD)
	if fd.isControlFD {
		// fd must be atleast readable or writable to use fsetxattr(2). If not, it
		// was opened with O_PATH and the operation will fail with EBADF.
		shouldUpgradeLock, err := fd.ensureReadableOrWritable()
		if err != nil {
			return 0, nil, err
		}
		if shouldUpgradeLock {
			fd.upgradeMu.RLock()
			defer fd.upgradeMu.Unlock()
		}
	}

	return 0, nil, unix.Fsetxattr(fd.no, string(req.Name), []byte(req.Value), int(req.Flags))
}

func buildLisafsHandlers() []lisafs.RPCHanlder {
	// Note that inline slice initialization has been explicitly avoided. It is
	// more readable to have handlers[MID] = HandlerFunc and helps in avoiding
	// incorrect assignment bugs because of having to manually count indices.
	var handlers [28]lisafs.RPCHanlder
	handlers[lisafs.Error] = nil // No error handler needed.
	handlers[lisafs.Mount] = MountHandler
	handlers[lisafs.Channel] = lisafs.ChannelHandler
	handlers[lisafs.Fstat] = StatHandler
	handlers[lisafs.SetStat] = SetStatHandler
	handlers[lisafs.Walk] = WalkHandler
	handlers[lisafs.OpenAt] = OpenAtHandler
	handlers[lisafs.OpenCreateAt] = OpenCreateAtHandler
	handlers[lisafs.Close] = CloseHandler
	handlers[lisafs.Fsync] = SyncHandler
	handlers[lisafs.PWrite] = WriteHandler
	handlers[lisafs.PRead] = ReadHandler
	handlers[lisafs.MkdirAt] = MkdirAtHandler
	handlers[lisafs.MknodAt] = MknodAtHandler
	handlers[lisafs.SymlinkAt] = SymlinkAtHandler
	handlers[lisafs.LinkAt] = LinkAtHandler
	handlers[lisafs.Fstat] = StatFSHandler
	handlers[lisafs.FAllocate] = AllocateHandler
	handlers[lisafs.ReadLinkAt] = ReadLinkAtHandler
	handlers[lisafs.FFlush] = nil
	handlers[lisafs.Connect] = ConnectHandler
	handlers[lisafs.UnlinkAt] = UnlinkAtHandler
	handlers[lisafs.RenameAt] = RenameAtHandler
	handlers[lisafs.Getdents64] = Getdents64Handler
	handlers[lisafs.FGetXattr] = GetXattrHandler
	handlers[lisafs.FSetXattr] = SetXattrHandler
	handlers[lisafs.FListXattr] = nil
	handlers[lisafs.FRemoveXattr] = nil
	return handlers[:]
}

// FD represents a host file descriptor and implements lisafs.FD.
//
// Reference Model:
// The connection holds a ref on this FD until the client is done using this
// FD. All requests that use this FD also hold a ref on it for their entire
// lifetime so that the FD is not destroyed preemptively. After the FD is
// destroyed (when all refs are dropped), the FD number is set to -1 to make
// future FD usages fail.
//
// Control FDs:
// Control FDs are file descriptors that are used by the client to perform
// path based filesystem operations. These represent a file at a path and
// are only opened during Walks.
//
// These are initially opened as read only (or with O_PATH if it represents a
// symlink or socket). The reason it is not opened as read-write is for better
// performance with 'overlay2' storage driver. overlay2 eagerly copies the
// entire file up when it's opened in write mode, and would perform badly when
// multiple files are only being opened for read (esp. startup).
//
// Upgrades:
// The control FD may be reopened with a wider access mode if the current
// access mode is not sufficient. Consequently, it could also have a mode wider
// than requested and must be verified before read/write operations.
//
// FDs opened via open(2) are not control FDs. open(2)-ed FDs can not be
// upgraded. Their open mode is immutable throughout thier lifetime.
//
// Avoid path based syscalls:
// File operations must use "at" functions whenever possible:
//   * Local operations must use AT_EMPTY_PATH:
//  	   fchownat(fd, "", AT_EMPTY_PATH, ...), instead of chown(fullpath, ...)
//   * Creation operations must use (fd + name):
//       mkdirat(fd, name, ...), instead of mkdir(fullpath, ...)
//
// Apart from being faster, it also adds another layer of defense against
// symlink attacks (note that O_NOFOLLOW applies only to the last element in
// the path).
//
// The few exceptions where path based operations can be done are: opening the
// root directory on Mount and Connect() for the socket address.
type FD struct {
	fdRefs

	// id is immutable and is used to identify this FD. id is guaranteed to be
	// unique in a connection's namespace.
	id lisafs.FDID

	// node represents the backing file's position in the filesystem tree. It is
	// protected by the server's rename mutex.
	node *node

	// isControlFD indicates whether this is a control FD and is immutable.
	isControlFD bool

	// ftype is equivalent to unix.Stat_t.Mode & unix.S_IFMT and is immutable.
	ftype uint32

	// upgradeMu protects the fields below when isControlFD is true. Otherwise
	// the fields are immutable. Holding it for reading ensures that fd will not
	// be closed or changed (upgraded). Hence users must acquire the read lock
	// while using this FD. This must be held for writing to upgrade.
	upgradeMu sync.RWMutex

	// no is the file descriptor number which can be used to make syscalls.
	no int
	// readable and writable denote the access mode of the opened FD `no`.
	readable bool
	writable bool
}

var _ lisafs.FD = (*FD)(nil)

// node represents a node on the filesystem tree. Multiple FDs (control and
// non-control) on the same node share the same node struct.
type node struct {
	// name is the file path's last component name. If this FD represents the
	// root directory, then name is "".
	name string

	// parent is parent directory's FD. Protected by server's rename mutex. If
	// this FD represents the root directory, then parent is nil.
	parent *FD
}

// isRoot returns true if fd represents the mount's root file.
//
// Precondition: server's rename mutex must be locked.
func (fd *FD) isRoot() bool {
	return fd.node.parent == nil
}

// upgrade attempts to make fd writable.
func (fd *FD) upgrade() error {
	if !fd.isControlFD {
		// Can not upgrade a non-control FD.
		return unix.EPERM
	}
	fd.upgradeMu.Lock()
	defer fd.upgradeMu.Unlock()

	if fd.writable {
		// Race occured, another goroutine upgraded this FD in between
		// fd.upgradeMu.RUnlock() and fd.upgradeMu.Lock().
		return nil
	}

	var flags int
	if fd.readable {
		flags = unix.O_RDWR
	} else {
		flags = unix.O_WRONLY
	}

	flags |= openFlags | unix.O_NONBLOCK
	upgradedFD, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(fd.no), flags, 0)
	if err != nil {
		return err
	}

	// Success! Update fd state. Since we are holding upgradeMu for writing,
	// there should be no other users.
	unix.Close(fd.no)
	fd.no = upgradedFD
	fd.writable = true
	return nil
}

// ensureWritable retuns if the control handle is already writable, otherwise
// upgrades it. Note that after the FD becomes writable, its users do not need
// to hold fd.upgradeMu anymore while using it because it won't change anymore.
func (fd *FD) ensureWritable() error {
	fd.upgradeMu.RLock()
	if fd.writable {
		fd.upgradeMu.RUnlock()
		return nil
	}
	fd.upgradeMu.RUnlock()
	return fd.upgrade()
}

// ensureReadableOrWritable upgrades fd if it is neither readable or writable.
// It also returns whether upgradeMu needs to be read locked by fd's users.
func (fd *FD) ensureReadableOrWritable() (bool, error) {
	fd.upgradeMu.RLock()
	shouldUpgrade := !fd.readable && !fd.writable
	writable := fd.writable
	fd.upgradeMu.RUnlock()
	if shouldUpgrade {
		// No need to hold upgradeMu to use fd anymore as it will be upgraded
		// and will no longer change.
		return false, fd.upgrade()
	}

	// We need to hold upgradeMu while we use fd if it is not upgraded yet.
	return !writable, nil
}

// initInode initializes the passed inode based on fd.
func (fd *FD) initInode(inode *lisafs.Inode) error {
	inode.ControlFD = fd.id
	return fd.fstatTo(&inode.Stat)
}

func (fd *FD) initInodeWithStat(inode *lisafs.Inode, stat *unix.Stat_t) {
	inode.ControlFD = fd.id
	copyUnixToLisaStat(stat, &inode.Stat)
}

// tryOpen tries to call open() with different modes as documented. It then
// initializes and returns the control FD.
func tryOpen(c *lisafs.Connection, name string, parent *FD, open func(flags int) (int, error)) (*FD, unix.Stat_t, error) {
	// Attempt to open file in the following in order:
	//   1. RDONLY | NONBLOCK: for all files, directories, ro mounts, FIFOs.
	//      Use non-blocking to prevent getting stuck inside open(2) for
	//      FIFOs. This option has no effect on regular files.
	//   2. PATH: for symlinks, sockets.
	options := []struct {
		flag     int
		readable bool
	}{
		{
			flag:     unix.O_RDONLY | unix.O_NONBLOCK,
			readable: true,
		},
		{
			flag:     unix.O_PATH,
			readable: false,
		},
	}

	for i, option := range options {
		fdno, err := open(option.flag | openFlags)
		if err == nil {
			var stat unix.Stat_t
			if err = unix.Fstat(fdno, &stat); err == nil {
				fd := &FD{
					no: fdno,
					node: &node{
						name:   name,
						parent: parent,
					},
					isControlFD: true,
					ftype:       stat.Mode & unix.S_IFMT,
					readable:    option.readable,
				}
				fd.initRefs(c)
				return fd, stat, nil
			}
		}

		e := extractErrno(err)
		if e == unix.ENOENT {
			// File doesn't exist, no point in retrying.
			return nil, unix.Stat_t{}, e
		}
		if i < len(options)-1 {
			continue
		}
		return nil, unix.Stat_t{}, e
	}
	panic("unreachable")
}

// initRefs intitializes the FD's reference counter and takes a ref on the
// parent. It also makes the FD visible for use on the connection. initRefs
// must be called before use.
func (fd *FD) initRefs(c *lisafs.Connection) {
	// Initialize fd with 1 ref which is transferred to c via c.InsertFD().
	fd.fdRefs.InitRefs()
	fd.id = c.InsertFD(fd)
	if fd.node.parent != nil {
		fd.node.parent.IncRef() // Child takes a ref on the parent.
	}
}

// DecRef implements refsvfs2.RefCounter.DecRef. Note that the context
// parameter should never be used as fsgofer has no context. It exists solely
// to comply with refsvfs2.RefCounter interface.
func (fd *FD) DecRef(context.Context) {
	fd.fdRefs.DecRef(func() {
		// No need to lock fd.upgradeMu as no refs are left so there is no other
		// user or upgrader.
		unix.Close(fd.no)
		fd.no = -1
		// No need to lock the rename mutex as no refs on fd are left so it could
		// not possibly be renamed concurrently (which would change fd.node).
		if fd.node.parent != nil {
			fd.node.parent.DecRef(nil) // Drop the ref on the parent.
		}
	})
}

// hostPath returns the host path of the file fd was opened on. This is
// expensive and must not be called on hot paths. hostPath acquires the rename
// mutex for reading so callers should not be holding it.
func (fd *FD) hostPath(c *lisafs.Connection) (path string) {
	// Lock the rename mutex for reading to ensure that the filesystem tree is not
	// changed while we traverse it upwards.
	c.WithRenameRLock(func() error {
		path = fd.hostPathLocked(c)
		return nil
	})
	return
}

// hostPathLocked is the same as hostPath with an extra precondition.
//
// Precondition: Server's rename mutex must be locked at least for reading.
func (fd *FD) hostPathLocked(c *lisafs.Connection) string {
	// Walk upwards and prepend name to res.
	res := ""
	for fd.node.parent != nil {
		// fd represents a non-root file. fd.node.name is valid.
		res = string(os.PathSeparator) + fd.node.name + res // path.Join() is expensive.
		fd = fd.node.parent
	}
	return c.MountPath() + res
}

func (fd *FD) fstatTo(stat *lisafs.StatX) error {
	if fd.isControlFD {
		fd.upgradeMu.RLock()
		defer fd.upgradeMu.RUnlock()
	}

	var unixStat unix.Stat_t
	if err := unix.Fstat(fd.no, &unixStat); err != nil {
		return err
	}

	copyUnixToLisaStat(&unixStat, stat)
	return nil
}

func copyUnixToLisaStat(unixStat *unix.Stat_t, stat *lisafs.StatX) {
	stat.Mask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_INO | unix.STATX_NLINK | unix.STATX_UID | unix.STATX_GID | unix.STATX_SIZE | unix.STATX_BLOCKS | unix.STATX_ATIME | unix.STATX_MTIME | unix.STATX_CTIME
	stat.Mode = unixStat.Mode
	stat.Dev = unixStat.Dev
	stat.Ino = unixStat.Ino
	stat.Nlink = uint32(unixStat.Nlink)
	stat.UID = lisafs.UID(unixStat.Uid)
	stat.GID = lisafs.GID(unixStat.Gid)
	stat.Rdev = unixStat.Rdev
	stat.Size = uint64(unixStat.Size)
	stat.Blksize = uint32(unixStat.Blksize)
	stat.Blocks = uint64(unixStat.Blocks)
	stat.Atime.Sec = unixStat.Atim.Sec
	stat.Atime.Nsec = unixStat.Atim.Nsec
	stat.Mtime.Sec = unixStat.Mtim.Sec
	stat.Mtime.Nsec = unixStat.Mtim.Nsec
	stat.Ctime.Sec = unixStat.Ctim.Sec
	stat.Ctime.Nsec = unixStat.Ctim.Nsec
}

// checkSafeName validates the name and returns nil or returns an error.
func checkSafeName(name string) error {
	if name != "" && !strings.Contains(name, "/") && name != "." && name != ".." {
		return nil
	}
	return unix.EINVAL
}
