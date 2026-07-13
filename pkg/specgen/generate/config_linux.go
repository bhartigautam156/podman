//go:build !remote

package generate

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"go.podman.io/common/pkg/config"
	"go.podman.io/podman/v6/libpod/define"
	"go.podman.io/podman/v6/pkg/rootless"
	"go.podman.io/podman/v6/pkg/util"
	"go.podman.io/storage/pkg/fileutils"

	spec "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/opencontainers/runtime-tools/generate"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"tags.cncf.io/container-device-interface/pkg/cdi"
)

// DevicesFromPath computes a list of devices
func DevicesFromPath(g *generate.Generator, devicePath string, config *config.Config) error {
	if isCDIDevice(devicePath) {
		registry, err := cdi.NewCache(
			cdi.WithSpecDirs(config.Engine.CdiSpecDirs.Get()...),
			cdi.WithAutoRefresh(false),
		)
		if err != nil {
			return fmt.Errorf("creating CDI registry: %w", err)
		}
		if err := registry.Refresh(); err != nil {
			logrus.Debugf("The following error was triggered when refreshing the CDI registry: %v", err)
		}
		if _, err := registry.InjectDevices(g.Config, devicePath); err != nil {
			return fmt.Errorf("setting up CDI devices: %w", err)
		}
		return nil
	}
	devs := strings.Split(devicePath, ":")
	resolvedDevicePath := devs[0]
	// check if it is a symbolic link
	if src, err := os.Lstat(resolvedDevicePath); err == nil && src.Mode()&os.ModeSymlink == os.ModeSymlink {
		if linkedPathOnHost, err := filepath.EvalSymlinks(resolvedDevicePath); err == nil {
			resolvedDevicePath = linkedPathOnHost
		}
	}
	st, err := os.Stat(resolvedDevicePath)
	if err != nil {
		return err
	}
	if st.IsDir() {
		found := false
		src := resolvedDevicePath
		dest := src
		var devmode string
		if len(devs) > 1 {
			if len(devs[1]) > 0 && devs[1][0] == '/' {
				dest = devs[1]
			} else {
				devmode = devs[1]
			}
		}
		if len(devs) > 2 {
			if devmode != "" {
				return fmt.Errorf("invalid device specification %s: %w", devicePath, unix.EINVAL)
			}
			devmode = devs[2]
		}

		// mount the internal devices recursively
		if err := filepath.WalkDir(resolvedDevicePath, func(dpath string, d fs.DirEntry, _ error) error {
			if d.Type()&os.ModeDevice == os.ModeDevice {
				found = true
				device := fmt.Sprintf("%s:%s", dpath, filepath.Join(dest, strings.TrimPrefix(dpath, src)))
				if devmode != "" {
					device = fmt.Sprintf("%s:%s", device, devmode)
				}
				if err := addDevice(g, device); err != nil {
					return fmt.Errorf("failed to add %s device: %w", dpath, err)
				}
			}
			return nil
		}); err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("no devices found in %s: %w", devicePath, unix.EINVAL)
		}
		return nil
	}
	return addDevice(g, strings.Join(append([]string{resolvedDevicePath}, devs[1:]...), ":"))
}

func BlockAccessToKernelFilesystems(privileged, pidModeIsHost bool, mask, unmask []string, g *generate.Generator) {
	if !privileged {
		for _, mp := range config.DefaultMaskedPaths() {
			// check that the path to mask is not in the list of paths to unmask
			if shouldMask(mp, unmask) {
				g.AddLinuxMaskedPaths(mp)
			}
		}
		for _, rp := range config.DefaultReadOnlyPaths {
			if shouldMask(rp, unmask) {
				g.AddLinuxReadonlyPaths(rp)
			}
		}

		if pidModeIsHost && rootless.IsRootless() {
			return
		}
	}

	// mask the paths provided by the user
	for _, mp := range mask {
		if !path.IsAbs(mp) && mp != "" {
			logrus.Errorf("Path %q is not an absolute path, skipping...", mp)
			continue
		}
		g.AddLinuxMaskedPaths(mp)
	}
}

// deviceGIDMissingFromSubgid checks if the device's owning GID is accessible
// to the current rootless user. If the user is a member of the device's group
// on the host but that GID is not in /etc/subgid, it logs a clear warning
// explaining exactly how to fix the issue.
//
// Returns true if the GID is already mapped (no action needed),
// false if it is missing and the user should be warned.
func deviceGIDMissingFromSubgid(src string) bool {
	// stat the device to get its GID
	var st syscall.Stat_t
	if err := syscall.Stat(src, &st); err != nil {
		// cannot stat — let it proceed, error will surface later
		return true
	}
	deviceGID := int(st.Gid)

	// Get current process supplementary groups (host groups of the user)
	hostGroups, err := os.Getgroups()
	if err != nil {
		return true
	}

	// Check if user is a member of the device group on the host
	userIsMember := false
	for _, g := range hostGroups {
		if g == deviceGID {
			userIsMember = true
			break
		}
	}

	if !userIsMember {
		// User is not even a member of this group on the host.
		// Warn them — Podman cannot fix this automatically.
		logrus.Warnf("Device %s is owned by GID %d. "+
			"You are not a member of this group on the host. "+
			"Access will be denied inside the container. "+
			"Ask your administrator to run: sudo usermod -aG <groupname> %s",
			src, deviceGID, os.Getenv("USER"))
		return false
	}

	// User IS a member — now check if GID is in /etc/subgid
	subgidFile := "/etc/subgid"
	username := os.Getenv("USER")
	if username == "" {
		// fallback: use UID to find username
		u, err := user.LookupId(fmt.Sprintf("%d", os.Getuid()))
		if err == nil {
			username = u.Username
		}
	}

	content, err := os.ReadFile(subgidFile)
	if err != nil {
		return true
	}

	// Parse /etc/subgid line by line
	// Format: username:start:count
	for _, line := range strings.Split(string(content), "\n") {
		parts := strings.Split(strings.TrimSpace(line), ":")
		if len(parts) != 3 {
			continue
		}
		if parts[0] != username {
			continue
		}
		start, err1 := strconv.Atoi(parts[1])
		count, err2 := strconv.Atoi(parts[2])
		if err1 != nil || err2 != nil {
			continue
		}
		// Check if deviceGID falls in this range
		if deviceGID >= start && deviceGID < start+count {
			return true // already mapped, all good
		}
	}

	// GID is not in subgid — warn with exact fix command
	logrus.Warnf("Device %s is owned by GID %d. "+
		"You are a member of this group on the host, but GID %d is not in /etc/subgid. "+
		"The device will appear as 'nobody:nobody' inside the container and access will be denied. "+
		"To fix this, run: echo \"%s:%d:1\" | sudo tee -a /etc/subgid && podman system migrate",
		src, deviceGID, deviceGID, username, deviceGID)

	return false
}

func addDevice(g *generate.Generator, device string) error {
	src, dst, permissions, err := ParseDevice(device)
	if err != nil {
		return err
	}
	dev, err := util.DeviceFromPath(src)
	if err != nil {
		return fmt.Errorf("%s is not a valid device: %w", src, err)
	}
	if rootless.IsRootless() {
		if err := fileutils.Exists(src); err != nil {
			return err
		}
		// Check device GID mapping and warn user if access will fail
		// This runs only when --device is used in rootless mode
		deviceGIDMissingFromSubgid(src)
		perm := "ro"
		if strings.Contains(permissions, "w") {
			perm = "rw"
		}
		devMnt := spec.Mount{
			Destination: dst,
			Type:        define.TypeBind,
			Source:      src,
			Options:     []string{"slave", "nosuid", "noexec", perm, "rbind"},
		}
		g.Config.Mounts = append(g.Config.Mounts, devMnt)
		return nil
	} else if src == "/dev/fuse" {
		// if the user is asking for fuse inside the container
		// make sure the module is loaded.
		f, err := unix.Open(src, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == nil {
			unix.Close(f)
		}
	}
	dev.Path = dst
	g.AddDevice(*dev)
	g.AddLinuxResourcesDevice(true, dev.Type, &dev.Major, &dev.Minor, permissions)
	return nil
}

func supportAmbientCapabilities() bool {
	err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, 0, 0, 0)
	return err == nil
}

func shouldMask(mask string, unmask []string) bool {
	for _, m := range unmask {
		if strings.ToLower(m) == "all" {
			return false
		}
		for m1 := range strings.SplitSeq(m, ":") {
			match, err := filepath.Match(m1, mask)
			if err != nil {
				logrus.Error(err.Error())
			}
			if match {
				return false
			}
		}
	}
	return true
}
