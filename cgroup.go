package main

import (
	"bufio"
	"github.com/cockroachdb/errors"
	"os"
	"os/exec"
	"strings"
)

// tailscaleCgroup returns the path to the cgroup for tailscaled.service.
func tailscaleCgroup() (string, error) {
	mp, err := cgroupMountPoint()
	if err != nil {
		return "", errors.Wrap(err, "detect cgroup mount point")
	}

	path, err := cgroupByService("tailscaled.service")
	if err != nil {
		return "", errors.Wrap(err, "detect cgroup for tailscaled.service")
	}

	return mp + path, nil
}

// cgroupMountPoint returns the first-found mount point of type cgroup2.
func cgroupMountPoint() (string, error) {
	f, err := os.Open("/proc/mounts")
	if err != nil {
		return "", errors.Wrap(err, "open /proc/mounts")
	}
	defer func() { _ = f.Close() }()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		// example fields: cgroup2 /sys/fs/cgroup/unified cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
		fields := strings.Split(scanner.Text(), " ")
		if len(fields) >= 3 && fields[2] == "cgroup2" {
			return fields[1], nil
		}
	}

	return "", errors.New("cgroup2 not mounted")
}

// cgroupByService returns the value of ControlGroup property for a specified systemd service.
func cgroupByService(serviceName string) (string, error) {
	out, err := exec.Command("systemctl", "show", "--property", "ControlGroup", serviceName).Output()
	if err != nil {
		return "", errors.Wrap(err, "run `systemctl show`")
	}

	output := string(out)
	parts := strings.Split(output, "=")
	if len(parts) != 2 {
		return "", errors.Newf("unexpected output format: %s", output)
	}

	c := strings.TrimSpace(parts[1])
	if c == "" {
		return "", errors.New("cgroup not found")
	}

	return c, nil
}
