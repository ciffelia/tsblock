package main

import (
	"errors"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"regexp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf.c

var blockedIfacesName = regexp.MustCompile(`^vxlan\.calico$|^cali`)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(fmt.Errorf("removing memory limit: %w", err))
	}

	tsCgroupPath, err := tailscaleCgroup()
	if err != nil {
		panic(fmt.Errorf("detecting tailscaled cgroup: %w", err))
	}
	log.Printf("found cgroup for tailscale: %s\n", tsCgroupPath)

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		panic(fmt.Errorf("loading eBPF objects: %w", err))
	}
	defer objs.Close()
	log.Println("loaded eBPF programs and maps into the kernel")

	// Link eBPF programs to the cgroup.
	lEgress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    tsCgroupPath,
		Attach:  ebpf.AttachCGroupInetEgress,
		Program: objs.RestrictNetworkInterfacesEgress,
	})
	if err != nil {
		panic(fmt.Errorf("linking restrict_network_interfaces_egress to the cgroup: %w", err))
	}
	defer lEgress.Close()

	lIngress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    tsCgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.RestrictNetworkInterfacesIngress,
	})
	if err != nil {
		panic(fmt.Errorf("linking restrict_network_interfaces_ingress to the cgroup: %w", err))
	}
	defer lIngress.Close()

	log.Println("attached eBPF programs to the cgroup")

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	handleError := func(err error) {
		panic(fmt.Errorf("processing a netlink message: %w", err))
	}
	if err := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: handleError,
		ListExisting:  true,
	}); err != nil {
		panic(fmt.Errorf("subscribing to link changes: %w", err))
	}
	log.Println("subscribed to link changes")

	for u := range ch {
		if err := handleLinkUpdate(objs.IfacesMap, &u); err != nil {
			panic(fmt.Errorf("processing LinkUpdate: %w", err))
		}
	}
}

func handleLinkUpdate(ifacesMap *ebpf.Map, u *netlink.LinkUpdate) error {
	ifaceName := u.Link.Attrs().Name
	ifaceIdx := uint32(u.Index)

	switch u.Header.Type {
	case unix.RTM_NEWLINK:
		log.Printf("interface created or updated: %d (%s)\n", ifaceIdx, ifaceName)
		if blockedIfacesName.MatchString(ifaceName) {
			if err := blockInterface(ifacesMap, ifaceIdx); err != nil {
				return fmt.Errorf("blocking interface: %w", err)
			}
		} else {
			if err := unblockInterface(ifacesMap, ifaceIdx); err != nil {
				return fmt.Errorf("unblocking interface: %w", err)
			}
		}

	case unix.RTM_DELLINK:
		log.Printf("interface removed: %d (%s)\n", ifaceIdx, ifaceName)
		if err := unblockInterface(ifacesMap, ifaceIdx); err != nil {
			return fmt.Errorf("unblocking interface: %w", err)
		}

	default:
		return fmt.Errorf("received a netlink message of unknown type: %x", u.Header.Type)
	}

	return nil
}

func blockInterface(ifacesMap *ebpf.Map, ifaceIdx uint32) error {
	log.Printf("blocking interface: %d\n", ifaceIdx)

	if err := ifacesMap.Put(ifaceIdx, uint8(0)); err != nil {
		return fmt.Errorf("creating/replacing a value in eBPF map: %w", err)
	}

	return nil
}

func unblockInterface(ifacesMap *ebpf.Map, ifaceIdx uint32) error {
	log.Printf("unblocking interface: %d\n", ifaceIdx)

	if err := ifacesMap.Delete(ifaceIdx); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("deleting a value from eBPF map: %w", err)
	}

	return nil
}
