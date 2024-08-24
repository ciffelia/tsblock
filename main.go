package main

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/cockroachdb/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"log"
	"regexp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go bpf bpf.c

var blockedIfacesName = regexp.MustCompile(`^cilium_|^lxc`)

func main() {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		panic(errors.Wrap(err, "remove memory limit for the current process"))
	}

	tsCgroupPath, err := tailscaleCgroup()
	if err != nil {
		panic(errors.Wrap(err, "detect tailscaled cgroup path"))
	}
	log.Printf("found cgroup for tailscale: %s\n", tsCgroupPath)

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		panic(errors.Wrap(err, "load eBPF objects"))
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
		panic(errors.Wrap(err, "link restrict_network_interfaces_egress to the cgroup"))
	}
	defer lEgress.Close()

	lIngress, err := link.AttachCgroup(link.CgroupOptions{
		Path:    tsCgroupPath,
		Attach:  ebpf.AttachCGroupInetIngress,
		Program: objs.RestrictNetworkInterfacesIngress,
	})
	if err != nil {
		panic(errors.Wrap(err, "link restrict_network_interfaces_ingress to the cgroup"))
	}
	defer lIngress.Close()

	log.Println("attached eBPF programs to the cgroup")

	ch := make(chan netlink.LinkUpdate)
	done := make(chan struct{})
	handleError := func(err error) {
		panic(errors.Wrap(err, "process a netlink message"))
	}
	if err := netlink.LinkSubscribeWithOptions(ch, done, netlink.LinkSubscribeOptions{
		ErrorCallback: handleError,
		ListExisting:  true,
	}); err != nil {
		panic(errors.Wrap(err, "subscribe to link changes"))
	}
	log.Println("subscribed to link changes")

	for u := range ch {
		if err := handleLinkUpdate(objs.IfacesMap, &u); err != nil {
			panic(errors.Wrap(err, "process LinkUpdate"))
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
				return errors.Wrapf(err, "block interface %d (%s)", ifaceIdx, ifaceName)
			}
		} else {
			if err := unblockInterface(ifacesMap, ifaceIdx); err != nil {
				return errors.Wrapf(err, "unblock interface %d (%s)", ifaceIdx, ifaceName)
			}
		}

	case unix.RTM_DELLINK:
		log.Printf("interface removed: %d (%s)\n", ifaceIdx, ifaceName)
		if err := unblockInterface(ifacesMap, ifaceIdx); err != nil {
			return errors.Wrapf(err, "unblock interface %d (%s)", ifaceIdx, ifaceName)
		}

	default:
		return errors.Newf("received a netlink message of unknown type %x for interface %d (%s)", u.Header.Type, ifaceIdx, ifaceName)
	}

	return nil
}

func blockInterface(ifacesMap *ebpf.Map, ifaceIdx uint32) error {
	log.Printf("blocking interface: %d\n", ifaceIdx)

	if err := ifacesMap.Put(ifaceIdx, uint8(0)); err != nil {
		return errors.Wrap(err, "add an entry to ifacesMap")
	}

	return nil
}

func unblockInterface(ifacesMap *ebpf.Map, ifaceIdx uint32) error {
	log.Printf("unblocking interface: %d\n", ifaceIdx)

	if err := ifacesMap.Delete(ifaceIdx); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return errors.Wrap(err, "remove an entry from ifacesMap")
	}

	return nil
}
