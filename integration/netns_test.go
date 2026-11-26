package integration

import (
	"runtime"

	"github.com/vishvananda/netns"
)

// newNetns creates a network namespace without switching the calling thread into it.
func newNetns() (netns.NsHandle, error) {
	handles := make(chan netns.NsHandle, 1)

	err := onNewThread(func() error {
		ns, err := netns.New()
		handles <- ns
		return err
	})

	return <-handles, err
}

// inNetns runs fn in the given network namespace. Sockets fn opens stay in that namespace.
func inNetns(ns netns.NsHandle, fn func() error) error {
	return onNewThread(func() error {
		if err := netns.Set(ns); err != nil {
			return err
		}

		return fn()
	})
}

// onNewThread runs fn on an OS thread of its own that is thrown away afterwards, so changing its namespace never
// affects the rest of the test.
func onNewThread(fn func() error) error {
	errs := make(chan error, 1)

	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with this goroutine
		errs <- fn()
	}()

	return <-errs
}
