package main

import (
	"sync"
	"sync/atomic"
	"unsafe"

	"github.com/go-i2p/i2pkeys"
	. "github.com/go-i2p/sam3"
)

/*
#include "sam3.h"
*/
import "C"

var (
	handleCounter uint64
	samRegistry   = struct {
		sync.RWMutex
		handles map[uintptr]*SAM
	}{
		handles: make(map[uintptr]*SAM),
	}
	keysRegistry = struct {
		sync.RWMutex
		handles map[uintptr]*i2pkeys.I2PKeys
	}{
		handles: make(map[uintptr]*i2pkeys.I2PKeys),
	}
)

func registerSAM(sam *SAM) uintptr {
	handle := uintptr(atomic.AddUint64(&handleCounter, 1))
	samRegistry.Lock()
	samRegistry.handles[handle] = sam
	samRegistry.Unlock()
	return handle
}

func getSAM(handle uintptr) *SAM {
	samRegistry.RLock()
	sam := samRegistry.handles[handle]
	samRegistry.RUnlock()
	return sam
}

func unregisterSAM(handle uintptr) {
	samRegistry.Lock()
	delete(samRegistry.handles, handle)
	samRegistry.Unlock()
}

func registerKeys(keys *i2pkeys.I2PKeys) uintptr {
	handle := uintptr(atomic.AddUint64(&handleCounter, 1))
	keysRegistry.Lock()
	keysRegistry.handles[handle] = keys
	keysRegistry.Unlock()
	return handle
}

func getKeys(handle uintptr) *i2pkeys.I2PKeys {
	keysRegistry.RLock()
	keys := keysRegistry.handles[handle]
	keysRegistry.RUnlock()
	return keys
}

func unregisterKeys(handle uintptr) {
	keysRegistry.Lock()
	delete(keysRegistry.handles, handle)
	keysRegistry.Unlock()
}

//export GoSam3Init
func GoSam3Init(cAddress *C.char) unsafe.Pointer {
	address := C.GoString(cAddress)
	sam, err := NewSAM(address)
	if err != nil {
		return nil
	}
	// Store SAM instance in Go-side registry
	handle := registerSAM(sam)
	return unsafe.Pointer(handle)
}

//export GoSam3Cleanup
func GoSam3Cleanup(handle unsafe.Pointer) {
	sam := getSAM(uintptr(handle))
	if sam != nil {
		sam.Close()
		unregisterSAM(uintptr(handle))
	}
}

//export GoSam3GenerateKeys
func GoSam3GenerateKeys(handle unsafe.Pointer) unsafe.Pointer {
	sam := getSAM(uintptr(handle))
	if sam == nil {
		return nil
	}

	keys, err := sam.NewKeys()
	if err != nil {
		return nil
	}

	// Store keys in Go-side registry
	keyHandle := registerKeys(&keys)
	return unsafe.Pointer(keyHandle)
}

func main() {}
