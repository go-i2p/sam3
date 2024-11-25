package common

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-i2p/logger"
)

// Package common provides shared UDP common functionality for SAM sessions
//
// It handles:
// - UDP port validation and defaults
// - Address resolution
// - Connection setup
// - Logging
//
// Example Usage:
//
//   cfg := &UDPSessionConfig{
//     Port: 7655,
//     ParentConn: samConn,
//     Log: logger,
//   }
//
//   session, err := NewUDPSession(cfg)
//   if err != nil {
//     // Handle error
//   }
//   defer session.Close()

// UDPSessionConfig holds all UDP session configuration
type UDPSessionConfig struct {
    Port           int
    ParentConn     net.Conn 
    Log            *logger.Logger
    DefaultPort    int
    AllowZeroPort  bool
    Style          string
    FromPort       string
    ToPort         string
    ReadTimeout    time.Duration
    WriteTimeout   time.Duration
}

// UDPSession represents an established UDP session
type UDPSession struct {
    LocalAddr  *net.UDPAddr
    RemoteAddr *net.UDPAddr
    Conn       *net.UDPConn
}

func (u *UDPSession) SetReadTimeout(timeout time.Duration) error {
    if u.Conn != nil {
        return u.Conn.SetReadDeadline(time.Now().Add(timeout))
    }
    return nil
}

func (u *UDPSession) SetWriteTimeout(timeout time.Duration) error {
    if u.Conn != nil {
        return u.Conn.SetWriteDeadline(time.Now().Add(timeout))
    }
    return nil
}

func (u UDPSession) LocalPort() int {
	return u.LocalAddr.Port
}

func (u UDPSession) Close() {
	u.Conn.Close()
}

// NewUDPSession creates and configures a new UDP session
func NewUDPSession(cfg *UDPSessionConfig) (*UDPSession, error) {
    if err := validatePort(cfg.Port, cfg.AllowZeroPort); err != nil {
        cfg.Log.WithError(err).Error("Invalid UDP port configuration")
        return nil, err
    }

    port := cfg.Port
    if port == 0 {
        port = cfg.DefaultPort
        cfg.Log.WithField("port", port).Debug("Using default UDP port")
    }

    laddr, raddr, err := resolveAddresses(cfg.ParentConn, port)
    if err != nil {
        return nil, fmt.Errorf("address resolution failed: %w", err)
    }

    conn, err := net.ListenUDP("udp4", laddr) 
    if err != nil {
        return nil, fmt.Errorf("UDP listen failed: %w", err)
    }

    return &UDPSession{
        LocalAddr:  laddr,
        RemoteAddr: raddr, 
        Conn:       conn,
    }, nil
}

func validatePort(port int, allowZero bool) error {
    if port < 0 || port > 65535 {
        return errors.New("port must be between 0-65535")
    }
    if port == 0 && !allowZero {
        return errors.New("port 0 not allowed in this context") 
    }
    return nil
}

func resolveAddresses(parent net.Conn, remotePort int) (*net.UDPAddr, *net.UDPAddr, error) {
    lhost, _, err := net.SplitHostPort(parent.LocalAddr().String())
    if err != nil {
        return nil, nil, err
    }

    laddr, err := net.ResolveUDPAddr("udp4", lhost+":0")
    if err != nil {
        return nil, nil, err
    }

    rhost, _, err := net.SplitHostPort(parent.RemoteAddr().String())
    if err != nil {
        return nil, nil, err
    }

    raddr, err := net.ResolveUDPAddr("udp4", rhost+":"+strconv.Itoa(remotePort))
    if err != nil {
        return nil, nil, err
    }

    return laddr, raddr, nil
}