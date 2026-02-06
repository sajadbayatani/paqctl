package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
)

// Config is the shared client/server configuration for GFK.
type Config struct {
	Mode                string           `json:"mode"`
	VPSIP               string           `json:"vps_ip"`
	XrayServerIPAddress string           `json:"xray_server_ip_address"`
	TCPPortMapping      map[string]int   `json:"tcp_port_mapping"`
	UDPPortMapping      map[string]int   `json:"udp_port_mapping"`
	VIO                 VIOConfig        `json:"vio"`
	QUIC                QUICConfig       `json:"quic"`
}

// VIOConfig controls the violated TCP transport layer.
type VIOConfig struct {
	TCPServerPort int    `json:"tcp_server_port"`
	TCPClientPort int    `json:"tcp_client_port"`
	UDPServerPort int    `json:"udp_server_port"`
	UDPClientPort int    `json:"udp_client_port"`
	TCPFlags      string `json:"tcp_flags"`
	Interface     string `json:"iface"`
	MyIP          string `json:"my_ip"`
	GatewayMAC    string `json:"gateway_mac"`
	LocalMAC      string `json:"local_mac"`
}

// QUICConfig controls the QUIC tunnel.
type QUICConfig struct {
	ServerPort       int    `json:"server_port"`
	ClientPort       int    `json:"client_port"`
	LocalIP          string `json:"local_ip"`
	IdleTimeoutSec   int    `json:"idle_timeout"`
	UDPTimeoutSec    int    `json:"udp_timeout"`
	MTU              int    `json:"mtu"`
	VerifyCert       bool   `json:"verify_cert"`
	MaxData          int64  `json:"max_data"`
	MaxStreamData    int64  `json:"max_stream_data"`
	AuthCode         string `json:"auth_code"`
	CertFile         string `json:"cert_file"`
	KeyFile          string `json:"key_file"`
}

func Load(path string) (Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var cfg Config
	if err := json.Unmarshal(b, &cfg); err != nil {
		return Config{}, err
	}
	applyDefaults(&cfg)
	return cfg, validate(&cfg)
}

func applyDefaults(cfg *Config) {
	if cfg.XrayServerIPAddress == "" {
		cfg.XrayServerIPAddress = "127.0.0.1"
	}
	if cfg.QUIC.LocalIP == "" {
		cfg.QUIC.LocalIP = "127.0.0.1"
	}
	if cfg.VIO.TCPFlags == "" {
		cfg.VIO.TCPFlags = "AP"
	}
	if cfg.TCPPortMapping == nil {
		cfg.TCPPortMapping = map[string]int{}
	}
	if cfg.UDPPortMapping == nil {
		cfg.UDPPortMapping = map[string]int{}
	}
}

func validate(cfg *Config) error {
	if cfg.VPSIP == "" {
		return errors.New("vps_ip is required")
	}
	if cfg.QUIC.AuthCode == "" {
		return errors.New("quic.auth_code is required")
	}
	if cfg.QUIC.ServerPort == 0 || cfg.QUIC.ClientPort == 0 {
		return errors.New("quic.server_port and quic.client_port are required")
	}
	if cfg.VIO.TCPServerPort == 0 || cfg.VIO.TCPClientPort == 0 || cfg.VIO.UDPServerPort == 0 || cfg.VIO.UDPClientPort == 0 {
		return errors.New("vio tcp/udp ports are required")
	}
	return nil
}

func (cfg *Config) TCPMappings() (map[int]int, error) {
	return parsePortMap(cfg.TCPPortMapping)
}

func (cfg *Config) UDPMappings() (map[int]int, error) {
	return parsePortMap(cfg.UDPPortMapping)
}

func parsePortMap(m map[string]int) (map[int]int, error) {
	res := make(map[int]int, len(m))
	for k, v := range m {
		kp, err := strconv.Atoi(k)
		if err != nil {
			return nil, fmt.Errorf("invalid port mapping key %q: %w", k, err)
		}
		res[kp] = v
	}
	return res, nil
}
