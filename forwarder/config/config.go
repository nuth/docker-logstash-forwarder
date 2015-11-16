// Package config implements functions to manipulate logstash-forwarder configs.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	docker "github.com/fsouza/go-dockerclient"
	logging "github.com/op/go-logging"
)

var log = logging.MustGetLogger("config")

// Network section of a configuration.
type Network struct {
	Servers        []string `json:"servers"`
	SslCertificate string   `json:"ssl certificate"`
	SslKey         string   `json:"ssl key"`
	SslCa          string   `json:"ssl ca"`
	Timeout        int64    `json:"timeout"`
}

// File section of a configuration.
type File struct {
	Paths  []string          `json:"paths"`
	Fields map[string]string `json:"fields"`
}

// LogstashForwarderConfig is the configs root structure.
type LogstashForwarderConfig struct {
	Network Network `json:"network"`
	Files   []File  `json:"files"`
}

// AddContainerLogFile adds the containers docker log file to this config.
func (config *LogstashForwarderConfig) AddContainerLogFile(container *docker.Container) {
	id := container.ID
	file := File{}
	file.Paths = []string{fmt.Sprintf("/var/lib/docker/containers/%s/%s-json.log", id, id)}
	file.Fields = make(map[string]string)
	file.Fields["type"] = "docker"
	file.Fields["codec"] = "json"
	file.Fields["docker.id"] = id
	file.Fields["docker.hostname"] = container.Config.Hostname
	file.Fields["docker.name"] = container.Name
	file.Fields["docker.image"] = container.Config.Image

	for k, v := range container.Config.Labels {
		file.Fields["docker.label."+k] = v
	}

	if container.Node != nil {
		file.Fields["docker.node.id"] = container.Node.ID
		file.Fields["docker.node.ip"] = container.Node.IP
		file.Fields["docker.node.name"] = container.Node.Name

		for k, v := range container.Node.Labels {
			file.Fields["docker.node.label."+k] = v
		}
	}

	config.Files = append(config.Files, file)
}

// NewFromFile returns a new config based on the file at path.
func NewFromFile(path string) (*LogstashForwarderConfig, error) {
    dfi, err := os.Stat(path)
    log.Debug("\"%s\"", path)
    if err != nil {
        log.Debug("%s", err.Error())
    } else {
        log.Debug("%s", dfi.Mode())
    }
	configFile, err := os.Open(path)
	defer configFile.Close()
	if err != nil {
		return nil, err
	}

	logstashConfig := new(LogstashForwarderConfig)

	jsonParser := json.NewDecoder(configFile)
    if err = jsonParser.Decode(&logstashConfig); err != nil {
        log.Debug("%s", err.Error())
		return nil, err
	}

	return logstashConfig, nil
}

// NewFromDefault returns a new default config.
func NewFromDefault(logstashEndpoint string) *LogstashForwarderConfig {
	network := Network{
		Servers:        strings.Split(logstashEndpoint, ","),
		SslCertificate: "/mnt/logstash-forwarder/logstash-forwarder.crt",
		SslKey:         "/mnt/logstash-forwarder/logstash-forwarder.key",
		SslCa:          "/mnt/logstash-forwarder/logstash-forwarder.crt",
		Timeout:        15,
	}

	config := &LogstashForwarderConfig{
		Network: network,
		Files:   []File{},
	}

	return config
}

// NewFromContainer returns a new config based on /etc/logstash-forwarder.conf within the container,
// if it exists.
func NewFromContainer(container *docker.Container) (*LogstashForwarderConfig, error) {
	filePath, filePath2, err := calculateFilePath(container, "/etc/logstash-forwarder.conf")

	if err != nil {
		return nil, err
	}

	config, err := NewFromFile(filePath)
    if err != nil {
        log.Debug("No logstash-forwarder config found in diff %s", container.ID)
        log.Debug("%s", err.Error());
		if filePath2 != "" {
			config2, err2 := NewFromFile(filePath2)
			if err2 != nil {
                log.Debug("No logstash-forwarder config found in mnt %s", container.ID)
                log.Debug("%s", err2.Error());
				return nil, err2
			}
			return NewFromContainer2(container, config2)
		} else {
            return nil, err
        }
	}
	return NewFromContainer2(container, config)
}

func NewFromContainer2(container *docker.Container, config *LogstashForwarderConfig) (*LogstashForwarderConfig, error) {
	log.Debug("Found logstash-forwarder config in %s", container.ID)
	id := container.ID

	for _, file := range config.Files {
		log.Debug("Adding files %s of type %s", file.Paths, file.Fields["type"])
        file.Fields["docker.id"] = id
        file.Fields["docker.hostname"] = container.Config.Hostname
        file.Fields["docker.name"] = container.Name
        file.Fields["docker.image"] = container.Config.Image
        for k, v := range container.Config.Labels {
            file.Fields["docker.label."+k] = v
        }

        if container.Node != nil {
            file.Fields["docker.node.id"] = container.Node.ID
            file.Fields["docker.node.ip"] = container.Node.IP
            file.Fields["docker.node.name"] = container.Node.Name

            for k, v := range container.Node.Labels {
                file.Fields["docker.node.label."+k] = v
            }
        }
		for i, path := range file.Paths {
			filePath, _, err := calculateFilePath(container, path)
			if err != nil {
				log.Warning("Unable to add log file: %s", err)
			} else {
                file.Paths[i] = filePath
                file.Fields["file.name"] = path;
            }
        }
	}
	return config, nil
}

func calculateFilePath(container *docker.Container, path string) (string, string, error) {
	for k, v := range container.Volumes {
		if strings.HasPrefix(path, k) {
			return v + strings.TrimPrefix(path, k), "", nil
		}
	}

	var prefix = "/var/lib/docker/"
	var res1 = ""
	var res2 = ""
	var suffix = ""
	switch container.Driver {
	case "aufs":
		res1 = prefix + "aufs/diff"
		res2 = prefix + "aufs/mnt"
	case "btrfs":
		res1 = prefix + "btrfs/subvolumes"
	case "devicemapper":
		res1 = prefix + "devicemapper/mnt"
		suffix = "/rootfs"
	case "overlay":
		res1 = prefix + "overlay"
		suffix += "/merged"
	default:
		return "", "", fmt.Errorf("Unable to calculate file path with unknown driver [%s]", container.Driver)
	}
	if res2 != "" {
		res2 = fmt.Sprintf("%s/%s%s%s", res2, container.ID, suffix, path)
	}

	return fmt.Sprintf("%s/%s%s%s", res1, container.ID, suffix, path), res2, nil
}
