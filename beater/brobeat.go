package beater

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/elastic/beats/libbeat/publisher"

	"github.com/blacktop/brobeat/config"
)

// Brobeat beat struct
type Brobeat struct {
	done   chan struct{}
	config config.Config
	client publisher.Client
}

// New creates beater
func New(b *beat.Beat, cfg *common.Config) (beat.Beater, error) {
	config := config.DefaultConfig
	if err := cfg.Unpack(&config); err != nil {
		return nil, fmt.Errorf("Error reading config file: %v", err)
	}

	bt := &Brobeat{
		done:   make(chan struct{}),
		config: config,
	}
	return bt, nil
}

// Run start beater
func (bt *Brobeat) Run(b *beat.Beat) error {
	logp.Info("brobeat is running! Hit CTRL-C to stop it.")

	bt.client = b.Publisher.Connect()
	path := bt.config.Path

	info, err := os.Stat(path)

	// Check that folder exists
	if os.IsNotExist(err) {
		logp.Err("error: folder does not exist.")
		return nil
	}
	// Check that path is a folder and not a file
	if info.IsDir() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		defer watcher.Close()

		err = watcher.Add(path)
		if err != nil {
			log.Fatal(err)
		}

		for {
			select {
			case event := <-watcher.Events:
				if event.Op&fsnotify.Chmod == fsnotify.Chmod {
					logp.Info("Created file:", event.Name)

					// stat, err := os.Stat(event.Name)
					// if err != nil {
					// 	logp.Err("Stat Error: ", err)
					// }
					// logp.Info("%#v", stat)

					// Parse bro-log file
					bro := ParseLogFile(event.Name)

					for _, log := range bro.Logs {
						fmt.Println(log)
						event := common.MapStr{
							"@timestamp":  common.Time(time.Now()),
							"type":        b.Name,
							"log.type":    log.Type,
							"log.created": log.Created,
						}
						for _, field := range log.Fields {
							// use ts field as @timestamp
							if field.Name == log.Type+".ts" {
								time, err := convertTs2Time(field.Value)
								if err != nil {
									return err
								}
								fmt.Println(time)
								event["@timestamp"] = common.Time(time)
							}
							// don't output fields with '-' values
							if field.Value != log.UnsetField {
								event[field.Name] = field.Value
							}
						}

						bt.client.PublishEvent(event)
						logp.Info("Event sent")
					}
				}
			case err = <-watcher.Errors:
				logp.Err("error:", err)
			case <-bt.done:
				return nil
			}
		}
	} else {
		logp.Err("error: path is not a folder")
	}

	return nil
}

// Stop stops beater
func (bt *Brobeat) Stop() {
	bt.client.Close()
	close(bt.done)
}
