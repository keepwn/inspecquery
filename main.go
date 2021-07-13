// @Author: keepwn
// @Date: 2021/7/10 15:04

package main

import (
	"flag"
	"log"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/patrickmn/go-cache"
)

var (
	c *cache.Cache
)

func main() {
	flSocket := flag.String("socket", "", "")
	flTimeout := flag.Int("timeout", 0, "")
	flag.Int("interval", 0, "")
	flag.Bool("verbose", false, "")
	flag.Parse()

	if *flSocket == "" {
		log.Fatalln("--socket flag cannot be empty")
	}

	timeout := time.Duration(*flTimeout) * time.Second

	// allow for osqueryd to create the socket path
	time.Sleep(2 * time.Second)

	server, err := osquery.NewExtensionManagerServer(
		"com.keepwn.extension.inspecquery",
		*flSocket,
		osquery.ServerTimeout(timeout),
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// init cache to improve performance
	c = cache.New(1*time.Minute, 10*time.Minute)

	server.RegisterPlugin(table.NewPlugin("inspec", InspecColumns(), InspecGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
