// @Author: keepwn
// @Date: 2021/7/10 15:04

package main

import (
	"flag"
	"log"
	"os"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
	"github.com/patrickmn/go-cache"
)

var (
	c *cache.Cache

	flSocket = flag.String("socket", "", "Path to the UNIX domain socket of extension")
	flTimeout = flag.Int("timeout", 5, "Wait for autoload extension")
	flInterval = flag.Int("interval", 5, "Delay of connecting check")
	flPathEnv = flag.String("pathenv", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/root/bin", "Set to PATH environment")
	flVerbose = flag.Bool("verbose", false, "")
)

func main() {
	flag.Parse()

	if *flSocket == "" {
		log.Fatalln("--socket flag cannot be empty")
	}

	// allow for osqueryd to create the socket path
	time.Sleep(2 * time.Second)

	server, err := osquery.NewExtensionManagerServer(
		"com.keepwn.extension.inspecquery",
		*flSocket,
		osquery.ServerTimeout(time.Duration(*flTimeout) * time.Second),
		osquery.ServerPingInterval(time.Duration(*flInterval) * time.Second),
	)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	// set PATH env
	_ = os.Setenv("PATH", *flPathEnv)

	// init cache to improve performance
	c = cache.New(1*time.Minute, 10*time.Minute)

	server.RegisterPlugin(table.NewPlugin("inspec", InspecColumns(), InspecGenerate))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}
