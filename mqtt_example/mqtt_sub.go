package main

import (
	"flag"
	"fmt"
	"net"
	"os"

	proto "github.com/huin/mqtt"
	"github.com/jeffallen/mqtt"
)

var host = flag.String("host", "192.168.0.99:1883", "hostname of broker")
var id = flag.String("id", "testpc", "client id")
var user = flag.String("user", "", "snqu")
var pass = flag.String("pass", "", "snqu2018")
var dump = flag.Bool("dump", false, "dump messages?")

func main() {
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "usage: sub topic [topic topic...]")
		return
	}

	conn, err := net.Dial("tcp", *host)
	if err != nil {
		fmt.Fprint(os.Stderr, "dial: ", err)
		return
	}
	cc := mqtt.NewClientConn(conn)
	cc.Dump = *dump
	cc.ClientId = *id

	tq := make([]proto.TopicQos, flag.NArg())
	for i := 0; i < flag.NArg(); i++ {
		tq[i].Topic = flag.Arg(i)
		tq[i].Qos = proto.QosAtMostOnce
	}

	if err := cc.Connect(*user, *pass); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("Connected with client id", cc.ClientId)
	cc.Subscribe(tq)

	for m := range cc.Incoming {
		fmt.Print(m.TopicName, "\t")
		m.Payload.WritePayload(os.Stdout)
		fmt.Println("\tr: ", m.Header.Retain)
	}
}
