package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/StackExchange/wmi"
	proto "github.com/huin/mqtt"
	_ "github.com/icattlecoder/godaemon"
	"github.com/jeffallen/mqtt"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

var logfilename = time.Now().Format("20060102")
var logfilepath = "./"
var logfiletype = "log"
var runlevel = "Run" //Debug / Run
var log = logrus.New()

//MQTT var set
var host = flag.String("host", "192.168.0.99:1883", "hostname of broker")
var id = flag.String("id", "testpc", "client id")
var user = flag.String("user", "", "")
var pass = flag.String("pass", "", "")

// var dump = flag.Bool("dump", false, "dump messages?")
// var retain = flag.Bool("retain", false, "retain message?")
// var wait = flag.Bool("wait", false, "stay connected after publishing?")
var topic = "test" //MQTT Topic

//CPU Info结构体初始化&&全局变量调用
type cpuInfo struct {
	Name                          string
	NumberOfCores                 uint32
	ThreadCount                   uint32
	VirtualizationFirmwareEnabled bool
	ProcessorID                   string
}

var cpuinfo []cpuInfo

//Process Info结构体初始化&&全局变量调用
type Process struct {
	Name                  string
	Description           string
	CreationDate          string
	ExecutablePath        string
	Handle                string
	WorkingSetSize        uint64
	PeakWorkingSetSize    uint32
	MinimumWorkingSetSize uint32
	MaximumWorkingSetSize uint32
	PageFileUsage         uint32
	PeakPageFileUsage     uint32
	ReadOperationCount    uint64
	ReadTransferCount     uint64
	Status                string
	ProcessID             uint32
}

var processlist []Process

//System Info结构体初始化&&全局变量调用
type operatingSystem struct {
	Name    string
	Version string
}

var operatingsystem []operatingSystem

//memoryStatusEx调用
var kernel = syscall.NewLazyDLL("Kernel32.dll")

type memoryStatusEx struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64 // in bytes
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

var memInfo memoryStatusEx

type iNetwork struct {
	Name       string
	IP         string
	MACAddress string
}
type intfInfo struct {
	Name       string
	MacAddress string
	Ipv4       []string
}

var network iNetwork

func getMemoryInfo() {
	GlobalMemoryStatusEx := kernel.NewProc("GlobalMemoryStatusEx")
	memInfo.cbSize = uint32(unsafe.Sizeof(memInfo))
	mem, _, _ := GlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memInfo)))
	if mem == 0 {
		return
	}
}
func getOSInfo() {
	err := wmi.Query("Select * from Win32_OperatingSystem", &operatingsystem)
	if err != nil {
		log.Warn("getOS Info: ", errors.WithStack(err))
		return
	}
}
func getCPUInfo() {
	err := wmi.Query("Select * from Win32_Processor ", &cpuinfo)
	if err != nil {
		log.Warn("getCPU Info: ", errors.WithStack(err))
		// log.WithFields(logrus.Fields{
		// 	"animal": "walrus",
		// }).Info(err)
		return
	}
	log.Debug("Get CPU Info Successful\r\n")
}
func getProcessList() {
	err := wmi.Query("Select * from Win32_Process ", &processlist)
	if err != nil {
		log.Warn("getProcess Info: ", errors.WithStack(err))
		return
	}
	log.Debug("Get Process List Successful\r\n")
}
func getNetworkInfo() error {
	intf, err := net.Interfaces()
	if err != nil {
		log.Error("get network info failed: ", err)
		return err
	}
	var is = make([]intfInfo, len(intf))
	for i, v := range intf {
		ips, err := v.Addrs()
		if err != nil {
			log.Error("get network addr failed:", err)
			return err
		}
		//此处过滤loopback（本地回环）和isatap（isatap隧道）
		if !strings.Contains(v.Name, "Loopback") && !strings.Contains(v.Name, "isatap") {
			is[i].Name = v.Name
			is[i].MacAddress = v.HardwareAddr.String()
			for _, ip := range ips {
				if strings.Contains(ip.String(), ".") {
					is[i].Ipv4 = append(is[i].Ipv4, ip.String())
				}
			}
			network.Name = is[i].Name
			network.MACAddress = is[i].MacAddress
			if len(is[i].Ipv4) > 0 {
				network.IP = is[i].Ipv4[0]
			}
			pubmsg(topic, network)
			log.Debug("Network name:= ", network.Name, "\t")
			log.Debug("IP:= ", network.IP, "\t")
			log.Debug("MACAddress:=", network.MACAddress, "\r\n")
		}

	}

	return nil
}
func main() {
	memoJSON := make(map[string]interface{})
	log.SetFormatter(&logrus.JSONFormatter{}) //设置Log输出格式
	//RunLevel 等级判断以及配置
	if runlevel == "Debug" {
		log.SetLevel(logrus.DebugLevel)
		logrus.SetOutput(os.Stdout)
		log.Debug("Debug Mode Enabled TTY LogOutPut")
	} else if runlevel == "Run" {
		fmt.Println("Running Mode Enabled FileLog Disabled TTY OutPut")
		logfileinit()
		log.SetLevel(logrus.InfoLevel)
	}
	for 0 > 1 {
		//*****************************************************
		//****************Debug Log level**********************
		//*****************************************************
		// log.Debug("Useful debugging information.")
		// log.Info("Something noteworthy happened!")
		// log.Warn("You should probably take a look at this.")
		// log.Error("Something failed but I'm not quitting.")
		// Calls os.Exit(1) after logging
		//log.Fatal("Bye.")
		// Calls panic() after logging
		//log.Panic("I'm bailing.")
		//***************************************************
	} //折叠LogLevel等级
begin:
	reqname, cmd, op := submsg() //订阅消息等待管理员请求
	log.Info("Get Cmd From:", reqname)
	fmt.Println("Get Cmd From:", reqname)
	log.Info("OP Role is:", op)
	fmt.Println("OP Role is:", op)
	//收到请求 判断请求进行操作
	if cmd == "info" {
		log.Info("Get Info Cmd Start Reporting")
		fmt.Println("Get Info Cmd Start Reporting")
		getCPUInfo()
		//topic = cpuinfo[0].ProcessorID
		log.Debug("CPU Name is", cpuinfo[0].Name)
		getProcessList()
		getOSInfo()
		log.Debug("OS is", operatingsystem[0].Name)
		getMemoryInfo()
		//MemInfo JSON interface 构建
		if true {
			memoJSON["cbSize"] = memInfo.cbSize
			memoJSON["dwMemoryLoad"] = memInfo.dwMemoryLoad
			memoJSON["ullTotalPhys"] = memInfo.ullTotalPhys
			memoJSON["ullAvailPhys"] = memInfo.ullAvailPhys
			memoJSON["ullTotalPageFile"] = memInfo.ullTotalPageFile
			memoJSON["ullAvailPageFile"] = memInfo.ullAvailPageFile
			memoJSON["ullTotalVirtual"] = memInfo.ullTotalVirtual
			memoJSON["ullAvailVirtual"] = memInfo.ullAvailVirtual
			memoJSON["ullAvailExtendedVirtual"] = memInfo.ullAvailExtendedVirtual
			log.Debug("Total Mem=: ", memInfo.ullTotalPhys, "\r\n")
			log.Debug("Free  Mem=: ", memInfo.ullAvailPhys, "\r\n")
		}
		getNetworkInfo()
		id := pubmsg(topic, cpuinfo)
		log.Debug("Pub with client id", id)
		pubmsg(topic, memoJSON)
		pubmsg(topic, processlist)
		log.Info("Report Finished")
		fmt.Println("Report Finished")
		goto begin
	} else if cmd == "close" {
		fmt.Println("Get Close Cmd")
		goto end
	} else {
		fmt.Println("Undefine Cmd No Respond")
		goto begin
	}
end:
	fmt.Println("Monitor Terminate")
}
func logfileinit() {
	file, err := os.OpenFile(logfilepath+logfilename+"."+logfiletype, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666) //写入，如果存在文件则追加写入 不清空文件
	if err == nil {
		log.Out = file
	} else {
		log.Info("Failed to log to file, using default stderr")
	}
}
func submsg() (string, string, string) {
	var name, cmd, op string
	conn, err := net.Dial("tcp", *host)
	if err != nil {
		fmt.Fprint(os.Stderr, "dial: ", err)
		log.Error("ERROR Create Connect", err)
	}
	cc := mqtt.NewClientConn(conn)
	//cc.Dump = *dump
	cc.ClientId = *id
	tq := make([]proto.TopicQos, 1)
	tq[0].Topic = "admin"
	tq[0].Qos = proto.QosAtMostOnce
	if err := cc.Connect(*user, *pass); err != nil {
		log.Error(err)
		os.Exit(1)
	}
	//fmt.Println("Connected with client id", cc.ClientId)
	cc.Subscribe(tq)
	for m := range cc.Incoming {
		// fmt.Print(m.TopicName, "\t")
		// m.Payload.WritePayload(os.Stdout)
		// fmt.Println("\tr: ", m.Header.Retain)
		payload := []byte(m.Payload.(proto.BytesPayload))
		var any interface{}
		if err = json.Unmarshal(payload, &any); err != nil {
			log.Error(err)
			any = "{\"status\":\"cmd error\"}"
			break
		}
		c := any.(map[string]interface{}) //Interface 对象实例化
		// fmt.Println(c["Name"])            //输出实例化对象
		// fmt.Println(c["Cmd"])
		name = c["Name"].(string)
		cmd = c["Cmd"].(string)
		op = c["op"].(string)
		break
	}
	return name, cmd, op
}
func pubmsg(topic string, info interface{}) string {
	conn, err := net.Dial("tcp", *host)
	if err != nil {
		fmt.Fprint(os.Stderr, "dial: ", err)
		log.Error("ERROR Create Connect", err)
	}
	cc := mqtt.NewClientConn(conn)
	//cc.Dump = *dump
	if err := cc.Connect(*user, *pass); err != nil {
		fmt.Fprintf(os.Stderr, "connect: %v\n", err)
		os.Exit(1)
	}
	//MQTT推送消息头
	head := "{\"transdata\":\"start\"}"
	// if data, err := json.Marshal(head); err == nil {

	// }
	cc.Publish(&proto.Publish{
		//Header:    proto.Header{Retain: *retain},
		TopicName: topic,
		Payload:   proto.BytesPayload(head),
	})
	// if *wait {
	// 	<-make(chan bool)
	// }
	m := info
	if data, err := json.Marshal(m); err == nil {
		//fmt.Printf("%s\n", data)
		cc.Publish(&proto.Publish{
			//Header:    proto.Header{Retain: *retain},
			TopicName: topic,
			Payload:   proto.BytesPayload(data),
		})
		// if *wait {
		// 	<-make(chan bool)
		// }
	}
	cc.Disconnect()
	return cc.ClientId
}
