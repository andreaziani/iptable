package main

import (
	"encoding/json"
	"fmt"
	"github.com/jessevdk/go-flags"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)


type Options struct {
	Input       string   `short:"i" long:"input" description:"input dir"`
	Output    string   `short:"o" long:"output" description:"output dir"`
}

type Subnet struct{
	Id int `json:"id"`
	Address string `json:"address"`
	Prefix int `json:"prefix"`
}

type Router struct{
	Id int `json:"id"`
}

type Link struct{
	RouterId int `json:"routerId"`
	InterfaceId string `json:"interfaceId"`
	Ip string `json:"ip"`
	SubnetId int `json:"subnetId"`
}

type Network struct{
	Routers []Router `json:"routers"`
	Subnets []Subnet `json:"subnets"`
	Links []Link `json:"links"`
}

type Communications struct{
	SourceSubnetId int `json:"sourceSubnetId"`
	TargetSubnetId int `json:"targetSubnetId"`
	Protocol string `json:"protocol"`
	SourcePortStart int `json:"sourcePortStart"`
	SourcePortEnd int `json:"sourcePortEnd"`
	TargetPortStart int `json:"targetPortStart"`
	TargetPortEnd int `json:"targetPortEnd"`
	Direction string `json:"direction"`
}

type Input struct{
	Net Network `json:"network"`
	Communication []Communications `json:"communications"`
}

func makeMatrix(i int, j int) [][]string{
	matrix := make([][]string, i)
	for k := 0; k < i; k++ {
		matrix[k] = make([]string, j)
	}
	return matrix
}

func visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatal(err)
		}
		*files = append(*files, path)
		return nil
	}
}


//dfs to find path between 2 subnets
func findPath(rAdj map[int][]int, sAdj map[int][]int, visitedRouters []bool, visitedSubnets []bool, routerParents []int, subnetParents []int, router bool, source int, dest int){
	if source == dest && !router {
		return
	}

	if router {
		visitedRouters[source] = true
		for i := 0; i < len(rAdj[source]); i++ {
			if !visitedSubnets[rAdj[source][i]]{
				subnetParents[rAdj[source][i]] = source
				findPath(rAdj, sAdj, visitedRouters, visitedSubnets, routerParents, subnetParents, !router, rAdj[source][i], dest)
			}
		}
	} else{
		visitedSubnets[source] = true
		for i := 0; i < len(sAdj[source]); i++ {
			if !visitedRouters[sAdj[source][i]] {
				routerParents[sAdj[source][i]] = source
				findPath(rAdj, sAdj, visitedRouters, visitedSubnets, routerParents, subnetParents, !router, sAdj[source][i], dest)
			}
		}
	}

}

func writeRule(folderPath string, filePath string, rules string){
	var rule string
	rule += "* nat\n" + ":OUTPUT ACCEPT [0:0]\n" + ":PREROUTING ACCEPT [0:0]\n" +
		":POSTROUTING ACCEPT [0:0]\n" + "\n" + "COMMIT\n" + "\n" + "* filter\n" +
		":INPUT DROP [0:0]\n" + ":OUTPUT DROP [0:0]\n:FORWARD DROP [0:0]\n"

	rule += rules

	rule += "\n" + "COMMIT\n"

	_ = os.MkdirAll(folderPath, os.ModePerm)
	f, err := os.Create(filePath)
	if err != nil{
		log.Println("create folder")
		log.Fatal(err)
	}

	defer f.Close()
	d1 := []byte(rule)
	n2, err := f.Write(d1)
	if err != nil{
		log.Println("write file")
		log.Fatal(err)
	}

	log.Println(strconv.Itoa(n2) + " written on " + filePath)
}

func tcpUdpRule(input Input, communications Communications, routerID int, sourceSubnetID int, destSubnetID int, interfaces [][]string, bidirectional bool) string{
	rule := "-A FORWARD -p " + communications.Protocol +  " --sport "  + strconv.Itoa(communications.SourcePortStart) +
		":" + strconv.Itoa(communications.SourcePortEnd) + " --dport " + strconv.Itoa(communications.TargetPortStart) + ":" + strconv.Itoa(communications.TargetPortEnd) +
		" -s " + input.Net.Subnets[communications.SourceSubnetId].Address + "/" + strconv.Itoa(input.Net.Subnets[communications.SourceSubnetId].Prefix) +
		" -d " + input.Net.Subnets[communications.TargetSubnetId].Address + "/" + strconv.Itoa(input.Net.Subnets[communications.TargetSubnetId].Prefix) +
		" -i " +  interfaces[routerID][sourceSubnetID] + " -o " + interfaces[routerID][destSubnetID] + " -m state --state NEW,ESTABLISHED -j ACCEPT\n"

	if bidirectional {
		rule += "-A FORWARD -p " + communications.Protocol +  " --sport "  + strconv.Itoa(communications.TargetPortStart) + ":" + strconv.Itoa(communications.TargetPortEnd) +
			" --dport " + strconv.Itoa(communications.SourcePortStart) + ":" + strconv.Itoa(communications.SourcePortEnd) +
			" -s " + input.Net.Subnets[communications.TargetSubnetId].Address + "/" + strconv.Itoa(input.Net.Subnets[communications.SourceSubnetId].Prefix) +
			" -d " + input.Net.Subnets[communications.SourceSubnetId].Address + "/" + strconv.Itoa(input.Net.Subnets[communications.TargetSubnetId].Prefix) +
			" -i " +  interfaces[routerID][destSubnetID] + " -o " + interfaces[routerID][sourceSubnetID] + " -m state --state ESTABLISHED -j ACCEPT\n"
	}

	return rule
}

func icmpRule(input Input, communications Communications, routerID int, sourceSubnetID int, destSubnetID int, interfaces [][]string, bidirectional bool) string{
	rule := "-A FORWARD -p " + communications.Protocol + " -s " + input.Net.Subnets[communications.SourceSubnetId].Address + "/" + strconv.Itoa(input.Net.Subnets[communications.SourceSubnetId].Prefix) +
		" -d " + input.Net.Subnets[communications.TargetSubnetId].Address + "/" + strconv.Itoa(input.Net.Subnets[communications.TargetSubnetId].Prefix) +
		" -i " +  interfaces[routerID][sourceSubnetID] + " -o " + interfaces[routerID][destSubnetID] + " -m state --state NEW,ESTABLISHED -j ACCEPT\n"

	if bidirectional {
		rule += "-A FORWARD -p " + communications.Protocol + " -s " + input.Net.Subnets[communications.TargetSubnetId].Address + "/" + strconv.Itoa(input.Net.Subnets[communications.SourceSubnetId].Prefix) +
			" -d " + input.Net.Subnets[communications.SourceSubnetId].Address + "/" + strconv.Itoa(input.Net.Subnets[communications.TargetSubnetId].Prefix) +
			" -i " +  interfaces[routerID][destSubnetID] + " -o " + interfaces[routerID][sourceSubnetID] + " -m state --state NEW,ESTABLISHED -j ACCEPT\n"
	}
	return rule
}

func main() {
	var opts Options

	_, err := flags.ParseArgs(&opts, os.Args)
	if err != nil {
		log.Println("parse arg")
		log.Fatal(err)
	}


	var inputFiles []string

	err = filepath.Walk(opts.Input, visit(&inputFiles))
	if err != nil {
		log.Println("file walk")
		log.Fatal(err)
	}
	inputFiles = inputFiles[1:] // skip directory

	_ = os.MkdirAll(opts.Output, os.ModePerm)


	// foreach input file
	for _, file := range inputFiles {
		dat, err := ioutil.ReadFile(file)
		if err != nil {
			log.Println("foreach file")
			log.Fatal(err)
		}


		n := file[len(opts.Input):]
		n = strings.Replace(n, ".json", "", -1)

		count, _ := strconv.Atoi(n)

		fmt.Print(count)
		var input Input
		_ = json.Unmarshal(dat, &input) // parse json

		routers := make(map[int][]int)
		subnets := make(map[int][]int)
		r := len(input.Net.Routers)
		s := len(input.Net.Subnets)
		interfaces := makeMatrix(r, s)

		//build topology
		for i := 0; i < len(input.Net.Links); i++ {
			routers[input.Net.Links[i].RouterId] = append(routers[input.Net.Links[i].RouterId],input.Net.Links[i].SubnetId)
			subnets[input.Net.Links[i].SubnetId] = append(subnets[input.Net.Links[i].SubnetId], input.Net.Links[i].RouterId)
			interfaces[input.Net.Links[i].RouterId][input.Net.Links[i].SubnetId] = input.Net.Links[i].InterfaceId
		}

		routersRule := make(map[int]string)
		for i := 0; i < len(input.Net.Routers); i++{
			routersRule[i] = ""
		}

		//find path between 2 subnets
		for i := 0; i < len(input.Communication); i++ {
			com := input.Communication[i]
			visitedRouters := make([]bool, len(input.Net.Routers))
			visitedSubnets := make([]bool, len(input.Net.Subnets))
			routerParents := make([]int, len(input.Net.Routers))
			subnetParents := make([]int, len(input.Net.Subnets))
			findPath(routers, subnets, visitedRouters, visitedSubnets, routerParents, subnetParents, false, com.SourceSubnetId,com.TargetSubnetId)

			after := com.TargetSubnetId
			curr := com.TargetSubnetId
			isRouter := false
			for curr != com.SourceSubnetId || isRouter {
				if isRouter {
					switch com.Protocol {
						case "tcp": routersRule[curr] += tcpUdpRule(input, com, curr, routerParents[curr], after, interfaces, com.Direction == "bidirectional")
						case "udp": routersRule[curr] += tcpUdpRule(input, com, curr, routerParents[curr], after, interfaces, com.Direction == "bidirectional")
						case "icmp": routersRule[curr] += icmpRule(input, com, curr, routerParents[curr], after, interfaces, com.Direction == "bidirectional")
					}
					after = curr
					curr = routerParents[curr]
					isRouter = false
				} else {
					after = curr
					curr = subnetParents[curr]
					isRouter = true
				}
			}
		}

		for i := 0; i < len(input.Net.Routers); i++{
			writeRule(opts.Output + "/" +strconv.Itoa(count), opts.Output + "/" +strconv.Itoa(count) + "/" +strconv.Itoa(i), routersRule[i])
		}

	}

}
