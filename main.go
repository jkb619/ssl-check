// sg-update project main.go
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"golang.org/x/crypto/ssh"
)

type Versions struct {
	Package_name    string
	Package_version string
}

type JsonObject struct {
	Defaults []Versions
}

func GetDefaultsFromFile(file string) JsonObject {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		panic("Missing defaults.json file " + err.Error())
	}
	var default_json JsonObject
	err = json.Unmarshal(content, &default_json)
	if err != nil {
		panic("Unmarshalling error from Json " + err.Error())
	}
	return default_json
}

func PublicKeyFile(file string) ssh.AuthMethod {
	buffer, err := ioutil.ReadFile(file)
	if err != nil {
		return nil
	}

	key, err := ssh.ParsePrivateKey(buffer)
	if err != nil {
		return nil
	}
	return ssh.PublicKeys(key)
}

func SshGetVersion(ip string, hostid string, hostapp string, expected_versions JsonObject) {

	sshConfig := &ssh.ClientConfig{
		User: "ec2-user",
		Auth: []ssh.AuthMethod{
			PublicKeyFile("/home/jobrown/.ssh/gbxit.pem"),
			// ssh.Password("test"),
		},
	}

	connection, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", ip, "22"), sshConfig)
	if err != nil {
		// panic("Failed to dial: " + err.Error())
		fmt.Println(hostid, " : ", ip, " : SSH_AUTH_FAILURE")
	} else {

		for packages := range expected_versions.Defaults {
			package_name := expected_versions.Defaults[packages].Package_name
			default_version := expected_versions.Defaults[packages].Package_version

			session, err := connection.NewSession()
			if err != nil {
				panic("Failed to create session: " + err.Error())
			}

			stdout, err := session.StdoutPipe()
			if err != nil {
				panic("Unable to setup stdout for session: %v" + err.Error())
			}

			r := bufio.NewReader(stdout)
			cmd := "rpm -qa|grep " + package_name + "-[0-9]"
			session.Run(cmd)
			package_bytes, _, err := r.ReadLine()
			if err != nil {
				panic("Unable to read ssh output: %v" + err.Error())
			}
			n := len(package_bytes)
			package_ver := string(package_bytes[:n])
			session.Close()
			status := "FAILED"
			if package_ver == default_version {
				status = "OK"
			}
			fmt.Println(hostid, ":", hostapp, ":", ip, ":", package_ver, ":", default_version, ":", status)
		}
		//session2, err := connection.NewSession()
		//if err != nil {
		//			panic("Failed to create session: " + err.Error())
		//		}
		//
		//		stdout, err := session2.StdoutPipe()
		//		if err != nil {
		//			panic("Unable to setup stdout for session: %v" + err.Error())
		//		}

		//		s := bufio.NewReader(stdout)
		//		cmd := "openssl s_client -connect 127.0.0.1:443 -ssl2"
		//		session2.Run(cmd)
		//		ssl_support_bytes, _, err := s.ReadLine()
		//		if err != nil {
		//			panic("Unable to read ssh output: %v" + err.Error())
		//		}
		//		fmt.Println(ssl_support_bytes)
		// n := len(ssl_support_bytes)
		// ssl_support := string(ssl_support_bytes[:n])
		//		session2.Close()
		// fmt.Println(hostid, ":", hostapp, ":", ip, ":", ssl_support)
		// os.Exit(0)
	}
}

func main() {
	fmt.Println("Start time: ", time.Now())
	defaults := GetDefaultsFromFile("./defaults.json")
	svc := ec2.New(session.New(), aws.NewConfig().WithRegion("us-east-1"))

	instance_params := &ec2.DescribeInstancesInput{
		DryRun: aws.Bool(false),
		Filters: []*ec2.Filter{
			{
				Name: aws.String("instance-state-name"),
				Values: []*string{
					aws.String("running"),
				},
			},
		},
	}

	instances, err := svc.DescribeInstances(instance_params)
	if err != nil {
		panic(err)
	}
	fmt.Println("> Number of instances: ", len(instances.Reservations))
	for idx, _ := range instances.Reservations {
		for _, inst := range instances.Reservations[idx].Instances {
			hostapp := "UNKNOWN"
			for _, tag := range inst.Tags {
				if *tag.Key == "Name" {
					hostapp = *tag.Value
				}
			}
			go SshGetVersion(*inst.PrivateIpAddress, *inst.InstanceId, hostapp, defaults)
		}
	}
	// fmt.Println("> first element: ", instances.Reservations[0])
	time.Sleep(10 * 1e9)
	fmt.Println("End time: ", time.Now())
}
