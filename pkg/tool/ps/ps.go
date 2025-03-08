/*
Copyright 2022 The Authors of https://github.com/CDK-TEAM/CDK .

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ps

import (
	"fmt"
	"github.com/shirou/gopsutil/v3/process"
	"log"
)

func RunPs() {
	ps, err := process.Processes()
	if err != nil {
		log.Fatal("get process list failed.")
	}
	for _, p := range ps {
		pexe, _ := p.Exe()
		ppid, _ := p.Ppid()
		user, _ := p.Username()
		fmt.Printf("%v\t%v\t%v\t%v\n", user, p.Pid, ppid, pexe)
	}
}
