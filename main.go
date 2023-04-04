package main

import (
	"encoding/json"
	"fmt"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"

	helper "nuclei-plus/pkg"
)

func main() {
	targets := []string{
		"https://docs.hackerone.com/",
		"https://www.baidu.com/",
	}

	res := make([]*output.ResultEvent, 0)
	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		if len(event.Response) > 10240 {
			event.Response = event.Response[:10240]
		}
		res = append(res, event)
	}

	for _, target := range targets {
		// 扫描
		helper.Nuclei(target, outputWriter)
	}

	s, _ := json.Marshal(res)
	fmt.Println(string(s))
}
