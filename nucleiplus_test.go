package nucleiplus

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"testing"

	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
)

func TestNuclei(t *testing.T) {
	// download config & templates
	Setup()

	// 待检测目标地址
	targets := []string{
		"http://192.168.126.128:8080",
	}

	// 指定模版
	home, _ := os.UserHomeDir()
	templatePath := path.Join(home, "nuclei-templates/CVE-2021-3129.yaml")

	// 设置输出对象
	res := make([]*output.ResultEvent, 0)
	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		if len(event.Response) > 10240 {
			event.Response = event.Response[:10240]
		}
		res = append(res, event)
	}

	for _, target := range targets {
		Nuclei(target, templatePath, outputWriter)
	}

	// 输出检测结果
	s, _ := json.Marshal(res)
	fmt.Println(string(s))
}
