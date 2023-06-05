package nucleiplus

import (
	"context"
	"os"
	"path"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/core"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/stringslice"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/testutils"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/ratelimit"
)

func Nuclei(outputWriter *testutils.MockOutputWriter, targets []string, templatePaths []string, debug bool, tags, excludeTags goflags.StringSlice) (err error) {
	cache := hosterrorscache.New(30, hosterrorscache.DefaultMaxHostsCount, nil)
	defer cache.Close()

	mockProgress := &testutils.MockProgressClient{}
	reportingClient, _ := reporting.New(&reporting.Options{}, "")
	defer reportingClient.Close()

	defaultOpts := types.DefaultOptions()
	protocolstate.Init(defaultOpts)
	protocolinit.Init(defaultOpts)

	if len(templatePaths) > 0 {
		defaultOpts.Templates = templatePaths
	}
	defaultOpts.Debug = debug
	defaultOpts.Validate = true
	defaultOpts.UpdateTemplates = true
	defaultOpts.Verbose = true
	defaultOpts.EnableProgressBar = true
	defaultOpts.ExcludeTags = excludeTags
	defaultOpts.Tags = tags

	interactOpts := interactsh.DefaultOptions(outputWriter, reportingClient, mockProgress)
	interactClient, err := interactsh.New(interactOpts)
	if err != nil {
		err = errors.Wrap(err, "Could not create interact client")
	}
	defer interactClient.Close()

	home, _ := os.UserHomeDir()
	catalog := disk.NewCatalog(path.Join(home, TemplatesDirectory))
	executorOpts := protocols.ExecutorOptions{
		Output:          outputWriter,
		Options:         defaultOpts,
		Progress:        mockProgress,
		Catalog:         catalog,
		IssuesClient:    reportingClient,
		RateLimiter:     ratelimit.New(context.Background(), 150, time.Second),
		Interactsh:      interactClient,
		HostErrorsCache: cache,
		Colorizer:       aurora.NewAurora(true),
		ResumeCfg:       types.NewResumeCfg(),
	}
	engine := core.New(defaultOpts)
	engine.SetExecuterOptions(executorOpts)

	workflowLoader, err := parsers.NewLoader(&executorOpts)
	if err != nil {
		err = errors.Wrap(err, "Could not create workflow loader")
	}
	executorOpts.WorkflowLoader = workflowLoader

	store, err := loader.New(loader.NewConfig(defaultOpts, catalog, executorOpts))
	if err != nil {
		err = errors.Wrap(err, "Could not create loader client")
	}
	store.Load()

	if len(store.Templates()) == 0 {
		err = errors.New("There is no POC template that meets the requirements")
		return
	}

	tpls, err := CustomTemplateFilter(store.Templates(), tags)

	var inputArgs []*contextargs.MetaInput
	for _, target := range targets {
		inputArgs = append(inputArgs, &contextargs.MetaInput{Input: target})
	}
	input := &inputs.SimpleInputProvider{Inputs: inputArgs}

	_ = engine.Execute(tpls, input)
	engine.WorkPool().Wait() // Wait for the scan to finish

	return
}

// CustomTemplateFilter 自定义模版过滤器
func CustomTemplateFilter(srcTpls []*templates.Template, tags goflags.StringSlice) (tpls []*templates.Template, err error) {
	for _, srcTpl := range srcTpls {
		if isTagAndMatch(srcTpl.Info.Tags, tags) {
			tpls = append(tpls, srcTpl)
		}
	}

	return
}

// isTagAndMatch 判断符合 包含tags标签列表要求 的模版
func isTagAndMatch(templateTags stringslice.StringSlice, tags goflags.StringSlice) bool {
	if IsStringSliceEqual(intersect(templateTags.ToSlice(), tags), tags) {
		return true
	}

	return false
}

// intersect 求俩string切片的交集
func intersect(a []string, b []string) []string {
	inter := make([]string, 0)
	mp := make(map[string]bool)

	for _, s := range a {
		if _, ok := mp[s]; !ok {
			mp[s] = true
		}
	}
	for _, s := range b {
		if _, ok := mp[s]; ok {
			inter = append(inter, s)
		}
	}

	return inter
}

// IsStringSliceEqual 判断俩string切片是否相等
func IsStringSliceEqual(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}

	if (x == nil) != (y == nil) {
		return false
	}

	for i, v := range x {
		if v != y[i] {
			return false
		}
	}

	return true
}
