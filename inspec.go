// @Author: keepwn
// @Date: 2021/7/10 15:04

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/osquery/osquery-go/plugin/table"
	"github.com/patrickmn/go-cache"
)

func InspecColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("profile_path"),
		table.TextColumn("group"),
		table.TextColumn("control"),
		table.TextColumn("title"),
		table.TextColumn("desc"),
		table.TextColumn("description"),
		table.TextColumn("impact"),
		table.TextColumn("result"),
	}
}

type ControlParam interface {
	ToString() string
}

type DefaultControlParam struct {
	Control string
}

func (p DefaultControlParam) ToString() string {
	return p.Control
}

type RegexControlParam struct {
	ControlRegex string
}

func (p RegexControlParam) ToString() string {
	// escape
	// must remove %
	reg := regexp.MustCompile("[^a-zA-Z0-9._-]+")
	regexStr := reg.ReplaceAllString(p.ControlRegex, "")

	return fmt.Sprintf("/%s/", regexStr)
}

func InspecGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	tmpDir, err := ioutil.TempDir("", "inspec")
	if err != nil {
		return nil, err
	}

	reportPath := filepath.Join(tmpDir, "report.json")

	var controlParam ControlParam

	// eg. where control = 'control-1.1'
	if cnstList, ok := queryContext.Constraints["control"]; ok {
		for _, cnst := range cnstList.Constraints {
			// eg. where control = 'control-1.1'
			// eg. where control IN ('control-1.1')
			// eg. where control IN ('control-1.1', 'control-1.2')
			// 	   Osquery will execute with different expression twice
			if cnst.Operator == table.OperatorEquals {
				controlParam = &DefaultControlParam{Control: cnst.Expression}
				break
			}
			// eg. where control like 'control-1.1%'
			// eg. where control like '%control-1.1'
			// eg. where control like '%control-1.1%'
			if cnst.Operator == table.OperatorLike {
				controlParam = &RegexControlParam{ControlRegex: cnst.Expression}
				break
			}
		}
	}

	if cnstList, ok := queryContext.Constraints["profile_path"]; ok {
		for _, cnst := range cnstList.Constraints {
			if cnst.Operator == table.OperatorEquals {
				// escape
				// only local path or remote path
				reg := regexp.MustCompile("[^a-zA-Z0-9:/._-]+")
				profilePath := reg.ReplaceAllString(cnst.Expression, "")

				// get from cache
				cacheKey := profilePath
				if controlParam != nil {
					cacheKey += "::" + controlParam.ToString()
				}

				if report, found := c.Get(cacheKey); found {
					log.Println(fmt.Sprintf("profile: %s, result from cached [%s]", profilePath, cacheKey))
					return report.(InspecReport).toRows(), nil
				}
				log.Println("profile: ", profilePath)

				result, err := InspecExec(profilePath, reportPath, controlParam)
				if err != nil {
					return nil, err
				}

				// put to cache
				c.Set(cacheKey, result, cache.DefaultExpiration)

				return result.toRows(), nil
			}
		}
	}
	return nil, errors.New("query to table exec must have a WHERE clause on 'profile_path'")
}

func IsInspecExists() bool {
	if _, err := exec.LookPath("inspec"); err != nil {
		return false
	}
	return true
}

func InspecExec(profile string, reportFile string, controlParam ControlParam) (InspecReport, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// check
	if !IsInspecExists() {
		return InspecReport{}, errors.New("didn't find 'inspec' executable")
	}

	// exec
	var cmd *exec.Cmd
	if controlParam == nil {
		cmd = exec.Command(
			"inspec",
			"exec",
			profile,
			fmt.Sprintf("--reporter=json:%s", reportFile),
			"--chef-license=accept-silent",
		)
	} else {
		cmd = exec.Command(
			"inspec",
			"exec",
			profile,
			fmt.Sprintf("--reporter=json:%s", reportFile),
			fmt.Sprintf("--controls=%s", controlParam.ToString()),
			"--chef-license=accept-silent",
		)
	}

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			if exitError.ExitCode() == 1 || exitError.ExitCode() == 2 || exitError.ExitCode() == 3 {
				log.Println(fmt.Sprintf("exit code: %d", exitError.ExitCode()))
				log.Println(fmt.Sprintf("err str: %s", stderr.String()))
				return InspecReport{}, err
			}
		}
		if stderr.String() != "" {
			log.Println(fmt.Sprintf("err str: %s", stderr.String()))
		}
	}

	// read report
	data, err := ioutil.ReadFile(reportFile)
	if err != nil {
		return InspecReport{}, err
	}

	var report InspecReport
	if err := json.Unmarshal(data, &report); err != nil {
		return InspecReport{}, err
	}

	report.profilePath = profile

	return report, nil
}
