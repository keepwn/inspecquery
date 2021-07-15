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
		table.TextColumn("id"),
		table.TextColumn("title"),
		table.TextColumn("desc"),
		table.TextColumn("description"),
		table.TextColumn("impact"),
		table.TextColumn("result"),
	}
}

func InspecGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	tmpDir, err := ioutil.TempDir("", "inspec")
	if err != nil {
		return nil, err
	}

	reportPath := filepath.Join(tmpDir, "report.json")

	if cnstList, ok := queryContext.Constraints["profile_path"]; ok {
		for _, cnst := range cnstList.Constraints {
			if cnst.Operator == table.OperatorEquals {
				// escape
				// only local path or remote path
				reg := regexp.MustCompile("[^a-zA-Z0-9:/._-]+")
				profilePath := reg.ReplaceAllString(cnst.Expression, "")

				log.Println("profile: ", profilePath)

				// get from cache
				if report, found := c.Get(profilePath); found {
					return report.(InspecReport).toRows(), nil
				}

				result, err := InspecExec(profilePath, reportPath)
				if err != nil {
					return nil, err
				}

				// put to cache
				c.Set(profilePath, result, cache.DefaultExpiration)

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

func InspecExec(profile string, reportFile string) (InspecReport, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	// check
	if !IsInspecExists() {
		return InspecReport{}, errors.New("didn't find 'inspec' executable")
	}

	// exec
	cmd := exec.Command("inspec", "exec", profile, fmt.Sprintf("--reporter=json:%s", reportFile), "--chef-license=accept-silent")
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
