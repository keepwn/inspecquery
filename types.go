// @Author: keepwn
// @Date: 2021/7/10 15:04

package main

import (
	"strconv"
)

type InspecReport struct {
	Platform Platform  `json:"platform"`
	Profiles []Profile `json:"profiles"`
	Version  string    `json:"version"`

	profilePath string
}

type Platform struct {
	Name    string `json:"name"`
	Release string `json:"release"`
}

type Profile struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	Sha256         string      `json:"sha256"`
	Title          string      `json:"title"`
	Maintainer     string      `json:"maintainer"`
	Summary        string      `json:"summary"`
	License        string      `json:"license"`
	Copyright      string      `json:"copyright"`
	CopyrightEmail string      `json:"copyright_email"`
	Supports       []Support   `json:"supports"`
	Attributes     []Attribute `json:"attributes"`
	Groups         []Group     `json:"groups"`
	Controls       []Control   `json:"controls"`
	Status         string      `json:"status"`
	StatusMessage  string      `json:"status_message"`
}

type Attribute struct {
	Name    string  `json:"name"`
	Options Options `json:"options"`
}

type Options struct {
	Type     string `json:"type"`
	Required bool   `json:"required"`
	Value    int64  `json:"value"`
}

type Control struct {
	ID           string        `json:"id"`
	Title        string        `json:"title"`
	Desc         string        `json:"desc"`
	Descriptions []Description `json:"descriptions"`
	Impact       interface{}   `json:"impact"`
	Tags         Tags          `json:"tags"`
	Results      []Result      `json:"results"`
}

type Description struct {
	Label string `json:"label"`
	Data  string `json:"data"`
}

type Result struct {
	Status         string  `json:"status"`
	CodeDesc       string  `json:"code_desc"`
	RunTime        float64 `json:"run_time"`
	StartTime      string  `json:"start_time"`
	ResourceClass  string  `json:"resource_class"`
	ResourceParams string  `json:"resource_params"`
	Message        string  `json:"message,omitempty"`
}

type Tags struct {
	Cis   string `json:"cis"`
	Level int64  `json:"level"`
}

type Group struct {
	ID       string   `json:"id"`
	Controls []string `json:"controls"`
	Title    string   `json:"title"`
}

type Support struct {
	PlatformFamily string `json:"platform-family"`
}

func (r InspecReport) toRows() []map[string]string {
	var rows []map[string]string

	for _, p := range r.Profiles {

		// create the map of controls
		controlsMap := make(map[string]Group)
		for _, g := range p.Groups {
			for _, c := range g.Controls {
				controlsMap[c] = g
			}
		}

		for _, c := range p.Controls {
			row := map[string]string{
				"group":   controlsMap[c.ID].Title,
				"control": c.ID,
				"title":   c.Title,
				"desc":    c.Desc,
			}

			if len(c.Descriptions) > 0 {
				row["description"] = c.Descriptions[0].Data
			}

			if c.Impact != nil {
				switch c.Impact.(type) {
				case int64:
					row["impact"] = strconv.FormatInt(c.Impact.(int64), 10)
				case float64:
					row["impact"] = strconv.FormatFloat(c.Impact.(float64), 'g', 12, 64)
				case string:
					row["impact"] = c.Impact.(string)
				}
			}

			result := "passed"

			for _, item := range c.Results {
				if item.Status == "failed" {
					result = "failed"
					break
				}
			}
			for _, item := range c.Results {
				if item.Status == "skipped" {
					result = "skipped"
					break
				}
			}

			row["result"] = result
			row["profile_path"] = r.profilePath
			rows = append(rows, row)
		}
	}

	return rows
}
