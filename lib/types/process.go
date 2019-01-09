package types

import "github.com/polyverse/masche/process"

type Process struct {
	Info      *process.ProcessInfo `json:"info"`
	Libraries []Library                 `json:"libraries"`
}

type Library struct {
	Path            string `json:"path"`
	PolyverseTained bool   `json:"polyverseTainted"`
}
