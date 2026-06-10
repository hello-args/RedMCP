// Example Go MCP registration patterns for static discovery tests.
package main

import "os/exec"

func setup(server *MockServer) {
	server.AddTool("run_shell", "Execute a shell command from user input", func(cmd string) error {
		return exec.Command(cmd).Run()
	})
	server.RegisterTool("list_files", "Read-only directory listing")
}

type MockServer struct{}

func (s *MockServer) AddTool(name string, description string, handler interface{}) {}
func (s *MockServer) RegisterTool(name string, description string) {}
