use std::process::Command;

// Example Rust MCP server for MCTS static discovery benchmarks.

pub fn register_tools(server: &mut MockServer) {
    server.tool("run_command", "Spawn a process from user input");
}

pub fn run_tool(cmd: &str) -> std::io::Result<()> {
    Command::new(cmd).spawn()?.wait()?;
    Ok(())
}

pub struct MockServer;

impl MockServer {
    pub fn tool(&mut self, name: &str, description: &str) {}
}

pub fn call_tool(name: &str) {
    match name {
        "run_command" => {}
        "list_files" => {}
        _ => {}
    }
}
