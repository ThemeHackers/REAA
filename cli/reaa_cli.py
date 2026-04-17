#!/usr/bin/env python3
"""
REAA CLI - Reverse Engineering Analysis Assistant Command Line Interface

A beautiful CLI tool for interacting with REAA API endpoints using rich library.
"""

import os
import sys
import json
import requests
from pathlib import Path
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich import print as rprint
import typer

# Initialize Rich Console
console = Console()

# API Configuration
API_BASE_URL = os.getenv("REAA_API_URL", "http://127.0.0.1:5000")
API_KEY = os.getenv("REAA_API_KEY", "")

# Initialize Typer App
app = typer.Typer(
    name="reaa",
    help="REAA - Reverse Engineering Analysis Assistant CLI",
    add_completion=True,
    rich_markup_mode="rich"
)

# Command Groups
auth_app = typer.Typer(help="Authentication commands")
analysis_app = typer.Typer(help="Binary analysis commands")
security_app = typer.Typer(help="Security analysis commands")
active_re_app = typer.Typer(help="Active Reverse Engineering commands")
rag_app = typer.Typer(help="RAG (Retrieval-Augmented Generation) commands")
orchestrator_app = typer.Typer(help="Orchestrator and multi-agent commands")
radare2_app = typer.Typer(help="Radare2 integration commands")
system_app = typer.Typer(help="System and monitoring commands")

app.add_typer(auth_app, name="auth", help="Authentication commands")
app.add_typer(analysis_app, name="analysis", help="Binary analysis commands")
app.add_typer(security_app, name="security", help="Security analysis commands")
app.add_typer(active_re_app, name="active-re", help="Active Reverse Engineering commands")
app.add_typer(rag_app, name="rag", help="RAG commands")
app.add_typer(orchestrator_app, name="orchestrator", help="Orchestrator commands")
app.add_typer(radare2_app, name="r2", help="Radare2 commands")
app.add_typer(system_app, name="system", help="System commands")


class APIClient:
    """API Client for REAA"""
    
    def __init__(self, base_url: str = API_BASE_URL, api_key: str = API_KEY):
        self.base_url = base_url
        self.api_key = api_key
        self.headers = {}
        if api_key:
            self.headers["Authorization"] = f"Bearer {api_key}"
    
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """GET request"""
        try:
            response = requests.get(f"{self.base_url}{endpoint}", headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
            return {"error": str(e)}
    
    def post(self, endpoint: str, data: Optional[Dict] = None, files: Optional[Dict] = None) -> Dict[str, Any]:
        """POST request"""
        try:
            response = requests.post(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                json=data,
                files=files
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
            return {"error": str(e)}
    
    def delete(self, endpoint: str) -> Dict[str, Any]:
        """DELETE request"""
        try:
            response = requests.delete(f"{self.base_url}{endpoint}", headers=self.headers)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            console.print(f"[red]Error: {e}[/red]")
            return {"error": str(e)}


# Global API Client
api_client = APIClient()


def print_header(title: str, subtitle: str = ""):
    """Print beautiful header"""
    console.print(Panel(
        f"[bold cyan]{title}[/bold cyan]\n{subtitle}" if subtitle else f"[bold cyan]{title}[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))


def print_table(data: List[Dict], title: str = ""):
    """Print data as beautiful table"""
    if not data:
        console.print("[yellow]No data to display[/yellow]")
        return
    
    table = Table(title=title, show_header=True, header_style="bold magenta")
    
    # Add columns from first item
    for key in data[0].keys():
        table.add_column(key, style="cyan", overflow="fold")
    
    # Add rows
    for item in data:
        table.add_row(*[str(v) for v in item.values()])
    
    console.print(table)


def print_json(data: Dict[str, Any], title: str = ""):
    """Print data as formatted JSON"""
    if title:
        console.print(f"[bold green]{title}[/bold green]")
    console.print(Syntax(json.dumps(data, indent=2), "json", theme="monokai"))


def print_success(message: str):
    """Print success message"""
    console.print(f"[green]✓[/green] {message}")


def print_error(message: str):
    """Print error message"""
    console.print(f"[red]✗[/red] {message}")


def print_warning(message: str):
    """Print warning message"""
    console.print(f"[yellow]⚠[/yellow] {message}")


def print_info(message: str):
    """Print info message"""
    console.print(f"[blue]ℹ[/blue] {message}")


# ============== ROOT COMMANDS ==============

@app.command()
def version():
    """Show REAA CLI version"""
    print_header("REAA CLI", "Version 1.0.0")
    console.print("\n[bold]API Endpoint:[/bold] ", API_BASE_URL)


@app.command()
def status():
    """Check REAA system status"""
    print_header("System Status")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Checking system status...", total=None)
        
        result = api_client.get("/api/system/status")
        progress.remove_task(task)
    
    if "error" not in result:
        print_table([result], "System Status")
        print_success("System is online")
    else:
        print_error("Failed to get system status")


@app.command()
def config(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="API base URL"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="API key")
):
    """Configure CLI settings"""
    global api_client, API_BASE_URL, API_KEY
    
    if url:
        API_BASE_URL = url
        api_client = APIClient(API_BASE_URL, API_KEY)
        print_success(f"API URL set to: {API_BASE_URL}")
    
    if key:
        API_KEY = key
        api_client = APIClient(API_BASE_URL, API_KEY)
        print_success("API key updated")
    
    if not url and not key:
        print_header("Current Configuration")
        console.print(f"[bold]API URL:[/bold] {API_BASE_URL}")
        console.print(f"[bold]API Key:[/bold] {'*' * len(API_KEY) if API_KEY else 'Not set'}")


# ============== AUTHENTICATION COMMANDS ==============

@auth_app.command("register")
def register(
    username: str = typer.Option(..., "--username", "-u", help="Username"),
    email: str = typer.Option(..., "--email", "-e", help="Email"),
    password: str = typer.Option(..., "--password", "-p", help="Password")
):
    """Register a new user"""
    print_header("User Registration")
    
    data = {
        "username": username,
        "email": email,
        "password": password
    }
    
    result = api_client.post("/api/auth/register", data=data)
    
    if "error" not in result:
        print_success("User registered successfully")
        print_json(result, "Registration Details")
    else:
        print_error("Registration failed")


@auth_app.command("login")
def login(
    username: str = typer.Option(..., "--username", "-u", help="Username"),
    password: str = typer.Option(..., "--password", "-p", help="Password")
):
    """Login and get API token"""
    print_header("User Login")
    
    data = {
        "username": username,
        "password": password
    }
    
    result = api_client.post("/api/auth/login", data=data)
    
    if "error" not in result and "token" in result:
        global API_KEY, api_client
        API_KEY = result["token"]
        api_client = APIClient(API_BASE_URL, API_KEY)
        print_success("Login successful")
        console.print(f"[bold]Token:[/bold] {result['token'][:20]}...")
        print_info("Use this token with --key option or set REAA_API_KEY environment variable")
    else:
        print_error("Login failed")


@auth_app.command("logout")
def logout():
    """Logout current user"""
    print_header("User Logout")
    
    result = api_client.post("/api/auth/logout")
    
    if "error" not in result:
        global API_KEY, api_client
        API_KEY = ""
        api_client = APIClient(API_BASE_URL, API_KEY)
        print_success("Logout successful")
    else:
        print_error("Logout failed")


@auth_app.command("me")
def me():
    """Get current user info"""
    print_header("Current User")
    
    result = api_client.get("/api/auth/me")
    
    if "error" not in result:
        print_table([result], "User Information")
    else:
        print_error("Failed to get user info")


# ============== ANALYSIS COMMANDS ==============

@analysis_app.command("upload")
def upload(
    file_path: str = typer.Argument(..., help="Path to binary file")
):
    """Upload binary for analysis"""
    print_header("Binary Upload")
    
    if not Path(file_path).exists():
        print_error(f"File not found: {file_path}")
        return
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Uploading binary...", total=None)
        
        with open(file_path, "rb") as f:
            files = {"file": (Path(file_path).name, f)}
            result = api_client.post("/upload", files=files)
        
        progress.remove_task(task)
    
    if "error" not in result:
        print_success("Binary uploaded successfully")
        print_json(result, "Upload Result")
    else:
        print_error("Upload failed")


@analysis_app.command("jobs")
def jobs():
    """List all analysis jobs"""
    print_header("Analysis Jobs")
    
    result = api_client.get("/api/jobs")
    
    if "error" not in result and "jobs" in result:
        print_table(result["jobs"], "Jobs List")
        print_info(f"Total jobs: {len(result['jobs'])}")
    else:
        print_error("Failed to get jobs")


@analysis_app.command("status")
def job_status(
    job_id: str = typer.Argument(..., help="Job ID")
):
    """Get job status"""
    print_header(f"Job Status: {job_id}")
    
    result = api_client.get(f"/api/jobs/{job_id}")
    
    if "error" not in result:
        print_json(result, "Job Details")
    else:
        print_error("Failed to get job status")


@analysis_app.command("delete")
def delete_job(
    job_id: str = typer.Argument(..., help="Job ID")
):
    """Delete a job"""
    print_header(f"Delete Job: {job_id}")
    
    if not Confirm.ask(f"Are you sure you want to delete job {job_id}?"):
        print_info("Operation cancelled")
        return
    
    result = api_client.delete(f"/api/jobs/{job_id}")
    
    if "error" not in result:
        print_success("Job deleted successfully")
    else:
        print_error("Failed to delete job")


@analysis_app.command("download")
def download_job(
    job_id: str = typer.Argument(..., help="Job ID"),
    output: str = typer.Option(".", "--output", "-o", help="Output directory")
):
    """Download job artifacts"""
    print_header(f"Download Job: {job_id}")
    
    result = api_client.get(f"/api/jobs/{job_id}/download")
    
    if "error" not in result:
        output_path = Path(output) / f"analysis_results_{job_id[:8]}.zip"
        with open(output_path, "wb") as f:
            f.write(result.content)
        print_success(f"Downloaded to: {output_path}")
    else:
        print_error("Failed to download job")


# ============== SECURITY ANALYSIS COMMANDS ==============

@security_app.command("analyze")
def security_analyze(
    job_id: str = typer.Argument(..., help="Job ID"),
    message: str = typer.Option("Analyze for vulnerabilities", "--message", "-m", help="Analysis message")
):
    """Analyze binary for security vulnerabilities"""
    print_header(f"Security Analysis: {job_id}")
    
    data = {
        "job_id": job_id,
        "message": message
    }
    
    result = api_client.post("/security/analyze", data=data)
    
    if "error" not in result:
        print_success("Security analysis completed")
        print_json(result, "Analysis Result")
    else:
        print_error("Security analysis failed")


@security_app.command("report")
def security_report(
    job_id: str = typer.Argument(..., help="Job ID")
):
    """Get security report for job"""
    print_header(f"Security Report: {job_id}")
    
    result = api_client.get(f"/security/report/{job_id}")
    
    if "error" not in result:
        print_json(result, "Security Report")
    else:
        print_error("Failed to get security report")


@security_app.command("scan")
def security_scan(
    job_id: str = typer.Argument(..., help="Job ID"),
    scan_type: str = typer.Option("comprehensive", "--type", "-t", help="Scan type (memory, apis, input, privilege, comprehensive)")
):
    """Scan binary for vulnerabilities"""
    print_header(f"Security Scan: {job_id}")
    
    data = {
        "job_id": job_id,
        "scan_type": scan_type
    }
    
    result = api_client.post("/security/scan", data=data)
    
    if "error" not in result:
        print_success(f"Scan completed ({scan_type})")
        print_json(result, "Scan Result")
    else:
        print_error("Scan failed")


# ============== ACTIVE RE COMMANDS ==============

@active_re_app.command("plan")
def active_re_plan(
    binary_path: str = typer.Argument(..., help="Path to binary"),
    analysis_goal: str = typer.Option("vulnerability detection", "--goal", "-g", help="Analysis goal"),
    binary_type: str = typer.Option("exe", "--type", "-t", help="Binary type")
):
    """Plan Active RE execution strategy"""
    print_header("Active RE Planning")
    
    data = {
        "binary_path": binary_path,
        "analysis_goal": analysis_goal,
        "binary_type": binary_type
    }
    
    result = api_client.post("/api/active-re/plan", data=data)
    
    if "error" not in result:
        print_success("Execution plan created")
        print_json(result, "Execution Plan")
    else:
        print_error("Failed to create plan")


@active_re_app.command("execute")
def active_re_execute(
    job_id: str = typer.Argument(..., help="Job ID"),
    binary_path: str = typer.Argument(..., help="Path to binary")
):
    """Execute binary with Frida instrumentation"""
    print_header("Active RE Execution")
    
    data = {
        "job_id": job_id,
        "binary_path": binary_path
    }
    
    result = api_client.post("/api/active-re/execute", data=data)
    
    if "error" not in result:
        print_success("Execution started")
        print_json(result, "Execution Result")
    else:
        print_error("Execution failed")


@active_re_app.command("monitor")
def active_re_monitor(
    job_id: str = typer.Argument(..., help="Job ID"),
    duration: int = typer.Option(30, "--duration", "-d", help="Monitoring duration in seconds")
):
    """Monitor binary execution"""
    print_header(f"Active RE Monitoring: {job_id}")
    
    data = {
        "job_id": job_id,
        "duration": duration
    }
    
    result = api_client.post("/api/active-re/monitor", data=data)
    
    if "error" not in result:
        print_success(f"Monitoring for {duration} seconds")
        print_json(result, "Monitoring Result")
    else:
        print_error("Monitoring failed")


@active_re_app.command("chat")
def active_re_chat(
    message: str = typer.Argument(..., help="Chat message")
):
    """Chat with Active RE agent"""
    print_header("Active RE Chat")
    
    data = {
        "message": message
    }
    
    result = api_client.post("/api/active-re/chat", data=data)
    
    if "error" not in result:
        print_success("Response received")
        console.print(f"[green]Agent:[/green] {result.get('response', 'No response')}")
    else:
        print_error("Chat failed")


# ============== RAG COMMANDS ==============

@rag_app.command("search")
def rag_search(
    query: str = typer.Argument(..., help="Search query"),
    n_results: int = typer.Option(5, "--n", "-n", help="Number of results")
):
    """Search RAG knowledge base"""
    print_header("RAG Search")
    
    data = {
        "query": query,
        "n_results": n_results
    }
    
    result = api_client.post("/api/rag/search", data=data)
    
    if "error" not in result:
        print_success("Search completed")
        print_json(result, "Search Results")
    else:
        print_error("Search failed")


@rag_app.command("similar-functions")
def similar_functions(
    function_code: str = typer.Argument(..., help="Function code to compare"),
    n_results: int = typer.Option(5, "--n", "-n", help="Number of results")
):
    """Find similar functions"""
    print_header("Similar Functions Search")
    
    data = {
        "function_code": function_code,
        "n_results": n_results
    }
    
    result = api_client.post("/api/rag/similar-functions", data=data)
    
    if "error" not in result:
        print_success("Similar functions found")
        print_json(result, "Similar Functions")
    else:
        print_error("Search failed")


@rag_app.command("vulnerabilities")
def search_vulnerabilities(
    code_snippet: str = typer.Argument(..., help="Code snippet to analyze"),
    n_results: int = typer.Option(5, "--n", "-n", help="Number of results")
):
    """Search vulnerability patterns"""
    print_header("Vulnerability Pattern Search")
    
    data = {
        "code_snippet": code_snippet,
        "n_results": n_results
    }
    
    result = api_client.post("/api/rag/vulnerabilities", data=data)
    
    if "error" not in result:
        print_success("Vulnerability patterns found")
        print_json(result, "Vulnerability Patterns")
    else:
        print_error("Search failed")


# ============== ORCHESTRATOR COMMANDS ==============

@orchestrator_app.command("plan")
def orchestrator_plan(
    binary_path: str = typer.Argument(..., help="Path to binary"),
    user_request: str = typer.Option("Comprehensive analysis", "--request", "-r", help="User request")
):
    """Plan analysis strategy with orchestrator"""
    print_header("Orchestrator Planning")
    
    data = {
        "binary_path": binary_path,
        "user_request": user_request
    }
    
    result = api_client.post("/api/orchestrator/plan", data=data)
    
    if "error" not in result:
        print_success("Strategy planned")
        print_json(result, "Strategy")
    else:
        print_error("Planning failed")


@orchestrator_app.command("execute")
def orchestrator_execute(
    job_id: str = typer.Argument(..., help="Job ID"),
    binary_path: str = typer.Argument(..., help="Path to binary")
):
    """Execute orchestrated analysis"""
    print_header("Orchestrator Execution")
    
    data = {
        "job_id": job_id,
        "binary_path": binary_path
    }
    
    result = api_client.post("/api/orchestrator/execute", data=data)
    
    if "error" not in result:
        print_success("Analysis started")
        print_json(result, "Execution Result")
    else:
        print_error("Execution failed")


@orchestrator_app.command("tasks")
def orchestrator_tasks():
    """Get all orchestrator tasks"""
    print_header("Orchestrator Tasks")
    
    result = api_client.get("/api/orchestrator/tasks")
    
    if "error" not in result:
        print_table(result.get("tasks", []), "Tasks")
    else:
        print_error("Failed to get tasks")


@orchestrator_app.command("approve")
def orchestrator_approve(
    job_id: str = typer.Argument(..., help="Job ID"),
    approved: bool = typer.Option(True, "--approve/--reject", help="Approve or reject")
):
    """Approve or reject operation"""
    print_header(f"Orchestrator Approval: {job_id}")
    
    data = {
        "job_id": job_id,
        "approved": approved
    }
    
    result = api_client.post("/api/orchestrator/approve", data=data)
    
    if "error" not in result:
        action = "approved" if approved else "rejected"
        print_success(f"Operation {action}")
    else:
        print_error("Approval failed")


# ============== RADARE2 COMMANDS ==============

@radare2_app.command("status")
def r2_status():
    """Get Radare2 status"""
    print_header("Radare2 Status")
    
    result = api_client.get("/api/r2/status")
    
    if "error" not in result:
        print_json(result, "Radare2 Status")
    else:
        print_error("Failed to get status")


@radare2_app.command("analyze")
def r2_analyze(
    binary_path: str = typer.Argument(..., help="Path to binary")
):
    """Analyze binary with Radare2"""
    print_header("Radare2 Analysis")
    
    data = {
        "binary_path": binary_path
    }
    
    result = api_client.post("/api/r2/analyze", data=data)
    
    if "error" not in result:
        print_success("Analysis completed")
        print_json(result, "Analysis Result")
    else:
        print_error("Analysis failed")


@radare2_app.command("functions")
def r2_functions():
    """List Radare2 functions"""
    print_header("Radare2 Functions")
    
    result = api_client.get("/api/r2/functions")
    
    if "error" not in result:
        print_table(result.get("functions", []), "Functions")
    else:
        print_error("Failed to get functions")


# ============== SYSTEM COMMANDS ==============

@system_app.command("docker")
def docker_status():
    """Get Docker container status"""
    print_header("Docker Status")
    
    result = api_client.get("/api/docker/status")
    
    if "error" not in result:
        print_table(result.get("containers", []), "Containers")
        console.print(f"[bold]Docker Version:[/bold] {result.get('docker_version', 'Unknown')}")
        console.print(f"[bold]Running Containers:[/bold] {result.get('running_containers', 0)}")
    else:
        print_error("Failed to get Docker status")


@system_app.command("gpu")
def gpu_status():
    """Get GPU status"""
    print_header("GPU Status")
    
    result = api_client.get("/gpu/status")
    
    if "error" not in result:
        print_json(result, "GPU Information")
    else:
        print_error("Failed to get GPU status")


@system_app.command("logs")
def docker_logs(
    container_name: str = typer.Argument(..., help="Container name"),
    lines: int = typer.Option(50, "--lines", "-n", help="Number of lines")
):
    """Get Docker container logs"""
    print_header(f"Docker Logs: {container_name}")
    
    result = api_client.get(f"/api/docker/logs/{container_name}", params={"lines": lines})
    
    if "error" not in result:
        console.print(Syntax(result.get("logs", ""), "log"))
    else:
        print_error("Failed to get logs")


if __name__ == "__main__":
    app()
