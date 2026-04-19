#!/usr/bin/env python3

import os
import sys
import json
import subprocess
import requests
import getpass
import keyring
from pathlib import Path
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.prompt import Prompt, Confirm
from rich.syntax import Syntax
from rich.markdown import Markdown
from rich.tree import Tree
from rich.columns import Columns
from rich.align import Align
from rich.text import Text
from rich import print as rprint
from rich.theme import Theme
import typer
from datetime import datetime

custom_theme = Theme({
    "info": "cyan",
    "warning": "yellow",
    "error": "bold red",
    "success": "bold green",
    "title": "bold magenta",
    "subtitle": "italic cyan",
    "border": "blue",
    "highlight": "reverse cyan",
    "path": "dim cyan",
    "number": "bold yellow",
    "string": "green",
    "key": "bold blue",
})

console = Console(theme=custom_theme)

API_BASE_URL = os.getenv("REAA_API_URL", "http://127.0.0.1:5000")
API_KEY = os.getenv("REAA_API_KEY", "")

app = typer.Typer(
    name="reaa",
    help="REAA - Reverse Engineering Analysis Assistant CLI",
    add_completion=True,
    rich_markup_mode="rich"
)

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


class SecureStorage:
    
    SERVICE_NAME = "reaa-cli"
    
    @staticmethod
    def save_api_key(api_key: str) -> bool:
        try:
            keyring.set_password(SecureStorage.SERVICE_NAME, "api_key", api_key)
            return True
        except Exception as e:
            console.print(f"[error]Failed to save API key securely: {e}[/error]")
            return False
    
    @staticmethod
    def get_api_key() -> Optional[str]:
        try:
            return keyring.get_password(SecureStorage.SERVICE_NAME, "api_key")
        except Exception as e:
            console.print(f"[warning]Failed to retrieve API key: {e}[/warning]")
            return None
    
    @staticmethod
    def delete_api_key() -> bool:
        try:
            keyring.delete_password(SecureStorage.SERVICE_NAME, "api_key")
            return True
        except Exception as e:
            console.print(f"[warning]Failed to delete API key: {e}[/warning]")
            return False


def show_auth_required_warning():
    """Show authentication required warning message"""
    console.print("\n[yellow][WARNING] Authentication required - You are not logged in[/yellow]")
    console.print("[yellow][WARNING] Authentication required - Please login first[/yellow]")
    console.print("[info]Use: reaa auth login --username <username> --password <password>[/info]")


class APIClient:

    def __init__(self, base_url: str = API_BASE_URL, api_key: str = API_KEY):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key or SecureStorage.get_api_key() or ""
        self.headers = {
            "Content-Type": "application/json",
            "User-Agent": "REAA-CLI/1.0.0"
        }
        if self.api_key:
            self.headers["Authorization"] = f"Bearer {self.api_key}"

    def _handle_401_error(self) -> bool:
        """Handle 401 unauthorized error by showing warning message"""
        show_auth_required_warning()
        return True

    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        try:
            response = requests.get(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                params=params,
                timeout=30
            )
            if response.status_code == 401:
                self._handle_401_error()
                return {"error": "Unauthorized"}
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            console.print("[error]Request timed out. Please try again.[/error]")
            return {"error": "Request timeout"}
        except requests.exceptions.ConnectionError:
            console.print("[error]Cannot connect to API. Check if the server is running.[/error]")
            return {"error": "Connection error"}
        except requests.exceptions.RequestException as e:
            console.print(f"[error]Request failed: {e}[/error]")
            return {"error": str(e)}
    
    def post(self, endpoint: str, data: Optional[Dict] = None, files: Optional[Dict] = None) -> Dict[str, Any]:
        try:
            headers = self.headers.copy()
            if files:
                headers.pop("Content-Type", None)

         
            response = requests.post(
                f"{self.base_url}{endpoint}",
                headers=headers,
                data=data if files else data,
                json=data if not files else None,
                files=files,
                timeout=300
            )
            if response.status_code == 401:
                self._handle_401_error()
                return {"error": "Unauthorized"}
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            console.print("[error]Request timed out. Please try again.[/error]")
            return {"error": "Request timeout"}
        except requests.exceptions.ConnectionError:
            console.print("[error]Cannot connect to API. Check if the server is running.[/error]")
            return {"error": "Connection error"}
        except requests.exceptions.RequestException as e:
            console.print(f"[error]Request failed: {e}[/error]")
            return {"error": str(e)}
    
    def delete(self, endpoint: str) -> Dict[str, Any]:
        try:
            response = requests.delete(
                f"{self.base_url}{endpoint}",
                headers=self.headers,
                timeout=30
            )
            if response.status_code == 401:
                self._handle_401_error()
                return {"error": "Unauthorized"}
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            console.print("[error]Request timed out. Please try again.[/error]")
            return {"error": "Request timeout"}
        except requests.exceptions.ConnectionError:
            console.print("[error]Cannot connect to API. Check if the server is running.[/error]")
            return {"error": "Connection error"}
        except requests.exceptions.RequestException as e:
            console.print(f"[error]Request failed: {e}[/error]")
            return {"error": str(e)}


api_client = APIClient()


def print_header(title: str, subtitle: str = "", emoji: str = "🔧"):
    title_text = Text(f"{emoji} {title}", style="title")
    if subtitle:
        content = Columns([
            Align.center(title_text),
            Align.center(Text(subtitle, style="subtitle"))
        ])
    else:
        content = Align.center(title_text)
    
    panel = Panel(
        content,
        border_style="border",
        padding=(1, 3),
        title="[bold]REAA CLI[/bold]",
        title_align="center"
    )
    console.print(panel)


def print_table(data: List[Dict], title: str = "", show_count: bool = True):
    if not data:
        console.print("[warning]⚠ No data to display[/warning]")
        return
    
    table = Table(
        title=title if title else None,
        show_header=True,
        header_style="bold magenta",
        title_style="title",
        title_justify="center",
        padding=(0, 1)
    )
    
    for key in data[0].keys():
        table.add_column(
            key.replace("_", " ").title(),
            style="cyan",
            overflow="fold",
            max_width=50
        )
    
    for i, item in enumerate(data):
        row_style = "" if i % 2 == 0 else "dim"
        table.add_row(*[str(v) for v in item.values()])
    
    console.print(table)
    
    if show_count:
        console.print(f"[info]ℹ Total: {len(data)} items[/info]\n")


def print_json(data: Dict[str, Any], title: str = ""):
    if title:
        console.print(f"\n[title]📄 {title}[/title]\n")
    
    json_str = json.dumps(data, indent=2, ensure_ascii=False)
    syntax = Syntax(json_str, "json", theme="monokai", line_numbers=True)
    console.print(syntax)


def print_success(message: str):
    console.print(f"[success]✓ {message}[/success]")


def print_error(message: str):
    console.print(f"[error]✗ {message}[/error]")


def print_warning(message: str):
    console.print(f"[warning]⚠ {message}[/warning]")


def print_info(message: str):
    console.print(f"[info]ℹ {message}[/info]")


def print_step(step: int, total: int, message: str):
    console.print(f"[info]Step {step}/{total}:[/info] {message}")


def print_separator(char: str = "─", length: int = 50):
    console.print(f"[dim]{char * length}[/dim]")



@app.command()
def version():
    """Show REAA CLI version"""
    print_header("REAA CLI", "Version 1.0.0")
    console.print("\n[bold]API Endpoint:[/bold] ", API_BASE_URL)


@app.command()
def run():
    """Start webui server in background"""
    print_header("Starting WebUI Server")
    

    project_root = Path(__file__).parent.parent
    
    webui_app = project_root / "webui" / "app.py"
    
    if not webui_app.exists():
        print_error(f"webui/app.py not found at {webui_app}")
        return
    
    print_info(f"Starting server from: {webui_app}")
    
    try:

        process = subprocess.Popen(
            [sys.executable, str(webui_app)],
            creationflags=subprocess.CREATE_NEW_CONSOLE,
            cwd=str(project_root)
        )
        print_success(f"WebUI server started (PID: {process.pid})")
        print_info(f"Access at: {API_BASE_URL}")
        print_info("Press Ctrl+C in the new window to stop the server")
    except Exception as e:
        print_error(f"Failed to start server: {e}")


@app.command()
def status():
    """Check REAA system status"""
    global API_KEY, api_client
    print_header("System Status")

    result = api_client.get("/api/system/status")

    if "error" in result and result.get("error") == "Unauthorized":
        show_auth_required_warning()
        return

    if "error" not in result:
        print_table([result], "System Status")
        print_success("System is online")
    else:
        print_error("Failed to get system status")


@app.command()
def config(
    url: Optional[str] = typer.Option(None, "--url", "-u", help="API base URL"),
    key: Optional[str] = typer.Option(None, "--key", "-k", help="API key"),
    save_key: bool = typer.Option(False, "--save", "-s", help="Save API key securely to system keyring"),
    remove_key: bool = typer.Option(False, "--remove", "-r", help="Remove API key from system keyring")
):
    """Configure CLI settings with secure storage support"""
    global api_client, API_BASE_URL, API_KEY
    
    print_header("Configuration", emoji="⚙️")
    
    if url:
        API_BASE_URL = url
        api_client = APIClient(API_BASE_URL, API_KEY)
        print_success(f"API URL set to: {API_BASE_URL}")
    
    if key:
        API_KEY = key
        api_client = APIClient(API_BASE_URL, API_KEY)
        print_success("API key updated (session only)")
        
        if save_key:
            if SecureStorage.save_api_key(key):
                print_success("API key saved securely to system keyring")
            else:
                print_warning("Failed to save API key securely")
    
    if remove_key:
        if SecureStorage.delete_api_key():
            print_success("API key removed from system keyring")
            API_KEY = ""
            api_client = APIClient(API_BASE_URL, API_KEY)
        else:
            print_warning("No API key in system keyring")
    
    if not url and not key and not save_key and not remove_key:
        print_separator()
        console.print(f"[bold]API URL:[/bold] {API_BASE_URL}")
        
        secure_key = SecureStorage.get_api_key()
        if secure_key:
            console.print(f"[bold]API Key (Secure Storage):[/bold] {'*' * 20}")
        elif API_KEY:
            console.print(f"[bold]API Key (Session):[/bold] {'*' * len(API_KEY)}")
        else:
            console.print("[bold]API Key:[/bold] Not set")
        
        print_separator()
        print_info("Use --save to store API key securely")
        print_info("Use --remove to remove stored API key")



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
        print_error(f"Registration failed: {result.get('error', 'Unknown error')}")


@auth_app.command("login")
def login(
    username: str = typer.Option(..., "--username", "-u", help="Username"),
    password: str = typer.Option(..., "--password", "-p", help="Password"),
    save: bool = typer.Option(False, "--save", "-s", help="Save API key securely to system keyring")
):
    """Login and get API token"""
    global API_KEY, api_client
    print_header("User Login")

    data = {
        "username": username,
        "password": password
    }

    result = api_client.post("/api/auth/login", data=data)

    if "error" not in result and "token" in result:
        API_KEY = result["token"]
        api_client = APIClient(API_BASE_URL, API_KEY)
        print_success("Login successful")
        console.print(f"[bold]Token:[/bold] {result['token']}")

        if save:
            if SecureStorage.save_api_key(API_KEY):
                print_success("API key saved securely to system keyring")
            else:
                print_warning("Failed to save API key securely")

        print_info("Use --save option to save token for future sessions")
    else:
        print_error(f"Login failed: {result.get('error', 'Unknown error')}")


@auth_app.command("logout")
def logout():
    """Logout current user"""
    global API_KEY, api_client
    print_header("User Logout")
    
    result = api_client.post("/api/auth/logout")
    
    if "error" not in result:
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
    print_header(f"Download Job: {job_id}", emoji="📥")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console
    ) as progress:
        task = progress.add_task("Downloading job artifacts...", total=None)
        result = api_client.get(f"/api/jobs/{job_id}/download")
        progress.remove_task(task)
    
    if "error" not in result:
        output_path = Path(output) / f"analysis_results_{job_id[:8]}.zip"
        with open(output_path, "wb") as f:
            f.write(result.content)
        print_success(f"Downloaded to: {output_path}")
    else:
        print_error("Failed to download job")


@analysis_app.command("memory")
def job_memory(
    job_id: str = typer.Argument(..., help="Job ID")
):
    """Get memory layout for job"""
    print_header(f"Memory Layout: {job_id}", emoji="🧠")
    
    result = api_client.get(f"/api/jobs/{job_id}/memory")
    
    if "error" not in result:
        print_json(result, "Memory Layout")
    else:
        print_error("Failed to get memory layout")


@analysis_app.command("memory-hex")
def job_memory_hex(
    job_id: str = typer.Argument(..., help="Job ID"),
    section_name: str = typer.Argument(..., help="Memory section name")
):
    """Get hex dump of memory section"""
    print_header(f"Memory Hex: {job_id} - {section_name}", emoji="📊")
    
    result = api_client.get(f"/api/jobs/{job_id}/memory/{section_name}/hex")
    
    if "error" not in result:
        print_json(result, "Memory Hex Dump")
    else:
        print_error("Failed to get memory hex")


@analysis_app.command("memory-analysis")
def job_memory_analysis(
    job_id: str = typer.Argument(..., help="Job ID")
):
    """Get memory analysis for job"""
    print_header(f"Memory Analysis: {job_id}", emoji="🔍")
    
    result = api_client.get(f"/api/jobs/{job_id}/memory/analysis")
    
    if "error" not in result:
        print_json(result, "Memory Analysis")
    else:
        print_error("Failed to get memory analysis")


@analysis_app.command("memory-strings")
def job_memory_strings(
    job_id: str = typer.Argument(..., help="Job ID")
):
    """Extract strings from memory"""
    print_header(f"Memory Strings: {job_id}", emoji="📝")
    
    result = api_client.get(f"/api/jobs/{job_id}/memory/strings")
    
    if "error" not in result:
        if "strings" in result:
            print_table(result["strings"], "Memory Strings", show_count=False)
        else:
            print_json(result, "Memory Strings")
    else:
        print_error("Failed to get memory strings")


@analysis_app.command("memory-xref")
def job_memory_xref(
    job_id: str = typer.Argument(..., help="Job ID"),
    address: str = typer.Argument(..., help="Memory address")
):
    """Get cross-references for address"""
    print_header(f"Cross-References: {job_id} - {address}", emoji="🔗")
    
    result = api_client.get(f"/api/jobs/{job_id}/memory/{address}/xref")
    
    if "error" not in result:
        print_json(result, "Cross-References")
    else:
        print_error("Failed to get cross-references")


@analysis_app.command("memory-compare")
def job_memory_compare(
    job_id: str = typer.Argument(..., help="Job ID"),
    section1: str = typer.Argument(..., help="First section name"),
    section2: str = typer.Argument(..., help="Second section name")
):
    """Compare memory sections"""
    print_header(f"Memory Compare: {section1} vs {section2}", emoji="⚖️")
    
    result = api_client.get(f"/api/jobs/{job_id}/memory/compare/{section1}/{section2}")
    
    if "error" not in result:
        print_json(result, "Memory Comparison")
    else:
        print_error("Failed to compare memory sections")


@analysis_app.command("memory-search")
def job_memory_search(
    job_id: str = typer.Argument(..., help="Job ID"),
    pattern: str = typer.Argument(..., help="Byte pattern to search (hex)"),
    offset: Optional[int] = typer.Option(None, "--offset", "-o", help="Start offset")
):
    """Search for byte patterns in memory"""
    print_header(f"Memory Pattern Search: {job_id}", emoji="🔎")
    
    data = {
        "job_id": job_id,
        "pattern": pattern
    }
    if offset is not None:
        data["offset"] = offset
    
    result = api_client.post(f"/api/jobs/{job_id}/memory/pattern/search", data=data)
    
    if "error" not in result:
        print_json(result, "Pattern Search Results")
    else:
        print_error("Failed to search memory patterns")



@security_app.command("analyze")
def security_analyze(
    job_id: str = typer.Argument(..., help="Job ID"),
    message: str = typer.Option("Analyze for vulnerabilities", "--message", "-m", help="Analysis message"),
    patterns: str = typer.Option("all", "--patterns", "-p", help="Vulnerability patterns (all, buffer-overflow, sql-injection, xss, cve, heuristic)"),
    depth: str = typer.Option("standard", "--depth", "-d", help="Analysis depth (quick, standard, deep)")
):
    """Analyze binary for security vulnerabilities with pattern matching"""
    print_header(f"Security Analysis: {job_id}")

    data = {
        "job_id": job_id,
        "message": message,
        "patterns": patterns,
        "depth": depth
    }

    result = api_client.post("/security/analyze", data=data)

    if "error" not in result:
        print_success(f"Security analysis completed ({patterns} scan, {depth} depth)")

      
        if "vulnerabilities" in result and result["vulnerabilities"]:
            print_table(result["vulnerabilities"], "Vulnerabilities Found")
            print_warning(f"Found {len(result['vulnerabilities'])} vulnerabilities")
        elif "vulnerabilities" in result:
            print_success("No vulnerabilities found")

        
        if "pattern_matches" in result and result["pattern_matches"]:
            print_table(result["pattern_matches"], "Pattern Matches")
            print_info(f"Found {len(result['pattern_matches'])} pattern matches")

       
        if "risk_score" in result:
            risk_level = "High" if result["risk_score"] >= 7 else "Medium" if result["risk_score"] >= 4 else "Low"
            console.print(f"[bold]Risk Score:[/bold] {result['risk_score']}/10 ({risk_level})")

        if "recommendations" in result and result["recommendations"]:
            print_header("Recommendations")
            for rec in result["recommendations"]:
                console.print(f"• {rec}")
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


@security_app.command("audit")
def security_audit(
    job_id: str = typer.Argument(..., help="Job ID"),
    checks: str = typer.Option("all", "--checks", "-c", help="Audit checks (all, memory, code, config, permissions, network)"),
    severity: str = typer.Option("medium", "--severity", "-s", help="Minimum severity (low, medium, high, critical)")
):
    """Perform comprehensive security audit"""
    print_header(f"Security Audit: {job_id}")

    data = {
        "job_id": job_id,
        "checks": checks,
        "severity": severity
    }

    result = api_client.post("/security/audit", data=data)

    if "error" not in result:
        print_success(f"Audit completed ({checks} checks, {severity}+ severity)")


        if "findings" in result and result["findings"]:
            print_table(result["findings"], "Audit Findings")
            print_warning(f"Found {len(result['findings'])} findings")
        else:
            print_success("No security issues found")

      
        if "compliance_score" in result:
            score = result["compliance_score"]
            status = "Compliant" if score >= 80 else "Partial" if score >= 60 else "Non-compliant"
            console.print(f"[bold]Compliance Score:[/bold] {score}% ({status})")

  
        if "summary" in result:
            print_header("Audit Summary")
            for key, value in result["summary"].items():
                console.print(f"[bold]{key}:[/bold] {value}")
    else:
        print_error("Security audit failed")


@security_app.command("metrics")
def security_metrics(
    job_id: str = typer.Argument(..., help="Job ID"),
    detailed: bool = typer.Option(False, "--detailed", "-d", help="Show detailed metrics")
):
    """Get security metrics for job"""
    print_header(f"Security Metrics: {job_id}")

    result = api_client.get(f"/security/metrics/{job_id}")

    if "error" not in result:
        if detailed:
            print_json(result, "Security Metrics")
        else:
        
            print_header("Security Metrics Summary")
            metrics_to_show = ["vulnerability_count", "risk_score", "compliance_score", "scan_coverage", "false_positive_rate"]
            for metric in metrics_to_show:
                if metric in result:
                    console.print(f"[bold]{metric}:[/bold] {result[metric]}")
    else:
        print_error("Failed to get security metrics")


@security_app.command("scan")
def security_scan(
    job_id: str = typer.Argument(..., help="Job ID"),
    scan_type: str = typer.Option("comprehensive", "--type", "-t", help="Scan type (memory, apis, input, privilege, comprehensive, strings, imports, entropy, anti-debug, packer)")
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

      
        if scan_type == "apis" and "dangerous_apis" in result:
            if result["dangerous_apis"]:
                print_table(result["dangerous_apis"], "Dangerous APIs Found")
                print_warning(f"Found {len(result['dangerous_apis'])} dangerous API calls")
            else:
                print_success("No dangerous APIs found")
        elif scan_type == "memory" and "memory_vulnerabilities" in result:
            if result["memory_vulnerabilities"]:
                print_table(result["memory_vulnerabilities"], "Memory Vulnerabilities")
                print_warning(f"Found {len(result['memory_vulnerabilities'])} memory vulnerabilities")
            else:
                print_success("No memory vulnerabilities found")
        elif scan_type == "strings" and "suspicious_strings" in result:
            if result["suspicious_strings"]:
                print_table(result["suspicious_strings"], "Suspicious Strings")
                print_warning(f"Found {len(result['suspicious_strings'])} suspicious strings")
            else:
                print_success("No suspicious strings found")
        elif scan_type == "imports" and "suspicious_imports" in result:
            if result["suspicious_imports"]:
                print_table(result["suspicious_imports"], "Suspicious Imports")
                print_warning(f"Found {len(result['suspicious_imports'])} suspicious imports")
            else:
                print_success("No suspicious imports found")
        else:
            print_json(result, "Scan Result")

   
        if "summary" in result:
            print_header("Scan Summary")
            for key, value in result["summary"].items():
                console.print(f"[bold]{key}:[/bold] {value}")
    else:
        print_error("Scan failed")



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



@radare2_app.command("status")
def r2_status():
    """Get Radare2 status"""
    print_header("Radare2 Status")
    
    result = api_client.get("/api/r2/status")
    
    if "error" not in result:
        print_json(result, "Radare2 Status")
    else:
        print_error("Failed to get status")


@radare2_app.command("functions")
def r2_functions():
    """List Radare2 functions"""
    print_header("Radare2 Functions")
    
    result = api_client.get("/api/r2/functions")
    
    if "error" not in result:
        print_table(result.get("functions", []), "Functions")
    else:
        print_error("Failed to get functions")



@system_app.command("docker")
def docker_status():
    """Get Docker container status"""
    print_header("Docker Status")

    result = api_client.get("/api/docker/status")

    if "error" not in result:
        containers = result.get("containers", [])
        if containers:
            print_table(containers, "Containers")
            print_info("Use CONTAINER_ID with: reaa system logs <container_name>")
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
    print_header(f"Docker Logs: {container_name}", emoji="📋")

    try:
        result = subprocess.run(
            ['docker', 'logs', '--tail', str(lines), container_name],
            capture_output=True,
            text=True,
            timeout=10
        )


        logs = result.stdout if result.stdout else ""
        if result.stderr:
            logs += "\n" + result.stderr

        if logs.strip():
            console.print(Syntax(logs, "log"))
        else:
            print_info("No logs available")
    except subprocess.TimeoutExpired:
        print_error("Docker logs command timeout")
    except Exception as e:
        print_error(f"Failed to get logs: {e}")


@app.command("settings")
def settings(
    setting_key: Optional[str] = typer.Option(None, "--key", "-k", help="Setting key"),
    setting_value: Optional[str] = typer.Option(None, "--value", "-v", help="Setting value")
):
    """Update or view settings"""
    print_header("Settings", emoji="⚙️")
    
    if setting_key and setting_value:
        data = {setting_key: setting_value}
        result = api_client.post("/api/settings", data=data)
        if "error" not in result:
            print_success(f"Setting {setting_key} updated")
        else:
            print_error("Failed to update setting")
    else:
        print_info("Use --key and --value to update settings")


@app.command("models")
def models(
    action: str = typer.Option("list", "--action", "-a", help="Action: list, current, switch, test, config")
):
    """Manage AI models"""
    print_header("AI Models", emoji="🤖")
    
    if action == "list":
        result = api_client.get("/api/models")
        if "error" not in result:
            print_table(result.get("models", []), "Available Models")
        else:
            print_error("Failed to get models")
    elif action == "current":
        result = api_client.get("/api/models/current")
        if "error" not in result:
            print_json(result, "Current Model")
        else:
            print_error("Failed to get current model")
    else:
        print_info("Actions: list, current, switch, test, config")



remote_app = typer.Typer(help="Remote collaboration commands")
app.add_typer(remote_app, name="remote", help="Remote collaboration commands")


@remote_app.command("health")
def remote_health():
    """Check remote collaboration health"""
    print_header("Remote Collaboration Health", emoji="🌐")
    
    result = api_client.get("/api/remote/health")
    
    if "error" not in result:
        print_json(result, "Remote Health Status")
    else:
        print_error("Failed to get remote health")


@remote_app.command("server-status")
def remote_server_status():
    """Get remote server status"""
    print_header("Remote Server Status", emoji="🖥️")
    
    result = api_client.get("/api/remote/server/status")
    
    if "error" not in result:
        print_json(result, "Server Status")
    else:
        print_error("Failed to get server status")


@remote_app.command("jobs")
def remote_jobs():
    """List remote jobs"""
    print_header("Remote Jobs", emoji="📋")
    
    result = api_client.get("/api/remote/jobs")
    
    if "error" not in result:
        print_table(result.get("jobs", []), "Remote Jobs")
    else:
        print_error("Failed to get remote jobs")


@remote_app.command("room-users")
def remote_room_users(
    job_id: str = typer.Argument(..., help="Job ID")
):
    """Get users in remote room"""
    print_header(f"Room Users: {job_id}", emoji="👥")
    
    result = api_client.get(f"/api/remote/room/{job_id}/users")
    
    if "error" not in result:
        print_table(result.get("users", []), "Room Users")
    else:
        print_error("Failed to get room users")


@remote_app.command("api-keys")
def remote_api_keys():
    """List remote API keys"""
    print_header("Remote API Keys", emoji="🔑")

    result = api_client.get("/api/remote/api-keys")

    if "error" not in result:
        api_keys = result.get("api_keys", [])
       
        if api_keys and isinstance(api_keys, list) and len(api_keys) > 0:
            if isinstance(api_keys[0], dict):
                print_table(api_keys, "API Keys")
            else:
                print_json(result, "API Keys")
        else:
            print_json(result, "API Keys")
    else:
        print_error("Failed to get API keys")


@remote_app.command("create-key")
def remote_create_key():
    """Create new remote API key"""
    print_header("Create API Key", emoji="🔑")
    
    result = api_client.post("/api/remote/api-keys")
    
    if "error" not in result:
        print_success("API key created")
        print_json(result, "New API Key")
    else:
        print_error("Failed to create API key")


@remote_app.command("delete-key")
def remote_delete_key(
    key: str = typer.Argument(..., help="API key to delete")
):
    """Delete remote API key"""
    print_header(f"Delete API Key", emoji="🔑")
    
    if not Confirm.ask(f"Are you sure you want to delete key {key[:10]}...?"):
        print_info("Operation cancelled")
        return
    
    result = api_client.delete(f"/api/remote/api-keys/{key}")
    
    if "error" not in result:
        print_success("API key deleted")
    else:
        print_error("Failed to delete API key")


if __name__ == "__main__":
    app()
