#!/usr/bin/env python3
"""
REAA - Reverse Engineering Analysis Assistant
Setup Script for Windows
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.status import Status
from rich.text import Text
from rich import print as rprint

# Initialize console
console = Console()

def print_success(message):
    """Print success message"""
    console.print(f"[green][OK][/green] {message}")

def print_warning(message):
    """Print warning message"""
    console.print(f"[yellow][WARNING][/yellow] {message}")

def print_info(message):
    """Print info message"""
    console.print(f"[blue][INFO][/blue] {message}")

def print_error(message):
    """Print error message"""
    console.print(f"[red][ERROR][/red] {message}")

def print_step(step_num, total_steps, description):
    """Print step header"""
    console.print(f"\n[cyan][{step_num}/{total_steps}][/cyan] {description}")

def run_command(cmd, description, continue_on_error=True):
    """Run a command and return success status"""
    console.print(f"[dim]Running: {cmd}[/dim]")
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print_success(description)
        return True
    except subprocess.CalledProcessError as e:
        print_warning(f"Failed: {description}")
        console.print(f"[red]Error: {e}[/red]")
        if continue_on_error:
            print_info("Continuing with setup...")
        return False

def check_python_version():
    """Check if Python is installed"""
    print_step(1, 10, "Checking Python version...")
    try:
        result = subprocess.run([sys.executable, "--version"], capture_output=True, text=True)
        version = result.stdout.strip()
        print_success(f"Python version: {version}")
        return True
    except Exception as e:
        print_warning("Python is not installed or not in PATH")
        console.print("Please install Python 3.14.x or 3.14.3 from https://www.python.org/")
        console.print("Continuing with setup...")
        return False

def create_virtual_environment():
    """Create Python virtual environment"""
    print_step(2, 10, "Creating virtual environment...")
    venv_path = Path(".venv")
    if venv_path.exists():
        print_info("Virtual environment already exists, skipping...")
        return True
    
    try:
        subprocess.run([sys.executable, "-m", "venv", ".venv"], check=True)
        print_success("Virtual environment created successfully")
        return True
    except Exception as e:
        print_warning("Failed to create virtual environment")
        console.print(f"[red]Error: {e}[/red]")
        console.print("Continuing with setup...")
        return False

def check_visual_cpp():
    """Check for Visual C++ Build Tools"""
    print_step(2.5, 10, "Checking Microsoft Visual C++ Build Tools...")
    try:
        result = subprocess.run(["where", "cl.exe"], capture_output=True, shell=True)
        if result.returncode == 0:
            print_success("Microsoft Visual C++ Build Tools found")
        else:
            print_warning("Microsoft Visual C++ Build Tools not found in PATH")
            console.print("Some packages require C++ compilation (Jpype1, uefi-firmware)")
            console.print()
            console.print("If these packages fail to install:")
            console.print("1. Use 'Developer Command Prompt for VS' instead of regular terminal")
            console.print("2. Or ensure 'Desktop development with C++' workload is installed")
            console.print("3. Or remove Jpype1 and uefi-firmware from requirements.txt")
            console.print()
            console.print("Continuing with installation...")
    except Exception as e:
        print_warning("Could not check for Visual C++ Build Tools")
        console.print("Continuing with installation...")

def install_dependencies():
    """Install Python dependencies"""
    print_step(3, 10, "Installing Python dependencies...")
    venv_python = Path(".venv/Scripts/python.exe")
    requirements = Path("requirements.txt")
    
    if not venv_python.exists():
        print_warning("Virtual environment not found, skipping dependencies")
        return False
    
    if not requirements.exists():
        print_warning("requirements.txt not found")
        return False
    
    try:
        subprocess.run([str(venv_python), "-m", "pip", "install", "-r", str(requirements)], check=True)
        print_success("Dependencies installed successfully")
        return True
    except Exception as e:
        print_warning("Failed to install dependencies")
        console.print(f"[red]Error: {e}[/red]")
        print_info("This may be due to missing Visual C++ Build Tools")
        console.print("Continuing with setup...")
        return False

def install_pytorch():
    """Install PyTorch with CUDA"""
    print_step(3.1, 10, "Installing PyTorch with CUDA for GPU support...")
    venv_python = Path(".venv/Scripts/python.exe")
    
    if not venv_python.exists():
        print_warning("Virtual environment not found, skipping PyTorch installation")
        return False
    
    try:
        subprocess.run([
            str(venv_python), "-m", "pip", "install",
            "torch", "torchvision", "torchaudio",
            "--index-url", "https://download.pytorch.org/whl/cu126"
        ], check=True)
        print_success("PyTorch with CUDA installed successfully")
        return True
    except Exception as e:
        print_warning("Failed to install PyTorch with CUDA")
        console.print(f"[red]Error: {e}[/red]")
        console.print("You can install it later with: pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu126")
        return False

def check_docker():
    """Check Docker installation"""
    print_step(4, 10, "Checking Docker installation...")
    try:
        result = subprocess.run(["docker", "--version"], capture_output=True, text=True)
        console.print(result.stdout.strip())
        
        result = subprocess.run(["docker-compose", "--version"], capture_output=True, text=True, shell=True)
        console.print(result.stdout.strip())
        print_success("Docker and Docker Compose are installed")
        return True
    except Exception as e:
        print_warning("Docker is not installed or not in PATH")
        console.print("Please install Docker Desktop from https://www.docker.com/products/docker-desktop")
        console.print("Continuing with setup...")
        return False

def configure_env():
    """Configure environment by copying .env.example to .env"""
    print_step(5, 10, "Configuring environment...")
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        print_info(".env already exists, skipping...")
        return True
    
    if env_example.exists():
        try:
            shutil.copy(env_example, env_file)
            print_success("Created .env from .env.example")
            print_info("Please edit .env with your settings before continuing")
            return True
        except Exception as e:
            print_warning("Failed to copy .env.example")
            console.print(f"[red]Error: {e}[/red]")
            return False
    else:
        print_warning(".env.example not found, skipping .env creation")
        return False

def build_docker():
    """Build Docker containers"""
    print_step(6, 10, "Building Docker containers (this may take a while)...")
    try:
        subprocess.run("docker-compose build", shell=True, check=True)
        print_success("Docker containers built successfully")
        return True
    except Exception as e:
        print_warning("Failed to build Docker containers")
        console.print(f"[red]Error: {e}[/red]")
        console.print("This may be due to network connectivity issues with Ubuntu repositories")
        console.print()
        console.print("Troubleshooting steps:")
        console.print("1. Check firewall/VPN that might be blocking Docker")
        console.print("2. Fix Docker DNS settings")
        console.print("3. Or run Docker build again when network is normal: docker-compose build && docker-compose up -d")
        console.print()
        console.print("You can build later with: docker-compose build")
        console.print("Continuing with setup...")
        return False

def start_docker():
    """Start Docker services"""
    print_step(7, 10, "Starting Docker services...")
    try:
        subprocess.run("docker-compose up -d", shell=True, check=True)
        print_success("Docker services started successfully")
        return True
    except Exception as e:
        print_warning("Failed to start Docker services")
        console.print(f"[red]Error: {e}[/red]")
        console.print("This may be due to build failure or Docker not running")
        console.print("You can start later with: docker-compose up -d")
        console.print("Continuing with setup...")
        return False

def install_ollama():
    """Install Ollama"""
    print_step(8, 10, "Checking Ollama installation...")
    try:
        result = subprocess.run(["ollama", "--version"], capture_output=True, text=True)
        console.print(result.stdout.strip())
        print_success("Ollama is already installed")
        ollama_cmd = "ollama"
    except Exception:
        print_info("Ollama is not installed, installing now...")
        console.print("This may require administrator privileges")
        try:
            subprocess.run(
                "powershell -ExecutionPolicy ByPass -Command \"& { irm https://ollama.com/install.ps1 | iex }\"",
                shell=True,
                check=True
            )
            print_success("Ollama installed successfully")
            # Set full path for current session
            ollama_cmd = rf"C:\Users\{os.environ['USERNAME']}\AppData\Local\Programs\Ollama\ollama.exe"
        except Exception as e:
            print_warning("Failed to install Ollama automatically")
            console.print(f"[red]Error: {e}[/red]")
            console.print("Please install Ollama manually from https://ollama.com/download")
            console.print("Or run in PowerShell: irm https://ollama.com/install.ps1 | iex")
            console.print("Continuing with setup...")
            ollama_cmd = None
    
    return ollama_cmd

def pull_ollama_model(ollama_cmd):
    """Pull llama3.2:3b model"""
    print_step(9, 10, "Checking llama3.2:3b model...")
    if not ollama_cmd:
        print_warning("Ollama not available, skipping model pull")
        return False
    
    try:
        result = subprocess.run([ollama_cmd, "list"], capture_output=True, text=True)
        if "llama3.2:3b" in result.stdout:
            print_success("llama3.2:3b model already exists, skipping...")
            return True
        
        print_info("llama3.2:3b model not found, pulling now (this may take a while)...")
        subprocess.run([ollama_cmd, "pull", "llama3.2:3b"], check=True)
        print_success("llama3.2:3b model pulled successfully")
        return True
    except Exception as e:
        print_warning("Failed to pull llama3.2:3b model")
        console.print(f"[red]Error: {e}[/red]")
        console.print("You can pull it later with: ollama pull llama3.2:3b")
        return False

def install_huggingface_cli():
    """Install Hugging Face CLI"""
    print_step(10, 10, "Installing Hugging Face CLI...")
    try:
        result = subprocess.run(["hf", "--version"], capture_output=True, text=True)
        console.print(result.stdout.strip())
        print_success("Hugging Face CLI is already installed")
    except Exception:
        print_info("Hugging Face CLI is not installed, installing now...")
        try:
            subprocess.run(
                "powershell -ExecutionPolicy ByPass -Command \"& { irm https://hf.co/cli/install.ps1 | iex }\"",
                shell=True,
                check=True
            )
            print_success("Hugging Face CLI installed successfully")
            print_info("Please login with: hf auth login")
        except Exception as e:
            print_warning("Failed to install Hugging Face CLI")
            console.print(f"[red]Error: {e}[/red]")
            console.print("You can install it later in PowerShell: irm https://hf.co/cli/install.ps1 | iex")

def print_next_steps():
    """Print next steps for the user"""
    console.print(Panel(
        "[bold green]Setup completed successfully![/bold green]",
        title="[bold]REAA Setup[/bold]",
        border_style="green"
    ))
    
    console.print("\n[bold]Next steps:[/bold]")
    console.print("1. If Python failed, install Python 3.14.x from https://www.python.org/")
    console.print("2. If venv failed, run: python -m venv .venv && .venv\\Scripts\\activate")
    console.print("3. If dependencies failed, run: pip install -r requirements.txt")
    console.print("4. If Docker failed, install from https://www.docker.com/products/docker-desktop")
    console.print("5. If Docker build failed, fix network and run: docker-compose build && docker-compose up -d")
    console.print("6. If Ollama failed, install from https://ollama.com/download")
    console.print("7. If Ollama model failed, run: ollama pull llama3.2:3b")
    console.print("8. If Hugging Face CLI failed, run in PowerShell: irm https://hf.co/cli/install.ps1 | iex")
    console.print("9. Login to Hugging Face: hf auth login")
    console.print("10. Edit .env file with your settings (if not already done)")
    console.print("11. Start Ollama server in a new terminal: ollama serve")
    console.print("12. Run the application: python webui\\app.py")
    console.print("13. Access WebUI at: http://127.0.0.1:5000")
    console.print("\n[bold cyan]Note: PyTorch with CUDA has been installed for GPU support[/bold cyan]")

def main():
    """Main setup function"""
    console.print(Panel(
        "[bold cyan]REAA - Reverse Engineering Analysis Assistant[/bold cyan]\n[yellow]Setup Script for Windows[/yellow]",
        title="[bold]Welcome[/bold]",
        border_style="cyan"
    ))
    
    # Run all setup steps
    check_python_version()
    create_virtual_environment()
    check_visual_cpp()
    install_dependencies()
    install_pytorch()
    check_docker()
    configure_env()
    build_docker()
    start_docker()
    ollama_cmd = install_ollama()
    pull_ollama_model(ollama_cmd)
    install_huggingface_cli()
    
    print_next_steps()
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
