#!/usr/bin/env python3

import os
import sys
import subprocess
import re
import logging
from datetime import datetime
from pathlib import Path
import shutil
from pathlib import Path


try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.status import Status
    from rich.text import Text
    from rich import print as rprint
except ImportError:
    print("Installing rich package...")
    subprocess.run([sys.executable, "-m", "pip", "install", "rich"], check=True)
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.status import Status
    from rich.text import Text
    from rich import print as rprint


console = Console()


log_file = Path("setup.log")
error_patterns = [
    r'\bERROR\b',
    r'\berror\b',
    r'\bFAIL\b',
    r'\bfail\b',
    r'\bFail\b',
    r'\bexception\b',
    r'\bException\b',
    r'\btraceback\b',
    r'\bTraceback\b',
    r'\bcritical\b',
    r'\bCritical\b',
    r'\bfatal\b',
    r'\bFatal\b',
]

def setup_logging():
    log_file.unlink(missing_ok=True)
    
    class ErrorHighlightingFormatter(logging.Formatter):
        def format(self, record):
            log_entry = super().format(record)
            for pattern in error_patterns:
                if re.search(pattern, log_entry, re.IGNORECASE):
                    return f"[ERROR_HIGHLIGHT]{log_entry}[/ERROR_HIGHLIGHT]"
            return log_entry
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file, mode='w', encoding='utf-8'),
        ]
    )
    return logging.getLogger('setup')

logger = setup_logging()

def scan_for_errors(text):
    highlighted = text
    for pattern in error_patterns:
        matches = list(re.finditer(pattern, highlighted, re.IGNORECASE))
        for match in reversed(matches):
            start = match.start()
            end = match.end()
            highlighted = highlighted[:start] + f"[RED]{highlighted[start:end]}[/RED]" + highlighted[end:]
    return highlighted

def log_with_error_scan(message, level='INFO'):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
 
    has_error = any(re.search(pattern, message, re.IGNORECASE) for pattern in error_patterns)
    
  
    with open(log_file, 'a', encoding='utf-8') as f:
        if has_error:
            f.write(f"{timestamp} - ERROR - {message}\n")
        else:
            f.write(f"{timestamp} - {level} - {message}\n")
    

    if has_error:
        console.print(f"[red]{message}[/red]")
    else:
        console.print(message)

def print_success(message):
    console.print(f"[green][OK][/green] {message}")
    log_with_error_scan(f"[OK] {message}", 'SUCCESS')

def print_warning(message):
    console.print(f"[yellow][WARNING][/yellow] {message}")
    log_with_error_scan(f"[WARNING] {message}", 'WARNING')

def print_info(message):
    console.print(f"[blue][INFO][/blue] {message}")
    log_with_error_scan(f"[INFO] {message}", 'INFO')

def print_error(message):
    console.print(f"[red][ERROR][/red] {message}")
    log_with_error_scan(f"[ERROR] {message}", 'ERROR')

def print_step(step_num, total_steps, description):
    console.print(f"\n[cyan][{step_num}/{total_steps}][/cyan] {description}")

def check_setup_completed():
    print_step(0, 15, "Checking if setup has been completed...")
    
    checks = {
        "venv": Path(".venv").exists(),
        "env": Path(".env").exists(),
        "docker_image": False,
        "ollama": False,
        "hf_cli": False
    }
    

    try:
        result = subprocess.run(["docker", "images", "reaa/active-re-linux:latest"], capture_output=True, text=True, shell=True)
        if "reaa/active-re-linux" in result.stdout:
            checks["docker_image"] = True
    except:
        pass
    

    try:
        result = subprocess.run(["ollama", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            checks["ollama"] = True
    except:
        pass
    

    try:
        result = subprocess.run(["hf", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            checks["hf_cli"] = True
    except:
        pass
    
    completed_count = sum(checks.values())
    total_count = len(checks)
    
    if completed_count == total_count:
        console.print(Panel(
            "[bold green]Setup appears to be already completed![/bold green]",
            title="[bold]Setup Status[/bold]",
            border_style="green"
        ))
        console.print("\n[yellow]All components are installed. To force reinstall, delete .venv and .env files.[/yellow]")
        response = input("\n[yellow]Continue with setup anyway? (y/n): [/yellow]")
        return response.lower() != 'y'
    elif completed_count > 0:
        console.print(f"[yellow]Setup partially completed ({completed_count}/{total_count} components). Continuing...[/yellow]")
        return False
    else:
        console.print("[blue]No components found. Starting fresh setup...[/blue]")
        return False

def run_command(cmd, description, continue_on_error=True):
    console.print(f"[dim]Running: {cmd}[/dim]")
    log_with_error_scan(f"Running: {cmd}", 'INFO')
    try:
        result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
        print_success(description)
        if result.stdout:
            log_with_error_scan(result.stdout, 'INFO')
        return True
    except subprocess.CalledProcessError as e:
        print_warning(f"Failed: {description}")
        console.print(f"[red]Error: {e}[/red]")
        log_with_error_scan(f"Failed: {description} - Error: {e}", 'ERROR')
        if result.stderr:
            log_with_error_scan(result.stderr, 'ERROR')
        if continue_on_error:
            print_info("Continuing with setup...")
        return False

def check_python_version():
    print_step(1, 15, "Checking Python version...")
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
    print_step(2, 15, "Creating virtual environment...")
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
    print_step(3, 15, "Checking Microsoft Visual C++ Build Tools...")
    has_cpp_tools = False
    try:
        result = subprocess.run(["where", "cl.exe"], capture_output=True, shell=True)
        if result.returncode == 0:
            print_success("Microsoft Visual C++ Build Tools found")
            has_cpp_tools = True
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
    return has_cpp_tools

def install_dependencies(has_cpp_tools=False):
    print_step(4, 15, "Installing Python dependencies...")
    venv_python = Path(".venv/Scripts/python.exe")
    requirements = Path("requirements.txt")
    
    if not venv_python.exists():
        print_warning("Virtual environment not found, skipping dependencies")
        return False
    
    if not requirements.exists():
        print_warning("requirements.txt not found")
        return False
    
    try:
        with open(requirements, 'r') as f:
            all_requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print_warning(f"Failed to read requirements.txt: {e}")
        return False
    
    cpp_packages = ['jpype1', 'uefi-firmware']
    
    standard_reqs = []
    cpp_reqs = []
    for req in all_requirements:
        req_lower = req.lower()
        if any(pkg in req_lower for pkg in cpp_packages):
            cpp_reqs.append(req)
        else:
            standard_reqs.append(req)
    
    if standard_reqs:
        print_info(f"Installing {len(standard_reqs)} standard dependencies...")
        try:
            with open('temp_requirements.txt', 'w') as f:
                f.write('\n'.join(standard_reqs))
            subprocess.run([str(venv_python), "-m", "pip", "install", "-r", "temp_requirements.txt"], check=True)
            print_success("Standard dependencies installed successfully")
            Path('temp_requirements.txt').unlink(missing_ok=True)
        except KeyboardInterrupt:
            print_warning("Installation cancelled by user")
            Path('temp_requirements.txt').unlink(missing_ok=True)
            print_info("You can resume installation by running this script again")
            return False
        except Exception as e:
            print_warning("Failed to install standard dependencies")
            console.print(f"[red]Error: {e}[/red]")
            Path('temp_requirements.txt').unlink(missing_ok=True)
            return False
    
    if cpp_reqs:
        if has_cpp_tools:
            print_info(f"Installing {len(cpp_reqs)} C++ dependent packages...")
            try:
                with open('temp_cpp_requirements.txt', 'w') as f:
                    f.write('\n'.join(cpp_reqs))
                subprocess.run([str(venv_python), "-m", "pip", "install", "-r", "temp_cpp_requirements.txt"], check=True)
                print_success("C++ dependent packages installed successfully")
                Path('temp_cpp_requirements.txt').unlink(missing_ok=True)
            except KeyboardInterrupt:
                print_warning("Installation cancelled by user")
                Path('temp_cpp_requirements.txt').unlink(missing_ok=True)
                print_info("You can resume installation by running this script again")
                return False
            except Exception as e:
                print_warning("Failed to install C++ dependent packages")
                console.print(f"[red]Error: {e}[/red]")
                Path('temp_cpp_requirements.txt').unlink(missing_ok=True)
                console.print("You can install these later manually:")
                console.print(f"pip install {' '.join(cpp_reqs)}")
                console.print("Continuing with setup...")
                return False
        else:
            print_warning(f"Skipping {len(cpp_reqs)} C++ dependent packages (no Visual C++ Build Tools)")
            console.print("Packages skipped:")
            for req in cpp_reqs:
                console.print(f"  - {req}")
            console.print()
            console.print("To install these packages later:")
            console.print("1. Install Visual C++ Build Tools")
            console.print("2. Run: pip install " + " ".join(cpp_reqs))
            console.print("Continuing with setup...")
    
    return True

def install_pytorch():
    print_step(5, 15, "Installing PyTorch with CUDA for GPU support...")
    venv_python = Path(".venv/Scripts/python.exe")
    
    if not venv_python.exists():
        print_warning("Virtual environment not found, skipping PyTorch installation")
        return False
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                print_info(f"Retry attempt {attempt + 1}/{max_retries}...")
            subprocess.run([
                str(venv_python), "-m", "pip", "install",
                "torch", "torchvision", "torchaudio",
                "--index-url", "https://download.pytorch.org/whl/cu126"
            ], check=True)
            print_success("PyTorch with CUDA installed successfully")
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                print_warning(f"Attempt {attempt + 1} failed, retrying...")
                import time
                time.sleep(2)
            else:
                print_warning("Failed to install PyTorch with CUDA after multiple attempts")
                console.print(f"[red]Error: {e}[/red]")
                console.print("You can install it later with: pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu126")
                return False

def check_docker():
    print_step(6, 15, "Checking Docker installation...")
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

def configure_environment_file():
    print_step(7, 15, "Configuring environment...")
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

def build_main_docker_containers():
    print_step(8, 15, "Building main Docker containers (this may take a while)...")
    max_retries = 2
    for attempt in range(max_retries):
        try:
            if attempt > 0:
                print_info(f"Retry attempt {attempt + 1}/{max_retries}...")
            subprocess.run("docker-compose build", shell=True, check=True)
            print_success("Docker containers built successfully")
            return True
        except Exception as e:
            if attempt < max_retries - 1:
                print_warning(f"Attempt {attempt + 1} failed, retrying...")
                import time
                time.sleep(5)
            else:
                print_warning("Failed to build Docker containers after multiple attempts")
                console.print(f"[red]Error: {e}[/red]")
                console.print("This may be due to network connectivity issues with Ubuntu repositories")
                console.print()
                console.print("Troubleshooting steps:")
                console.print("1. Check firewall/VPN that might be blocking Docker")
                console.print("2. Fix Docker DNS settings")
                console.print("3. Or run Docker build again when network is normal: docker-compose build ; docker-compose up -d")
                console.print()
                console.print("You can build later with: docker-compose build")
                console.print("Continuing with setup...")
                return False

def start_docker_services():
    print_step(11, 15, "Starting Docker services...")
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

def build_active_re_windows_image():
    print_step(9, 15, "Building Active RE Windows sandbox Docker image (this may take a while)...")
    active_re_windows_dir = Path("docker/active-re-windows")

    if not active_re_windows_dir.exists():
        print_warning("Active RE Windows directory not found, skipping...")
        return False

    print_info("This image is used for running Windows binaries in sandbox with Wine")

    try:
        max_retries = 2
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    print_info(f"Retry attempt {attempt + 1}/{max_retries}...")
                subprocess.run(
                    f"docker build -t reaa/active-re-windows:latest .",
                    cwd=str(active_re_windows_dir),
                    shell=True,
                    check=True
                )
                print_success("Active RE Windows sandbox image built successfully")
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    import time
                    time.sleep(5)
                else:
                    raise
    except Exception as e:
        print_warning("Failed to build Active RE Windows sandbox image")
        console.print(f"[red]Error: {e}[/red]")
        console.print("This may be due to network connectivity issues with Ubuntu repositories")
        console.print()
        console.print("You can build it later with:")
        console.print("  cd docker/active-re-windows")
        console.print("  docker build -t reaa/active-re-windows:latest .")
        console.print("Continuing with setup...")
        return False


def build_active_re_sandbox_image():
    print_step(10, 15, "Building Active RE Linux sandbox Docker image (this may take a while)...")
    active_re_dir = Path("docker/active-re")

    if not active_re_dir.exists():
        print_warning("Active RE directory not found, skipping...")
        return False
    
    try:
        original_dir = os.getcwd()
        os.chdir(active_re_dir)
        
        max_retries = 2
        for attempt in range(max_retries):
            try:
                if attempt > 0:
                    print_info(f"Retry attempt {attempt + 1}/{max_retries}...")
                subprocess.run("docker build -t reaa/active-re-linux:latest .", shell=True, check=True)
                print_success("Active RE Linux sandbox image built successfully")
                return True
            except Exception as e:
                if attempt < max_retries - 1:
                    print_warning(f"Attempt {attempt + 1} failed, retrying...")
                    import time
                    time.sleep(5)
                else:
                    raise
    except Exception as e:
        print_warning("Failed to build Active RE sandbox image")
        console.print(f"[red]Error: {e}[/red]")
        console.print("This may be due to network connectivity issues with Ubuntu repositories")
        console.print()
        console.print("You can build it later with:")
        console.print("  cd docker/active-re")
        console.print("  docker build -t reaa/active-re-linux:latest .")
        console.print("Continuing with setup...")
        return False
    finally:
        os.chdir(original_dir)

def install_ollama_runtime():
    print_step(12, 15, "Checking Ollama installation...")
    try:
        result = subprocess.run(["ollama", "--version"], capture_output=True, text=True)
        console.print(result.stdout.strip())
        print_success("Ollama is already installed")
        ollama_cmd = "ollama"
    except Exception:
        print_info("Ollama is not installed, installing now...")
        console.print("This may require administrator privileges")
        
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print_warning("Not running as administrator")
                console.print("Ollama installation may fail without admin privileges")
                console.print("Please run this script as administrator or install Ollama manually")
        except:
            pass
        
        try:
            subprocess.run(
                "powershell -ExecutionPolicy ByPass -Command \"& { irm https://ollama.com/install.ps1 | iex }\"",
                shell=True,
                check=True
            )
            print_success("Ollama installed successfully")
  
            ollama_cmd = rf"C:\Users\{os.environ['USERNAME']}\AppData\Local\Programs\Ollama\ollama.exe"
        except Exception as e:
            print_warning("Failed to install Ollama automatically")
            console.print(f"[red]Error: {e}[/red]")
            console.print("Please install Ollama manually from https://ollama.com/download")
            console.print("Or run in PowerShell as administrator: irm https://ollama.com/install.ps1 | iex")
            console.print("Continuing with setup...")
            ollama_cmd = None
    
    return ollama_cmd

def download_ollama_model(ollama_cmd):
    print_step(13, 15, "Checking llama3.2:3b model...")
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

def install_huggingface_cli_tool():
    print_step(14, 15, "Installing Hugging Face CLI...")
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

def install_reaa():
    print_step(15, 15, "Installing REAA CLI...")
    venv_python = Path(".venv/Scripts/python.exe")
    cli_dir = Path("cli")

    if not venv_python.exists():
        print_warning("Virtual environment not found, skipping CLI installation")
        return False

    if not cli_dir.exists():
        print_warning("CLI directory not found, skipping...")
        return False

    try:
        print_info("Installing reaa-cli package from cli/ directory...")
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "-e", str(cli_dir)],
            check=True
        )
        print_success("reaa-cli installed successfully")
        print_info("You can now use: rea --help")
        return True
    except Exception as e:
        print_warning("Failed to install reaa-cli")
        console.print(f"[red]Error: {e}[/red]")
        console.print("You can install it later with: .venv\\Scripts\\python -m pip install -e cli")
        console.print("Continuing with setup...")
        return False

def display_error_summary():
    if not log_file.exists():
        return
    
    error_count = 0
    warning_count = 0
    
    with open(log_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        for line in lines:
            if '- ERROR -' in line:
                error_count += 1
            elif '- WARNING -' in line:
                warning_count += 1
    
    if error_count > 0 or warning_count > 0:
        console.print(f"\n[bold red]Setup completed with issues:[/bold red]")
        console.print(f"  [red]Errors: {error_count}[/red]")
        console.print(f"  [yellow]Warnings: {warning_count}[/yellow]")
        console.print(f"  [blue]Log file: {log_file}[/blue]")
        console.print("\n[bold]View errors:[/bold]")
        console.print(f"  Get-Content {log_file} | Select-String -Pattern 'ERROR'")
    else:
        console.print(f"\n[bold green]Setup completed without errors![/bold green]")
        console.print(f"  [blue]Log file: {log_file}[/blue]")

def display_setup_completion_instructions():
    console.print(Panel(
        "[bold green]Setup completed successfully![/bold green]",
        title="[bold]REAA Setup[/bold]",
        border_style="green"
    ))
    
    display_error_summary()
    
    console.print("\n[bold]Next steps:[/bold]")
    console.print("1. If Python failed, install Python 3.14.x from https://www.python.org/")
    console.print("2. If venv failed, run: python -m venv .venv ; .venv\\Scripts\\activate")
    console.print("3. If dependencies failed, run: pip install -r requirements.txt")
    console.print("4. If Docker failed, install from https://www.docker.com/products/docker-desktop")
    console.print("5. If Docker build failed, fix network and run: docker-compose build ; docker-compose up -d")
    console.print("6. If Active RE Windows image build failed, run: cd docker/active-re-windows ; docker build -t reaa/active-re-windows:latest .")
    console.print("7. If Active RE Linux image build failed, run: cd docker/active-re ; docker build -t reaa/active-re-linux:latest .")
    console.print("8. If Ollama failed, install from https://ollama.com/download")
    console.print("9. If Ollama model failed, run: ollama pull llama3.2:3b")
    console.print("10. If Hugging Face CLI failed, run in PowerShell: irm https://hf.co/cli/install.ps1 | iex")
    console.print("11. Login to Hugging Face: hf auth login")
    console.print("12. Edit .env file with your settings (if not already done)")
    console.print("13. Start Ollama server in a new terminal: ollama serve")
    console.print("14. Run the application: python webui\\app.py")
    console.print("15. Access WebUI at: http://127.0.0.1:5000")
    console.print("16. If reaa-cli installation failed, run: .venv\\Scripts\\python -m pip install -e cli")
    console.print("17. Use CLI: rea --help")
    console.print("\n[bold cyan]Note: PyTorch with CUDA has been installed for GPU support[/bold cyan]")

def main():
    console.print(Panel(
        "[bold cyan]REAA - Reverse Engineering Analysis Assistant[/bold cyan]\n[yellow]Setup Script for Windows[/yellow]",
        title="[bold]Welcome[/bold]",
        border_style="cyan"
    ))
    
    log_with_error_scan("="*80, 'INFO')
    log_with_error_scan("Starting REAA Setup", 'INFO')
    log_with_error_scan(f"Log file: {log_file}", 'INFO')
    log_with_error_scan("="*80, 'INFO')
    
    if check_setup_completed():
        log_with_error_scan("Setup already completed, exiting", 'INFO')
        input("\nPress Enter to exit...")
        return
    
    check_python_version()
    create_virtual_environment()
    has_cpp_tools = check_visual_cpp()
    install_dependencies(has_cpp_tools)
    install_pytorch()
    check_docker()
    configure_environment_file()
    build_main_docker_containers()
    build_active_re_windows_image()
    build_active_re_sandbox_image()
    start_docker_services()
    ollama_cmd = install_ollama_runtime()
    download_ollama_model(ollama_cmd)
    install_huggingface_cli_tool()
    install_reaa()
    
    log_with_error_scan("="*80, 'INFO')
    log_with_error_scan("Setup completed successfully", 'INFO')
    log_with_error_scan(f"Log file saved to: {log_file}", 'INFO')
    log_with_error_scan("="*80, 'INFO')
    
    display_setup_completion_instructions()
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
