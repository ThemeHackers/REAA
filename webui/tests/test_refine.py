#!/usr/bin/env python3
import os
import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich import print as rprint

console = Console()


os.environ['LLM4DECOMPILE_MODEL_PATH'] = 'LLM4Binary/llm4decompile-1.3b-v2'

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


try:
    import torch
    console.print(Panel(
        f"[bold blue]PyTorch version:[/bold blue] {torch.__version__}\n[bold green]CUDA available:[/bold green] {torch.cuda.is_available()}",
        title="[bold]PyTorch Check[/bold]",
        border_style="blue"
    ))
    if not torch.cuda.is_available():
        console.print("\n[red][X] CUDA is NOT available in this environment[/red]")
        console.print("[yellow]To install CUDA version of PyTorch, run:[/yellow]")
        console.print("  pip uninstall torch torchvision torchaudio")
        console.print("  pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124")
        sys.exit(1)
    console.print(f"[cyan]CUDA device count:[/cyan] {torch.cuda.device_count()}")
    for i in range(torch.cuda.device_count()):
        console.print(f"[dim]Device {i}:[/dim] {torch.cuda.get_device_name(i)}")
except ImportError:
    console.print("[red][X] Failed to import torch[/red]")
    sys.exit(1)

from core.llm_refiner import get_refiner

def test_refiner():
    console.print(Panel(
        "[bold cyan]Testing LLM Refiner[/bold cyan]",
        title="[bold]REAA Test[/bold]",
        border_style="cyan"
    ))

    console.print("\n[bold][1][/bold] [blue]Getting LLM refiner...[/blue]")
    start_load = time.time()
    refiner = get_refiner()
    load_time = time.time() - start_load
    console.print(f"[dim]    Model load time: {load_time:.2f} seconds ({load_time/60:.2f} minutes)[/dim]")

    if not refiner:
        console.print("[red][X] Failed to get refiner[/red]")
        return False

    if not refiner.is_available():
        console.print("[red][X] Refiner not available[/red]")
        return False

    console.print("[green][OK] Refiner available[/green]")

    test_pseudocode = """
void DloadReleaseSectionWriteAccess(void)

{
  ulong local_8;
  
  if ((IMAGE_LOAD_CONFIG_DIRECTORY32_0041f398.GuardFlags & IMAGE_GUARD_PROTECT_DELAYLOAD_IAT) != 0)
  {
    DloadLock();
    DAT_0042acc8 = DAT_0042acc8 + -1;
    if (DAT_0042acc8 == 0) {
      DloadProtectSection(DAT_0042accc,&local_8);
    }
    DloadUnlock();
  }
  return;
}
"""

    console.print(f"\n[bold][2][/bold] [blue]Testing refinement with pseudocode (length: {len(test_pseudocode)})...[/blue]")
    console.print(f"[dim]Pseudocode:\n{test_pseudocode}[/dim]")

    try:
        start_refine = time.time()
        refined = refiner.refine_pseudo_code(test_pseudocode)
        refine_time = time.time() - start_refine
        console.print(f"[dim]    Refinement time: {refine_time:.2f} seconds ({refine_time/60:.2f} minutes)[/dim]")

        if refined:
            console.print(f"\n[green][OK] Refinement successful![/green]")
            console.print(f"\n[bold]Refined code:[/bold]\n{refined}")
            console.print(f"\n[cyan]Refined code length:[/cyan] {len(refined)}")
            console.print(f"\n[yellow]Total time:[/yellow] {load_time + refine_time:.2f} seconds ({(load_time + refine_time)/60:.2f} minutes)")
            return True
        else:
            console.print("\n[red][X] Refinement returned None[/red]")
            return False

    except Exception as e:
        console.print(f"\n[red][X] Refinement failed with error: {e}[/red]")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_refiner()

    console.print(Panel(
        "[bold green]TEST PASSED[/bold green]" if success else "[bold red]TEST FAILED[/bold red]",
        title="[bold]Test Result[/bold]",
        border_style="green" if success else "red"
    ))

    sys.exit(0 if success else 1)
