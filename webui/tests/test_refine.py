#!/usr/bin/env python3
"""
Test script for LLM refiner to verify device mismatch fix
"""
import os
import sys
import time


os.environ['LLM4DECOMPILE_MODEL_PATH'] = 'LLM4Binary/llm4decompile-1.3b-v2'

project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)


try:
    import torch
    print(f"PyTorch version: {torch.__version__}")
    print(f"CUDA available: {torch.cuda.is_available()}")
    if not torch.cuda.is_available():
        print("\n[X] CUDA is NOT available in this environment")
        print("To install CUDA version of PyTorch, run:")
        print("pip uninstall torch torchvision torchaudio")
        print("pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124")
        sys.exit(1)
    print(f"CUDA device count: {torch.cuda.device_count()}")
    for i in range(torch.cuda.device_count()):
        print(f"Device {i}: {torch.cuda.get_device_name(i)}")
except ImportError:
    print("[X] Failed to import torch")
    sys.exit(1)

from core.llm_refiner import get_refiner

def test_refiner():
    """Test LLM refiner with a simple pseudocode"""
    print("=" * 60)
    print("Testing LLM Refiner")
    print("=" * 60)

    print("\n[1] Getting LLM refiner...")
    start_load = time.time()
    refiner = get_refiner()
    load_time = time.time() - start_load
    print(f"    Model load time: {load_time:.2f} seconds ({load_time/60:.2f} minutes)")

    if not refiner:
        print("[X] Failed to get refiner")
        return False

    if not refiner.is_available():
        print("[X] Refiner not available")
        return False

    print("[OK] Refiner available")

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

    print(f"\n[2] Testing refinement with pseudocode (length: {len(test_pseudocode)})...")
    print(f"Pseudocode:\n{test_pseudocode}")

    try:
        start_refine = time.time()
        refined = refiner.refine_pseudo_code(test_pseudocode)
        refine_time = time.time() - start_refine
        print(f"    Refinement time: {refine_time:.2f} seconds ({refine_time/60:.2f} minutes)")

        if refined:
            print(f"\n[OK] Refinement successful!")
            print(f"\nRefined code:\n{refined}")
            print(f"\nRefined code length: {len(refined)}")
            print(f"\nTotal time: {load_time + refine_time:.2f} seconds ({(load_time + refine_time)/60:.2f} minutes)")
            return True
        else:
            print("\n[X] Refinement returned None")
            return False

    except Exception as e:
        print(f"\n[X] Refinement failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_refiner()

    print("\n" + "=" * 60)
    if success:
        print("[OK] TEST PASSED")
    else:
        print("[X] TEST FAILED")
    print("=" * 60)

    sys.exit(0 if success else 1)
