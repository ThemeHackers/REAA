import os
import sys
import platform
import subprocess
from pathlib import Path

# Ensure we're using the venv Python
if not os.path.exists(os.path.join(os.path.dirname(sys.executable), "activate.bat")):
    venv_python = Path(__file__).parent.parent.parent / ".venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        sys.executable = str(venv_python)

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

try:
    import frida
    print(f"Frida imported successfully, version: {frida.__version__}")
except ImportError as e:
    print(f"Frida import failed: {e}")

from core.frida_instrumentation import get_frida, FRIDA_AVAILABLE, FridaInstrumentation

def test_frida_wine_availability():
    """Test to diagnose why Frida fails with Wine on Windows"""
    
    print("=" * 80)
    print("FRIDA WINE DIAGNOSTIC TEST")
    print("=" * 80)
    
    # Test 1: Check platform
    print(f"\n[TEST 1] Platform: {platform.system()}")
    print(f"Platform detail: {platform.platform()}")
    
    # Test 2: Check if Frida is available
    print(f"\n[TEST 2] Frida available: {FRIDA_AVAILABLE}")
    
    if FRIDA_AVAILABLE:
        frida = get_frida()
        print(f"Frida device: {frida.device}")
        print(f"Frida device type: {frida.device.type if frida.device else 'N/A'}")
    
    # Test 3: Check if Wine is available on host system
    print("\n[TEST 3] Checking Wine availability on host...")
    try:
        result = subprocess.run(['wine', '--version'], capture_output=True, text=True, timeout=5)
        print(f"Wine is available: {result.returncode == 0}")
        if result.returncode == 0:
            print(f"Wine version: {result.stdout.strip()}")
    except FileNotFoundError:
        print("Wine is NOT available on host system (FileNotFoundError)")
    except Exception as e:
        print(f"Wine check failed: {e}")
    
    # Test 4: Check if we can run .exe directly on Windows
    print("\n[TEST 4] Can we run .exe directly on Windows?")
    if platform.system() == "Windows":
        print("YES - On Windows, .exe files run natively without Wine")
        print("Frida should spawn .exe directly (without Wine)")
    else:
        print("NO - On Linux/macOS, Wine is needed to run .exe files")
        print("Frida needs Wine to spawn .exe files")
    
    # Test 5: Test binary path
    test_binary = r"C:\Users\1com310568\Downloads\REAA\data\0747c71021e842d2a10c785717f91191\caesar_cipher.exe"
    print(f"\n[TEST 5] Test binary: {test_binary}")
    print(f"Binary exists: {Path(test_binary).exists()}")
    
    # Test 6: Try Frida spawn without Wine
    if FRIDA_AVAILABLE and platform.system() == "Windows":
        print("\n[TEST 6] Attempting Frida spawn WITHOUT Wine...")
        frida = FridaInstrumentation()  # Fresh instance
        try:
            # On Windows, spawn .exe directly
            print(f"DEBUG: Calling spawn_process with use_wine=False")
            result = frida.spawn_process(test_binary, use_wine=False)
            print(f"Spawn without Wine: {'SUCCESS' if result else 'FAILED'}")
            if result:
                print("Frida can spawn .exe directly on Windows without Wine")
                frida.detach()
        except Exception as e:
            print(f"Spawn without Wine failed: {e}")
    
    # Test 7: Try Frida spawn with Wine (this should fail on Windows)
    # Commented out to focus on TEST 6
    # if FRIDA_AVAILABLE and platform.system() == "Windows":
    #     print("\n[TEST 7] Attempting Frida spawn WITH Wine (expected to fail)...")
    #     frida = FridaInstrumentation()  # Fresh instance
    #     try:
    #         result = frida.spawn_process(test_binary, use_wine=True)
    #         print(f"Spawn with Wine: {'SUCCESS' if result else 'FAILED'}")
    #     except Exception as e:
    #         print(f"Spawn with Wine failed (expected): {e}")
    
    print("\n" + "=" * 80)
    print("DIAGNOSIS SUMMARY")
    print("=" * 80)
    print("\nPROBLEM IDENTIFIED:")
    print("- Frida is running on Windows host")
    print("- Wine is NOT available on Windows host")
    print("- The code tries to use Wine with Frida on Windows")
    print("- This causes 'ExecutableNotFoundError: unable to find executable at wine'")
    
    print("\nSOLUTION:")
    print("- On Windows: Frida should spawn .exe files directly (use_wine=False)")
    print("- Wine is only needed inside Docker container for sandbox execution")
    print("- Frida instrumentation runs on host, not inside container")
    print("- Remove use_wine=True when Frida is on Windows platform")
    print("=" * 80)

if __name__ == "__main__":
    test_frida_wine_availability()
