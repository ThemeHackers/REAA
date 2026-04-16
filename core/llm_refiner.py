"""
LLM Refiner Module for REAA
Uses llm4decompile model to refine Ghidra pseudo-code
"""
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from pathlib import Path
import logging
import structlog
from typing import Optional, Dict, Any
import time
import signal
from .config import settings

log = structlog.get_logger()


class TimeoutError(Exception):
    """Custom timeout exception for model generation"""
    pass


class LLMRefiner:
    """Service for refining decompiled code using LLM4Decompile"""

    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the LLM refiner

        Args:
            model_path: Path to the llm4decompile model. If None, uses env var or default
        """
        self.model_path = model_path or settings.LLM4DECOMPILE_MODEL_PATH
        self.tokenizer = None
        self.model = None
        self.device = None
        self._initialized = False
    
    def load_model(self) -> bool:
        """
        Load the LLM model and tokenizer

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.model_path:
            log.warning("LLM4DECOMPILE_MODEL_PATH not set, skipping model load")
            return False

        try:
       
            is_local = Path(self.model_path).exists()

            if is_local:
                log.info(f"Loading LLM refiner model from local path: {self.model_path}")
            else:
                log.info(f"Loading LLM refiner model from HuggingFace: {self.model_path}")

            
            device_setting = settings.LLM4DECOMPILE_DEVICE.lower()
            if device_setting == "auto":
                self.device = "cuda" if torch.cuda.is_available() else "cpu"
            else:
                self.device = device_setting
            log.info(f"Using device: {self.device}")


            dtype_str = settings.LLM4DECOMPILE_DTYPE.lower()
            dtype_map = {
                "float16": torch.float16,
                "float32": torch.float32,
                "bfloat16": torch.bfloat16,
                "float8": torch.float8_e4m3fn if hasattr(torch, "float8_e4m3fn") else torch.float16,
            }
            dtype = dtype_map.get(dtype_str, torch.float16)

         
            model_kwargs = {
                "trust_remote_code": True,
                "dtype": dtype,
            }

          
            if self.device == "cuda":
                model_kwargs["device_map"] = "auto"

       
            if settings.LLM4DECOMPILE_MAX_MEMORY:
                model_kwargs["max_memory"] = eval(settings.LLM4DECOMPILE_MAX_MEMORY)

           
            if settings.LLM4DECOMPILE_QUANTIZATION:
                model_kwargs["quantization_config"] = eval(settings.LLM4DECOMPILE_QUANTIZATION)

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                **model_kwargs
            )

            self._initialized = True
            log.info(f"LLM refiner loaded successfully on {self.device}")
            return True

        except Exception as e:
            log.error(f"Failed to load LLM refiner: {e}")
            self._initialized = False
            return False
    
    def clean_tokens(self, text: str) -> str:
        """Clean special tokens from model output"""
        text = text.replace("Ġ", " ")
        text = text.replace("Ċ", "\n")
        text = text.replace("ĉ", "\n")
        text = text.replace("Ĥ", "\n\n")
        return text
    
    def refine_pseudo_code(
        self,
        pseudo_code: str,
        max_new_tokens: Optional[int] = None,
        max_retries: int = 3,
        timeout_seconds: int = 300
    ) -> Optional[str]:
        """
        Refine Ghidra pseudo-code to readable C code with retry logic and timeout

        Args:
            pseudo_code: The pseudo-code to refine
            max_new_tokens: Maximum number of tokens to generate (uses settings if None)
            max_retries: Maximum number of retry attempts on failure
            timeout_seconds: Maximum time to wait for model generation

        Returns:
            str: Refined code, or None if refinement failed after all retries
        """
        if not self._initialized:
            log.error("LLM refiner not initialized, attempting to load model...")
            if not self.load_model():
                log.error("Failed to initialize LLM refiner after retry")
                return None

        if not pseudo_code or not pseudo_code.strip():
            log.error("Empty pseudo-code provided")
            return None

        for attempt in range(max_retries):
            try:
                prompt = f"# This is the assembly code:\n{pseudo_code}\n# What is the source code?\n"

                log.info(f"[DEBUG] Tokenizing prompt (length: {len(prompt)}), attempt {attempt + 1}/{max_retries}")
                inputs = self.tokenizer(prompt, return_tensors="pt")

                if self.device == "cuda":
                    inputs = inputs.to("cuda")
                    log.info(f"[DEBUG] Moved inputs to CUDA")
                else:
                    log.info(f"[DEBUG] self.device: {self.device}, inputs on CPU")

                tokens_limit = max_new_tokens or settings.LLM4DECOMPILE_MAX_NEW_TOKENS
                log.info(f"[DEBUG] Starting model.generate with max_new_tokens: {tokens_limit}")

                def handler(signum, frame):
                    raise TimeoutError("Model generation timed out")

                if hasattr(signal, 'SIGALRM'):
                    signal.signal(signal.SIGALRM, handler)
                    signal.alarm(timeout_seconds)

                try:
                    with torch.no_grad():
                        log.info(f"[DEBUG] Inside torch.no_grad, calling model.generate")
                        outputs = self.model.generate(
                            **inputs,
                            max_new_tokens=tokens_limit,
                            temperature=settings.LLM4DECOMPILE_TEMPERATURE,
                            do_sample=True,
                            repetition_penalty=settings.LLM4DECOMPILE_REPETITION_PENALTY,
                            top_p=settings.LLM4DECOMPILE_TOP_P,
                            top_k=settings.LLM4DECOMPILE_TOP_K,
                            pad_token_id=self.tokenizer.eos_token_id
                        )
                        log.info(f"[DEBUG] model.generate completed")
                finally:
                    if hasattr(signal, 'SIGALRM'):
                        signal.alarm(0)

                refined_code = self.tokenizer.decode(outputs[0][len(inputs[0]):-1])
                refined_code = self.clean_tokens(refined_code)

                if not refined_code or not refined_code.strip():
                    log.warning(f"Refinement returned empty code on attempt {attempt + 1}")
                    if attempt < max_retries - 1:
                        time.sleep(2 ** attempt)
                        continue
                    else:
                        return None

                log.info(f"Refinement successful, output length: {len(refined_code)}")
                return refined_code

            except TimeoutError as e:
                log.error(f"Timeout during refinement attempt {attempt + 1}: {e}")
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                else:
                    return None
            except torch.cuda.OutOfMemoryError as e:
                log.error(f"CUDA out of memory during refinement attempt {attempt + 1}: {e}")
                torch.cuda.empty_cache()
                if attempt < max_retries - 1:
                    time.sleep(5)
                    continue
                else:
                    return None
            except Exception as e:
                log.error(f"Error during refinement attempt {attempt + 1}: {e}", exc_info=True)
                if attempt < max_retries - 1:
                    time.sleep(2 ** attempt)
                    continue
                else:
                    return None

        return None
    
    def refine_function_from_file(
        self, 
        input_file: Path, 
        output_file: Path
    ) -> bool:
        """
        Refine pseudo-code from a file and save to another file
        
        Args:
            input_file: Path to input pseudo-code file
            output_file: Path to save refined code
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
          
            pseudo_code = input_file.read_text(encoding='utf-8')
            
            
            refined_code = self.refine_pseudo_code(pseudo_code)
            if refined_code is None:
                return False
            
          
            output_file.parent.mkdir(parents=True, exist_ok=True)
            output_file.write_text(refined_code, encoding='utf-8')
            
            log.info(f"Saved refined code to {output_file}")
            return True
            
        except Exception as e:
            log.error(f"Error refining from file: {e}")
            return False
    
    def is_available(self) -> bool:
        """Check if the refiner is available and initialized"""
        return self._initialized
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get device information"""
        return {
            "device": self.device,
            "cuda_available": torch.cuda.is_available(),
            "initialized": self._initialized,
            "model_path": self.model_path
        }



_refiner_instance: Optional[LLMRefiner] = None


def get_refiner() -> LLMRefiner:
    """Get or create the global refiner instance"""
    global _refiner_instance
    if _refiner_instance is None:
        _refiner_instance = LLMRefiner()
        _refiner_instance.load_model()
    return _refiner_instance


def initialize_refiner(model_path: Optional[str] = None) -> bool:
    """
    Initialize the global refiner instance
    
    Args:
        model_path: Optional custom model path
        
    Returns:
        bool: True if successful
    """
    global _refiner_instance
    try:
        _refiner_instance = LLMRefiner(model_path)
        return _refiner_instance.load_model()
    except Exception as e:
        log.error(f"Failed to initialize refiner: {e}")
        return False
