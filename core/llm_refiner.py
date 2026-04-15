"""
LLM Refiner Module for REAA
Uses llm4decompile-1.3B-v2 model to refine Ghidra pseudo-code
"""
import torch
from transformers import AutoTokenizer, AutoModelForCausalLM
from pathlib import Path
import logging
import structlog
from typing import Optional, Dict, Any

log = structlog.get_logger()


class LLMRefiner:
    """Service for refining decompiled code using LLM4Decompile"""
    
    def __init__(self, model_path: Optional[str] = None):
        """
        Initialize the LLM refiner
        
        Args:
            model_path: Path to the llm4decompile model. If None, uses default path
        """
        self.model_path = model_path or self._get_default_model_path()
        self.tokenizer = None
        self.model = None
        self.device = None
        self._initialized = False
        
    def _get_default_model_path(self) -> str:
        """Get default model path from RD folder"""
        
        rd_folder = Path(__file__).parent.parent / "RD" / "llm4decompile-1.3b-v2"
        if rd_folder.exists():
            return str(rd_folder)
      
        return "LLM4Binary/llm4decompile-1.3b-v2"
    
    def load_model(self) -> bool:
        """
        Load the LLM model and tokenizer
        
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            log.info(f"Loading LLM refiner model from {self.model_path}")
            
        
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            log.info(f"Using device: {self.device}")
            
          
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path)
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True
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
        max_new_tokens: int = 2048
    ) -> Optional[str]:
        """
        Refine Ghidra pseudo-code to readable C code
        
        Args:
            pseudo_code: The pseudo-code to refine
            max_new_tokens: Maximum number of tokens to generate
            
        Returns:
            str: Refined code, or None if refinement failed
        """
        if not self._initialized:
            log.error("LLM refiner not initialized")
            return None
        
        try:
         
            prompt = f"# This is the pseudo-code:\n{pseudo_code}\n# What is the source code?\n"
            
           
            inputs = self.tokenizer(prompt, return_tensors="pt").to(self.model.device)
            
          
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=max_new_tokens,
                    temperature=0.7,
                    do_sample=True,
                    pad_token_id=self.tokenizer.eos_token_id
                )
            
             
            refined_code = self.tokenizer.decode(outputs[0][len(inputs[0]):-1])
            refined_code = self.clean_tokens(refined_code)
            
            log.info(f"Refinement successful, output length: {len(refined_code)}")
            return refined_code
            
        except Exception as e:
            log.error(f"Error during refinement: {e}")
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
