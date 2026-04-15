import os
import json
from typing import Dict, Any, List, Optional
from openai import OpenAI


class ModelManager:
    """Manager for AI model operations and configuration"""
    
    def __init__(self):
        self.client = OpenAI(
            base_url=os.getenv("API_BASE", "http://localhost:11434/v1"),
            api_key=os.getenv("API_KEY", "ollama")
        )
        self.model = os.getenv("MODEL_NAME", "llama3.2:3b")
        self.models_dir = os.path.join(os.path.dirname(__file__), "models")
        
        if not os.path.exists(self.models_dir):
            os.makedirs(self.models_dir)
        
        self.current_config = self.load_model_config()
    
    def _get_config_file(self) -> str:
        return os.path.join(self.models_dir, "model_config.json")
    
    def load_model_config(self) -> Dict[str, Any]:
        """Load model configuration from file"""
        config_file = self._get_config_file()
        if os.path.exists(config_file):
            try:
                with open(config_file, 'r') as f:
                    return json.load(f)
            except Exception:
                pass
        
        return {
            "current_model": "qwen2.5:3b",
            "available_models": [
                {"name": "qwen2.5:3b", "description": "Qwen 2.5 3B parameter model (best for RTX 2060)", "size": "3B", "vram": "4GB"},
                {"name": "qwen2.5:7b", "description": "Qwen 2.5 7B parameter model (good for RTX 2060 with quantization)", "size": "7B", "vram": "6GB"},
                {"name": "qwen2:7b", "description": "Qwen 2 7B parameter model", "size": "7B", "vram": "6GB"},
                {"name": "qwen2.5:8b", "description": "Qwen 2.5 8B parameter model", "size": "8B", "vram": "8GB"},
                {"name": "llama3:8b", "description": "Llama 3 8B parameter model", "size": "8B", "vram": "8GB"},
                {"name": "mistral:7b", "description": "Mistral 7B parameter model", "size": "7B", "vram": "6GB"},
                {"name": "gemma:7b", "description": "Gemma 7B parameter model", "size": "7B", "vram": "6GB"},
                {"name": "nvidia/nemotron-3-super-120b-a12b:free", "description": "NVIDIA Nemotron 3 Super 120B parameter model (free, cloud)", "size": "120B", "vram": "cloud"}
            ],
            "api_base": os.getenv("API_BASE", "http://localhost:11434/v1"),
            "api_key": os.getenv("API_KEY", "ollama"),
            "default_temperature": 0.7,
            "default_max_tokens": 4096
        }
    
    def save_model_config(self, config: Dict[str, Any]):
        """Save model configuration to file"""
        config_file = self._get_config_file()
        with open(config_file, 'w') as f:
            json.dump(config, f, indent=2)
        self.current_config = config
    
    def get_available_models(self) -> List[Dict[str, Any]]:
        """Get list of available models"""
        return self.current_config.get("available_models", [])
    
    def get_current_model(self) -> str:
        """Get current active model name"""
        return self.current_config.get("current_model", self.model)
    
    def set_model(self, model_name: str) -> bool:
        """Set the current model"""
        available_models = [m["name"] for m in self.get_available_models()]
        
        if model_name not in available_models:
            return False
        
        self.model = model_name
        self.current_config["current_model"] = model_name
        self.save_model_config(self.current_config)
        

        self.client = OpenAI(
            base_url=self.current_config.get("api_base", "http://localhost:11434/v1"),
            api_key=self.current_config.get("api_key", "ollama")
        )
        
        return True
    
    def test_model_connection(self) -> Dict[str, Any]:
        """Test connection to the model API"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": "Hello"}],
                max_tokens=10
            )
            
            return {
                "success": True,
                "model": self.model,
                "response": response.choices[0].message.content if response.choices else ""
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_model_info(self, model_name: str = None) -> Optional[Dict[str, Any]]:
        """Get information about a specific model"""
        if model_name is None:
            model_name = self.model
        
        for model in self.get_available_models():
            if model["name"] == model_name:
                return model
        
        return None
    
    def update_api_config(self, api_base: str = None, api_key: str = None) -> bool:
        """Update API configuration"""
        try:
            if api_base:
                self.current_config["api_base"] = api_base
            if api_key:
                self.current_config["api_key"] = api_key
            
            self.save_model_config(self.current_config)
        
            self.client = OpenAI(
                base_url=self.current_config.get("api_base", "http://localhost:11434/v1"),
                api_key=self.current_config.get("api_key", "ollama")
            )
            
            return True
        except Exception:
            return False
    
    def chat_completion(self, messages: List[Dict[str, Any]], **kwargs) -> str:
        """Perform a chat completion with the current model"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=kwargs.get("temperature", self.current_config.get("default_temperature", 0.7)),
                max_tokens=kwargs.get("max_tokens", self.current_config.get("default_max_tokens", 4096))
            )
            
            return response.choices[0].message.content if response.choices else ""
        except Exception as e:
            raise Exception(f"Chat completion failed: {str(e)}")
    
    def chat_completion_stream(self, messages: List[Dict[str, Any]], **kwargs):
        """Stream chat completion with the current model"""
        try:
            stream = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=kwargs.get("temperature", self.current_config.get("default_temperature", 0.7)),
                max_tokens=kwargs.get("max_tokens", self.current_config.get("default_max_tokens", 4096)),
                stream=True
            )
            
            for chunk in stream:
                content = chunk.choices[0].delta.content
                if content:
                    yield content
        except Exception as e:
            raise Exception(f"Stream completion failed: {str(e)}")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status"""
        connection_test = self.test_model_connection()
        
        return {
            "current_model": self.get_current_model(),
            "api_base": self.current_config.get("api_base"),
            "connection_status": "connected" if connection_test["success"] else "disconnected",
            "available_models_count": len(self.get_available_models()),
            "config_file_exists": os.path.exists(self._get_config_file())
        }


model_manager = ModelManager()
