"""Security hardening regression tests."""

import unittest
import hashlib
import os
import sys

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
WEBUI_DIR = os.path.dirname(CURRENT_DIR)
REPO_ROOT = os.path.dirname(WEBUI_DIR)
sys.path.insert(0, WEBUI_DIR)
sys.path.insert(0, REPO_ROOT)

from auth import AuthManager
from core.llm_refiner import LLMRefiner


class TestAuthHardening(unittest.TestCase):
    def test_generate_token_without_secret_fails(self):
        manager = AuthManager(secret_key=None)
        with self.assertRaises(RuntimeError):
            manager.generate_token("user-1")

    def test_token_hash_is_stable_sha256(self):
        manager = AuthManager(secret_key="unit-test-secret")
        token = "sample.token.value"
        expected = hashlib.sha256(token.encode("utf-8")).hexdigest()
        self.assertEqual(manager._token_hash(token), expected)


class TestLLMConfigParsingHardening(unittest.TestCase):
    def test_safe_parse_accepts_dict_literal(self):
        refiner = LLMRefiner(model_path="dummy")
        parsed = refiner._safe_parse_dict_config("{'cuda:0': '10GiB'}", "MAX_MEMORY")
        self.assertEqual(parsed, {'cuda:0': '10GiB'})

    def test_safe_parse_rejects_non_dict(self):
        refiner = LLMRefiner(model_path="dummy")
        with self.assertRaises(ValueError):
            refiner._safe_parse_dict_config("['not', 'a', 'dict']", "MAX_MEMORY")

    def test_safe_parse_rejects_code_execution_payload(self):
        refiner = LLMRefiner(model_path="dummy")
        payload = "__import__('os').system('echo vulnerable')"
        with self.assertRaises(ValueError):
            refiner._safe_parse_dict_config(payload, "MAX_MEMORY")


if __name__ == '__main__':
    unittest.main()
