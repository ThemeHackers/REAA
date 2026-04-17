from setuptools import setup, find_packages

setup(
    name="reaa-cli",
    version="1.0.0",
    description="REAA - Reverse Engineering Analysis Assistant CLI",
    author="REAA Team",
    packages=[],
    py_modules=["reaa_cli"],
    install_requires=[
        "typer>=0.9.0",
        "rich>=13.0.0",
        "requests>=2.31.0",
        "keyring>=24.0.0",
    ],
    entry_points={
        "console_scripts": [
            "reaa=reaa_cli:app",
        ],
    },
    python_requires=">=3.8",
)
