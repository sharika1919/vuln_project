#!/usr/bin/env python3
"""
Setup script for Auto Security Scanner
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="auto-security-scanner",
    version="2.0.0",
    author="Security Team",
    author_email="security@example.com",
    description="Professional cross-platform security scanner integrating multiple tools",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/auto-security-scanner",
    py_modules=["auto_scanner"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No external dependencies - uses standard library only
    ],
    extras_require={
        "enhanced": [
            "requests>=2.28.0",
            "colorama>=0.4.4",
            "tqdm>=4.64.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "auto-scanner=auto_scanner:main",
        ],
    },
    keywords="security scanner vulnerability nuclei subfinder reconnaissance",
    project_urls={
        "Bug Reports": "https://github.com/example/auto-security-scanner/issues",
        "Source": "https://github.com/example/auto-security-scanner",
    },
)
