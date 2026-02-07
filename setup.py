"""Package setup for Deriv-AI-Hackathon."""

from setuptools import find_packages, setup

setup(
    name="deriv-ai-hackathon",
    version="1.0.0",
    description="AI Shield system with WAF, pentesting, secure LLM pipeline, and Streamlit UI",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "python-dotenv>=1.0.1",
        "streamlit>=1.33.0",
        "pandas>=2.0.0",
        "numpy>=1.24.0",
        "openai>=1.35.0",
        "faiss-cpu>=1.7.4",
        "reportlab>=4.0.9",
    ],
)

