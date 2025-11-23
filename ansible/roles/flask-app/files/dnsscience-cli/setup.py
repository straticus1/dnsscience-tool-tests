from setuptools import setup, find_packages

setup(
    name="dnsscience",
    version="1.0.0",
    description="DNS Science - DNS and Email Security Scanner CLI",
    long_description=open("README.md").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="DNS Science",
    author_email="support@dnsscience.io",
    url="https://dnsscience.io",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "click>=8.0.0",
        "tabulate>=0.9.0",
        "python-dotenv>=0.19.0",
    ],
    entry_points={
        "console_scripts": [
            "dnsscience=dnsscience.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
)
