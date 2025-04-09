from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = fh.read().splitlines()

setup(
    name="sistema-criptografico",
    version="0.9.0",
    author="Tu Nombre",
    author_email="tu-email@ejemplo.com",
    description="Un sistema criptográfico avanzado y completo",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tu-usuario/sistema-criptografico",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "cripto=src.main:main",
        ],
    },
)
