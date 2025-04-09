import sys
import os

print("Python version:", sys.version)
print("Current working directory:", os.getcwd())
print("Files in current directory:", os.listdir("."))

try:
    from src.core.encryption import EncryptionEngine
    print("Successfully imported EncryptionEngine from src.core.encryption")
except ImportError as e:
    print("Failed to import from src.core.encryption:", e)

try:
    from src.core.key_management import KeyManager
    print("Successfully imported KeyManager from src.core.key_management")
except ImportError as e:
    print("Failed to import from src.core.key_management:", e)

try:
    import src
    print("Successfully imported src module")
    print("src.__path__:", src.__path__)
except ImportError as e:
    print("Failed to import src module:", e)

# Try to import from the alternate src directory
try:
    sys.path.insert(0, os.path.join(os.getcwd(), "src (1)"))
    print("Added 'src (1)' to sys.path")

    # Try to import a module from src (1)
    import importlib.util
    spec = importlib.util.spec_from_file_location("encryption", os.path.join(os.getcwd(), "src (1)", "core (1)", "encryption (1).py"))
    if spec:
        encryption_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(encryption_module)
        print("Successfully imported encryption module from 'src (1)'")
        print("Available classes:", dir(encryption_module))
    else:
        print("Could not find encryption module in 'src (1)'")
except Exception as e:
    print("Error when importing from 'src (1)':", e)
