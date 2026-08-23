import importlib.util
from pathlib import Path
import tarfile
import tempfile
import unittest
import warnings
import zipfile

ROOT = Path(__file__).resolve().parents[2]


def load_tool(name: str):
    path = ROOT / "tools" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReleaseArtifactSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        warnings.simplefilter("ignore", UserWarning)
        cls.archive = load_tool("verify_release_archive")
        cls.python_artifact = load_tool("verify_python_artifact")
        cls.python_source = load_tool("verify_python_source")
        cls.vsix = load_tool("verify_vsix")
    def test_native_archive_rejects_duplicate_and_unrooted_names(self):
        stem = "ventris-0.1.0-x86_64-unknown-linux-gnu/"
        with self.assertRaises(ValueError):
            self.archive._safe_names([f"{stem}ventris", f"{stem}ventris"], stem)
        with self.assertRaises(ValueError):
            self.archive._safe_names([f"{stem}../README.md"], stem)
    def test_python_source_rejects_duplicate_and_unrooted_names(self):
        stem = "ventris_client-0.1.0/"
        with self.assertRaises(ValueError):
            self.python_source._safe_names(
                [f"{stem}README.md", f"{stem}README.md"], stem
            )
        with self.assertRaises(ValueError):
            self.python_source._safe_names([f"{stem}../README.md"], stem)

    def test_python_source_rejects_symlink_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "source.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                info = tarfile.TarInfo("ventris_client-0.1.0/README.md")
                info.type = tarfile.SYMTYPE
                info.linkname = "outside"
                archive.addfile(info)
            with self.assertRaises(ValueError):
                self.python_source.verify(path, "0.1.0")

    def test_python_wheel_rejects_duplicate_zip_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.whl"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("ventris/__init__.py", "")
                archive.writestr("ventris/__init__.py", "duplicate")
            with self.assertRaises(ValueError):
                self.python_artifact.verify(path, "0.1.0")
    def test_python_wheel_accepts_thin_adapter_payload(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ventris_client-0.1.0-py3-none-any.whl"
            metadata = "ventris_client-0.1.0.dist-info/"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("ventris/__init__.py", "")
                archive.writestr("ventris/cli.py", "")
                archive.writestr(f"{metadata}METADATA", "")
                archive.writestr(f"{metadata}RECORD", "")
                archive.writestr(f"{metadata}licenses/LICENSE", "")
            self.python_artifact.verify(path, "0.1.0")


    def test_vsix_rejects_duplicate_zip_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "duplicate.vsix"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("extension/package.json", "{}")
                archive.writestr("extension/package.json", "duplicate")
            with self.assertRaises(ValueError):
                self.vsix.verify(path, "0.1.0")


if __name__ == "__main__":
    unittest.main()
