import os
import platform

def get_project_root():
	return os.path.dirname(os.path.abspath(__file__))

def get_domain_path():
	return os.path.join(get_project_root(), 'metric1_domain')

def get_working_dir(selected_analysis, selected_heuristic):
	return os.path.join(get_project_root(), selected_analysis, selected_heuristic, 'src')

def get_validate_binary():
	"""Return absolute path to the platform-appropriate VAL Validate binary.

	Resolution order:
	  1. VAL_BIN_PATH env override (full absolute path).
	  2. Backend/VAL/build/linux64/Release/bin/Validate (Linux, e.g. Docker).
	  3. Backend/VAL/build/macos64/Release/bin/Validate (macOS host).
	The vendored macOS Mach-O binary cannot run on Linux ("Exec format
	error" / errno 8), so the Docker image builds a Linux ELF copy into
	linux64/Release/bin/.
	"""
	override = os.environ.get("VAL_BIN_PATH")
	if override:
		return override
	val_root = os.path.abspath(
		os.path.join(get_project_root(), '..', '..', 'VAL', 'build')
	)
	system = platform.system()
	arch_dir = 'linux64' if system == 'Linux' else 'macos64'
	return os.path.join(val_root, arch_dir, 'Release', 'bin', 'Validate')