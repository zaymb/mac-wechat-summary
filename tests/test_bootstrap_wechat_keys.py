from pathlib import Path
import shutil
import subprocess
import time

from bootstrap_wechat_keys import terminate_temporary_copy, temporary_copy_pids


def test_temporary_copy_cleanup_targets_only_owned_executables(tmp_path):
    app = tmp_path / "WeChat-debug.app"
    executable = app / "Contents" / "MacOS" / "owned-sleeper"
    executable.parent.mkdir(parents=True)
    compiler = shutil.which("cc")
    assert compiler is not None
    subprocess.run(
        [compiler, "-x", "c", "-", "-o", str(executable)],
        input="#include <unistd.h>\nint main(void) { sleep(30); return 0; }\n",
        text=True,
        check=True,
    )
    process = subprocess.Popen([str(executable)])
    try:
        deadline = time.monotonic() + 2
        while process.pid not in temporary_copy_pids(app):
            if time.monotonic() >= deadline:
                raise AssertionError("owned fixture process was not discovered")
            time.sleep(0.05)

        terminate_temporary_copy(app)

        assert process.wait(timeout=2) == -15
        assert process.pid not in temporary_copy_pids(app)
    finally:
        if process.poll() is None:
            process.terminate()
            process.wait(timeout=2)
