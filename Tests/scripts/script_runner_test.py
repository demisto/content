import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import script_runner  # noqa: E402

BASE_ARGS = ["pytest", "-v"]
FILES = [
    "Packs/PackA/Integrations/IntA/IntA_test.py",
    "Packs/PackB/Integrations/IntB/IntB_test.py",
    "Packs/PackC/Scripts/ScriptC/ScriptC_test.py",
]


@pytest.fixture(autouse=True)
def clear_jobs_env(monkeypatch):
    """Make sure no ambient SCRIPT_RUNNER_JOBS leaks into a test."""
    monkeypatch.delenv(script_runner.JOBS_ENV_VAR, raising=False)


def expected_calls(files):
    """The (args, cwd) pairs run_command should be called with for the given files."""
    return {(tuple(BASE_ARGS + [os.path.abspath(f)]), os.path.dirname(f)) for f in files}


class RunCommandRecorder:
    """Stands in for run_command, recording every (args, cwd) it is called with."""

    def __init__(self, returncodes=None):
        self.returncodes = returncodes or {}
        self.calls = []
        self.thread_names = set()
        self._lock = threading.Lock()

    def __call__(self, args, directory):
        with self._lock:
            self.calls.append((tuple(args), directory))
            self.thread_names.add(threading.current_thread().name)
        return self.returncodes.get(args[-1], 0)

    @property
    def call_set(self):
        return set(self.calls)


@pytest.fixture
def recorder(monkeypatch):
    def _make(returncodes=None):
        rec = RunCommandRecorder(returncodes)
        monkeypatch.setattr(script_runner, "run_command", rec)
        return rec

    return _make


class TestGetJobs:
    def test_unset_defaults_to_one(self):
        assert script_runner.get_jobs() == 1

    @pytest.mark.parametrize("value", ["", "abc", "0", "-3", "1.5", " "])
    def test_malformed_values_fall_back_to_one(self, monkeypatch, value):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, value)
        assert script_runner.get_jobs() == 1

    @pytest.mark.parametrize("value,expected", [("1", 1), ("2", 2), ("4", 4), ("8", 8)])
    def test_valid_values(self, monkeypatch, value, expected):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, value)
        assert script_runner.get_jobs() == expected

    @pytest.mark.parametrize("value", ["9", "64", "999"])
    def test_clamped_to_max_jobs(self, monkeypatch, value):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, value)
        assert script_runner.get_jobs() == script_runner.MAX_JOBS


class TestSerialPath:
    def test_default_env_runs_every_file_with_its_own_cwd(self, recorder):
        rec = recorder()
        assert script_runner.run_script(BASE_ARGS, FILES) == 0
        assert rec.call_set == expected_calls(FILES)
        assert len(rec.calls) == len(FILES)

    def test_default_env_uses_single_thread(self, recorder):
        rec = recorder()
        script_runner.run_script(BASE_ARGS, FILES)
        assert rec.thread_names == {threading.current_thread().name}

    def test_non_zero_returncode_returns_one(self, recorder):
        rec = recorder({os.path.abspath(FILES[1]): 2})
        assert script_runner.run_script(BASE_ARGS, FILES) == 1
        assert rec.call_set == expected_calls(FILES)

    @pytest.mark.parametrize("value", ["", "abc", "0", "-3"])
    def test_malformed_env_still_runs_serially(self, monkeypatch, recorder, value):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, value)
        rec = recorder()
        assert script_runner.run_script(BASE_ARGS, FILES) == 0
        assert rec.call_set == expected_calls(FILES)
        assert rec.thread_names == {threading.current_thread().name}

    def test_single_file_with_jobs_four_stays_serial(self, monkeypatch, recorder):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, "4")
        pool_created = []
        monkeypatch.setattr(
            script_runner,
            "ThreadPool",
            lambda n: pool_created.append(n),
        )
        rec = recorder()
        assert script_runner.run_script(BASE_ARGS, FILES[:1]) == 0
        assert pool_created == []
        assert rec.call_set == expected_calls(FILES[:1])


class TestParallelPath:
    def test_all_files_run_once_with_correct_cwd(self, monkeypatch, recorder):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, "4")
        rec = recorder()
        assert script_runner.run_script(BASE_ARGS, FILES) == 0
        assert rec.call_set == expected_calls(FILES)
        assert len(rec.calls) == len(FILES)

    def test_uses_worker_threads(self, monkeypatch, recorder):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, "4")
        rec = recorder()
        script_runner.run_script(BASE_ARGS, FILES)
        assert threading.current_thread().name not in rec.thread_names

    def test_non_zero_returncode_returns_one(self, monkeypatch, recorder):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, "4")
        rec = recorder({os.path.abspath(FILES[2]): 3})
        assert script_runner.run_script(BASE_ARGS, FILES) == 1
        assert rec.call_set == expected_calls(FILES)

    def test_pool_size_clamped_to_max_jobs(self, monkeypatch, recorder):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, "999")
        recorder()
        sizes = []
        real_thread_pool = script_runner.ThreadPool

        def spy(n):
            sizes.append(n)
            return real_thread_pool(n)

        monkeypatch.setattr(script_runner, "ThreadPool", spy)
        assert script_runner.run_script(BASE_ARGS, FILES) == 0
        assert sizes == [script_runner.MAX_JOBS]

    def test_pool_is_closed_and_joined_when_worker_raises(self, monkeypatch):
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, "4")

        def boom(args, directory):
            raise RuntimeError("boom")

        monkeypatch.setattr(script_runner, "run_command", boom)

        closed = []
        joined = []
        real_thread_pool = script_runner.ThreadPool

        def spy(n):
            pool = real_thread_pool(n)
            real_close, real_join = pool.close, pool.join
            pool.close = lambda: (closed.append(True), real_close())[1]
            pool.join = lambda: (joined.append(True), real_join())[1]
            return pool

        monkeypatch.setattr(script_runner, "ThreadPool", spy)

        assert script_runner.run_script(BASE_ARGS, FILES) == 1
        assert closed
        assert joined

    def test_worker_exception_does_not_stop_remaining_files(self, monkeypatch):
        """A raising worker does not fail-fast: the pool keeps draining its chunks.

        pool.map() is synchronous and only propagates the exception once every chunk has
        finished, so by the time run_script sees it there is no queued work left to abandon.
        Only the remainder of the raising worker's own chunk is skipped. jobs=2 over 40 files
        gives chunksize 5, so most files still execute.
        """
        monkeypatch.setenv(script_runner.JOBS_ENV_VAR, "2")
        files = [f"Packs/Pack{i}/Integrations/Int{i}/Int{i}_test.py" for i in range(40)]
        executed = []
        lock = threading.Lock()

        def run(args, directory):
            with lock:
                executed.append(args[-1])
            if args[-1] == os.path.abspath(files[0]):
                raise RuntimeError("boom")
            return 0

        monkeypatch.setattr(script_runner, "run_command", run)

        assert script_runner.run_script(BASE_ARGS, files) == 1
        assert len(executed) > 1
