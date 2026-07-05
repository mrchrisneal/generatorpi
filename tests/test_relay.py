# test_relay.py -- relay + generator control logic: press_button, start_generator
# and stop_generator. time.sleep is patched to a no-op (no_sleep fixture) so nothing
# blocks, and relay_start_stop is a MagicMock (gpiozero is mocked), so NO real
# hardware is ever driven. Also verifies the relay_lock rejects overlapping sequences.
import pytest


@pytest.fixture(autouse=True)
def _reset_relay_mock(module):
    """Reset the relay MagicMock's call records before each test."""
    module.relay_start_stop.reset_mock()


class TestPressButton:
    def test_energizes_then_deenergizes(self, module, no_sleep):
        module.press_button()
        assert module.relay_start_stop.on.called
        assert module.relay_start_stop.off.called
        # on() must be called before off().
        on_order = module.relay_start_stop.on.call_count
        off_order = module.relay_start_stop.off.call_count
        assert on_order == 1 and off_order == 1


class TestStartGenerator:
    def test_success_single_attempt(self, module, no_sleep):
        result = module.start_generator()
        assert result["success"] is True
        assert module.generator_state["running"] is True
        assert module.generator_state["last_command"] == "start"
        # Default MAX_START_RETRIES=1 -> 2 presses (prime + start).
        assert module.relay_start_stop.on.call_count == 2

    def test_multiple_retries_press_count(self, module, no_sleep):
        # 2 attempts -> 4 presses total, and the retry-delay branch is exercised.
        module.CONFIG["MAX_START_RETRIES"] = 2
        result = module.start_generator()
        assert result["success"] is True
        assert module.generator_state["start_attempts"] == 2
        assert module.relay_start_stop.on.call_count == 4

    def test_rejected_when_already_running(self, module, no_sleep):
        with module.state_lock:
            module.generator_state["running"] = True
        result = module.start_generator()
        assert result["success"] is False
        assert "already marked as running" in result["message"]
        # No presses happened.
        assert module.relay_start_stop.on.call_count == 0
        # And the relay lock was released (finally block) -> not stuck.
        assert not module.relay_lock.locked()

    def test_rejected_when_relay_lock_held(self, module, no_sleep):
        # Simulate an overlapping sequence by holding the relay lock.
        assert module.relay_lock.acquire(blocking=False)
        try:
            result = module.start_generator()
            assert result["success"] is False
            assert "already in progress" in result["message"]
            assert module.relay_start_stop.on.call_count == 0
        finally:
            module.relay_lock.release()

    def test_releases_lock_after_success(self, module, no_sleep):
        module.start_generator()
        # Lock must be free again so subsequent sequences can run.
        assert not module.relay_lock.locked()


class TestStopGenerator:
    def test_success(self, module, no_sleep):
        with module.state_lock:
            module.generator_state["running"] = True
        result = module.stop_generator()
        assert result["success"] is True
        assert module.generator_state["running"] is False
        assert module.generator_state["last_command"] == "stop"
        assert module.generator_state["last_stop_time"] is not None
        assert module.relay_start_stop.on.call_count == 1  # single press

    def test_rejected_when_relay_lock_held(self, module, no_sleep):
        assert module.relay_lock.acquire(blocking=False)
        try:
            result = module.stop_generator()
            assert result["success"] is False
            assert "already in progress" in result["message"]
            assert module.relay_start_stop.on.call_count == 0
        finally:
            module.relay_lock.release()

    def test_releases_lock_after_success(self, module, no_sleep):
        module.stop_generator()
        assert not module.relay_lock.locked()
