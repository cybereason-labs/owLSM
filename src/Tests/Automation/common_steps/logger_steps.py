from pytest_bdd import given, when, then, parsers
from globals.system_related_globals import system_globals

@given(parsers.parse('I ensure owLSM log contains "{message}"'))
@when(parsers.parse('I ensure owLSM log contains "{message}"'))
@then(parsers.parse('I ensure owLSM log contains "{message}"'))
def I_ensure_owlsm_log_contains(message):
    with open(system_globals.OWLSM_LOGGER_LOG, 'r') as f:
        assert message in f.read(), f"Message '{message}' not found in owLSM log"