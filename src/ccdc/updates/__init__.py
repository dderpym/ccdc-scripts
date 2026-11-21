"""Reviewed package updates: the remote half of `ccdcctl update` (the interactive review is src/controller/updates.py)."""
from ccdc.ansible import AnsibleScript
from ccdc.runner import RemoteError, failure_message


class ManageUpdates(AnsibleScript):
    """One request to the host's package manager: run(target, payload=request.json).

    The request document (action plan|apply|inspect|restart plus its fields) arrives as standard
    input; the answer is one JSON object. Native maintainer hooks stay enabled, nothing reboots.
    """
    source = "remote.py"
    support = ("update_services.py", "procinfo.py")
    stdin = True

    def parse(self, result, **kwargs):
        if result["rc"] != 0:
            raise RemoteError(failure_message(result))
        state = super().parse(result, **kwargs)
        if not isinstance(state, dict):
            raise ValueError("invalid remote update result")
        if state.get("error"):
            raise RemoteError(str(state["error"]))
        return state
