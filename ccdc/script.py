"""The most abstract unit of execution: anything with a run() that may return anything."""
import inspect


class Script:
    def run(self, *args, **kwargs):
        raise NotImplementedError

    def bind(self, **prefill):
        """This script with some arguments filled in; a one-step ComposedScript."""
        return ComposedScript(Step(self, **prefill))

    @property
    def name(self):
        return type(self).__name__


class Step:
    """One script in a sequence plus the arguments the sequence fixes for it."""

    def __init__(self, script, **prefill):
        self.script, self.prefill = script, prefill

    def call(self, injected):
        # Arguments handed to the composition reach only the steps that accept them;
        # they win over prefilled values so a caller can always override a default.
        arguments = {**self.prefill, **accepted(self.script.run, injected)}
        return self.script.run(**arguments)


def accepted(function, values):
    parameters = inspect.signature(function).parameters.values()
    if any(p.kind is p.VAR_KEYWORD for p in parameters):
        return dict(values)
    names = {p.name for p in parameters}
    return {key: value for key, value in values.items() if key in names}


class ComposedScript(Script):
    """Scripts run in order; run() returns each step's result in order.

    A step may be a bare Script or Step(script, **prefilled). A failing step raises
    and later steps do not run.
    """

    def __init__(self, *steps):
        self.steps = [step if isinstance(step, Step) else Step(step) for step in steps]

    def run(self, **injected):
        return [step.call(injected) for step in self.steps]

    @property
    def name(self):
        return " + ".join(step.script.name for step in self.steps)
