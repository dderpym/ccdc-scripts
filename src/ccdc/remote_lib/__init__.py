"""Helper modules shipped to targets with the AnsibleScripts that list them in `support`.

They run on the target (python3.9+, standard library only) and are imported there as
plain modules: `import procfs`. Never import them on the controller.
"""
