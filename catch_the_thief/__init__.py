"""catch-the-thief: identify unknown AI agents in your app and jail them instead of trusting them."""
from .consent import ConsentError, Parole
from .core import (ACTIONS, DEFAULT_POLICY, HUMAN, PAROLED, SUSPECT, UNCERTAIN, VERIFIED, Decision, Thief,
                   Verdict)
from .signals import Signal
from .webbotauth import KeyDirectory, generate_keypair, sign_request, thumbprint, verify_request

__version__ = "0.1.0"
__all__ = ["Thief", "Verdict", "Decision", "KeyDirectory", "Parole", "ConsentError", "Signal",
           "sign_request", "verify_request", "thumbprint", "generate_keypair", "DEFAULT_POLICY", "ACTIONS",
           "HUMAN", "UNCERTAIN", "SUSPECT", "VERIFIED", "PAROLED"]
