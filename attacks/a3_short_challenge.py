"""A3: a 4-bit interactive login challenge can be guessed offline.

Run from the repository root with either:

    python -m attacks.a3_short_challenge
    python attacks/a3_short_challenge.py
"""
import argparse
import secrets
import sys
from pathlib import Path
from typing import Callable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from treasury.group import G, P, Q
from treasury.login import (generate_challenge, register_login_secret,
                            verify_interactive_login)
from treasury.logging_utils import get_logger

ChallengeSource = Callable[[], int]

# An attacker may use any z in [0, q); a 128-bit z is still in range and keeps
# the offline demonstration fast without changing the acceptance probability.
_ATTACK_Z_BITS = 128
_DEFAULT_TRIALS = 256


def forge_response(X_M: int, guessed_challenge: int, z: int | None = None,
                   p: int = P, q: int = Q, g: int = G) -> tuple[int, int]:
    """Forge (R, z) without x_M for an anticipated challenge."""
    if z is None:
        z = secrets.randbits(_ATTACK_Z_BITS)
    R = pow(g, z, p) * pow(X_M, -(guessed_challenge % q), p) % p
    return R, z


def attack_trial(X_M: int, weak: bool,
                 guess_source: ChallengeSource | None = None,
                 challenge_source: ChallengeSource | None = None) -> bool:
    """Run one forged login and report whether the verifier accepted it."""
    guess = generate_challenge(weak=weak, source=guess_source)
    R, z = forge_response(X_M, guess)
    challenge = generate_challenge(weak=weak, source=challenge_source)
    return verify_interactive_login(R, z, challenge, X_M, P, Q, G)


def measure_success(trials: int, X_M: int, weak: bool = False,
                    guess_source: ChallengeSource | None = None,
                    challenge_source: ChallengeSource | None = None) -> tuple[int, int]:
    """Return (successes, trials) for the forged-login attack."""
    if isinstance(trials, bool) or not isinstance(trials, int) or trials < 1:
        raise ValueError("trials must be a positive integer")
    successes = sum(attack_trial(X_M, weak, guess_source, challenge_source)
                    for _ in range(trials))
    return successes, trials


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="A3 short-challenge login attack")
    parser.add_argument("--trials", type=int, default=_DEFAULT_TRIALS)
    args = parser.parse_args(argv)
    if args.trials < 1:
        parser.error("--trials must be positive")

    logger = get_logger("a3")
    _, X_M = register_login_secret("A3-victim", P, Q, G)
    logger.info("A3: attacker does not know x_M; forging R = g^z * X_M^(-e)")

    for weak, label in ((True, "4-bit weak"), (False, "128-bit secure")):
        successes, total = measure_success(args.trials, X_M, weak=weak)
        logger.info("%s challenge: %d/%d forged logins accepted (%.2f%%)",
                    label, successes, total, 100.0 * successes / total)


if __name__ == "__main__":
    main()
