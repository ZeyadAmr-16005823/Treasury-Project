"""Milestone 1 signed requests and sequence-number replay protection."""
from .config import GROUP
from .crypto_utils import sign_raw, verify_raw
from .encoding import canonical_json

REQUEST_FIELDS = frozenset({"op", "seq", "body", "name", "sig"})


def request_transcript(group: str, name: str, seq: int, op: str, body: dict) -> list:
    return ["request", group, name, seq, op, body]


def sign_request(private_key, group: str, name: str, seq: int, op: str, body: dict) -> dict:
    """Return a request carrying a signature over its full transcript.

    The signed ``name`` lets the server reconstruct the transcript without an
    extra argument, and binds the request to the certified session identity.
    """
    transcript = request_transcript(group, name, seq, op, body)
    return {
        "op": op,
        "seq": seq,
        "body": body,
        "name": name,
        "sig": sign_raw(private_key, canonical_json(transcript)),
    }


def verify_request(public_key, request: dict, last_sequence: int) -> bool:
    """Verify the request signature and require a strictly increasing sequence.

    ``last_sequence`` is the highest sequence already accepted from this member;
    equal or smaller values are replays and are rejected.
    """
    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS:
        return False
    if not isinstance(request["name"], str) or not isinstance(request["op"], str):
        return False
    if not isinstance(request["body"], dict):
        return False
    seq = request["seq"]
    if type(seq) is not int or seq <= last_sequence:
        return False
    transcript = request_transcript(GROUP, request["name"], seq, request["op"], request["body"])
    return verify_raw(public_key, canonical_json(transcript), request["sig"])
