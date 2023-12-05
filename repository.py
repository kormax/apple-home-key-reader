import copy
import hashlib
import json
import logging
from threading import Lock
from typing import List, Optional

from entity import Endpoint, Issuer

log = logging.getLogger()


class Repository:
    """Serves as a way of emulating a storage/database"""

    _issuers: List[Issuer]

    def __init__(self, storage_file_path):
        self.storage_file_path = storage_file_path
        self._reader_private_key = bytes.fromhex("00" * 32)
        self._reader_identifier = bytes.fromhex("00" * 8)
        self._issuers = list()
        self._transaction_lock = Lock()
        self._state_lock = Lock()
        self._load_state_from_file()

    def _load_state_from_file(self):
        try:
            with self._state_lock:
                configuration = json.load(open(self.storage_file_path, "r+"))
                self._reader_private_key = bytes.fromhex(
                    configuration.get("reader_private_key", "00" * 32)
                )
                self._reader_identifier = bytes.fromhex(
                    configuration.get("reader_identifier", "00" * 8)
                )
                self._issuers = [
                    Issuer.from_dict(issuer)
                    for _, issuer in configuration.get("issuers", {}).items()
                ]
        except Exception:
            log.exception(
                f"Could not load Home Key configuration. Assuming that device is not yet configured..."
            )
            pass

    def _save_state_to_file(self):
        with self._state_lock:
            json.dump(
                {
                    "reader_private_key": self._reader_private_key.hex(),
                    "reader_identifier": self._reader_identifier.hex(),
                    "issuers": {
                        issuer.id.hex(): issuer.to_dict() for issuer in self._issuers
                    },
                },
                open(self.storage_file_path, "w"),
                indent=2,
            )

    def _refresh_state(self):
        self._save_state_to_file()
        self._load_state_from_file()

    def get_reader_private_key(self):
        return self._reader_private_key

    def set_reader_private_key(self, reader_private_key):
        with self._transaction_lock:
            self._reader_private_key = reader_private_key
            self._refresh_state()

    def get_reader_identifier(self):
        return self._reader_identifier

    def set_reader_identifier(self, reader_identifier):
        with self._transaction_lock:
            self._reader_identifier = reader_identifier
            self._refresh_state()

    def get_reader_group_identifier(self):
        return (
            hashlib.sha256("key-identifier".encode() + self.get_reader_private_key())
        ).digest()[:8]

    def get_all_issuers(self):
        return copy.deepcopy([i for i in self._issuers])

    def get_all_endpoints(self):
        return copy.deepcopy(
            [endpoint for issuer in self._issuers for endpoint in issuer.endpoints]
        )

    def get_endpoint_by_public_key(self, public_key: bytes) -> Optional[Endpoint]:
        return next(
            (
                endpoint
                for endpoint in self.get_all_endpoints()
                if endpoint.public_key == public_key
            ),
            None,
        )

    def get_endpoint_by_id(self, id) -> Optional[Endpoint]:
        return next(
            (endpoint for endpoint in self.get_all_endpoints() if endpoint.id == id),
            None,
        )

    def get_issuer_by_public_key(self, public_key) -> Optional[Issuer]:
        return next(
            (
                issuer
                for issuer in self.get_all_issuers()
                if issuer.public_key == public_key
            ),
            None,
        )

    def get_issuer_by_id(self, id) -> Optional[Issuer]:
        return next(
            (issuer for issuer in self.get_all_issuers() if issuer.id == id), None
        )

    def remove_issuer(self, issuer: Issuer):
        with self._transaction_lock:
            issuers = [i for i in copy.deepcopy(self._issuers) if i.id != issuer.id]
            self._issuers = issuers
            self._refresh_state()

    def upsert_issuer(self, issuer: Issuer):
        with self._transaction_lock:
            issuer = copy.deepcopy(issuer)
            issuers = [
                (i if i.id != issuer.id else issuer)
                for i in copy.deepcopy(self._issuers)
            ]
            if issuer not in issuers:
                issuers.append(issuer)
            self._issuers = issuers
            self._refresh_state()

    def upsert_endpoint(self, issuer_id, endpoint: Endpoint):
        with self._transaction_lock:
            issuer = next(
                (issuer for issuer in self._issuers if issuer.id == issuer_id), None
            )
            endpoints = [
                (e if e.id != endpoint.id else endpoint) for e in issuer.endpoints
            ]
            if endpoint not in endpoints:
                endpoints.append(endpoint)
            issuer.endpoints = endpoints
            self._refresh_state()

    def upsert_issuers(self, issuers: List[Issuer]):
        issuers = {issuer.id: copy.deepcopy(issuer) for issuer in issuers}
        with self._transaction_lock:
            iss = [issuers.get(i.id, i) for i in copy.deepcopy(self._issuers)]
            for issuer in issuers.values():
                if issuer not in iss:
                    iss.append(issuer)
            self._issuers = iss
            self._refresh_state()
