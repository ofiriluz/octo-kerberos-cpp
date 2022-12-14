from typing import Final, Optional, Dict, Any

DEFAULT_KERBEROS_PORT: Final[int]
DEFAULT_TGT_LIFETIME_SECONDS: Final[int]
DEFAULT_SERVICE_TICKET_LIFETIME_SECONDS: Final[int]

class KRB5UserCredentials(object):
    def __init__(self, username: str, password: str): ...

    def username(self) -> str: ...

    def password(self) -> str: ...

    def set_username(self, username: str): ...

    def set_pasword(self, password: str): ...


class KRB5TGTTicket(object):
    def __init__(self, tgt_user: str): ...

    def ticket(self) -> bytes: ...

    def encoded_ticket(self) -> str: ...

    def ticket_purpose(self) -> str: ...

    def ticket_type(self) -> str: ...

    def ticket_expiration_time(self) -> int: ...

    def tgt_user(self) -> str: ...

    def serialize(self) -> Optional[Dict[str, Any]]: ...

    def deserialize(self, data: Dict[str, Any]) -> bool: ...


class KRB5ServiceTicket(object):
    def __init__(self, service: str): ...

    def ticket(self) -> bytes: ...

    def encoded_ticket(self) -> str: ...

    def ticket_purpose(self) -> str: ...

    def ticket_type(self) -> str: ...

    def ticket_expiration_time(self) -> int: ...

    def service(self) -> str: ...

    def serialize(self) -> Optional[Dict[str, Any]]: ...

    def deserialize(self, data: Dict[str, Any]) -> bool: ...


class KRB5Authenticator(object):
    def __init__(self, realm: str, kdc_host: Optional[str] = ...,
                 kdc_port: Optional[int] = ...,
                 session_id: Optional[str] = ...,
                 streamlined: Optional[bool] = ...): ...

    def initialize_authenticator(self) -> bool: ...

    def cleanup_authenticator(self) -> bool: ...

    def is_initialized(self) -> bool: ...

    def is_streamlined(self) -> bool: ...

    def generate_tgt(self, creds: KRB5UserCredentials,
                     lifetime_seconds: Optional[int] = ...) -> KRB5TGTTicket: ...

    def deserialize_tgt(self, data: Dict[str, Any]) -> KRB5TGTTicket: ...

    def generate_service_ticket(self, tgt: KRB5TGTTicket, service: str,
                                lifetime_seconds: Optional[int] = ...) -> KRB5ServiceTicket: ...

    def deserialize_service_ticket(self, data: Dict[str, Any]) -> KRB5ServiceTicket: ...
