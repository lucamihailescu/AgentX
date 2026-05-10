from .base import AuthError, MailboxProvider, Message
from .google import GoogleProvider
from .microsoft import MicrosoftProvider

PROVIDERS: dict[str, type[MailboxProvider]] = {
    MicrosoftProvider.NAME: MicrosoftProvider,
    GoogleProvider.NAME: GoogleProvider,
}


def get_provider(name: str | None) -> type[MailboxProvider]:
    if not name or name not in PROVIDERS:
        raise ValueError(f"unknown provider: {name!r}")
    return PROVIDERS[name]


__all__ = [
    "AuthError",
    "MailboxProvider",
    "Message",
    "PROVIDERS",
    "get_provider",
]
