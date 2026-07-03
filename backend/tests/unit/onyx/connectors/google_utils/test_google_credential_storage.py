"""Guards Google app-credential storage, row prefill, and PKCE restoration."""

from typing import Any
from typing import cast

import pytest
from sqlalchemy.orm import Session

from onyx.configs.constants import DocumentSource
from onyx.configs.constants import KV_CRED_KEY
from onyx.configs.constants import KV_GOOGLE_DRIVE_CRED_KEY
from onyx.connectors.google_utils.google_kv import build_service_account_creds
from onyx.connectors.google_utils.google_kv import get_auth_url
from onyx.connectors.google_utils.google_kv import get_google_app_cred
from onyx.connectors.google_utils.google_kv import update_credential_access_tokens
from onyx.connectors.google_utils.google_kv import upsert_google_app_cred
from onyx.connectors.google_utils.shared_constants import (
    DB_CREDENTIALS_AUTHENTICATION_METHOD,
)
from onyx.connectors.google_utils.shared_constants import (
    DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY,
)
from onyx.connectors.google_utils.shared_constants import (
    DB_CREDENTIALS_DICT_SERVICE_ACCOUNT_KEY,
)
from onyx.connectors.google_utils.shared_constants import DB_CREDENTIALS_DICT_TOKEN_KEY
from onyx.connectors.google_utils.shared_constants import (
    DB_CREDENTIALS_PRIMARY_ADMIN_KEY,
)
from onyx.connectors.google_utils.shared_constants import (
    GoogleOAuthAuthenticationMethod,
)
from onyx.db.models import User
from onyx.server.documents.models import GoogleAppCredentials
from onyx.server.documents.models import GoogleAppWebCredentials
from onyx.server.documents.models import GoogleServiceAccountKey


class _StubCredentialJson:
    def __init__(self, value: dict[str, object]) -> None:
        self._value = value

    def get_value(self, apply_mask: bool) -> dict[str, object]:
        assert apply_mask is False
        return self._value.copy()


class _StubCredential:
    def __init__(self, credential_json: dict[str, object]) -> None:
        self.credential_json = _StubCredentialJson(credential_json)


def _make_app_creds() -> GoogleAppCredentials:
    return GoogleAppCredentials(
        web=GoogleAppWebCredentials(
            client_id="client-id.apps.googleusercontent.com",
            project_id="test-project",
            auth_uri="https://accounts.google.com/o/oauth2/auth",
            token_uri="https://oauth2.googleapis.com/token",
            auth_provider_x509_cert_url="https://www.googleapis.com/oauth2/v1/certs",
            client_secret="secret",
            redirect_uris=["https://example.com/callback"],
            javascript_origins=["https://example.com"],
        )
    )


def _make_service_account_key() -> GoogleServiceAccountKey:
    return GoogleServiceAccountKey(
        type="service_account",
        project_id="test-project",
        private_key_id="private-key-id",
        private_key="-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        client_email="test@test-project.iam.gserviceaccount.com",
        client_id="123",
        auth_uri="https://accounts.google.com/o/oauth2/auth",
        token_uri="https://oauth2.googleapis.com/token",
        auth_provider_x509_cert_url="https://www.googleapis.com/oauth2/v1/certs",
        client_x509_cert_url="https://www.googleapis.com/robot/v1/metadata/x509/test",
        universe_domain="googleapis.com",
    )


def test_upsert_google_app_cred_stores_dict(monkeypatch: Any) -> None:
    stored: dict[str, Any] = {}

    def _upsert_encrypted_kv(key: str, value: dict[str, Any]) -> None:
        stored["key"] = key
        stored["value"] = value

    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.upsert_encrypted_kv",
        _upsert_encrypted_kv,
    )

    upsert_google_app_cred(_make_app_creds(), DocumentSource.GOOGLE_DRIVE)

    assert stored["key"] == KV_GOOGLE_DRIVE_CRED_KEY
    assert isinstance(stored["value"], dict)
    assert stored["value"]["web"]["client_id"] == "client-id.apps.googleusercontent.com"


def test_build_service_account_creds_puts_key_on_credential_row() -> None:
    key = _make_service_account_key()

    credential = build_service_account_creds(
        DocumentSource.GOOGLE_DRIVE,
        service_account_key=key,
        primary_admin_email="admin@test-project.com",
    )

    credential_json = credential.credential_json
    assert (
        credential_json[DB_CREDENTIALS_DICT_SERVICE_ACCOUNT_KEY]
        == key.model_dump_json()
    )
    assert credential_json[DB_CREDENTIALS_PRIMARY_ADMIN_KEY] == "admin@test-project.com"
    assert credential.source == DocumentSource.GOOGLE_DRIVE


@pytest.mark.parametrize("legacy_string", [False, True])
def test_get_google_app_cred_accepts_dict_and_legacy_string(
    monkeypatch: Any, legacy_string: bool
) -> None:
    payload: dict[str, Any] = _make_app_creds().model_dump(mode="json")
    stored_value: object = (
        payload if not legacy_string else _make_app_creds().model_dump_json()
    )

    def _load_encrypted_kv(key: str) -> object:
        assert key == KV_GOOGLE_DRIVE_CRED_KEY
        return stored_value

    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.load_encrypted_kv",
        _load_encrypted_kv,
    )

    creds = get_google_app_cred(DocumentSource.GOOGLE_DRIVE)

    assert creds.web.client_id == "client-id.apps.googleusercontent.com"


@pytest.mark.parametrize("legacy_string", [False, True])
def test_get_auth_url_accepts_dict_and_legacy_string(
    monkeypatch: Any, legacy_string: bool
) -> None:
    payload = _make_app_creds().model_dump(mode="json")
    stored_value: object = (
        payload if not legacy_string else _make_app_creds().model_dump_json()
    )
    stored_state: dict[str, object] = {}

    class _StubFlow:
        code_verifier: str | None = None

        def authorization_url(self, prompt: str) -> tuple[str, None]:
            assert prompt == "consent"
            self.code_verifier = "test-verifier"
            return "https://accounts.google.com/o/oauth2/auth?state=test-state", None

    def _fetch_credential_by_id_for_user(
        credential_id: int,
        user: User,
        db_session: Session,
        get_editable: bool = True,
    ) -> _StubCredential:
        del user, db_session
        assert credential_id == 42
        assert get_editable is True
        return _StubCredential({DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY: stored_value})

    def _update_credential_json(
        credential_id: int,
        credential_json: dict[str, object],
        user: User,
        db_session: Session,
    ) -> object:
        del credential_id, credential_json, user, db_session
        raise AssertionError("update_credential_json should not be called")

    def _load_encrypted_kv(key: str) -> object:
        del key
        raise AssertionError("load_encrypted_kv should not be called")

    def _upsert_encrypted_kv(key: str, value: dict[str, Any]) -> None:
        stored_state["key"] = key
        stored_state["value"] = value

    def _from_client_config(
        _app_config: object, *, scopes: object, redirect_uri: object
    ) -> _StubFlow:
        del scopes, redirect_uri
        return _StubFlow()

    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.fetch_credential_by_id_for_user",
        _fetch_credential_by_id_for_user,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.update_credential_json",
        _update_credential_json,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.load_encrypted_kv",
        _load_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.upsert_encrypted_kv",
        _upsert_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.InstalledAppFlow.from_client_config",
        _from_client_config,
    )

    auth_url = get_auth_url(
        42,
        DocumentSource.GOOGLE_DRIVE,
        cast(User, None),
        cast(Session, None),
    )

    assert auth_url.startswith("https://accounts.google.com")
    assert stored_state["value"] == {
        "value": "test-state",
        "code_verifier": "test-verifier",
    }


def test_update_credential_access_tokens_restores_pkce_verifier(
    monkeypatch: Any,
) -> None:
    """The token exchange restores the PKCE verifier from the KV store."""
    captured: dict[str, Any] = {}
    payload = _make_app_creds().model_dump(mode="json")

    class _StubCreds:
        def to_json(self) -> str:
            return "{}"

    class _StubFlow:
        code_verifier: str | None = None

        def fetch_token(self, code: str) -> None:
            captured["code"] = code
            captured["code_verifier"] = self.code_verifier

        @property
        def credentials(self) -> _StubCreds:
            return _StubCreds()

    def _fetch_credential_by_id_for_user(
        credential_id: int,
        user: User,
        db_session: Session,
        get_editable: bool = True,
    ) -> _StubCredential:
        del user, db_session
        assert credential_id == 42
        assert get_editable is True
        return _StubCredential({DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY: payload})

    def _from_client_config(
        _app_config: object, *, scopes: object, redirect_uri: object
    ) -> _StubFlow:
        del scopes, redirect_uri
        return _StubFlow()

    def _update_credential_json(
        credential_id: int,
        credential_json: dict[str, object],
        user: User,
        db_session: Session,
    ) -> bool:
        del user, db_session
        assert credential_id == 42
        captured["new_creds_dict"] = credential_json
        return True

    def _load_encrypted_kv(key: str) -> object:
        assert key == KV_CRED_KEY.format("42")
        return {"value": "test-state", "code_verifier": "test-verifier"}

    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.fetch_credential_by_id_for_user",
        _fetch_credential_by_id_for_user,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.load_encrypted_kv",
        _load_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.InstalledAppFlow.from_client_config",
        _from_client_config,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv._get_current_oauth_user",
        lambda _creds, _source: "admin@example.com",
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.update_credential_json",
        _update_credential_json,
    )

    creds = update_credential_access_tokens(
        "auth-code",
        42,
        cast(User, None),
        cast(Session, None),
        DocumentSource.GOOGLE_DRIVE,
        GoogleOAuthAuthenticationMethod.UPLOADED,
    )

    assert creds is not None
    assert captured["code"] == "auth-code"
    assert captured["code_verifier"] == "test-verifier"
    assert captured["new_creds_dict"][DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY] == payload
    assert captured["new_creds_dict"][DB_CREDENTIALS_DICT_TOKEN_KEY] == "{}"
    assert (
        captured["new_creds_dict"][DB_CREDENTIALS_PRIMARY_ADMIN_KEY]
        == "admin@example.com"
    )
    assert (
        captured["new_creds_dict"][DB_CREDENTIALS_AUTHENTICATION_METHOD]
        == GoogleOAuthAuthenticationMethod.UPLOADED.value
    )


def test_get_auth_url_prefills_app_credential_on_row_when_missing(
    monkeypatch: Any,
) -> None:
    default_payload = _make_app_creds().model_dump(mode="json")
    stored_state: dict[str, object] = {}
    captured: dict[str, Any] = {}

    class _StubFlow:
        code_verifier: str | None = None

        def authorization_url(self, prompt: str) -> tuple[str, None]:
            assert prompt == "consent"
            self.code_verifier = "test-verifier"
            return "https://accounts.google.com/o/oauth2/auth?state=test-state", None

    def _fetch_credential_by_id_for_user(
        credential_id: int,
        user: User,
        db_session: Session,
        get_editable: bool = True,
    ) -> _StubCredential:
        del user, db_session
        assert credential_id == 42
        assert get_editable is True
        return _StubCredential({})

    def _load_encrypted_kv(key: str) -> object:
        assert key == KV_GOOGLE_DRIVE_CRED_KEY
        return default_payload

    def _upsert_encrypted_kv(key: str, value: dict[str, Any]) -> None:
        stored_state["key"] = key
        stored_state["value"] = value

    def _update_credential_json(
        credential_id: int,
        credential_json: dict[str, object],
        user: User,
        db_session: Session,
    ) -> object:
        del user, db_session
        assert credential_id == 42
        captured["credential_json"] = credential_json
        return True

    def _from_client_config(
        _app_config: object, *, scopes: object, redirect_uri: object
    ) -> _StubFlow:
        del scopes, redirect_uri
        return _StubFlow()

    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.fetch_credential_by_id_for_user",
        _fetch_credential_by_id_for_user,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.load_encrypted_kv",
        _load_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.update_credential_json",
        _update_credential_json,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.upsert_encrypted_kv",
        _upsert_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.InstalledAppFlow.from_client_config",
        _from_client_config,
    )

    auth_url = get_auth_url(
        42,
        DocumentSource.GOOGLE_DRIVE,
        cast(User, None),
        cast(Session, None),
    )

    assert auth_url.startswith("https://accounts.google.com")
    assert (
        captured["credential_json"][DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY]
        == default_payload
    )
    assert stored_state["value"] == {
        "value": "test-state",
        "code_verifier": "test-verifier",
    }


def test_get_auth_url_uses_app_credential_on_row_without_rewrite(
    monkeypatch: Any,
) -> None:
    payload = _make_app_creds().model_dump(mode="json")

    class _StubFlow:
        code_verifier: str | None = None

        def authorization_url(self, prompt: str) -> tuple[str, None]:
            assert prompt == "consent"
            self.code_verifier = "test-verifier"
            return "https://accounts.google.com/o/oauth2/auth?state=test-state", None

    def _fetch_credential_by_id_for_user(
        credential_id: int,
        user: User,
        db_session: Session,
        get_editable: bool = True,
    ) -> _StubCredential:
        del user, db_session
        assert credential_id == 42
        assert get_editable is True
        return _StubCredential({DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY: payload})

    def _load_encrypted_kv(key: str) -> object:
        del key
        raise AssertionError("load_encrypted_kv should not be called")

    def _update_credential_json(
        credential_id: int,
        credential_json: dict[str, object],
        user: User,
        db_session: Session,
    ) -> object:
        del credential_id, credential_json, user, db_session
        raise AssertionError("update_credential_json should not be called")

    def _from_client_config(
        _app_config: object, *, scopes: object, redirect_uri: object
    ) -> _StubFlow:
        del scopes, redirect_uri
        return _StubFlow()

    def _upsert_encrypted_kv(key: str, value: dict[str, Any]) -> None:
        del key, value

    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.fetch_credential_by_id_for_user",
        _fetch_credential_by_id_for_user,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.load_encrypted_kv",
        _load_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.update_credential_json",
        _update_credential_json,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.upsert_encrypted_kv",
        _upsert_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.InstalledAppFlow.from_client_config",
        _from_client_config,
    )

    auth_url = get_auth_url(
        42,
        DocumentSource.GOOGLE_DRIVE,
        cast(User, None),
        cast(Session, None),
    )

    assert auth_url.startswith("https://accounts.google.com")


def test_get_auth_url_uses_per_connector_app_over_default(
    monkeypatch: Any,
) -> None:
    row_client_id = "row-client-999.apps.googleusercontent.com"
    row_payload = _make_app_creds().model_dump(mode="json")
    row_payload["web"]["client_id"] = row_client_id
    stored_state: dict[str, object] = {}

    class _StubFlow:
        code_verifier: str | None = None

        def __init__(self, captured_client_id: str) -> None:
            self.captured_client_id = captured_client_id

        def authorization_url(self, prompt: str) -> tuple[str, None]:
            assert prompt == "consent"
            self.code_verifier = "test-verifier"
            return (
                "https://accounts.google.com/o/oauth2/auth?"
                f"client_id={self.captured_client_id}&state=test-state"
            ), None

    def _fetch_credential_by_id_for_user(
        credential_id: int,
        user: User,
        db_session: Session,
        get_editable: bool = True,
    ) -> _StubCredential:
        del user, db_session
        assert credential_id == 42
        assert get_editable is True
        return _StubCredential({DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY: row_payload})

    def _load_encrypted_kv(key: str) -> object:
        del key
        raise AssertionError("load_encrypted_kv should not be called")

    def _upsert_encrypted_kv(key: str, value: dict[str, Any]) -> None:
        stored_state["key"] = key
        stored_state["value"] = value

    def _update_credential_json(
        credential_id: int,
        credential_json: dict[str, object],
        user: User,
        db_session: Session,
    ) -> object:
        del credential_id, credential_json, user, db_session
        raise AssertionError("update_credential_json should not be called")

    def _from_client_config(
        app_config: object, *, scopes: object, redirect_uri: object
    ) -> _StubFlow:
        del scopes, redirect_uri
        config = cast(dict[str, Any], app_config)
        return _StubFlow(config["web"]["client_id"])

    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.fetch_credential_by_id_for_user",
        _fetch_credential_by_id_for_user,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.load_encrypted_kv",
        _load_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.update_credential_json",
        _update_credential_json,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.upsert_encrypted_kv",
        _upsert_encrypted_kv,
    )
    monkeypatch.setattr(
        "onyx.connectors.google_utils.google_kv.InstalledAppFlow.from_client_config",
        _from_client_config,
    )

    auth_url = get_auth_url(
        42,
        DocumentSource.GOOGLE_DRIVE,
        cast(User, None),
        cast(Session, None),
    )

    assert f"client_id={row_client_id}" in auth_url
    assert "client-id.apps.googleusercontent.com" not in auth_url
    assert stored_state["value"] == {
        "value": "test-state",
        "code_verifier": "test-verifier",
    }
