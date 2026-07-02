import json
from typing import Any
from typing import cast
from urllib.parse import parse_qs
from urllib.parse import ParseResult
from urllib.parse import urlparse

from google.oauth2.credentials import Credentials as OAuthCredentials
from google_auth_oauthlib.flow import InstalledAppFlow
from sqlalchemy.orm import Session

from onyx.configs.app_configs import WEB_DOMAIN
from onyx.configs.constants import DocumentSource
from onyx.configs.constants import KV_CRED_KEY
from onyx.configs.constants import KV_GMAIL_CRED_KEY
from onyx.configs.constants import KV_GOOGLE_DRIVE_CRED_KEY
from onyx.connectors.google_utils.resources import get_drive_service
from onyx.connectors.google_utils.resources import get_gmail_service
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
from onyx.connectors.google_utils.shared_constants import GOOGLE_SCOPES
from onyx.connectors.google_utils.shared_constants import (
    GoogleOAuthAuthenticationMethod,
)
from onyx.connectors.google_utils.shared_constants import MISSING_SCOPES_ERROR_STR
from onyx.connectors.google_utils.shared_constants import ONYX_SCOPE_INSTRUCTIONS
from onyx.db.credentials import fetch_credential_by_id_for_user
from onyx.db.credentials import update_credential_json
from onyx.db.encrypted_kv_store import delete_encrypted_kv
from onyx.db.encrypted_kv_store import load_encrypted_kv
from onyx.db.encrypted_kv_store import upsert_encrypted_kv
from onyx.db.models import User
from onyx.key_value_store.factory import get_kv_store
from onyx.key_value_store.interface import unwrap_str
from onyx.server.documents.models import CredentialBase
from onyx.server.documents.models import GoogleAppCredentials
from onyx.server.documents.models import GoogleServiceAccountKey
from onyx.utils.logger import setup_logger

logger = setup_logger()


def _load_google_json(raw: object) -> dict[str, Any]:
    """Accept both the current (dict) and legacy (JSON string) KV payload shapes.

    Payloads written before the fix for serializing Google credentials into
    ``EncryptedJson`` columns are stored as JSON strings; new writes store dicts.
    Once every install has re-uploaded their Google credentials the legacy
    ``str`` branch can be removed.
    """
    if isinstance(raw, dict):
        return raw  # ty: ignore[invalid-return-type]
    if isinstance(raw, str):
        return json.loads(raw)
    raise ValueError(f"Unexpected Google credential payload type: {type(raw)!r}")


def _build_frontend_google_drive_redirect(source: DocumentSource) -> str:
    if source == DocumentSource.GOOGLE_DRIVE:
        return f"{WEB_DOMAIN}/admin/connectors/google-drive/auth/callback"
    elif source == DocumentSource.GMAIL:
        return f"{WEB_DOMAIN}/admin/connectors/gmail/auth/callback"
    else:
        raise ValueError(f"Unsupported source: {source}")


def _get_current_oauth_user(creds: OAuthCredentials, source: DocumentSource) -> str:
    if source == DocumentSource.GOOGLE_DRIVE:
        drive_service = get_drive_service(creds)
        user_info = (
            drive_service.about()  # ty: ignore[unresolved-attribute]
            .get(
                fields="user(emailAddress)",
            )
            .execute()
        )
        email = user_info.get("user", {}).get("emailAddress")
    elif source == DocumentSource.GMAIL:
        gmail_service = get_gmail_service(creds)
        user_info = (
            gmail_service.users()  # ty: ignore[unresolved-attribute]
            .getProfile(
                userId="me",
                fields="emailAddress",
            )
            .execute()
        )
        email = user_info.get("emailAddress")
    else:
        raise ValueError(f"Unsupported source: {source}")
    return email


def verify_csrf(credential_id: int, state: str) -> None:
    csrf = unwrap_str(get_kv_store().load(KV_CRED_KEY.format(str(credential_id))))
    if csrf != state:
        raise PermissionError(
            "State from Google Drive Connector callback does not match expected"
        )


def update_credential_access_tokens(
    auth_code: str,
    credential_id: int,
    user: User,
    db_session: Session,
    source: DocumentSource,
    auth_method: GoogleOAuthAuthenticationMethod,
) -> OAuthCredentials | None:
    app_credentials = _app_cred_on_row(credential_id, source, user, db_session)
    flow = InstalledAppFlow.from_client_config(
        app_credentials,
        scopes=GOOGLE_SCOPES[source],
        redirect_uri=_build_frontend_google_drive_redirect(source),
    )
    # PKCE: the token exchange runs in a separate request from get_auth_url,
    # so the autogenerated verifier only survives via the KV store.
    kv_payload = get_kv_store().load(KV_CRED_KEY.format(str(credential_id)))
    if isinstance(kv_payload, dict):
        code_verifier = kv_payload.get("code_verifier")  # ty: ignore[invalid-argument-type]
        if isinstance(code_verifier, str):
            flow.code_verifier = code_verifier
    flow.fetch_token(code=auth_code)
    creds = flow.credentials
    token_json_str = creds.to_json()

    # Get user email from Google API so we know who
    # the primary admin is for this connector
    try:
        email = _get_current_oauth_user(creds, source)
    except Exception as e:
        if MISSING_SCOPES_ERROR_STR in str(e):
            raise PermissionError(ONYX_SCOPE_INSTRUCTIONS) from e
        raise e

    new_creds_dict = {
        # update_credential_json replaces the row's json, so keep the app cred here
        DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY: app_credentials,
        DB_CREDENTIALS_DICT_TOKEN_KEY: token_json_str,
        DB_CREDENTIALS_PRIMARY_ADMIN_KEY: email,
        DB_CREDENTIALS_AUTHENTICATION_METHOD: auth_method.value,
    }

    if not update_credential_json(credential_id, new_creds_dict, user, db_session):
        return None
    return creds


def build_service_account_creds(
    source: DocumentSource,
    service_account_key: GoogleServiceAccountKey,
    primary_admin_email: str | None = None,
    name: str | None = None,
) -> CredentialBase:
    credential_dict = {
        DB_CREDENTIALS_DICT_SERVICE_ACCOUNT_KEY: service_account_key.model_dump_json(),
    }
    if primary_admin_email:
        credential_dict[DB_CREDENTIALS_PRIMARY_ADMIN_KEY] = primary_admin_email

    credential_dict[DB_CREDENTIALS_AUTHENTICATION_METHOD] = (
        GoogleOAuthAuthenticationMethod.UPLOADED.value
    )

    return CredentialBase(
        credential_json=credential_dict,
        admin_public=True,
        source=source,
        name=name,
    )


def _app_cred_on_row(
    credential_id: int,
    source: DocumentSource,
    user: User,
    db_session: Session,
) -> dict[str, Any]:
    """OAuth app credential for this connector, read off the credential row.

    Pre-fills the row from the instance default on first use so the row is the
    single source of truth for the rest of the OAuth flow (no runtime fallback)."""
    credential = fetch_credential_by_id_for_user(credential_id, user, db_session)
    if credential is None:
        raise ValueError(f"Credential {credential_id} not found")
    existing_json = (
        credential.credential_json.get_value(apply_mask=False)
        if credential.credential_json
        else {}
    )
    existing = existing_json.get(DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY)
    if existing is not None:
        return _load_google_json(existing)

    default = _load_google_json(load_encrypted_kv(_app_cred_default_key(source)))
    # get_value returns SensitiveValue's cached dict, so build a new one rather
    # than mutating it in place.
    updated_json = {**existing_json, DB_CREDENTIALS_DICT_APP_CREDENTIAL_KEY: default}
    if update_credential_json(credential_id, updated_json, user, db_session) is None:
        raise ValueError(
            f"Failed to persist app credential onto credential {credential_id}"
        )
    return default


def get_auth_url(
    credential_id: int,
    source: DocumentSource,
    user: User,
    db_session: Session,
) -> str:
    credential_json = _app_cred_on_row(credential_id, source, user, db_session)
    flow = InstalledAppFlow.from_client_config(
        credential_json,
        scopes=GOOGLE_SCOPES[source],
        redirect_uri=_build_frontend_google_drive_redirect(source),
    )
    auth_url, _ = flow.authorization_url(prompt="consent")

    parsed_url = cast(ParseResult, urlparse(auth_url))
    params = parse_qs(parsed_url.query)

    get_kv_store().store(
        KV_CRED_KEY.format(credential_id),
        {
            "value": params.get("state", [None])[0],
            # authorization_url() autogenerates a PKCE verifier. Persist it for
            # the callback's token exchange, which runs in a separate request.
            "code_verifier": flow.code_verifier,
        },
        encrypt=True,
    )
    return str(auth_url)


def _app_cred_default_key(source: DocumentSource) -> str:
    """Encrypted-table key holding the instance-default OAuth app credential."""
    if source == DocumentSource.GOOGLE_DRIVE:
        return KV_GOOGLE_DRIVE_CRED_KEY
    if source == DocumentSource.GMAIL:
        return KV_GMAIL_CRED_KEY
    raise ValueError(f"Unsupported source: {source}")


def get_google_app_cred(source: DocumentSource) -> GoogleAppCredentials:
    """The instance-default OAuth app credential (Postgres, never cached)."""
    creds = _load_google_json(load_encrypted_kv(_app_cred_default_key(source)))
    return GoogleAppCredentials(**creds)


def upsert_google_app_cred(
    app_credentials: GoogleAppCredentials, source: DocumentSource
) -> None:
    upsert_encrypted_kv(
        _app_cred_default_key(source), app_credentials.model_dump(mode="json")
    )


def delete_google_app_cred(source: DocumentSource) -> None:
    delete_encrypted_kv(_app_cred_default_key(source))
