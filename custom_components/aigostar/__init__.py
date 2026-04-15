"""Aigostar integration for Home Assistant — token bypass mode."""
from __future__ import annotations

import logging
import time
from datetime import timedelta

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall
from homeassistant.helpers.event import async_track_time_interval

from .alibaba_api import full_login_sync, list_devices_sync, refresh_iot_token_sync
from .const import (
    APP_KEY, APP_SECRET,
    CONF_EMAIL, CONF_PASSWORD,
    CONF_IOT_TOKEN, CONF_REFRESH_TOKEN, CONF_IDENTITY_ID,
    DOMAIN,
)

_LOGGER = logging.getLogger(__name__)

PLATFORMS = ["light"]
TOKEN_REFRESH_INTERVAL = timedelta(hours=1)
DEVICE_SYNC_INTERVAL = timedelta(minutes=5)

# Internal key used to persist token creation timestamp across restarts
_CONF_TOKEN_ISSUED_AT = "token_issued_at"

SERVICE_SYNC = "sync_devices"


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    data = dict(entry.data)
    email    = data.get(CONF_EMAIL, "")
    password = data.get(CONF_PASSWORD, "")

    # --- TOKEN BYPASS ---------------------------------------------------
    # If bypass_aigostar.py injected pre-obtained tokens, use them directly
    # and skip the UC OAuth flow (which always fails with NEED_SECURITY_CODE).
    stored_token   = data.get(CONF_IOT_TOKEN, "")
    stored_refresh = data.get(CONF_REFRESH_TOKEN, "")
    stored_ident   = data.get(CONF_IDENTITY_ID, "")

    if stored_token:
        _LOGGER.info(
            "Aigostar: using pre-obtained iotToken (%s...)", stored_token[:8]
        )
        # Try the stored token first; if it's expired, try the refreshToken
        iot_token     = stored_token
        refresh_token = stored_refresh
        identity_id   = stored_ident
        token_expire  = 72000
        # Restore the real issuance time if we persisted it; otherwise assume now
        token_created = data.get(_CONF_TOKEN_ISSUED_AT, time.time())

        # Quick validation: list devices to confirm the token works
        try:
            devices = await hass.async_add_executor_job(
                list_devices_sync, APP_KEY, APP_SECRET, iot_token,
            )
            _LOGGER.info("Aigostar: stored token valid, %d devices found", len(devices))
        except Exception as exc:
            _LOGGER.warning(
                "Aigostar: stored iotToken rejected (%s), attempting refresh...", exc
            )
            if refresh_token and identity_id:
                try:
                    new_session = await hass.async_add_executor_job(
                        refresh_iot_token_sync,
                        refresh_token, identity_id, APP_KEY, APP_SECRET,
                    )
                    iot_token     = new_session["iotToken"]
                    refresh_token = new_session.get("refreshToken", refresh_token)
                    identity_id   = new_session.get("identityId", identity_id)
                    token_expire  = int(new_session.get("iotTokenExpire", 72000))
                    token_created = time.time()
                    # Persist immediately so the refreshed token survives a restart
                    new_data = {**data}
                    new_data[CONF_IOT_TOKEN]        = iot_token
                    new_data[CONF_REFRESH_TOKEN]    = refresh_token
                    new_data[CONF_IDENTITY_ID]      = identity_id
                    new_data[_CONF_TOKEN_ISSUED_AT] = token_created
                    hass.config_entries.async_update_entry(entry, data=new_data)
                    devices = await hass.async_add_executor_job(
                        list_devices_sync, APP_KEY, APP_SECRET, iot_token,
                    )
                    _LOGGER.info(
                        "Aigostar: token refreshed OK, %d devices found", len(devices)
                    )
                except Exception as exc2:
                    _LOGGER.error(
                        "Aigostar: token refresh also failed: %s. "
                        "Run bypass_aigostar.py again to get fresh tokens.", exc2
                    )
                    return False
            else:
                _LOGGER.error(
                    "Aigostar: stored token expired and no refreshToken available. "
                    "Run bypass_aigostar.py to get fresh tokens."
                )
                return False
    else:
        # --- ORIGINAL FLOW (email + password → UC OAuth) ----------------
        # This will only work if the server doesn't require a security code.
        _LOGGER.info("Aigostar: no pre-obtained tokens found, attempting UC login...")
        try:
            session = await hass.async_add_executor_job(
                full_login_sync, email, password, APP_KEY, APP_SECRET,
            )
        except Exception as exc:
            _LOGGER.error("Aigostar: login failed: %s", exc)
            return False

        iot_token     = session["iotToken"]
        refresh_token = session.get("refreshToken", "")
        identity_id   = session.get("identityId", "")
        token_expire  = int(session.get("iotTokenExpire", 7200))
        token_created = time.time()

        devices = await hass.async_add_executor_job(
            list_devices_sync, APP_KEY, APP_SECRET, iot_token,
        )
        _LOGGER.info("Aigostar: login OK, %d devices found", len(devices))

    # --- SHARED STATE ---------------------------------------------------
    entry_data = {
        "devices":       devices,
        "iot_token":     iot_token,
        "refresh_token": refresh_token,
        "identity_id":   identity_id,
        "token_expire":  token_expire,
        "token_created": token_created,
        "email":         email,
        "password":      password,
        "app_key":       APP_KEY,
        "app_secret":    APP_SECRET,
    }

    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN][entry.entry_id] = entry_data

    # --- PERIODIC TOKEN REFRESH -----------------------------------------
    async def _refresh_token(_now=None):
        ed = hass.data[DOMAIN].get(entry.entry_id)
        if not ed:
            return

        elapsed = time.time() - ed["token_created"]
        # Refresh when less than 30 min remains (token_expire - 1800)
        if elapsed < ed["token_expire"] - 1800:
            return

        _LOGGER.info("Aigostar: refreshing iotToken (elapsed=%ds)", int(elapsed))

        try:
            if ed["refresh_token"] and ed["identity_id"]:
                new_session = await hass.async_add_executor_job(
                    refresh_iot_token_sync,
                    ed["refresh_token"], ed["identity_id"],
                    APP_KEY, APP_SECRET,
                )
            else:
                # No refreshToken → fall back to full login (may fail)
                new_session = await hass.async_add_executor_job(
                    full_login_sync,
                    ed["email"], ed["password"], APP_KEY, APP_SECRET,
                )

            new_token    = new_session["iotToken"]
            new_refresh  = new_session.get("refreshToken", ed["refresh_token"])
            new_identity = new_session.get("identityId",   ed["identity_id"])
            new_expire   = int(new_session.get("iotTokenExpire", 72000))
            now          = time.time()

            ed["iot_token"]     = new_token
            ed["refresh_token"] = new_refresh
            ed["identity_id"]   = new_identity
            ed["token_expire"]  = new_expire
            ed["token_created"] = now

            # Persist new tokens to config entry so they survive HA restarts
            new_data = {**entry.data}
            new_data[CONF_IOT_TOKEN]         = new_token
            new_data[CONF_REFRESH_TOKEN]     = new_refresh
            new_data[CONF_IDENTITY_ID]       = new_identity
            new_data[_CONF_TOKEN_ISSUED_AT]  = now
            hass.config_entries.async_update_entry(entry, data=new_data)

            for entity in hass.data.get(f"{DOMAIN}_entities", {}).get(entry.entry_id, []):
                entity.update_token(new_token)

            _LOGGER.info(
                "Aigostar: iotToken refreshed and persisted (expires in %ds)", new_expire
            )

        except Exception as exc:
            _LOGGER.warning(
                "Aigostar: token refresh failed: %s. "
                "Run bypass_aigostar.py to get fresh tokens.", exc
            )

    # --- PERIODIC DEVICE SYNC -------------------------------------------
    async def _periodic_sync(_now=None):
        ed = hass.data[DOMAIN].get(entry.entry_id)
        if not ed:
            return
        try:
            new_devices = await hass.async_add_executor_job(
                list_devices_sync, APP_KEY, APP_SECRET, ed["iot_token"],
            )
            known_ids = {d["iotId"] for d in ed["devices"] if "iotId" in d}
            new_ids = {d["iotId"] for d in new_devices if d.get("iotId")} - known_ids
            if new_ids:
                _LOGGER.info(
                    "Aigostar auto-sync: %d new devices, reloading integration", len(new_ids)
                )
                await hass.config_entries.async_reload(entry.entry_id)
        except Exception as exc:
            _LOGGER.debug("Aigostar auto-sync failed: %s", exc)

    unsub_refresh = async_track_time_interval(hass, _refresh_token, TOKEN_REFRESH_INTERVAL)
    unsub_sync    = async_track_time_interval(hass, _periodic_sync, DEVICE_SYNC_INTERVAL)
    entry_data["unsub_refresh"] = unsub_refresh
    entry_data["unsub_sync"]    = unsub_sync

    # --- SERVICE --------------------------------------------------------
    async def _handle_sync_service(call: ServiceCall) -> None:
        for eid in list(hass.data.get(DOMAIN, {})):
            cfg_entry = hass.config_entries.async_get_entry(eid)
            if cfg_entry:
                _LOGGER.info("Aigostar sync_devices: reloading %s", cfg_entry.title)
                await hass.config_entries.async_reload(eid)

    if not hass.services.has_service(DOMAIN, SERVICE_SYNC):
        hass.services.async_register(DOMAIN, SERVICE_SYNC, _handle_sync_service)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    entry_data = hass.data[DOMAIN].get(entry.entry_id, {})
    for key in ("unsub_refresh", "unsub_sync"):
        unsub = entry_data.get(key)
        if unsub:
            unsub()

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        hass.data.get(f"{DOMAIN}_entities", {}).pop(entry.entry_id, None)
        if not hass.data.get(DOMAIN):
            hass.services.async_remove(DOMAIN, SERVICE_SYNC)
    return unload_ok
