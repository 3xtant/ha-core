"""The Azure SMS Service integration."""
from __future__ import annotations

import base64
from datetime import UTC, datetime
import hashlib
import hmac
import json
import ssl
from urllib import request

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, ServiceCall

from .const import CONST_AZ_COMM_URL, CONST_PATH, DOMAIN

CONF_SECRET = "sms_secret"
CONF_SERVICE_NAME = "service_name"
CONF_QUERY = "query"
CONF_FROM_NUMBER = "from_number"


def send_request(req: request.Request, context: ssl.SSLContext):
    """Whoever wrote this linter rule sucks."""

    with request.urlopen(req, context=context) as response:
        response_string = json.load(response)
    return response_string


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Azure SMS Service from a config entry."""

    hass.data.setdefault(DOMAIN, {})

    def async_register_az_sms_svc(name, az_sms_svc_config):
        """Create HA service for Azure SMS Service."""
        secret = None
        service_name = None
        from_number = None
        query = None

        if CONF_SECRET in az_sms_svc_config.data:
            secret = az_sms_svc_config.data[CONF_SECRET]

        if CONF_SERVICE_NAME in az_sms_svc_config.data:
            service_name = az_sms_svc_config.data[CONF_SERVICE_NAME]

        if CONF_QUERY in az_sms_svc_config.data:
            query = az_sms_svc_config.data[CONF_QUERY]

        if CONF_FROM_NUMBER in az_sms_svc_config.data:
            from_number = az_sms_svc_config.data[CONF_FROM_NUMBER]

        async def async_service_handler(service: ServiceCall) -> None:
            """Call API and send a message."""

            path_and_query = None

            def compute_content_hash(content):
                sha_256 = hashlib.sha256()
                sha_256.update(content)
                hashed_bytes = sha_256.digest()
                base64_encoded_bytes = base64.b64encode(hashed_bytes)
                content_hash = base64_encoded_bytes.decode("utf-8")
                return content_hash

            def compute_signature(string_to_sign, secret):
                decoded_secret = base64.b64decode(secret)
                encoded_string_to_sign = string_to_sign.encode("ascii")
                hashed_bytes = hmac.digest(
                    decoded_secret, encoded_string_to_sign, digest=hashlib.sha256
                )
                encoded_signature = base64.b64encode(hashed_bytes)
                signature = encoded_signature.decode("utf-8")
                return signature

            def format_date(dt):
                days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
                months = [
                    "Jan",
                    "Feb",
                    "Mar",
                    "Apr",
                    "May",
                    "Jun",
                    "Jul",
                    "Aug",
                    "Sep",
                    "Oct",
                    "Nov",
                    "Dec",
                ]
                utc = dt.utctimetuple()

                return "{}, {:02} {} {:04} {:02}:{:02}:{:02} GMT".format(
                    days[utc.tm_wday],
                    utc.tm_mday,
                    months[utc.tm_mon - 1],
                    utc.tm_year,
                    utc.tm_hour,
                    utc.tm_min,
                    utc.tm_sec,
                )

            host = None
            resource_endpoint = None
            if service_name:
                host = f"{service_name}.{CONST_AZ_COMM_URL}"
                resource_endpoint = f"https://{host}"
            if query:
                path_and_query = f"{CONST_PATH}?{query}"

            # Create a uri you are going to call.
            request_uri = f"{resource_endpoint}{path_and_query}"

            # Endpoint sms?api-version=2021-03-07 accepts a message and recipients as a body.
            body = {
                "from": f"{from_number}",
                "smsRecipients": [{"to": service.data.get("to_number", "")}],
                "message": service.data.get(
                    "message", "🏠 Today's forecast is ☀️ 72/45"
                ),
            }

            serialized_body = json.dumps(body)
            content = serialized_body.encode("utf-8")

            # Specify the 'x-ms-date' header as the current UTC timestamp according to the RFC1123 standard
            utc_now = datetime.now(UTC)
            date = format_date(utc_now)
            # Compute a content hash for the 'x-ms-content-sha256' header.
            content_hash = compute_content_hash(content)

            # Prepare a string to sign.
            string_to_sign = f"POST\n{path_and_query}\n{date};{host};{content_hash}"
            # Compute the signature.
            signature = compute_signature(string_to_sign, secret)
            # Concatenate the string, which will be used in the authorization header.
            authorization_header = f"HMAC-SHA256 SignedHeaders=x-ms-date;host;x-ms-content-sha256&Signature={signature}"

            request_headers = {}
            # Add a date header.
            request_headers["x-ms-date"] = date
            # Add content hash header.
            request_headers["x-ms-content-sha256"] = content_hash
            # Add authorization header.
            request_headers["Authorization"] = authorization_header
            # Add content type header.
            request_headers["Content-Type"] = "application/json"

            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            tls_context.verify_mode = ssl.CERT_REQUIRED
            tls_context.check_hostname = True
            tls_context.load_default_certs()

            req = request.Request(request_uri, content, request_headers, method="POST")
            await hass.async_add_executor_job(send_request, req, tls_context)

        # register service
        hass.services.async_register(DOMAIN, name, async_service_handler)

    async_register_az_sms_svc("sms", entry)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    hass.services.async_remove(DOMAIN, "sms")

    return True
