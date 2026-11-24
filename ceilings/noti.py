import asyncio
import json
import logging
import smtplib
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
from email.policy import SMTP
from uuid import UUID

from email_validator import EmailNotValidError
from sqlalchemy import text

from .broker import BROKER_ERRORS, LOGIN_QUEUE, connect
from .db import database_engine
from .email_address import UnsupportedLocalPart, login_address
from .security import utcnow

logger = logging.getLogger(__name__)
TERMINAL = ("sent", "failed", "unknown", "expired")


def smtp_result(status):
    if 400 <= status < 500:
        return "temporary"
    return "sent" if 200 <= status < 300 else "failed"


def send_code(command):
    try:
        recipient = login_address(command["email"]).ascii_email
    except (EmailNotValidError, UnsupportedLocalPart):
        return "failed"
    email = EmailMessage(policy=SMTP)
    email["From"] = "Ceilings <login@ceilings.test>"
    email["To"] = recipient
    email["Subject"] = "Код входа в панель Ceilings" if command["role"] == "admin" else "Код входа в Ceilings"
    email.set_content(f"Код входа: {command['code']}\nКод действует 10 минут с момента запроса.\n")
    smtp = smtplib.SMTP(timeout=4)
    data_started = False
    try:
        status, _ = smtp.connect("mailpit-smtp", 1025)
        if status != 220:
            return smtp_result(status)
        status, _ = smtp.helo("noti.ceilings.test")
        if status != 250:
            return smtp_result(status)
        status, _ = smtp.mail("login@ceilings.test")
        if status != 250:
            return smtp_result(status)
        status, _ = smtp.rcpt(recipient)
        if status not in (250, 251):
            return smtp_result(status)
        data_started = True
        status, _ = smtp.data(email.as_bytes())
        return smtp_result(status)
    except smtplib.SMTPResponseException as error:
        return smtp_result(error.smtp_code)
    except (OSError, smtplib.SMTPException, UnicodeError):
        return "unknown" if data_started else "failed"
    finally:
        smtp.close()


def save_state(connection, command_id, expires, state, attempt, retry_at=None):
    connection.execute(text("""INSERT INTO app.code_deliveries (command_id,expires_at,state,attempt,retry_at)
        VALUES (:id,:expires,:state,:attempt,:retry_at)
        ON CONFLICT (command_id) DO UPDATE SET state=EXCLUDED.state, attempt=EXCLUDED.attempt,
        retry_at=EXCLUDED.retry_at"""),
                       {"id": command_id, "expires": expires, "state": state, "attempt": attempt, "retry_at": retry_at})
    connection.commit()


def deliver(engine, command, command_id, expires):
    with engine.connect() as connection:
        connection.execute(text("SELECT pg_advisory_lock(hashtextextended(:id, 0))"), {"id": str(command_id)})
        connection.commit()
        row = connection.execute(text("SELECT state,attempt,retry_at FROM app.code_deliveries WHERE command_id=:id"),
                                 {"id": command_id}).one_or_none()
        connection.commit()
        if row and row.state in TERMINAL:
            return row.state
        attempt = row.attempt if row else 0
        if row and row.state == "sending":
            save_state(connection, command_id, expires, "unknown", attempt)
            return "unknown"
        if row and row.retry_at:
            time.sleep(max(0, (min(expires, row.retry_at) - utcnow()).total_seconds()))
        while utcnow() < expires:
            attempt += 1
            save_state(connection, command_id, expires, "sending", attempt)
            result = send_code(command)
            if result != "temporary" or attempt >= 2:
                state = "failed" if result == "temporary" else result
                save_state(connection, command_id, expires, state, attempt)
                return state
            retry_at = utcnow() + timedelta(seconds=5)
            save_state(connection, command_id, expires, "retry", attempt, retry_at)
            time.sleep(max(0, (min(retry_at, expires) - utcnow()).total_seconds()))
        if utcnow() < expires + timedelta(hours=24):
            save_state(connection, command_id, expires, "expired", attempt)
        return "expired"


def parse_message(message):
    command = json.loads(message.body)
    command_id = UUID(command["id"])
    expires = datetime.fromisoformat(command["expires_at"])
    if (str(command_id) != message.message_id or expires.tzinfo is None
            or command["role"] not in ("client", "admin")
            or not isinstance(command["email"], str)
            or len(command["code"]) != 6 or not command["code"].isascii() or not command["code"].isdigit()):
        raise ValueError("Invalid code command")
    return command, command_id, expires


def cleanup_deliveries(engine):
    with engine.begin() as connection:
        connection.execute(text("""DELETE FROM app.code_deliveries WHERE expires_at <= :cutoff
            AND state IN ('sent','failed','unknown','expired')"""), {"cutoff": utcnow() - timedelta(hours=24)})


async def cleanup_loop(engine):
    while True:
        try:
            await asyncio.to_thread(cleanup_deliveries, engine)
        except Exception as error:
            logger.warning("Login mail cleanup: %s", type(error).__name__)
        await asyncio.sleep(60)


async def consume_codes():
    engine = database_engine("noti")
    cleanup = asyncio.create_task(cleanup_loop(engine))
    try:
        while True:
            try:
                async with await connect("noti_codes") as connection:
                    channel = await connection.channel()
                    await channel.set_qos(prefetch_count=1)
                    queue = await channel.get_queue(LOGIN_QUEUE, ensure=False)
                    async with queue.iterator() as messages:
                        async for message in messages:
                            try:
                                command, command_id, expires = parse_message(message)
                            except (ValueError, KeyError, TypeError, AttributeError):
                                logger.warning("Invalid login mail command")
                                await message.reject(requeue=False)
                                continue
                            try:
                                state = await asyncio.to_thread(deliver, engine, command, command_id, expires)
                            except Exception as error:
                                logger.warning("Login mail %s: %s", command_id, type(error).__name__)
                                await asyncio.sleep(1)
                                await message.reject(requeue=True)
                            else:
                                logger.info("Login mail %s: %s", command_id, state)
                                await message.ack()
            except BROKER_ERRORS as error:
                logger.warning("Login mail broker: %s", type(error).__name__)
                await asyncio.sleep(1)
    finally:
        cleanup.cancel()
        await asyncio.gather(cleanup, return_exceptions=True)
        engine.dispose()
