import asyncio
import json
import ssl
from pathlib import Path

import aio_pika
from aio_pika.exceptions import AMQPException

LOGIN_EXCHANGE = "ceilings.login"
LOGIN_QUEUE = "ceilings.login.mail"
BROKER_ERRORS = (AMQPException, OSError, RuntimeError)


async def connect(user):
    context = ssl.create_default_context(cafile="/run/trust/root.crt")
    return await aio_pika.connect(host="rabbitmq.ceilings.test", port=5671, virtualhost="ceilings",
                                 login=user, password=Path("/run/secrets/broker_password").read_text().strip(),
                                 ssl=True, ssl_context=context, timeout=3, heartbeat=30)


async def publish_code(command):
    message = aio_pika.Message(json.dumps(command).encode(), message_id=command["id"],
                               delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                               content_type="application/json")
    try:
        async with asyncio.timeout(4):
            for delay in (0, 0.25, 0.75):
                await asyncio.sleep(delay)
                try:
                    async with asyncio.timeout(1):
                        async with await connect("auth_publisher") as connection:
                            channel = await connection.channel(publisher_confirms=True, on_return_raises=True)
                            exchange = await channel.get_exchange(LOGIN_EXCHANGE, ensure=False)
                            await exchange.publish(message, routing_key="mail", mandatory=True)
                            return True
                except BROKER_ERRORS:
                    continue
    except TimeoutError:
        pass
    return False
