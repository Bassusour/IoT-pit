import asyncio
import os
import signal
import time
from gmqtt import Client as MQTTClient

STOP = asyncio.Event()

def on_connect(client, flags, rc, properties):
    print('Connected')

def on_message(client, topic, payload, qos, properties):
    print('RECV MSG:', payload)

def on_disconnect(client, packet, exc=None):
    print('Disconnected')

def on_subscribe(client, mid, qos, properties):
    print('SUBSCRIBED')

def on_pubrel(client, mid, properties):
    print(f'PUBREL received for message ID: {mid}')
    client.pubcomp(mid)

def ask_exit(*args):
    STOP.set()

async def main(broker_host):
    client = MQTTClient("client-id")

    client.on_connect = on_connect
    client.on_message = on_message
    client.on_disconnect = on_disconnect
    client.on_subscribe = on_subscribe
    client.on_pubrel = on_pubrel  # Set the on_pubrel callback

    await client.connect(broker_host, 1883)

    for i in range(100):
        client.subscribe("abc" + str(i))
        print(f'Sent SUBSCRIBE request {i+1}')

    # Publish a message with QoS 2 to trigger PUBREL
    client.publish('your/topic', 'Your message', qos=2)

    await STOP.wait()
    await client.disconnect()

if __name__ == '__main__':
    loop = asyncio.get_event_loop()

    host = '127.0.0.1'

    loop.add_signal_handler(signal.SIGINT, ask_exit)
    loop.add_signal_handler(signal.SIGTERM, ask_exit)

    loop.run_until_complete(main(host))
