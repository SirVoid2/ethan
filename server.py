import asyncio, websockets, json, os

connected = {}       # username -> websocket
public_keys = {}     # username -> public key

async def handler(ws):
    try:
        async for msg in ws:
            data = json.loads(msg)

            if data["type"] == "register":
                username = data["username"]
                connected[username] = ws
                public_keys[username] = data["public_key"]

                # broadcast updated keys to all clients
                update = json.dumps({"type": "keys_update", "keys": public_keys})
                await asyncio.gather(*[c.send(update) for c in connected.values()])
            
            elif data["type"] == "message":
                target = data["to"]
                if target in connected:
                    await connected[target].send(msg)
    except:
        pass
    finally:
        for u, c in list(connected.items()):
            if c == ws:
                del connected[u]
                del public_keys[u]
                break

async def main():
    port = int(os.environ.get("PORT", 8765))  # Render assigns $PORT
    async with websockets.serve(handler, "0.0.0.0", port):
        print(f"Server running on port {port}")
        await asyncio.Future()  # run forever

if __name__ == "__main__":
    asyncio.run(main())
