import asyncio

async def func_1():
    print("going to wait 1 second")
    await asyncio.sleep(1)
    print("Arad")

async def func_2():
    print("going to wait 3 seconds")
    await asyncio.sleep(3)
    print("Naknik")

async def main():
    a = func_1()
    b = func_2()
    await b
    await a

asyncio.run(main())