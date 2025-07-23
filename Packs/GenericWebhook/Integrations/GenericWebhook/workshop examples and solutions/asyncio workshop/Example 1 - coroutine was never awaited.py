import asyncio

async def func_1():
    print("Arad")

async def func_2():
    print("Naknik")

async def main():
    a = func_1()
    b = func_2()
    await a

asyncio.run(main())