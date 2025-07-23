import asyncio

async def func_1():
    print("going to wait 3 seconds in func_1")
    await asyncio.sleep(3)
    print("Arad")
    print("finished waiting in func_1")

async def func_2():
    print("going to wait 1 seconds in func_2")
    await asyncio.sleep(1)
    print("Naknik")
    print("finished waiting in func_2")

async def main():
    a = func_1()
    asyncio.create_task(func_2())
    await a

asyncio.run(main())