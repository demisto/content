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
    asyncio.create_task(func_2())
    await a
    print("finished calling func_1 & func_2, going to sleep for 4 seconds.")
    await asyncio.sleep(4)
    print("finished sleeping for 4 seconds.")

asyncio.run(main())