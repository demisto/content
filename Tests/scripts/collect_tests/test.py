
UNREMOVABLE_PACKS = None

def a():
    print(UNREMOVABLE_PACKS)

def main():
    global UNREMOVABLE_PACKS
    UNREMOVABLE_PACKS = 'aaaaa'
    a()



if __name__ == '__main__':
    main()