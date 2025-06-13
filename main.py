from hashlib import sha1, sha256, sha512, md5
from bcrypt import checkpw
from re import fullmatch, findall
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Event
from time import time

hash_types = {
    32: md5,
    40: sha1,
    64: sha256,
    128: sha512,
}

wordlist = []
STEPS = 4000

stop = Event()

half = 0
total = 0

def clean_hash(raw_hash: str) -> tuple[str, str] | str :
    if fullmatch(r'^\$?(SHA(256|512)?)?\$?\w{1,33}(\$|\:|\@)([a-fA-F0-9]{128}|[a-fA-F0-9]{64})$', raw_hash):
        return (findall(r'(?:\$?SHA(?:256|512)?\$?)?(\w{1,33})', raw_hash)[0], findall(r'([a-fA-F0-9]{128}|[a-fA-F0-9]{64})', raw_hash)[0])
    if fullmatch(r'^\$?(SHA(256|512)?)?\$?([a-fA-F0-9]{128}|[a-fA-F0-9]{64})(\$|\:|\@)\w{1,33}$', raw_hash):
        return (findall(r'(\w{1,33})$', raw_hash)[0], findall(r'([a-fA-F0-9]{128}|[a-fA-F0-9]{64})', raw_hash)[0])
    return raw_hash

def fuck(index: int, hash_str: str, stop: Event):

    if stop.is_set():
        return (False,)

    type_index = index // 4
    mode = index % 4

    if mode == 0:
        start = STEPS * type_index
        end = STEPS * (type_index + 1)
        passwords = wordlist[start:end]

    elif mode == 1:
        start = total - STEPS * type_index - 1
        end = total - STEPS * (type_index + 1) - 1
        passwords = wordlist[start:end:-1] if start > end else []

    elif mode == 2:
        start = half - STEPS * type_index - 1
        end = half - STEPS * (type_index + 1) - 1
        passwords = wordlist[start:end:-1] if start > end else []
    else:
        start = half + STEPS * type_index
        end = half - STEPS * (type_index + 1)
        passwords = wordlist[start:end]

    for password in passwords:
        if stop.is_set():
            return (False,)
        if len(hash_str) == 60 and checkpw(password.encode(), hash_str.encode()):
            return (True, password)
        elif len(hash_str) != 60 and hash_types[len(hash_str)](password.encode()).hexdigest() == hash_str:
            return (True, password)
    return (False,)

if __name__ == "__main__":
    with open('wordlist.txt', 'r', encoding='latin-1') as file:
        wordlist = [line.strip() for line in file if line.strip()]
        half = len(wordlist) // 2
        total = len(wordlist)

    hash_str = clean_hash(input("Hash: ").strip())
    with ThreadPoolExecutor(max_workers=20) as executor:
        start = time()
        max_iters = (len(wordlist) + STEPS -1) // STEPS * 4
        futures = [executor.submit(fuck, i+1, hash_str, stop) for i in range(max_iters)]
        
        for future in as_completed(futures):
            result = future.result()
            if result[0]:
                end = time()
                stop.set()
                print(f"Password found: {result[1]} in {end - start} seconds")
                break
