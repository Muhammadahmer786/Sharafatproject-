"""Generate synthetic input data for the FYP demonstration; never execute the PE."""
from pathlib import Path
import struct
from PIL import Image

root = Path(__file__).resolve().parents[1] / "examples"
root.mkdir(exist_ok=True)
data = bytearray(1024)
data[:2] = b"MZ"
struct.pack_into("<I", data, 60, 128)
data[128:132] = b"PE\0\0"
struct.pack_into("<HHIIIHH", data, 132, 0x14c, 1, 0, 0, 0, 224, 0x102)
off = 152
struct.pack_into("<H", data, off, 0x10b)
for offset, value in [(16, 0x1000), (20, 0x1000), (28, 0x400000), (92, 16)]:
    struct.pack_into("<I", data, off+offset, value)
struct.pack_into("<II", data, off+32, 0x1000, 0x200)
struct.pack_into("<II", data, off+56, 0x2000, 0x200)
struct.pack_into("<H", data, off+68, 3)
sec = off+224
data[sec:sec+8] = b".text\0\0\0"
struct.pack_into("<IIII", data, sec+8, 1, 0x1000, 512, 512)
struct.pack_into("<I", data, sec+36, 0x60000020)
data[512] = 0xc3
(root / "synthetic-demo.exe").write_bytes(data)
(root / "sample-document.txt").write_text(
    "Sentinel Lab university demonstration.\nThis is synthetic, non-confidential test content.\n"
    "The recovered document should match these bytes exactly.\n", encoding="utf-8")
pixels = bytes(channel for y in range(600) for x in range(800)
               for channel in (24+x*50//800, 72+y*65//600, 78+(x+y)*70//1400))
Image.frombytes("RGB", (800,600), pixels).save(root / "cover.png", "PNG")
print("Created three synthetic demo files under examples/.")
