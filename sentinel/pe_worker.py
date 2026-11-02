"""Read bounded bytes on stdin. Never load or execute the sample as code."""
import collections
import json
import math
import sys

def main():
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (384*1024*1024,384*1024*1024))
        resource.setrlimit(resource.RLIMIT_CPU, (10,10))
    except (ImportError, ValueError, OSError):
        pass
    import pefile
    data = sys.stdin.buffer.read(10*1024*1024+1)
    try:
        if len(data) > 10*1024*1024 or len(data) < 256:
            raise ValueError("Unsupported or oversized PE file.")
        pe = pefile.PE(data=data, fast_load=True)
        if pe.FILE_HEADER.Machine not in (0x14c,0x8664):
            raise ValueError("Only x86 and x64 native Windows PE files are supported.")
        if pe.OPTIONAL_HEADER.Magic not in (0x10b,0x20b):
            raise ValueError("Unsupported PE optional header.")
        if not 1 <= len(pe.sections) <= 96:
            raise ValueError("Invalid or excessive PE section count.")
        dirs = pe.OPTIONAL_HEADER.DATA_DIRECTORY
        if len(dirs) > 14 and (dirs[14].VirtualAddress or dirs[14].Size):
            raise ValueError("Managed .NET PE files are outside this prototype's supported scope.")
        sections, indicators = [], []
        for sec in pe.sections:
            start,size = sec.PointerToRawData,sec.SizeOfRawData
            if size and (start < pe.OPTIONAL_HEADER.SizeOfHeaders or start+size > len(data)):
                raise ValueError("PE section data is truncated or malformed.")
            name=sec.Name.rstrip(b"\0").decode("ascii","replace")[:32]
            counts=collections.Counter(data[start:start+size])
            entropy=-sum((n/size)*math.log2(n/size) for n in counts.values()) if size else 0
            wx=bool(sec.Characteristics & 0x20000000 and sec.Characteristics & 0x80000000)
            sections.append({"name":name,"size":size,"entropy":round(entropy,2),"rva":hex(sec.VirtualAddress),
                             "permissions": "".join(x for flag,x in [(0x40000000,"R"),(0x80000000,"W"),(0x20000000,"X")] if sec.Characteristics&flag)})
            if wx:
                indicators.append({"title":"Writable and executable section","severity":"medium",
                                   "detail":"This combination deserves review; legitimate programs can also use it.",
                                   "evidence":f"Section {name}, RVA {hex(sec.VirtualAddress)}"})
            if entropy > 7.2 and size >= 512:
                indicators.append({"title":"High-entropy section","severity":"low",
                                   "detail":"May indicate compression, encryption or packing; not a malware verdict.",
                                   "evidence":f"Section {name}: {entropy:.2f} bits/byte"})
        output={"architecture":"x64" if pe.FILE_HEADER.Machine==0x8664 else "x86",
                "kind":"DLL" if pe.FILE_HEADER.Characteristics&0x2000 else "EXE",
                "entry_point":hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),"sections":sections,
                "indicators":indicators,"limitations":"Static header/section inspection only. No decompilation or AI ran in this step."}
        pe.close()
    except ValueError as exc:
        output={"error":str(exc)}
    except Exception:
        output={"error":"This file is not a valid, supported Windows PE executable."}
    sys.stdout.write(json.dumps(output))

if __name__=="__main__":
    main()
