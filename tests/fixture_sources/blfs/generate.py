"""Synthetic BLFS tables matching the independently measured ABL/DRAM layout."""
from pathlib import Path
import hashlib,json,struct
ROOT=Path(__file__).resolve().parents[3]
lz4=ROOT/'tests/fixtures/lz4_frame/sample.lz4'
info=json.loads(lz4.with_name('expected.json').read_text())['children']['']
files={'Boot/test.bmp.lz4':lz4.read_bytes(),'Fonts/test.txt':b'independent BLFS fixture payload\n'}
image=bytearray(32+64*len(files))
children={}
for i,(name,payload) in enumerate(files.items()):
    off=32+i*64
    image[off:off+len(name)] = name.encode()
    struct.pack_into('<II',image,off+48,len(payload),len(image))
    image.extend(payload)
    children[name]={'length':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
    if name.endswith('.lz4'): children[name]['children']={'':info}
struct.pack_into('<4sIIII',image,0,b'sFlB',1,len(files),len(files),len(image))
for name,prefix in [('blfs',b''),('blfs_embedded',b'\x5f\x24\x03\xd5'+b'\xa5'*124),
                    ('blfs_entry_metadata',b'\xa5'*128),('blfs_corrupt',b'')]:
    out=ROOT/'tests/fixtures'/name
    out.mkdir(exist_ok=True)
    raw=prefix+image
    if name=='blfs_entry_metadata':
        raw=bytearray(raw)
        for i in range(len(files)):
            struct.pack_into('<II',raw,len(prefix)+32+i*64+56,0xffffffff if i==0 else 0,4)
    expected={'native_format':'blfs','sample':'sample.blfs'}
    if name=='blfs_corrupt': raw=raw[:-1];expected['expect_failure']=True
    else:
        expected['children']=children
        if prefix: expected['embedded_range']=[len(prefix),len(raw)]
    (out/'sample.blfs').write_bytes(raw)
    (out/'expected.json').write_text(json.dumps(expected,indent=2)+'\n')
