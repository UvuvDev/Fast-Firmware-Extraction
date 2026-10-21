"""Synthetic APBL envelopes using Python's independent SHA-384 implementation."""
from pathlib import Path
import hashlib,json,struct
ROOT=Path(__file__).resolve().parents[3]

def wrap(payload):
    image=bytearray(0x5000)
    struct.pack_into('<I',image,0,2)
    image[0x463c:0x4640]=b'APBL'
    struct.pack_into('<I',image,0x4640,2)
    struct.pack_into('<I',image,0x4648,len(payload))
    image[0x4674:0x46a4]=hashlib.sha384(payload).digest()
    return image+payload

for name in ['apbl','apbl_resources','apbl_corrupt']:
    resources=name!='apbl'
    payload=b'\x5f\x24\x03\xd5'+b'\x1f\x20\x03\xd5'*31
    expected={'native_format':'apbl','sample':'sample.bin'}
    if resources:
        path=ROOT/'tests/fixtures/blfs/sample.blfs'
        payload+=path.read_bytes()
    raw=wrap(payload)
    if name=='apbl_corrupt': raw=raw[:-1];expected['expect_failure']=True
    else:
        child={'length':len(payload),'sha256':hashlib.sha256(payload).hexdigest()}
        if resources:
            child['children']=json.loads(path.with_name('expected.json').read_text())['children']
            child['embedded_range']=[128,len(payload)]
        expected['children']={'payload.bin':child}
    out=ROOT/'tests/fixtures'/name
    out.mkdir(exist_ok=True)
    (out/'sample.bin').write_bytes(raw)
    (out/'expected.json').write_text(json.dumps(expected,indent=2)+'\n')
