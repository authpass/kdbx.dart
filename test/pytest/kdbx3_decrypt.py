#!/bin/env python3
# Evan Widloski - 2018-04-11
# keepass decrypt experimentation
# only works on AES encrypted database with unprotected entries

# Useful reference: https://gist.github.com/msmuenchen/9318327
#                   https://framagit.org/okhin/pygcrypt/#use
#                   https://github.com/libkeepass/libkeepass/tree/master/libkeepass

import struct

database = 'test.kdbx'
password = b'FooBar'
# password = None
#keyfile = 'test3.key'
keyfile = None

b = []
with open(database, 'rb') as f:
    b = bytearray(f.read())

# ---------- Header Stuff ----------

# file magic number (4 bytes)
magic = b[0:4]
# keepass version (2 bytes)
version = b[4:8]
# database minor version (2 bytes)
minor_version = b[8:10]
# database major version (2 bytes)
major_version = b[10:12]

# header item lookup table
header_item_ids = {0: 'end',
                   1: 'comment',
                   2: 'cipher_id',
                   3: 'compression_flags',
                   4: 'master_seed',
                   5: 'transform_seed',
                   6: 'transform_rounds',
                   7: 'encryption_iv',
                   8: 'protected_stream_key',
                   9: 'stream_start_bytes',
                   10: 'inner_random_stream_id'
}

# read dynamic header

# offset of first header byte
offset = 12
# dict containing header items
header = {}

# loop until end of header
while b[offset] != 0:
    # read size of item (2 bytes)
    size = struct.unpack('<H', b[offset + 1:offset + 3])[0]
    # insert item into header dict
    header[header_item_ids[b[offset]]] = b[offset + 3:offset + 3 + size]
    # move to next header item
    # (1 byte for header item id, 2 bytes for item size, `size` bytes for data)
    offset += 1 + 2 + size

# move from `end` to start of payload
size = struct.unpack('<H', b[offset + 1:offset + 3])[0]
offset += 1 + 2 + size

# ---------- Payload Stuff ----------

from pygcrypt.ciphers import Cipher
from pygcrypt.context import Context
import hashlib
import zlib
from lxml import etree
import base64

encrypted_payload = b[offset:]

# hash the password
if password:
    password_composite = hashlib.sha256(password).digest()
else:
    password_composite = b''
# hash the keyfile
if keyfile:
    # try to read XML keyfile
    try:
        with open(keyfile, 'r') as f:
            tree = etree.parse(f).getroot()
            keyfile_composite = base64.b64decode(tree.find('Key/Data').text)
    # otherwise, try to read plain keyfile
    except Exception as e:
        try:
            with open(keyfile, 'rb') as f:
                key = f.read()
                # if the length is 32 bytes we assume it is the key
                if len(key) == 32:
                    keyfile_composite = key
                # if the length is 64 bytes we assume the key is hex encoded
                if len(key) == 64:
                    keyfile_composite =  key.decode('hex')
                # anything else may be a file to hash for the key
                keyfile_composite = hashlib.sha256(key).digest()
        except:
            raise IOError('Could not read keyfile')

else:
    keyfile_composite = b''

# create composite key from password and keyfile composites
key_composite = hashlib.sha256(password_composite + keyfile_composite).digest()

# set up a context for AES128-ECB encryption to find transformed_key
context = Context()
cipher = Cipher(b'AES', u'ECB')
context.cipher = cipher
context.key = bytes(header['transform_seed'])
context.iv = b'\x00' * 16

# get the number of rounds from the header and transform the key_composite
rounds = struct.unpack('<Q', header['transform_rounds'])[0]
transformed_key = key_composite
for _ in range(0, rounds):
    transformed_key = context.cipher.encrypt(transformed_key)

# combine the transformed key with the header master seed to find the master_key
transformed_key = hashlib.sha256(transformed_key).digest()
master_key = hashlib.sha256(bytes(header['master_seed']) + transformed_key).digest()

# set up a context for AES128-CBC decryption to find the decrypted payload
context = Context()
cipher = Cipher(b'AES', u'CBC')
context.cipher = cipher
context.key = master_key
context.iv = bytes(header['encryption_iv'])
raw_payload_area = context.cipher.decrypt(bytes(encrypted_payload))

# verify decryption
if header['stream_start_bytes'] != raw_payload_area[:len(header['stream_start_bytes'])]:
    raise IOError('Decryption failed')

# remove stream start bytes
offset = len(header['stream_start_bytes'])
payload_data = b''

# read payload block data, block by block
while True:
    # read index of block (4 bytes)
    block_index = struct.unpack('<I', raw_payload_area[offset:offset + 4])[0]
    print('read block_index %d' % block_index)
    # read block_data sha256 hash (32 bytes)
    block_hash = raw_payload_area[offset + 4:offset + 36]
    # read block_data length (4 bytes)
    block_length = struct.unpack('<I', raw_payload_area[offset + 36:offset + 40])[0]
    # read block_data
    block_data = raw_payload_area[offset + 40:offset + 40 + block_length]

    # check if last block
    if block_hash == b'\x00' * 32 and block_length == 0:
        break

    # verify block validity
    if block_hash != hashlib.sha256(block_data).digest():
        raise IOError('Block hash verification failed')

    # append verified block_data and move to next block
    payload_data += block_data
    offset += 40 + block_length

# check if payload_data is compressed
if struct.unpack('<I', header['compression_flags']):
    # decompress using gzip
    xml_data = zlib.decompress(payload_data, 16 + 15)
else:
    xml_data = payload_data

print("got xml_data: %s" % xml_data)

