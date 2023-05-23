# coding:utf-8
import binascii
import hashlib
import os

from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
from Crypto.Util.number import bytes_to_long

from modules.huaweiapi.obs import const, util


class CipherGenerator(object):
    def __init__(self, need_sha256=False):
        self.need_sha256 = need_sha256
        self.crypto_mod = "CipherGenerator"
        self.master_key_sha256 = ""

    def new(self, readable):
        pass

    @staticmethod
    def gen_random_key(key_length):
        return os.urandom(key_length)

    def get_crypto_info_from_headers(self, header_dict):
        key_list = [i for i in header_dict.keys()]
        for key in key_list:
            if key.startswith("x-obs-meta"):
                header_dict[key.replace("x-obs-meta-", "")] = header_dict.pop(key)
        key_list = [i for i in header_dict.keys()]
        for key in key_list:
            if key.startswith("x-amz-meta"):
                header_dict[key.replace("x-amz-meta-", "")] = header_dict.pop(key)
        if "encrypted-algorithm" not in header_dict:
            raise Exception("Crypto mod is not in object's metadata")
        header_dict["crypto_mod"] = header_dict.pop("encrypted-algorithm")
        if header_dict["crypto_mod"] != self.crypto_mod:
            raise Exception("Object's crypto mod is not equals cipher-generator's, "
                            "please change a different cipher-generator")
        return header_dict

    def check_record(self, record, crypto_info):
        return record["crypto_mod"] == crypto_info["crypto_mod"] \
               and record["master_key_sha256"] == self.master_key_sha256


class OBSCipher(object):
    def __init__(self, readable, is_decrypt=False, need_sha256=False):
        self._file = readable
        self.sha256 = hashlib.sha256()
        self.encrypted_sha256 = hashlib.sha256()
        self.crypto_mod = "EncryptedObject"
        self.is_decrypt = is_decrypt
        self.read_count = 0
        self.need_sha256 = need_sha256
        if self.is_decrypt:
            self.read = self.decrypt
            self.original_response = self._file
            self.status = self.original_response.status
            self.reason = self.original_response.reason
        else:
            self.read = self.encrypt
            self.original_response = None
            self.status = None
            self.reason = None

    def decrypt(self, n=const.READ_ONCE_LENGTH):
        pass

    def encrypt(self, n=const.READ_ONCE_LENGTH):
        pass

    def gen_need_metadata_and_headers(self, metadata, headers=None):
        if self.need_sha256:
            metadata["plaintext-sha256"], metadata["encrypted-sha256"], metadata[
                "plaintext-content-length"] = self.calculate_sha256()
            if headers is not None:
                headers.sha256 = metadata["encrypted-sha256"]
        metadata["encrypted-algorithm"] = self.crypto_mod
        return metadata

    def calculate_sha256(self, read_length=None):
        return self.sha256.hexdigest(), self.encrypted_sha256.hexdigest(), self.read_count

    def get_content_length(self):
        current_pointer = self._file.tell()
        self._file.seek(0, 2)
        total_length = self._file.tell()
        self._file.seek(current_pointer)
        return total_length

    def getheader(self, key, default_value=None):
        if not self.is_decrypt:
            return None
        return self.original_response.getheader(key, default_value)

    def getheaders(self):
        if not self.is_decrypt:
            return None
        return self.original_response.getheaders()

    def gen_need_record(self, record):
        record["crypto_mod"] = self.crypto_mod
        return record

    def crypto_info(self):
        return self.safe_crypto_info()

    def safe_crypto_info(self):
        return {"crypto_mod": self.crypto_mod}

    def close(self):
        if hasattr(self._file, 'close') and callable(self._file.close):
            self._file.close()

    def __str__(self):
        return "EncryptedObject"


class CTRCipherGenerator(CipherGenerator):
    def __init__(self, crypto_key, master_key_info=None, crypto_iv=None, *args, **kwargs):
        super(CTRCipherGenerator, self).__init__(*args, **kwargs)
        self.crypto_key = util.covert_string_to_bytes(crypto_key)
        self.crypto_iv = util.covert_string_to_bytes(crypto_iv)
        self.crypto_mod = "AES256-Ctr/iv_base64/NoPadding"
        self.master_key_sha256 = hashlib.sha256(self.crypto_key).hexdigest()
        self.master_key_info = "" if master_key_info is None else master_key_info

    def new(self, readable, is_decrypt=False, crypto_info=None):
        if crypto_info is not None:
            iv = binascii.a2b_base64(crypto_info["crypto_iv"])
            return OBSCtrCipher(readable, self.crypto_key, self.master_key_info, self.master_key_sha256,
                                iv, is_decrypt, self.need_sha256)
        if self.crypto_iv is None:
            return OBSCtrCipher(readable, self.crypto_key, self.master_key_info, self.master_key_sha256,
                                self.gen_random_key(16), is_decrypt, self.need_sha256)
        return OBSCtrCipher(readable, self.crypto_key, self.master_key_info, self.master_key_sha256,
                            self.crypto_iv, is_decrypt, self.need_sha256)

    def get_crypto_info_from_headers(self, header_dict):
        header_dict = super(CTRCipherGenerator, self).get_crypto_info_from_headers(header_dict)
        if "encrypted-start" not in header_dict:
            raise Exception("Encryption info is not in metadata")
        header_dict["crypto_iv"] = header_dict.pop("encrypted-start")
        if self.crypto_iv is not None and header_dict["crypto_iv"] != self.crypto_iv:
            raise Exception("Crypto_iv is different between local and server")
        if "master-key-info" in header_dict:
            header_dict["master_key_info"] = header_dict.pop("master-key-info")
        return header_dict

    def check_download_record(self, record, crypto_info):
        return super(CTRCipherGenerator, self).check_record(record, crypto_info) \
               and record["master_key_sha256"] == crypto_info["master_key_sha256"] \
               and record["crypto_iv"] == crypto_info["crypto_iv"]

    def check_upload_record(self, record, crypto_info):
        is_iv_match = binascii.a2b_base64(record["crypto_iv"]) == self.crypto_iv if self.crypto_iv else True
        return super(CTRCipherGenerator, self).check_record(record, crypto_info) \
               and is_iv_match \
               and record["master_key_info"] == crypto_info["master_key_info"] \
               and record["master_key_sha256"] == crypto_info["master_key_sha256"]


class OBSCtrCipher(OBSCipher):
    def __init__(self, readable, crypto_key, master_key_info, master_key_sha256,
                 crypto_iv=None, is_decrypt=False, need_sha256=False):
        super(OBSCtrCipher, self).__init__(readable, is_decrypt, need_sha256)
        self.master_key_sha256 = master_key_sha256
        ctr = Counter.new(128, initial_value=bytes_to_long(crypto_iv))
        self.crypto_iv = crypto_iv
        self.crypto_mod = "AES256-Ctr/iv_base64/NoPadding"
        if (const.IS_PYTHON2 and isinstance(crypto_key, unicode)) \
                or (not const.IS_PYTHON2 and isinstance(crypto_key, str)):
            crypto_key = crypto_key.encode("UTF-8")
        self.crypto_key = crypto_key
        self.master_key_info = master_key_info
        self.aes = AES.new(crypto_key, mode=AES.MODE_CTR, counter=ctr)

    def encrypt(self, n=const.READ_ONCE_LENGTH):
        chunk = self._file.read(n)
        if not isinstance(chunk, bytes):
            # todo 这个说明是否合适
            raise Exception("Only support bytes for encrypt, please open your stream with 'rb' mode")
        encrypted_chunk = self.aes.encrypt(chunk)
        return encrypted_chunk

    def decrypt(self, n=const.READ_ONCE_LENGTH):
        return self.aes.decrypt(self.original_response.read(n))

    def gen_need_metadata_and_headers(self, metadata, headers=None):
        metadata["encrypted-start"] = binascii.b2a_base64(self.crypto_iv).strip().decode("UTF-8")
        metadata["master-key-info"] = self.master_key_info
        return super(OBSCtrCipher, self).gen_need_metadata_and_headers(metadata, headers)

    def calculate_sha256(self, total_read_length=None):
        current_pointer = self._file.tell()
        current_read_length = 0
        while True:
            if total_read_length is not None and total_read_length - current_read_length > const.READ_ONCE_LENGTH:
                read_size = total_read_length - current_read_length
            else:
                read_size = const.READ_ONCE_LENGTH
            chunk = self._file.read(read_size)
            if not chunk or (total_read_length is not None and current_read_length == total_read_length):
                self.seek(current_pointer)
                return self.sha256.hexdigest(), self.encrypted_sha256.hexdigest(), self.read_count
            if not isinstance(chunk, bytes):
                # todo 这个说明是否合适
                raise Exception("Only support bytes for encrypt, please open your stream with 'rb' mode")
            self.sha256.update(chunk)
            encrypted_chunk = self.aes.encrypt(chunk)
            self.encrypted_sha256.update(encrypted_chunk)
            self.read_count += len(chunk)
            current_read_length += read_size

    def seek(self, offset, whence=0):
        if whence == 1:
            current_pointer = self._file.tell()
        elif whence == 2:
            self._file.seek(0, 2)
            current_pointer = self._file.tell()
        else:
            current_pointer = 0
        self.seek_iv(offset + current_pointer)
        self._file.seek(offset + current_pointer)

    def seek_iv(self, offset):
        now_iv = bytes_to_long(self.crypto_iv) + int(offset / 16)
        new_ctr = Counter.new(128, initial_value=now_iv)
        self.aes = AES.new(self.crypto_key, mode=AES.MODE_CTR, counter=new_ctr)
        if self.is_decrypt:
            self.aes.decrypt(b"1" * (offset % 16))
        else:
            self.aes.encrypt(b"1" * (offset % 16))

    def gen_need_record(self, record):
        record["crypto_iv"] = binascii.b2a_base64(self.crypto_iv).strip().decode("UTF-8")
        record["master_key_info"] = self.master_key_info
        record["master_key_sha256"] = self.master_key_sha256
        return super(OBSCtrCipher, self).gen_need_record(record)

    def safe_crypto_info(self):
        crypto_info = super(OBSCtrCipher, self).safe_crypto_info()
        crypto_info["crypto_iv"] = binascii.b2a_base64(self.crypto_iv).strip().decode("UTF-8")
        crypto_info["master_key_info"] = self.master_key_info
        crypto_info["master_key_sha256"] = self.master_key_sha256
        return crypto_info

    def __str__(self):
        return "OBSCtrCipher Encrypted Object start at " + binascii.b2a_base64(self.crypto_iv).strip().decode("UTF-8")


class CtrRSACipherGenerator(CipherGenerator):
    def __init__(self, master_crypto_key_path, master_key_info=None, *args, **kwargs):
        super(CtrRSACipherGenerator, self).__init__(*args, **kwargs)
        with open(master_crypto_key_path, "rb") as f:
            key = f.read()
            self.master_key_sha256 = hashlib.sha256(key).hexdigest()
            self.master_crypto_key = RSA.importKey(key)
        self.rsa = PKCS1_v1_5.new(self.master_crypto_key)
        self.crypto_mod = "AES256-Ctr/RSA-Object-Key/NoPadding"
        self.master_key_info = "" if master_key_info is None else master_key_info

    def new(self, readable, is_decrypt=False, crypto_info=None):
        if crypto_info is not None:
            iv = binascii.a2b_base64(crypto_info["crypto_iv"])
            if "object_encryption_key" in crypto_info:
                object_encryption_key = binascii.a2b_base64(crypto_info["object_encryption_key"])
            else:
                object_encryption_key = self.decrypt_object_encryption_key(crypto_info["encrypted_object_key"])
                if object_encryption_key == 0:
                    raise Exception("Wrong private key, could not decrypt object encryption key")
            return OBSCtrRSACipher(readable, object_encryption_key, crypto_info["encrypted_object_key"],
                                   self.master_key_info, self.master_key_sha256, iv, is_decrypt, self.need_sha256)
        random_key = self.gen_random_key(32)
        random_iv = self.gen_random_key(16)
        return OBSCtrRSACipher(readable, random_key, self.encrypt_object_encryption_key(random_key),
                               self.master_key_info,
                               self.master_key_sha256, random_iv, is_decrypt, self.need_sha256)

    def encrypt_object_encryption_key(self, key_str):
        return binascii.b2a_base64(self.rsa.encrypt(key_str)).strip().decode("UTF-8")

    def decrypt_object_encryption_key(self, key_str):
        return self.rsa.decrypt(binascii.a2b_base64(key_str), 0)

    def get_crypto_info_from_headers(self, header_dict):
        header_dict = super(CtrRSACipherGenerator, self).get_crypto_info_from_headers(header_dict)
        if "encrypted-object-key" not in header_dict:
            raise Exception("Encryption info is not in metadata")
        header_dict["encrypted_object_key"] = header_dict.pop("encrypted-object-key")
        header_dict["crypto_iv"] = header_dict.pop("encrypted-start")
        if "master-key-info" in header_dict:
            header_dict["master_key_info"] = header_dict.pop("master-key-info")
        return header_dict

    def check_download_record(self, record, crypto_info):
        return super(CtrRSACipherGenerator, self).check_record(record, crypto_info) \
               and record["master_key_sha256"] == crypto_info["master_key_sha256"] \
               and record["crypto_iv"] == crypto_info["crypto_iv"] \
               and record["encrypted_object_key"] == crypto_info["encrypted_object_key"]

    def check_upload_record(self, record, crypto_info):
        return super(CtrRSACipherGenerator, self).check_record(record, crypto_info) \
               and record["master_key_info"] == crypto_info["master_key_info"] \
               and record["master_key_sha256"] == crypto_info["master_key_sha256"]


class OBSCtrRSACipher(OBSCtrCipher):
    def __init__(self, readable, crypto_key, encrypted_object_key, master_key_info, master_key_sha256,
                 crypto_iv=None, is_decrypt=False, need_sha256=False):
        super(OBSCtrRSACipher, self).__init__(readable, crypto_key, master_key_info, master_key_sha256, crypto_iv,
                                              is_decrypt, need_sha256)
        self.encrypted_object_key = encrypted_object_key
        self.crypto_mod = "AES256-Ctr/RSA-Object-Key/NoPadding"
        self.master_key_info = master_key_info

    def gen_need_metadata_and_headers(self, metadata, headers=None):
        metadata["encrypted-object-key"] = self.encrypted_object_key
        return super(OBSCtrRSACipher, self).gen_need_metadata_and_headers(metadata, headers)

    def gen_need_record(self, record):
        record["encrypted_object_key"] = self.encrypted_object_key
        record["master_key_sha256"] = self.master_key_sha256
        record["object_encryption_key"] = binascii.b2a_base64(self.crypto_key).strip().decode("UTF-8")
        return super(OBSCtrRSACipher, self).gen_need_record(record)

    def crypto_info(self):
        crypto_info = self.safe_crypto_info()
        crypto_info["object_encryption_key"] = binascii.b2a_base64(self.crypto_key).strip().decode("UTF-8")
        return crypto_info

    def safe_crypto_info(self):
        crypto_info = super(OBSCtrRSACipher, self).safe_crypto_info()
        crypto_info["encrypted_object_key"] = self.encrypted_object_key
        crypto_info["master_key_info"] = self.master_key_info
        crypto_info["master_key_sha256"] = self.master_key_sha256
        return crypto_info

    def __str__(self):
        return "OBSCtrRSACipher Encrypted Object start at " \
               + binascii.b2a_base64(self.crypto_iv).strip().decode("UTF-8")
