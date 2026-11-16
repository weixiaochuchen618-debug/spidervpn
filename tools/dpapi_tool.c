/*
 * 独立的 DPAPI 信封工具：只给 tests/fixtures/pairing 的夹具生成器用。
 *
 * 存在理由：PowerShell 5.1 跑在 .NET Framework 上，System.Security.dll 不在默认
 * 加载集里，而本机策略禁止 Add-Type / Assembly.Load，所以拿不到
 * [System.Security.Cryptography.ProtectedData]。这里直接调 Win32 的
 * CryptProtectData / CryptUnprotectData —— 与 Rust 侧完全无关的另一份实现，
 * 正好当交叉验证的「对端」。
 *
 * 编译（mingw-w64）：
 *   gcc -O2 -o dpapi_tool.exe dpapi_tool.c -lcrypt32
 *
 * 用法：
 *   dpapi_tool.exe protect   <entropy_file> <plain_file> <out_b64_file>
 *   dpapi_tool.exe unprotect <entropy_file> <b64_file>   <out_plain_file>
 *
 * 失败时返回非 0，并在 stderr 打印 GetLastError。
 */

#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int read_file(const char *path, BYTE **data, DWORD *len) {
    FILE *file = fopen(path, "rb");
    long size;
    BYTE *buffer;

    if (file == NULL) {
        fprintf(stderr, "open %s failed\n", path);
        return 0;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return 0;
    }
    size = ftell(file);
    if (size < 0) {
        fclose(file);
        return 0;
    }
    rewind(file);
    buffer = (BYTE *)malloc((size_t)size + 1);
    if (buffer == NULL) {
        fclose(file);
        return 0;
    }
    if (size > 0 && fread(buffer, 1, (size_t)size, file) != (size_t)size) {
        free(buffer);
        fclose(file);
        return 0;
    }
    fclose(file);
    *data = buffer;
    *len = (DWORD)size;
    return 1;
}

static int write_file(const char *path, const BYTE *data, DWORD len) {
    FILE *file = fopen(path, "wb");
    int ok;

    if (file == NULL) {
        fprintf(stderr, "create %s failed\n", path);
        return 0;
    }
    ok = (len == 0) || (fwrite(data, 1, len, file) == len);
    if (fclose(file) != 0) {
        ok = 0;
    }
    return ok;
}

static int to_base64(const BYTE *data, DWORD len, char **text) {
    DWORD chars = 0;
    char *buffer;

    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &chars)) {
        return 0;
    }
    buffer = (char *)malloc((size_t)chars + 1);
    if (buffer == NULL) {
        return 0;
    }
    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, buffer, &chars)) {
        free(buffer);
        return 0;
    }
    *text = buffer;
    return 1;
}

static int from_base64(const char *text, DWORD text_len, BYTE **data, DWORD *len) {
    DWORD bytes = 0;
    BYTE *buffer;

    if (!CryptStringToBinaryA(text, text_len, CRYPT_STRING_BASE64, NULL, &bytes, NULL, NULL)) {
        return 0;
    }
    buffer = (BYTE *)malloc(bytes == 0 ? 1 : bytes);
    if (buffer == NULL) {
        return 0;
    }
    if (!CryptStringToBinaryA(text, text_len, CRYPT_STRING_BASE64, buffer, &bytes, NULL, NULL)) {
        free(buffer);
        return 0;
    }
    *data = buffer;
    *len = bytes;
    return 1;
}

int main(int argc, char **argv) {
    BYTE *entropy_bytes = NULL;
    BYTE *input_bytes = NULL;
    DWORD entropy_len = 0;
    DWORD input_len = 0;
    DATA_BLOB entropy_blob;
    DATA_BLOB input_blob;
    DATA_BLOB output_blob;
    int ok = 0;

    if (argc != 5) {
        fprintf(stderr,
                "usage:\n"
                "  dpapi_tool.exe protect   <entropy_file> <plain_file> <out_b64_file>\n"
                "  dpapi_tool.exe unprotect <entropy_file> <b64_file>   <out_plain_file>\n");
        return 2;
    }
    if (!read_file(argv[2], &entropy_bytes, &entropy_len) || !read_file(argv[3], &input_bytes, &input_len)) {
        free(entropy_bytes);
        free(input_bytes);
        return 3;
    }
    entropy_blob.cbData = entropy_len;
    entropy_blob.pbData = entropy_bytes;
    input_blob.cbData = input_len;
    input_blob.pbData = input_bytes;
    output_blob.cbData = 0;
    output_blob.pbData = NULL;

    if (strcmp(argv[1], "protect") == 0) {
        char *text = NULL;
        if (!CryptProtectData(&input_blob, NULL, &entropy_blob, NULL, NULL,
                              CRYPTPROTECT_UI_FORBIDDEN, &output_blob)) {
            fprintf(stderr, "CryptProtectData failed: %lu\n", (unsigned long)GetLastError());
        } else if (!to_base64(output_blob.pbData, output_blob.cbData, &text)) {
            fprintf(stderr, "base64 encode failed: %lu\n", (unsigned long)GetLastError());
        } else if (!write_file(argv[4], (const BYTE *)text, (DWORD)strlen(text))) {
            fprintf(stderr, "write %s failed\n", argv[4]);
        } else {
            ok = 1;
        }
        if (text != NULL) {
            SecureZeroMemory(text, strlen(text));
            free(text);
        }
    } else if (strcmp(argv[1], "unprotect") == 0) {
        BYTE *cipher = NULL;
        DWORD cipher_len = 0;
        if (!from_base64((const char *)input_bytes, input_len, &cipher, &cipher_len)) {
            fprintf(stderr, "base64 decode failed: %lu\n", (unsigned long)GetLastError());
        } else {
            DATA_BLOB cipher_blob;
            cipher_blob.cbData = cipher_len;
            cipher_blob.pbData = cipher;
            if (!CryptUnprotectData(&cipher_blob, NULL, &entropy_blob, NULL, NULL,
                                    CRYPTPROTECT_UI_FORBIDDEN, &output_blob)) {
                fprintf(stderr, "CryptUnprotectData failed: %lu\n", (unsigned long)GetLastError());
            } else if (!write_file(argv[4], output_blob.pbData, output_blob.cbData)) {
                fprintf(stderr, "write %s failed\n", argv[4]);
            } else {
                ok = 1;
            }
            SecureZeroMemory(cipher, cipher_len);
            free(cipher);
        }
    } else {
        fprintf(stderr, "unknown command: %s\n", argv[1]);
    }

    if (output_blob.pbData != NULL) {
        SecureZeroMemory(output_blob.pbData, output_blob.cbData);
        LocalFree(output_blob.pbData);
    }
    if (input_bytes != NULL) {
        SecureZeroMemory(input_bytes, input_len);
        free(input_bytes);
    }
    free(entropy_bytes);
    return ok ? 0 : 1;
}
