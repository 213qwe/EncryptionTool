#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE

//需要导入OpenSSL等依赖库

#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

// OpenSSL 头文件
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bn.h>

#pragma warning(disable:4996)
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "comdlg32.lib")
// Link libcrypto.lib and Crypt32.lib from project settings.

enum {
    IDC_ALGO_COMBO = 5001,
    IDC_HASH_COMBO,
    IDC_INPUT_EDIT,
    IDC_OUTPUT_EDIT,
    IDC_KEY_EDIT,
    IDC_BROWSE_BTN,
    IDC_BROWSE_FileBTN,
    IDC_FILEPATH_EDIT,
    IDC_FILEPATH_EDIT2,
    IDC_RSA_PRIV_EDIT,
    IDC_RSA_PUB_EDIT,
    IDC_SAVE_PRIV_BTN,
    IDC_SAVE_PUB_BTN,
    IDC_LOAD_PRIV_BTN,
    IDC_LOAD_PUB_BTN,

    // 文件模式控件ID
    IDC_ALGO_COMBO_FILE = 5101,
    IDC_HASH_COMBO_FILE,
    IDC_KEY_EDIT_FILE,

    // 文件模式新按钮
    IDM_SEND_FILE = 4001,
    IDM_RECEIVE_FILE,

    // 字符串模式操作
    IDM_GEN_RSA = 1001,
    IDM_SEND = 3001,
    IDM_RECEIVE = 3002,
    IDC_P_EDIT = 5200,
    IDC_Q_EDIT,
    IDC_FILE_P_EDIT,
    IDC_FILE_Q_EDIT
};

static HINSTANCE hInst;
static HWND hMainWnd;
static HWND hTab;
static HWND hAlgoCombo, hHashCombo;
static HWND hInputEdit, hOutputEdit, hKeyEdit;
static HWND hFilePathEdit, hBrowseBtn;
static HWND hFilePathEdit2, hBrowseBtn2;
static HWND hGenerateBtn, hRSAPrvEdit, hRSAPubEdit, hSymKeyBtn;
static HWND hSavePrivBtn, hSavePubBtn, hLoadPrivBtn, hLoadPubBtn;
static HWND hKeyLabel;

// File Mode 控件
static HWND hFileAlgoCombo, hFileHashCombo;
static HWND hFileKeyEdit;
static HWND hFilePrivLabel, hFilePubLabel;
static HWND hFileRSAPrvEdit, hFileRSAPubEdit;
static HWND hFileGenerateBtn, hFileLoadPubBtn, hFileLoadPrivBtn;
static HWND hFileSavePubBtn, hFileSavePrivBtn;
static HWND hFileSendBtn, hFileReceiveBtn;  // 新增按钮
static HWND hPEdit, hQEdit, hFilePEdit, hFileQEdit;

// 存储不同Tab页的控件句柄
static HWND hStringControls[40];
static HWND hFileControls[40];
static int nStringControls = 0;
static int nFileControls = 0;
static unsigned char g_generated_sym_key[32];  // 存储生成的对称密钥
static int g_sym_key_generated = 0;// 添加一个全局标志来跟踪密钥是否已生成

// Two RSA slots: own (private) and peer (other side's public)
static RSA* g_own_rsa = NULL;   // private+public of "me" (used for signing and for decrypting when acting as receiver)
static RSA* g_peer_rsa = NULL;  // public key of communication peer (used for encrypting symmetric key when sending, and verifying signature when receiving)

static unsigned char g_sym_key[32];
static unsigned char g_sym_iv[16];

// 在全局变量部分添加窗口大小相关变量
static int g_windowWidth = 850;
static int g_windowHeight = 700;

void append_output(const char* fmt, ...) {
    char buf[8192];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    int len = GetWindowTextLengthA(hOutputEdit);
    SendMessageA(hOutputEdit, EM_SETSEL, (WPARAM)len, (LPARAM)len);
    SendMessageA(hOutputEdit, EM_REPLACESEL, 0, (LPARAM)buf);
}

// ==================== 实现的 DES 算法 ====================
// DES 置换表（与标准一致）
static const int IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const int FP[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
};

static const int PC1[56] = {
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4
};

static const int PC2[48] = {
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const int SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const int E[48] = {
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
};

static const int P[32] = {
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25
};

static const int S[8][4][16] = {
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

// 将 8 字节数组转换为 64 位整数（大端序）
static uint64_t bytes_to_uint64_be(const unsigned char* bytes) {
    uint64_t result = 0;
    int i;
    for (i = 0; i < 8; i++) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

// 将 64 位整数转换为 8 字节数组（大端序）
static void uint64_to_bytes_be(uint64_t value, unsigned char* bytes) {
    int i;
    for (i = 0; i < 8; i++) {
        bytes[i] = (value >> (56 - 8 * i)) & 0xFF;
    }
}

// 置换函数 - 使用位操作
static uint64_t permute_bits(uint64_t input, const int* table, int n) {
    uint64_t result = 0;
    int i;
    for (i = 0; i < n; i++) {
        int pos = table[i] - 1;
        if (input & (1ULL << (63 - pos))) {
            result |= (1ULL << (n - 1 - i));
        }
    }
    return result;
}

// 生成子密钥
static void generate_subkeys_simple(uint64_t key, uint64_t* subkeys) {
    // PC1 置换 (64位 -> 56位)
    uint64_t pc1 = permute_bits(key, PC1, 56);

    uint32_t left = (pc1 >> 28) & 0x0FFFFFFF;
    uint32_t right = pc1 & 0x0FFFFFFF;

    int i;
    for (i = 0; i < 16; i++) {
        // 循环左移
        left = ((left << SHIFTS[i]) | (left >> (28 - SHIFTS[i]))) & 0x0FFFFFFF;
        right = ((right << SHIFTS[i]) | (right >> (28 - SHIFTS[i]))) & 0x0FFFFFFF;

        // 合并并 PC2 置换 (56位 -> 48位)
        uint64_t combined = ((uint64_t)left << 28) | right;
        subkeys[i] = permute_bits(combined, PC2, 48);
    }
}

// F 函数
static uint32_t f_function_simple(uint32_t right, uint64_t subkey) {
    // E 扩展 (32位 -> 48位)
    uint64_t expanded = permute_bits(right, E, 48);

    // 与子密钥异或
    expanded ^= subkey;

    // S盒替换
    uint32_t result = 0;
    int i;
    for (i = 0; i < 8; i++) {
        int block = (expanded >> (42 - 6 * i)) & 0x3F;
        int row = ((block & 0x20) >> 4) | (block & 0x01);
        int col = (block >> 1) & 0x0F;
        int s_val = S[i][row][col];
        result |= (s_val << (28 - 4 * i));
    }

    // P置换
    return permute_bits(result, P, 32);
}

// 完整的 DES 加密单个块
static void des_encrypt_block(const unsigned char* input, const unsigned char* key_bytes, unsigned char* output) {
    uint64_t key = bytes_to_uint64_be(key_bytes);
    uint64_t data = bytes_to_uint64_be(input);

    // 生成子密钥
    uint64_t subkeys[16];
    generate_subkeys_simple(key, subkeys);

    // 初始置换 IP
    uint64_t permuted = permute_bits(data, IP, 64);

    uint32_t left = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t right = permuted & 0xFFFFFFFF;

    // 16轮 Feistel 网络
    int i;
    for (i = 0; i < 16; i++) {
        uint32_t temp = right;

        // F 函数
        uint32_t f_result = f_function_simple(right, subkeys[i]);

        // 左半部分与F函数结果异或
        right = left ^ f_result;
        left = temp;
    }

    // 最后交换左右部分
    uint64_t final_data = ((uint64_t)right << 32) | left;

    // 逆初始置换 FP
    uint64_t ciphertext = permute_bits(final_data, FP, 64);

    uint64_to_bytes_be(ciphertext, output);
}

// 完整的 DES 解密单个块
static void des_decrypt_block(const unsigned char* input, const unsigned char* key_bytes, unsigned char* output) {
    uint64_t key = bytes_to_uint64_be(key_bytes);
    uint64_t data = bytes_to_uint64_be(input);

    // 生成子密钥
    uint64_t subkeys[16];
    generate_subkeys_simple(key, subkeys);

    // 初始置换 IP
    uint64_t permuted = permute_bits(data, IP, 64);

    uint32_t left = (permuted >> 32) & 0xFFFFFFFF;
    uint32_t right = permuted & 0xFFFFFFFF;

    // 16轮 Feistel 网络（子密钥逆序使用）
    int i;
    for (i = 15; i >= 0; i--) {
        uint32_t temp = right;

        // F 函数
        uint32_t f_result = f_function_simple(right, subkeys[i]);

        // 左半部分与F函数结果异或
        right = left ^ f_result;
        left = temp;
    }

    // 最后交换左右部分
    uint64_t final_data = ((uint64_t)right << 32) | left;

    // 逆初始置换 FP
    uint64_t plaintext = permute_bits(final_data, FP, 64);

    uint64_to_bytes_be(plaintext, output);
}

// 完整的 DES CBC 加密
static int des_cbc_encrypt(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** out, int* out_len) {
    append_output("DES CBC Encrypt: plaintext_len=%d\n", plaintext_len);

    // 计算填充长度
    int pad_len = 8 - (plaintext_len % 8);
    if (pad_len == 0) pad_len = 8;
    int total_len = plaintext_len + pad_len;

    // 分配内存
    unsigned char* padded = (unsigned char*)malloc(total_len);
    if (!padded) return 0;

    // 复制数据并添加填充
    memcpy(padded, plaintext, plaintext_len);
    memset(padded + plaintext_len, pad_len, pad_len);

    unsigned char* ciphertext = (unsigned char*)malloc(total_len);
    if (!ciphertext) {
        free(padded);
        return 0;
    }

    unsigned char prev_block[8];
    memcpy(prev_block, iv, 8);

    int i;
    for (i = 0; i < total_len; i += 8) {
        unsigned char block[8];
        int j;

        // 与前一密文块异或
        for (j = 0; j < 8; j++) {
            block[j] = padded[i + j] ^ prev_block[j];
        }

        // 完整的 DES 加密
        des_encrypt_block(block, key, ciphertext + i);

        // 更新前一密文块
        memcpy(prev_block, ciphertext + i, 8);
    }

    free(padded);
    *out = ciphertext;
    *out_len = total_len;
    append_output("DES CBC Encrypt: success, total_len=%d\n", total_len);
    return 1;
}

// 完整的 DES CBC 解密
static int des_cbc_decrypt(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** out, int* out_len) {
    append_output("DES CBC Decrypt: ciphertext_len=%d\n", ciphertext_len);

    if (ciphertext_len % 8 != 0) {
        append_output("DES CBC Decrypt: ciphertext length not multiple of 8\n");
        return 0;
    }

    unsigned char* plaintext = (unsigned char*)malloc(ciphertext_len);
    if (!plaintext) {
        append_output("DES CBC Decrypt: memory allocation failed\n");
        return 0;
    }

    unsigned char prev_block[8];
    memcpy(prev_block, iv, 8);

    int i;
    for (i = 0; i < ciphertext_len; i += 8) {
        unsigned char block[8];

        // 完整的 DES 解密
        des_decrypt_block(ciphertext + i, key, block);

        // 与前一密文块异或
        int j;
        for (j = 0; j < 8; j++) {
            plaintext[i + j] = block[j] ^ prev_block[j];
        }

        // 更新前一密文块
        memcpy(prev_block, ciphertext + i, 8);
    }

    // 检查并去除填充
    int pad_byte = plaintext[ciphertext_len - 1];
    append_output("DES CBC Decrypt: padding byte=%d\n", pad_byte);

    if (pad_byte < 1 || pad_byte > 8) {
        append_output("DES CBC Decrypt: invalid padding byte\n");
        free(plaintext);
        return 0;
    }

    // 验证填充
    int valid_padding = 1;
    for (i = ciphertext_len - pad_byte; i < ciphertext_len; i++) {
        if (plaintext[i] != pad_byte) {
            valid_padding = 0;
            append_output("Padding mismatch at position %d: expected %d, got %d\n",
                i, pad_byte, plaintext[i]);
            break;
        }
    }

    if (!valid_padding) {
        append_output("DES CBC Decrypt: padding verification failed\n");
        free(plaintext);
        return 0;
    }

    int actual_len = ciphertext_len - pad_byte;
    unsigned char* result = (unsigned char*)malloc(actual_len);
    if (!result) {
        append_output("DES CBC Decrypt: result memory allocation failed\n");
        free(plaintext);
        return 0;
    }

    memcpy(result, plaintext, actual_len);
    free(plaintext);

    *out = result;
    *out_len = actual_len;
    append_output("DES CBC Decrypt: success, actual_len=%d\n", actual_len);
    return 1;
}

// ==================== AES 常量定义 ====================

// AES S盒
static const unsigned char aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// 逆S盒
static const unsigned char aes_inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// 轮常数
static const unsigned char rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// ==================== AES 核心函数 ====================
// 字节替换
static void sub_bytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_sbox[state[i]];
    }
}

// 逆行字节替换
static void inv_sub_bytes(unsigned char state[16]) {
    for (int i = 0; i < 16; i++) {
        state[i] = aes_inv_sbox[state[i]];
    }
}

// 行移位
static void shift_rows(unsigned char state[16]) {
    unsigned char temp;

    // 第1行左移1位
    temp = state[1];
    state[1] = state[5];
    state[5] = state[9];
    state[9] = state[13];
    state[13] = temp;

    // 第2行左移2位
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // 第3行左移3位
    temp = state[15];
    state[15] = state[11];
    state[11] = state[7];
    state[7] = state[3];
    state[3] = temp;
}

// 逆行移位
static void inv_shift_rows(unsigned char state[16]) {
    unsigned char temp;

    // 第1行右移1位
    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    // 第2行右移2位
    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    // 第3行右移3位
    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

// GF(2^8)乘法
static unsigned char gf_multiply(unsigned char a, unsigned char b) {
    unsigned char result = 0;
    unsigned char hi_bit;

    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            result ^= a;
        }
        hi_bit = a & 0x80;
        a <<= 1;
        if (hi_bit) {
            a ^= 0x1b;  // 模x^8 + x^4 + x^3 + x + 1
        }
        b >>= 1;
    }

    return result;
}

// 列混合
static void mix_columns(unsigned char state[16]) {
    unsigned char temp[16];
    int i;

    for (i = 0; i < 4; i++) {
        temp[4 * i + 0] = gf_multiply(0x02, state[4 * i + 0]) ^ gf_multiply(0x03, state[4 * i + 1]) ^ state[4 * i + 2] ^ state[4 * i + 3];
        temp[4 * i + 1] = state[4 * i + 0] ^ gf_multiply(0x02, state[4 * i + 1]) ^ gf_multiply(0x03, state[4 * i + 2]) ^ state[4 * i + 3];
        temp[4 * i + 2] = state[4 * i + 0] ^ state[4 * i + 1] ^ gf_multiply(0x02, state[4 * i + 2]) ^ gf_multiply(0x03, state[4 * i + 3]);
        temp[4 * i + 3] = gf_multiply(0x03, state[4 * i + 0]) ^ state[4 * i + 1] ^ state[4 * i + 2] ^ gf_multiply(0x02, state[4 * i + 3]);
    }

    memcpy(state, temp, 16);
}

// 逆列混合
static void inv_mix_columns(unsigned char state[16]) {
    unsigned char temp[16];
    int i;

    for (i = 0; i < 4; i++) {
        temp[4 * i + 0] = gf_multiply(0x0e, state[4 * i + 0]) ^ gf_multiply(0x0b, state[4 * i + 1]) ^ gf_multiply(0x0d, state[4 * i + 2]) ^ gf_multiply(0x09, state[4 * i + 3]);
        temp[4 * i + 1] = gf_multiply(0x09, state[4 * i + 0]) ^ gf_multiply(0x0e, state[4 * i + 1]) ^ gf_multiply(0x0b, state[4 * i + 2]) ^ gf_multiply(0x0d, state[4 * i + 3]);
        temp[4 * i + 2] = gf_multiply(0x0d, state[4 * i + 0]) ^ gf_multiply(0x09, state[4 * i + 1]) ^ gf_multiply(0x0e, state[4 * i + 2]) ^ gf_multiply(0x0b, state[4 * i + 3]);
        temp[4 * i + 3] = gf_multiply(0x0b, state[4 * i + 0]) ^ gf_multiply(0x0d, state[4 * i + 1]) ^ gf_multiply(0x09, state[4 * i + 2]) ^ gf_multiply(0x0e, state[4 * i + 3]);
    }

    memcpy(state, temp, 16);
}

// 轮密钥加
static void add_round_key(unsigned char state[16], const unsigned char* round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

// 密钥扩展
static void key_expansion(const unsigned char* key, unsigned char* round_keys) {
    unsigned char temp[4];
    int i, j;

    // 复制初始密钥
    memcpy(round_keys, key, 32);

    // 生成扩展密钥
    for (i = 8; i < 60; i++) {
        // 复制前一个word
        memcpy(temp, round_keys + (i - 1) * 4, 4);

        if (i % 8 == 0) {
            // 字节循环移位
            unsigned char t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;

            // 字节替换
            for (j = 0; j < 4; j++) {
                temp[j] = aes_sbox[temp[j]];
            }

            // 与轮常数异或
            temp[0] ^= rcon[i / 8];
        }
        else if (i % 8 == 4) {
            // 字节替换
            for (j = 0; j < 4; j++) {
                temp[j] = aes_sbox[temp[j]];
            }
        }

        // 生成新的word
        for (j = 0; j < 4; j++) {
            round_keys[i * 4 + j] = round_keys[(i - 8) * 4 + j] ^ temp[j];
        }
    }
}

// ==================== AES 加密解密函数 ====================
// AES-256 加密单个块
static void aes_encrypt_block(const unsigned char* input, const unsigned char* key, unsigned char* output) {
    unsigned char state[16];
    unsigned char round_keys[240]; // 60 * 4 bytes for AES-256

    // 扩展密钥
    key_expansion(key, round_keys);

    // 复制输入到状态矩阵
    memcpy(state, input, 16);

    // 初始轮密钥加
    add_round_key(state, round_keys);

    // 前13轮
    for (int round = 1; round < 14; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys + round * 16);
    }

    // 最后一轮（无列混合）
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys + 14 * 16);

    // 复制结果到输出
    memcpy(output, state, 16);
}

// AES-256 解密单个块
static void aes_decrypt_block(const unsigned char* input, const unsigned char* key, unsigned char* output) {
    unsigned char state[16];
    unsigned char round_keys[240]; // 60 * 4 bytes for AES-256

    // 扩展密钥
    key_expansion(key, round_keys);

    // 复制输入到状态矩阵
    memcpy(state, input, 16);

    // 初始轮密钥加（使用最后一轮密钥）
    add_round_key(state, round_keys + 14 * 16);

    // 前13轮
    for (int round = 13; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, round_keys + round * 16);
        inv_mix_columns(state);
    }

    // 最后一轮（无逆列混合）
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, round_keys);

    // 复制结果到输出
    memcpy(output, state, 16);
}

// ==================== AES CBC 模式实现 ====================

// AES CBC 加密
static int aes_cbc_encrypt(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** out, int* out_len) {
    append_output("AES CBC Encrypt: plaintext_len=%d\n", plaintext_len);

    // 计算填充长度
    int pad_len = 16 - (plaintext_len % 16);
    if (pad_len == 0) pad_len = 16;
    int total_len = plaintext_len + pad_len;

    // 分配内存
    unsigned char* padded = (unsigned char*)malloc(total_len);
    if (!padded) return 0;

    // 复制数据并添加填充
    memcpy(padded, plaintext, plaintext_len);
    memset(padded + plaintext_len, pad_len, pad_len);

    unsigned char* ciphertext = (unsigned char*)malloc(total_len);
    if (!ciphertext) {
        free(padded);
        return 0;
    }

    unsigned char prev_block[16];
    memcpy(prev_block, iv, 16);

    int i;
    for (i = 0; i < total_len; i += 16) {
        unsigned char block[16];
        int j;

        // 与前一密文块异或
        for (j = 0; j < 16; j++) {
            block[j] = padded[i + j] ^ prev_block[j];
        }

        // AES 加密
        aes_encrypt_block(block, key, ciphertext + i);

        // 更新前一密文块
        memcpy(prev_block, ciphertext + i, 16);
    }

    free(padded);
    *out = ciphertext;
    *out_len = total_len;
    append_output("AES CBC Encrypt: success, total_len=%d\n", total_len);
    return 1;
}

// AES CBC 解密
static int aes_cbc_decrypt(const unsigned char* ciphertext, int ciphertext_len,
    const unsigned char* key, const unsigned char* iv,
    unsigned char** out, int* out_len) {
    append_output("AES CBC Decrypt: ciphertext_len=%d\n", ciphertext_len);

    if (ciphertext_len % 16 != 0) {
        append_output("AES CBC Decrypt: ciphertext length not multiple of 16\n");
        return 0;
    }

    unsigned char* plaintext = (unsigned char*)malloc(ciphertext_len);
    if (!plaintext) {
        append_output("AES CBC Decrypt: memory allocation failed\n");
        return 0;
    }

    unsigned char prev_block[16];
    memcpy(prev_block, iv, 16);

    int i;
    for (i = 0; i < ciphertext_len; i += 16) {
        unsigned char block[16];

        // AES 解密
        aes_decrypt_block(ciphertext + i, key, block);

        // 与前一密文块异或
        int j;
        for (j = 0; j < 16; j++) {
            plaintext[i + j] = block[j] ^ prev_block[j];
        }

        // 更新前一密文块
        memcpy(prev_block, ciphertext + i, 16);
    }

    // 检查并去除填充
    int pad_byte = plaintext[ciphertext_len - 1];
    append_output("AES CBC Decrypt: padding byte=%d\n", pad_byte);

    if (pad_byte < 1 || pad_byte > 16) {
        append_output("AES CBC Decrypt: invalid padding byte\n");
        free(plaintext);
        return 0;
    }

    // 验证填充
    int valid_padding = 1;
    for (i = ciphertext_len - pad_byte; i < ciphertext_len; i++) {
        if (plaintext[i] != pad_byte) {
            valid_padding = 0;
            append_output("Padding mismatch at position %d: expected %d, got %d\n",
                i, pad_byte, plaintext[i]);
            break;
        }
    }

    if (!valid_padding) {
        append_output("AES CBC Decrypt: padding verification failed\n");
        free(plaintext);
        return 0;
    }

    int actual_len = ciphertext_len - pad_byte;
    unsigned char* result = (unsigned char*)malloc(actual_len);
    if (!result) {
        append_output("AES CBC Decrypt: result memory allocation failed\n");
        free(plaintext);
        return 0;
    }

    memcpy(result, plaintext, actual_len);
    free(plaintext);

    *out = result;
    *out_len = actual_len;
    append_output("AES CBC Decrypt: success, actual_len=%d\n", actual_len);
    return 1;
}

// ==================== 对称加密/解密函数 ====================
int symmetric_encrypt(const unsigned char* plaintext, int plaintext_len,
    const unsigned char* key, const unsigned char* iv,
    const char* algo, unsigned char** out, int* out_len) {

    if (strcmp(algo, "DES") == 0) {
        // 使用完整的 DES 实现
        append_output("Using full DES implementation\n");
        return des_cbc_encrypt(plaintext, plaintext_len, key, iv, out, out_len);
    }
    else if (strcmp(algo, "AES") == 0) {
        // 使用完整的 AES 实现
        append_output("Using full AES implementation\n");
        return aes_cbc_encrypt(plaintext, plaintext_len, key, iv, out, out_len);
    }

    append_output("Unknown algorithm: %s\n", algo);
    return 0;
}

int symmetric_decrypt(const unsigned char* ciphertext, int cipher_len,
    const unsigned char* key, const unsigned char* iv,
    const char* algo, unsigned char** out, int* out_len) {

    if (strcmp(algo, "DES") == 0) {
        // 使用完整的 DES 实现
        append_output("Using full DES implementation\n");
        return des_cbc_decrypt(ciphertext, cipher_len, key, iv, out, out_len);
    }
    else if (strcmp(algo, "AES") == 0) {
        // 使用完整的 AES 实现
        append_output("Using full AES implementation\n");
        return aes_cbc_decrypt(ciphertext, cipher_len, key, iv, out, out_len);
    }

    append_output("Unknown algorithm: %s\n", algo);
    return 0;
}

void add_string_control(HWND hWnd) {
    if (nStringControls < 40) hStringControls[nStringControls++] = hWnd;
}
void add_file_control(HWND hWnd) {
    if (nFileControls < 40) hFileControls[nFileControls++] = hWnd;
}

void show_tab_controls(int tabIndex) {
    for (int i = 0; i < nStringControls; i++) {
        ShowWindow(hStringControls[i], SW_HIDE);
        EnableWindow(hStringControls[i], FALSE);
    }
    for (int i = 0; i < nFileControls; i++) {
        ShowWindow(hFileControls[i], SW_HIDE);
        EnableWindow(hFileControls[i], FALSE);
    }
    if (tabIndex == 0) {
        for (int i = 0; i < nStringControls; i++) {
            ShowWindow(hStringControls[i], SW_SHOW);
            EnableWindow(hStringControls[i], TRUE);
        }
    }
    else {
        for (int i = 0; i < nFileControls; i++) {
            ShowWindow(hFileControls[i], SW_SHOW);
            EnableWindow(hFileControls[i], TRUE);
        }
    }
    InvalidateRect(hTab, NULL, TRUE);
    UpdateWindow(hTab);
}

char* bin_to_hex(const unsigned char* bin, int len) {
    if (!bin || len <= 0) {
        char* s = (char*)malloc(1);
        if (s) s[0] = '\0';
        return s;
    }
    char* hex = (char*)malloc((size_t)len * 2 + 1);
    if (!hex) return NULL;
    for (int i = 0; i < len; ++i) {
        snprintf(hex + (size_t)i * 2, 3, "%02x", bin[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

unsigned char hexchar(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

unsigned char* hex_to_bin(const char* hex, int* out_len) {
    if (!hex) { *out_len = 0; return NULL; }
    int L = (int)strlen(hex);
    int n = L / 2;
    unsigned char* bin = (unsigned char*)malloc(n);
    if (!bin) { *out_len = 0; return NULL; }
    for (int i = 0; i < n; ++i) {
        bin[i] = (hexchar(hex[i * 2]) << 4) | hexchar(hex[i * 2 + 1]);
    }
    *out_len = n;
    return bin;
}

void show_openssl_errors() {
    unsigned long e;
    while ((e = ERR_get_error())) {
        char buf[256];
        ERR_error_string_n(e, buf, sizeof(buf));
        append_output("[OpenSSL] %s\n", buf);
    }
}

unsigned char* read_file_all(const char* path, size_t* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    unsigned char* buf = (unsigned char*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, sz, f);
    (void)r;
    buf[sz] = 0;
    fclose(f);
    *out_len = sz;
    return buf;
}

int write_file_all(const char* path, const unsigned char* buf, size_t len) {
    FILE* f = fopen(path, "wb");
    if (!f) return 0;
    fwrite(buf, 1, len, f);
    fclose(f);
    return 1;
}

// ==================== SHA-256 常量定义 ====================

// SHA-256 初始哈希值
static const uint32_t sha256_init_state[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// SHA-256 常量
static const uint32_t sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// ==================== SHA-256 辅助函数 ====================

// 右旋转
static uint32_t rotr(uint32_t x, int n) {
    return (x >> n) | (x << (32 - n));
}

// 右移位
static uint32_t shr(uint32_t x, int n) {
    return x >> n;
}

// SHA-256 逻辑函数
static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (~x & z);
}

static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

static uint32_t sigma0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

static uint32_t sigma1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

static uint32_t gamma0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ shr(x, 3);
}

static uint32_t gamma1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ shr(x, 10);
}

// 字节序转换（大端序）
static uint32_t bswap_32(uint32_t x) {
    return ((x & 0x000000FF) << 24) |
        ((x & 0x0000FF00) << 8) |
        ((x & 0x00FF0000) >> 8) |
        ((x & 0xFF000000) >> 24);
}

// ==================== SHA-256 核心实现 ====================

typedef struct {
    uint32_t state[8];
    uint64_t count;
    unsigned char buffer[64];
} sha256_ctx;

// SHA-256 初始化
static void sha256_init(sha256_ctx* ctx) {
    for (int i = 0; i < 8; i++) {
        ctx->state[i] = sha256_init_state[i];
    }
    ctx->count = 0;
}

// SHA-256 转换函数
static void sha256_transform(sha256_ctx* ctx, const unsigned char data[64]) {
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2;
    int i;

    // 将数据转换为32位字数组
    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4] << 24) |
            ((uint32_t)data[i * 4 + 1] << 16) |
            ((uint32_t)data[i * 4 + 2] << 8) |
            ((uint32_t)data[i * 4 + 3]);
    }

    // 扩展消息
    for (i = 16; i < 64; i++) {
        w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
    }

    // 初始化工作变量
    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    // 主循环
    for (i = 0; i < 64; i++) {
        t1 = h + sigma1(e) + ch(e, f, g) + sha256_k[i] + w[i];
        t2 = sigma0(a) + maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    // 更新状态
    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

// SHA-256 更新
static void sha256_update(sha256_ctx* ctx, const unsigned char* data, size_t len) {
    size_t i;
    size_t index = (size_t)(ctx->count & 63);
    size_t part_len = 64 - index;

    ctx->count += len;

    // 处理缓冲区中的数据
    if (len >= part_len) {
        memcpy(&ctx->buffer[index], data, part_len);
        sha256_transform(ctx, ctx->buffer);

        for (i = part_len; i + 63 < len; i += 64) {
            sha256_transform(ctx, &data[i]);
        }

        index = 0;
    }
    else {
        i = 0;
    }

    // 保存剩余数据
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

// SHA-256 结束
static void sha256_final(sha256_ctx* ctx, unsigned char digest[32]) {
    unsigned char bits[8];
    size_t index, pad_len;
    uint64_t bit_count = ctx->count * 8;

    // 保存位计数（大端序）
    for (int i = 0; i < 8; i++) {
        bits[i] = (unsigned char)((bit_count >> (56 - i * 8)) & 0xff);
    }

    // 添加填充：1位后跟0位，直到长度满足 mod 512 = 448
    index = (size_t)(ctx->count & 63);
    pad_len = (index < 56) ? (56 - index) : (120 - index);

    unsigned char padding[64];
    padding[0] = 0x80;
    for (size_t i = 1; i < pad_len; i++) {
        padding[i] = 0x00;
    }

    sha256_update(ctx, padding, pad_len);

    // 添加长度
    sha256_update(ctx, bits, 8);

    // 生成最终哈希值（大端序）
    for (int i = 0; i < 8; i++) {
        uint32_t state = ctx->state[i];
        digest[i * 4] = (unsigned char)(state >> 24);
        digest[i * 4 + 1] = (unsigned char)(state >> 16);
        digest[i * 4 + 2] = (unsigned char)(state >> 8);
        digest[i * 4 + 3] = (unsigned char)state;
    }
}

// ==================== MD5 自实现 ====================

// MD5 初始哈希值
static const uint32_t md5_init_state[4] = {
    0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
};

// MD5 常量
static const uint32_t md5_k[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

// MD5 移位量
static const int md5_s[64] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

typedef struct {
    uint32_t state[4];
    uint64_t count;
    unsigned char buffer[64];
} md5_ctx;

// MD5 辅助函数
static uint32_t md5_f(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
static uint32_t md5_g(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
static uint32_t md5_h(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
static uint32_t md5_i(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

static uint32_t md5_rotate_left(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

// MD5 初始化
static void md5_init(md5_ctx* ctx) {
    ctx->count = 0;
    for (int i = 0; i < 4; i++) {
        ctx->state[i] = md5_init_state[i];
    }
}

// MD5 转换
static void md5_transform(md5_ctx* ctx, const unsigned char block[64]) {
    uint32_t a = ctx->state[0], b = ctx->state[1], c = ctx->state[2], d = ctx->state[3];
    uint32_t x[16];

    // 将块转换为16个32位字
    for (int i = 0; i < 16; i++) {
        x[i] = (uint32_t)block[i * 4] |
            ((uint32_t)block[i * 4 + 1] << 8) |
            ((uint32_t)block[i * 4 + 2] << 16) |
            ((uint32_t)block[i * 4 + 3] << 24);
    }

    // 四轮主循环
    for (int i = 0; i < 64; i++) {
        uint32_t f, g;

        if (i < 16) {
            f = md5_f(b, c, d);
            g = i;
        }
        else if (i < 32) {
            f = md5_g(b, c, d);
            g = (5 * i + 1) % 16;
        }
        else if (i < 48) {
            f = md5_h(b, c, d);
            g = (3 * i + 5) % 16;
        }
        else {
            f = md5_i(b, c, d);
            g = (7 * i) % 16;
        }

        f = f + a + md5_k[i] + x[g];
        a = d;
        d = c;
        c = b;
        b = b + md5_rotate_left(f, md5_s[i]);
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

// MD5 更新
static void md5_update(md5_ctx* ctx, const unsigned char* data, size_t len) {
    size_t index = (size_t)(ctx->count & 63);
    size_t part_len = 64 - index;

    ctx->count += len;

    if (len >= part_len) {
        memcpy(&ctx->buffer[index], data, part_len);
        md5_transform(ctx, ctx->buffer);

        for (size_t i = part_len; i + 63 < len; i += 64) {
            md5_transform(ctx, &data[i]);
        }

        index = 0;
    }
    else {
        memcpy(&ctx->buffer[index], data, len);
        return;
    }

    memcpy(ctx->buffer, &data[len - index], index);
}

// MD5 结束
static void md5_final(md5_ctx* ctx, unsigned char digest[16]) {
    unsigned char bits[8];
    size_t index, pad_len;

    // 保存位计数（小端序）
    uint64_t bit_count = ctx->count * 8;
    for (int i = 0; i < 8; i++) {
        bits[i] = (unsigned char)((bit_count >> (i * 8)) & 0xff);
    }

    // 添加填充
    index = (size_t)(ctx->count & 63);
    pad_len = (index < 56) ? (56 - index) : (120 - index);

    unsigned char padding[64] = { 0x80 };
    md5_update(ctx, padding, pad_len);

    // 添加长度
    md5_update(ctx, bits, 8);

    // 生成最终哈希值（小端序）
    for (int i = 0; i < 4; i++) {
        digest[i * 4] = (unsigned char)(ctx->state[i] & 0xff);
        digest[i * 4 + 1] = (unsigned char)((ctx->state[i] >> 8) & 0xff);
        digest[i * 4 + 2] = (unsigned char)((ctx->state[i] >> 16) & 0xff);
        digest[i * 4 + 3] = (unsigned char)((ctx->state[i] >> 24) & 0xff);
    }
}

// ==================== 修改哈希计算函数 ====================

// 自实现的 SHA-256
void compute_sha256_self(const unsigned char* data, size_t len, unsigned char out[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

// 自实现的 MD5
void compute_md5_self(const unsigned char* data, size_t len, unsigned char out[16]) {
    md5_ctx ctx;
    md5_init(&ctx);
    md5_update(&ctx, data, len);
    md5_final(&ctx, out);
}

int my_rsa_public_encrypt(const BIGNUM* e, const BIGNUM* n, const unsigned char* in, int in_len, unsigned char** out, int* out_len) {
    if (!e || !n || !in || in_len <= 0) return 0;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return 0;

    // 将明文转换为大整数m
    BIGNUM* m = BN_bin2bn(in, in_len, NULL);
    if (!m) {
        BN_CTX_free(ctx);
        return 0;
    }

    // 计算密文c = m^e mod n
    BIGNUM* c = BN_new();
    if (!BN_mod_exp(c, m, e, n, ctx)) {
        BN_free(m);
        BN_CTX_free(ctx);
        return 0;
    }

    // 转换为字节数组（保证长度与n的字节数一致）
    int rsa_size = BN_num_bytes(n);
    *out = (unsigned char*)malloc(rsa_size);
    if (!*out) {
        BN_free(m);
        BN_free(c);
        BN_CTX_free(ctx);
        return 0;
    }
    *out_len = BN_bn2bin(c, *out);
    if (*out_len < rsa_size) {  // 不足则补前导0
        memmove(*out + (rsa_size - *out_len), *out, *out_len);
        memset(*out, 0, rsa_size - *out_len);
        *out_len = rsa_size;
    }

    BN_free(m);
    BN_free(c);
    BN_CTX_free(ctx);
    return 1;
}

int my_rsa_private_decrypt(const BIGNUM* d, const BIGNUM* n, const unsigned char* in, int in_len, unsigned char** out, int* out_len) {
    if (!d || !n || !in || in_len <= 0) return 0;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return 0;

    // 将密文转换为大整数c
    BIGNUM* c = BN_bin2bn(in, in_len, NULL);
    if (!c) {
        BN_CTX_free(ctx);
        return 0;
    }

    // 计算明文m = c^d mod n
    BIGNUM* m = BN_new();
    if (!BN_mod_exp(m, c, d, n, ctx)) {
        BN_free(c);
        BN_CTX_free(ctx);
        return 0;
    }

    // 转换为字节数组
    *out_len = BN_num_bytes(m);
    *out = (unsigned char*)malloc(*out_len);
    if (!*out) {
        BN_free(c);
        BN_free(m);
        BN_CTX_free(ctx);
        return 0;
    }
    BN_bn2bin(m, *out);

    BN_free(c);
    BN_free(m);
    BN_CTX_free(ctx);
    return 1;
}

int my_rsa_sign_digest(const BIGNUM* d, const BIGNUM* n, const unsigned char* digest, unsigned int digest_len, unsigned char** sig, unsigned int* sig_len) {
    if (!d || !n || !digest || digest_len <= 0) return 0;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return 0;

    // 将消息摘要转换为大整数h
    BIGNUM* h = BN_bin2bn(digest, digest_len, NULL);
    if (!h) {
        BN_CTX_free(ctx);
        return 0;
    }

    // 计算签名s = h^d mod n
    BIGNUM* s = BN_new();
    if (!BN_mod_exp(s, h, d, n, ctx)) {
        BN_free(h);
        BN_CTX_free(ctx);
        return 0;
    }

    // 转换为字节数组（保证长度与n的字节数一致）
    int rsa_size = BN_num_bytes(n);
    *sig = (unsigned char*)malloc(rsa_size);
    if (!*sig) {
        BN_free(h);
        BN_free(s);
        BN_CTX_free(ctx);
        return 0;
    }
    *sig_len = BN_bn2bin(s, *sig);
    if (*sig_len < rsa_size) {  // 不足则补前导0
        memmove(*sig + (rsa_size - *sig_len), *sig, *sig_len);
        memset(*sig, 0, rsa_size - *sig_len);
        *sig_len = rsa_size;
    }

    BN_free(h);
    BN_free(s);
    BN_CTX_free(ctx);
    return 1;
}

int my_rsa_verify_digest(const BIGNUM* e, const BIGNUM* n, const unsigned char* digest, unsigned int digest_len, const unsigned char* sig, unsigned int sig_len) {
    if (!e || !n || !digest || !sig || digest_len <= 0 || sig_len <= 0) return 0;

    BN_CTX* ctx = BN_CTX_new();
    if (!ctx) return 0;

    // 将签名转换为大整数s
    BIGNUM* s = BN_bin2bn(sig, sig_len, NULL);
    if (!s) {
        BN_CTX_free(ctx);
        return 0;
    }

    // 将原消息摘要转换为大整数h
    BIGNUM* h = BN_bin2bn(digest, digest_len, NULL);
    if (!h) {
        BN_free(s);
        BN_CTX_free(ctx);
        return 0;
    }

    // 计算h' = s^e mod n
    BIGNUM* h_prime = BN_new();
    if (!BN_mod_exp(h_prime, s, e, n, ctx)) {
        BN_free(s);
        BN_free(h);
        BN_CTX_free(ctx);
        return 0;
    }

    // 比较h和h'是否一致
    int ret = (BN_cmp(h, h_prime) == 0) ? 1 : 0;

    BN_free(s);
    BN_free(h);
    BN_free(h_prime);
    BN_CTX_free(ctx);
    return ret;
}

// Save text from edit to file (ANSI)
int save_text_from_edit_to_file(HWND hEdit, const char* fname) {
    int len = GetWindowTextLengthA(hEdit);
    if (len <= 0) return 0;
    char* buf = (char*)malloc((size_t)len + 1);
    if (!buf) return 0;
    GetWindowTextA(hEdit, buf, len + 1);
    FILE* f = fopen(fname, "wb");
    if (!f) { free(buf); return 0; }
    fwrite(buf, 1, len, f);
    fclose(f); free(buf);
    return 1;
}

// 手动加载 PEM 文件的替代函数
int load_private_key_manual(const char* fname) {
    size_t file_len;
    unsigned char* file_data = read_file_all(fname, &file_len);
    if (!file_data) return 0;

    // 将文件内容转换为 BIO
    BIO* bio = BIO_new_mem_buf(file_data, (int)file_len);
    if (!bio) {
        free(file_data);
        return 0;
    }

    RSA* rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(file_data);

    if (!rsa) {
        show_openssl_errors();
        return 0;
    }

    if (g_own_rsa) {
        RSA_free(g_own_rsa);
    }
    g_own_rsa = rsa;

    // 更新 UI
    BIO* bio_out = BIO_new(BIO_s_mem());
    if (PEM_write_bio_RSAPrivateKey(bio_out, g_own_rsa, NULL, NULL, 0, NULL, NULL)) {
        char* pem;
        long n = BIO_get_mem_data(bio_out, &pem);
        SetWindowTextA(hRSAPrvEdit, pem);
        SetWindowTextA(hFileRSAPrvEdit, pem);
    }
    BIO_free(bio_out);

    append_output("Loaded private key (own) from %s\n", fname);
    return 1;
}

int load_public_key_manual(const char* fname) {
    size_t file_len;
    unsigned char* file_data = read_file_all(fname, &file_len);
    if (!file_data) return 0;

    BIO* bio = BIO_new_mem_buf(file_data, (int)file_len);
    if (!bio) {
        free(file_data);
        return 0;
    }

    RSA* pub = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);
    free(file_data);

    if (!pub) {
        show_openssl_errors();
        return 0;
    }

    if (g_peer_rsa) {
        RSA_free(g_peer_rsa);
    }
    g_peer_rsa = pub;

    // 更新 UI
    BIO* bio_out = BIO_new(BIO_s_mem());
    if (PEM_write_bio_RSA_PUBKEY(bio_out, g_peer_rsa)) {
        char* pem;
        long n = BIO_get_mem_data(bio_out, &pem);
        SetWindowTextA(hRSAPubEdit, pem);
        SetWindowTextA(hFileRSAPubEdit, pem);
    }
    BIO_free(bio_out);

    append_output("Loaded peer public key from %s\n", fname);
    return 1;
}

void save_privkey_to_file_dialog() {
    char path[1024];
    OPENFILENAMEA ofn;
    char szFile[1024] = { 0 };
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "PEM Files\0*.pem;*.key;*.pub\0All\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = "pem";
    if (GetSaveFileNameA(&ofn) == TRUE) {
        strncpy(path, szFile, sizeof(path) - 1);
        path[sizeof(path) - 1] = 0;
        if (save_text_from_edit_to_file(hRSAPrvEdit, path)) append_output("Saved private key to %s\n", path);
        else append_output("Failed to save private key to %s\n", path);
    }
}

void save_pubkey_to_file_dialog() {
    char path[1024];
    OPENFILENAMEA ofn;
    char szFile[1024] = { 0 };
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "PEM Files\0*.pem;*.key;*.pub\0All\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrDefExt = "pub";
    if (GetSaveFileNameA(&ofn) == TRUE) {
        strncpy(path, szFile, sizeof(path) - 1);
        path[sizeof(path) - 1] = 0;
        if (save_text_from_edit_to_file(hRSAPubEdit, path)) append_output("Saved public key to %s\n", path);
        else append_output("Failed to save public key to %s\n", path);
    }
}

int open_file_dialog(char* outPath, int maxlen) {
    OPENFILENAMEA ofn;
    char szFile[1024] = { 0 };
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hMainWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.lpstrFilter = "All\0*.*\0PEM Files\0*.pem;*.key;*.pub\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    if (GetOpenFileNameA(&ofn) == TRUE) {
        strncpy(outPath, szFile, (size_t)maxlen - 1);
        outPath[maxlen - 1] = 0;
        return 1;
    }
    return 0;
}

int generate_rsa_keypair_with_primes(int p_bits, int q_bits) {
    // 先定义所有变量
    BIGNUM* p = NULL, * q = NULL, * n = NULL, * p1 = NULL, * q1 = NULL, * phi = NULL;
    BIGNUM* e = NULL, * d = NULL, * dmp1 = NULL, * dmq1 = NULL, * iqmp = NULL;
    BN_CTX* ctx = NULL;
    RSA* rsa = NULL;
    BIO* bio = NULL;
    int total_bits = 0;
    char* p_hex = NULL;
    char* q_hex = NULL;
    char* n_hex = NULL;
    char* e_hex = NULL;
    char* d_hex = NULL;
    char* sym_key_hex = NULL;
    // 然后开始执行
    if (g_own_rsa) {
        RSA_free(g_own_rsa);
        g_own_rsa = NULL;
    }

    append_output("Generating RSA key with p=%d bits, q=%d bits...\n", p_bits, q_bits);

    // 生成大素数p
    p = BN_new();
    if (!p) goto cleanup;

    if (!BN_generate_prime_ex(p, p_bits, 1, NULL, NULL, NULL)) {
        append_output("Failed to generate prime p\n");
        goto cleanup;
    }
    p_hex = BN_bn2hex(p);
    append_output("生成素数p（%d位）：%s\n", p_bits, p_hex);
    OPENSSL_free(p_hex);

    // 生成大素数q
    q = BN_new();
    if (!q) {
        goto cleanup;
    }

    if (!BN_generate_prime_ex(q, q_bits, 1, NULL, NULL, NULL)) {
        append_output("Failed to generate prime q\n");
        goto cleanup;
    }
    q_hex = BN_bn2hex(q);
    append_output("生成素数q（%d位）：%s\n", q_bits, q_hex);
    OPENSSL_free(q_hex);
    // 计算n = p * q
    n = BN_new();
    if (!n) {
        goto cleanup;
    }

    ctx = BN_CTX_new();
    if (!ctx) {
        goto cleanup;
    }

    if (!BN_mul(n, p, q, ctx)) {
        append_output("Failed to compute n = p * q\n");
        goto cleanup;
    }
    n_hex = BN_bn2hex(n);
    append_output("计算公钥模数n = p*q：%s\n", n_hex);
    OPENSSL_free(n_hex);
    // 计算φ(n) = (p-1)*(q-1)
    p1 = BN_new();
    q1 = BN_new();
    phi = BN_new();

    if (!p1 || !q1 || !phi) {
        goto cleanup;
    }

    // p1 = p - 1, q1 = q - 1
    if (!BN_sub(p1, p, BN_value_one()) || !BN_sub(q1, q, BN_value_one())) {
        append_output("Failed to compute p-1 and q-1\n");
        goto cleanup;
    }

    // phi = (p-1)*(q-1)
    if (!BN_mul(phi, p1, q1, ctx)) {
        append_output("Failed to compute phi(n)\n");
        goto cleanup;
    }

    // 选择公钥指数e（通常为65537）
    e = BN_new();
    if (!e) {
        goto cleanup;
    }

    if (!BN_set_word(e, 65537)) {
        append_output("Failed to set public exponent\n");
        goto cleanup;
    }
    e_hex = BN_bn2hex(e);
    append_output("公钥指数e：%s\n", e_hex);
    OPENSSL_free(e_hex);

    // 计算私钥指数d = e^-1 mod phi
    d = BN_new();
    if (!d) {
        goto cleanup;
    }

    if (!BN_mod_inverse(d, e, phi, ctx)) {
        append_output("Failed to compute private exponent d\n");
        goto cleanup;
    }
    d_hex = BN_bn2hex(d);
    append_output("私钥指数d：%s\n", d_hex);
    OPENSSL_free(d_hex);

    // 创建RSA结构体并设置所有参数
    rsa = RSA_new();
    if (!rsa) {
        goto cleanup;
    }

    // 设置RSA参数
    if (RSA_set0_key(rsa, n, e, d) != 1) {
        append_output("Failed to set RSA key parameters\n");
        goto cleanup;
    }

    if (RSA_set0_factors(rsa, p, q) != 1) {
        append_output("Failed to set RSA factors\n");
        goto cleanup;
    }

    // 计算CRT参数（用于加速解密）
    dmp1 = BN_new();  // d mod (p-1)
    dmq1 = BN_new();  // d mod (q-1)
    iqmp = BN_new();  // q^-1 mod p

    if (!dmp1 || !dmq1 || !iqmp) {
        goto cleanup;
    }

    // dmp1 = d mod (p-1)
    if (!BN_mod(dmp1, d, p1, ctx)) {
        append_output("Failed to compute dmp1\n");
        goto cleanup;
    }

    // dmq1 = d mod (q-1)
    if (!BN_mod(dmq1, d, q1, ctx)) {
        append_output("Failed to compute dmq1\n");
        goto cleanup;
    }

    // iqmp = q^-1 mod p
    if (!BN_mod_inverse(iqmp, q, p, ctx)) {
        append_output("Failed to compute iqmp\n");
        goto cleanup;
    }

    if (RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1) {
        append_output("Failed to set RSA CRT parameters\n");
        goto cleanup;
    }

    g_own_rsa = rsa;

    // 计算总位数
    total_bits = BN_num_bits(n);
    append_output("Generated RSA key with total %d bits (p=%d, q=%d)\n",
        total_bits, p_bits, q_bits);

    // 生成对称密钥
    if (RAND_bytes(g_generated_sym_key, 32) != 1) {
        append_output("Symmetric key generation failed.\n");
        g_sym_key_generated = 0;
    }
    else {
        g_sym_key_generated = 1;
        append_output("Symmetric key generated successfully.\n");
    }
    sym_key_hex = bin_to_hex(g_generated_sym_key, 32);
    append_output("生成对称密钥（32字节）：%s\n", sym_key_hex);
    free(sym_key_hex);

    // 将PEM格式输出到文本框
    bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_RSAPrivateKey(bio, g_own_rsa, NULL, NULL, 0, NULL, NULL)) {
        char* pem;
        long n_len = BIO_get_mem_data(bio, &pem);
        SetWindowTextA(hRSAPrvEdit, pem);
        SetWindowTextA(hFileRSAPrvEdit, pem);
    }
    BIO_free(bio);

    bio = BIO_new(BIO_s_mem());
    if (PEM_write_bio_RSA_PUBKEY(bio, g_own_rsa)) {
        char* pem;
        long n_len = BIO_get_mem_data(bio, &pem);
        SetWindowTextA(hRSAPubEdit, pem);
        SetWindowTextA(hFileRSAPubEdit, pem);
    }
    BIO_free(bio);

    // 清理临时变量，注意我们已经将p、q、n、e、d等交给了RSA结构体，所以不需要释放
    // 但是RSA结构体会管理这些内存，所以我们这里不需要释放，只需要释放其他临时变量
    BN_free(p1);
    BN_free(q1);
    BN_free(phi);
    BN_CTX_free(ctx);

    return 1;

cleanup:
    // 在清理时，注意哪些变量已经赋值，需要释放，哪些没有
    if (p) BN_free(p);
    if (q) BN_free(q);
    if (n) BN_free(n);
    if (p1) BN_free(p1);
    if (q1) BN_free(q1);
    if (phi) BN_free(phi);
    if (e) BN_free(e);
    if (d) BN_free(d);
    if (dmp1) BN_free(dmp1);
    if (dmq1) BN_free(dmq1);
    if (iqmp) BN_free(iqmp);
    if (ctx) BN_CTX_free(ctx);
    if (rsa) RSA_free(rsa);
    if (bio) BIO_free(bio);
    return 0;
}

// --- New: Send/Receive full hybrid flow (String Mode) ---
static void sender_full_flow_string(const char* algo)
{
    if (!g_own_rsa || !g_peer_rsa) {
        append_output("Own private key or peer public key not loaded.\r\n");
        return;
    }

    // 检查对称密钥是否已生成
    if (!g_sym_key_generated) {
        append_output("Error: Symmetric key not generated. Please click 'Generate Keys' first.\r\n");
        return;
    }

    // 检查对称密钥是否为全零（未初始化）
    int is_zero_key = 1;
    for (int i = 0; i < 32; i++) {
        if (g_generated_sym_key[i] != 0) {
            is_zero_key = 0;
            break;
        }
    }
    if (is_zero_key) {
        append_output("Error: Symmetric key is zero (not properly generated). Please click 'Generate Keys' first.\r\n");
        return;
    }

    int len = GetWindowTextLengthW(hInputEdit);
    if (len <= 0) {
        append_output("No input message.\r\n");
        return;
    }

    // 读取输入框中的字符串
    wchar_t* wbuf = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
    if (!wbuf) return;
    GetWindowTextW(hInputEdit, wbuf, len + 1);

    // 转换为多字节字符串
    int bytes = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
    char* message = (char*)malloc(bytes);
    if (!message) {
        free(wbuf);
        return;
    }
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, message, bytes, NULL, NULL);
    size_t mlen = strlen(message);

    append_output("=== Sender Full Flow ===\r\n");
    append_output("Original message: %s\r\n", message);

    // 计算消息摘要
    int hidx = (int)SendMessageA(hHashCombo, CB_GETCURSEL, 0, 0);
    char hashname[16] = "SHA256";
    if (hidx == 0) strcpy(hashname, "MD5"); else strcpy(hashname, "SHA256");

    unsigned char digest[32] = { 0 };
    unsigned int dlen = 0;
    if (strcmp(hashname, "MD5") == 0) {
        compute_md5_self((unsigned char*)message, mlen, digest);
        dlen = 16;
    }
    else {
        compute_sha256_self((unsigned char*)message, mlen, digest);
        dlen = 32;
    }

    // 签名：E(H(M), RKA)
    unsigned char* signature = NULL;
    unsigned int siglen = 0;
    //if (!rsa_sign_digest(g_own_rsa, digest, dlen, &signature, &siglen, hashname)) {
    //    append_output("Signature generation failed.\r\n");
    //    free(wbuf);
    //    free(message);
    //    return;
    //}
    // 步骤1：从 g_own_rsa（自己的私钥）中提取 d 和 n
    const BIGNUM* own_d = NULL;
    const BIGNUM* own_n = NULL;
    RSA_get0_key(g_own_rsa, &own_n, NULL, &own_d);
    if (!own_d || !own_n) {
        append_output("RSA sign: Failed to extract d/n from own private key\n");
        // 原错误处理逻辑（释放 file_data、message 等）
        return;
    }

    // 步骤2：调用自主实现的 my_rsa_sign_digest（暂不处理 hashname，后续可补充）
    if (!my_rsa_sign_digest(own_d, own_n, digest, dlen, &signature, &siglen)) {
        append_output("Signature generation failed.\r\n");
        free(wbuf);
        free(message);
        return;
    }
    // 拼接 M || E(H(M), RKA)
    int msg_sig_len = (int)(mlen + siglen);
    unsigned char* message_with_signature = (unsigned char*)malloc(msg_sig_len);
    if (!message_with_signature) {
        append_output("Memory allocation failed for message with signature.\r\n");
        free(wbuf);
        free(message);
        free(signature);
        return;
    }
    memcpy(message_with_signature, message, mlen);
    memcpy(message_with_signature + mlen, signature, siglen);

    // 使用预先生成的对称密钥
    unsigned char keybuf[32] = { 0 };
    unsigned char ivbuf[16] = { 0 };
    memcpy(keybuf, g_generated_sym_key, 32);

    // 生成IV（仍然随机生成）
    if (RAND_bytes(ivbuf, 16) != 1) {
        append_output("RAND_bytes failed for IV generation.\r\n");
        free(wbuf);
        free(message);
        free(signature);
        free(message_with_signature);
        return;
    }

    append_output("Using pre-generated symmetric key from Generate Keys.\r\n");

    // 调试信息：显示实际用于加密的密钥
    append_output("Key used for encryption: ");
    int key_len = (strcmp(algo, "AES") == 0) ? 32 : 8;
    for (int i = 0; i < key_len; i++) {
        append_output("%02x ", keybuf[i]);
    }
    append_output("\n");

    append_output("IV used for encryption: ");
    int iv_len = (strcmp(algo, "AES") == 0) ? 16 : 8;
    for (int i = 0; i < iv_len; i++) {
        append_output("%02x ", ivbuf[i]);
    }
    append_output("\n");

    // 对称加密 M||E(H(M), RKA)
    unsigned char* encrypted_payload = NULL;
    int encrypted_payload_len = 0;
    if (!symmetric_encrypt(message_with_signature, msg_sig_len, keybuf, ivbuf, algo, &encrypted_payload, &encrypted_payload_len)) {
        append_output("Symmetric encryption failed.\r\n");
        free(wbuf);
        free(message);
        free(signature);
        free(message_with_signature);
        return;
    }

    // RSA 加密对称密钥 K: E(K, UKB)
    int keylen_to_encrypt = (strcmp(algo, "AES") == 0) ? 32 : 8;
    unsigned char* encrypted_key = NULL;
    int encrypted_key_len = 0;
    /*if (!rsa_encrypt_with_pubkey(g_peer_rsa, keybuf, keylen_to_encrypt, &encrypted_key, &encrypted_key_len)) {
        append_output("RSA encrypt symmetric key failed.\r\n");
        free(wbuf);
        free(message);
        free(signature);
        free(message_with_signature);
        free(encrypted_payload);
        return;
    }*/
    // 步骤1：从 g_peer_rsa（peer 的公钥）中提取 e 和 n
    const BIGNUM* peer_e = NULL;
    const BIGNUM* peer_n = NULL;
    RSA_get0_key(g_peer_rsa, &peer_n, &peer_e, NULL); // 解密用不到 d，传 NULL
    if (!peer_e || !peer_n) {
        append_output("RSA encrypt: Failed to extract e/n from peer public key\n");
        free(wbuf);
        free(message);
        free(signature);
        free(message_with_signature);
        free(encrypted_payload);
        return;
    }

    // 步骤2：调用自主实现的 my_rsa_public_encrypt
    if (!my_rsa_public_encrypt(peer_e, peer_n, keybuf, keylen_to_encrypt, &encrypted_key, &encrypted_key_len)) {
        append_output("RSA encrypt symmetric key failed.\r\n");
        // 原错误处理逻辑（如 free(wbuf)、free(message) 等）
        return;
    }

    // 转为十六进制显示
    char* payload_hex = bin_to_hex(encrypted_payload, encrypted_payload_len);
    char* key_hex = bin_to_hex(encrypted_key, encrypted_key_len);
    char* iv_hex = bin_to_hex(ivbuf, 16);

    if (payload_hex && key_hex && iv_hex) {
        append_output("Encrypted Payload (E(M||E(H(M), RKA), K)):\r\n");
        append_output("%s\r\n", payload_hex);
        append_output("Encrypted Symmetric Key (E(K, UKB)):\r\n");
        append_output("%s\r\n", key_hex);
        append_output("IV:\r\n");
        append_output("%s\r\n", iv_hex);
        append_output("=== End Sender Full Flow ===\r\n");

        // 输出文件保存
        if (!write_file_all("send_payload.enc", encrypted_payload, encrypted_payload_len) ||
            !write_file_all("send_key.enc", encrypted_key, encrypted_key_len) ||
            !write_file_all("send_iv.iv", ivbuf, 16)) {
            append_output("Warning: Failed to write output files.\r\n");
        }
    }
    else {
        append_output("Hex conversion failed.\r\n");
    }

    // 清理内存
    free(wbuf);
    free(message);
    free(signature);
    free(message_with_signature);
    free(encrypted_payload);
    free(encrypted_key);
    free(payload_hex);
    free(key_hex);
    free(iv_hex);
}

static void receiver_full_flow_string(const char* algo) {
    if (!g_own_rsa) {
        append_output("Receive failed: own private key not loaded.\n");
        return;
    }
    if (!g_peer_rsa) {
        append_output("Receive failed: peer public key not loaded.\n");
        return;
    }

    append_output("=== Receiver Full Flow ===\n");

    // 读取发送方生成的文件
    size_t enc_payload_len;
    unsigned char* enc_payload = read_file_all("send_payload.enc", &enc_payload_len);
    if (!enc_payload) {
        append_output("Receive failed: send_payload.enc not found.\n");
        return;
    }

    size_t enc_key_len;
    unsigned char* enc_key = read_file_all("send_key.enc", &enc_key_len);
    if (!enc_key) {
        append_output("Receive failed: send_key.enc not found.\n");
        free(enc_payload);
        return;
    }

    size_t iv_len;
    unsigned char* iv_data = read_file_all("send_iv.iv", &iv_len);
    if (!iv_data) {
        append_output("Receive failed: send_iv.iv not found.\n");
        free(enc_payload);
        free(enc_key);
        return;
    }

    // 调试信息：显示加密的对称密钥
    append_output("Encrypted symmetric key length: %d\n", (int)enc_key_len);
    append_output("First 16 bytes of encrypted key: ");
    for (int i = 0; i < 16 && i < enc_key_len; i++) {
        append_output("%02x ", enc_key[i]);
    }
    append_output("\n");

    // 1. 用RKB解密对称密钥：D(E(K, UKB), RKB) = K
    unsigned char* symkey = NULL;
    int symkey_len = 0;
    /*if (!rsa_decrypt_with_privkey(g_own_rsa, enc_key, (int)enc_key_len, &symkey, &symkey_len)) {
        append_output("RSA decrypt symmetric key failed.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        return;
    }*/
    // 步骤1：从 g_own_rsa（自己的私钥）中提取 d 和 n
    const BIGNUM* own_d = NULL;
    const BIGNUM* own_n = NULL;
    RSA_get0_key(g_own_rsa, &own_n, NULL, &own_d); // 解密用不到 e，传 NULL
    if (!own_d || !own_n) {
        append_output("RSA decrypt: Failed to extract d/n from own private key\n");
        // 原错误处理逻辑（释放 enc_payload、enc_key 等）
        return;
    }

    // 步骤2：调用自主实现的 my_rsa_private_decrypt
    if (!my_rsa_private_decrypt(own_d, own_n, enc_key, (int)enc_key_len, &symkey, &symkey_len)) {
        append_output("RSA decrypt symmetric key failed.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        return;
    }

    // 调试信息：显示解密后的对称密钥
    append_output("Decrypted symmetric key length: %d\n", symkey_len);
    append_output("Decrypted symmetric key: ");
    for (int i = 0; i < symkey_len; i++) {
        append_output("%02x ", symkey[i]);
    }
    append_output("\n");

    // 2. 用K解密得到 M||E(H(M), RKA)
    unsigned char keybuf[32];
    unsigned char ivbuf[16];
    memset(keybuf, 0, sizeof(keybuf));
    memset(ivbuf, 0, sizeof(ivbuf));

    if (strcmp(algo, "AES") == 0) {
        memcpy(keybuf, symkey, symkey_len > 32 ? 32 : symkey_len);
        memcpy(ivbuf, iv_data, iv_len > 16 ? 16 : iv_len);
    }
    else {
        memcpy(keybuf, symkey, symkey_len > 8 ? 8 : symkey_len);
        memcpy(ivbuf, iv_data, iv_len > 8 ? 8 : iv_len);
    }

    // 调试信息：显示实际用于解密的密钥和IV
    append_output("Key used for decryption: ");
    int key_len = (strcmp(algo, "AES") == 0) ? 32 : 8;
    for (int i = 0; i < key_len; i++) {
        append_output("%02x ", keybuf[i]);
    }
    append_output("\n");

    append_output("IV used for decryption: ");
    int iv_len_used = (strcmp(algo, "AES") == 0) ? 16 : 8;
    for (int i = 0; i < iv_len_used; i++) {
        append_output("%02x ", ivbuf[i]);
    }
    append_output("\n");

    unsigned char* decrypted_data = NULL;
    int decrypted_len = 0;
    if (!symmetric_decrypt(enc_payload, (int)enc_payload_len, keybuf, ivbuf, algo, &decrypted_data, &decrypted_len)) {
        append_output("Symmetric decryption failed.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        free(symkey);
        return;
    }

    // 3. 分离 M 和 E(H(M), RKA)
    int rsa_size = RSA_size(g_peer_rsa);
    if (decrypted_len <= rsa_size) {
        append_output("Decrypted data too short to contain message and signature.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        free(symkey);
        free(decrypted_data);
        return;
    }

    int message_len = decrypted_len - rsa_size;
    unsigned char* message = (unsigned char*)malloc(message_len + 1);
    unsigned char* signature = (unsigned char*)malloc(rsa_size);
    if (!message || !signature) {
        append_output("Memory allocation failed.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        free(symkey);
        free(decrypted_data);
        free(message);
        free(signature);
        return;
    }

    memcpy(message, decrypted_data, message_len);
    message[message_len] = 0;
    memcpy(signature, decrypted_data + message_len, rsa_size);

    append_output("Decrypted message: %.*s\n", message_len, message);

    // 4. 计算接收到的消息的摘要 H(M)
    int hidx = (int)SendMessageA(hHashCombo, CB_GETCURSEL, 0, 0);
    char hashname[16] = "SHA256";
    if (hidx == 0) strcpy(hashname, "MD5"); else strcpy(hashname, "SHA256");

    unsigned char computed_digest[32];
    unsigned int dlen = 0;

    if (strcmp(hashname, "MD5") == 0) {
        compute_md5_self(message, message_len, computed_digest);
        dlen = 16;
    }
    else {
        compute_sha256_self(message, message_len, computed_digest);
        dlen = 32;
    }

    // 5. 用UKA验证签名：D(E(H(M), RKA), UKA) = H(M)
    //int ok = rsa_verify_digest(g_peer_rsa, computed_digest, dlen, signature, rsa_size, hashname);
    // 步骤1：从 g_peer_rsa（peer 的公钥）中提取 e 和 n
    const BIGNUM* peer_e = NULL;
    const BIGNUM* peer_n = NULL;
    RSA_get0_key(g_peer_rsa, &peer_n, &peer_e, NULL);
    if (!peer_e || !peer_n) {
        append_output("RSA verify: Failed to extract e/n from peer public key\n");
        // 原错误处理逻辑（释放 message、signature 等）
        return;
    }

    // 步骤2：调用自主实现的 my_rsa_verify_digest（暂不处理 hashname）
    int ok = my_rsa_verify_digest(peer_e, peer_n, computed_digest, dlen, signature, rsa_size);

    append_output("Signature verification: %s\n", ok ? "OK" : "FAILED");

    if (ok) {
        append_output("The signature is valid. Message authentication successful.\n");

        // 将解密的消息显示在输入框中
        wchar_t* wmessage = (wchar_t*)malloc((message_len + 1) * sizeof(wchar_t));
        if (wmessage) {
            int wlen = MultiByteToWideChar(CP_UTF8, 0, (char*)message, message_len, NULL, 0);
            MultiByteToWideChar(CP_UTF8, 0, (char*)message, message_len, wmessage, wlen);
            wmessage[wlen] = 0;
            SetWindowTextW(hInputEdit, wmessage);
            free(wmessage);
        }
    }
    else {
        append_output("The signature is invalid. Message may have been tampered with.\n");
    }

    append_output("=== End Receiver Full Flow ===\n");

    // 清理内存
    free(enc_payload);
    free(enc_key);
    free(iv_data);
    free(symkey);
    free(decrypted_data);
    free(message);
    free(signature);
}

// File Mode 发送函数
static void sender_full_flow_file(const char* filepath, const char* algo) {
    if (!g_own_rsa || !g_peer_rsa) {
        append_output("Own private key or peer public key not loaded.\r\n");
        return;
    }

    // 检查对称密钥是否已生成
    if (!g_sym_key_generated) {
        append_output("Error: Symmetric key not generated. Please click 'Generate Keys' first.\r\n");
        return;
    }

    // 检查对称密钥是否为全零（未初始化）
    int is_zero_key = 1;
    for (int i = 0; i < 32; i++) {
        if (g_generated_sym_key[i] != 0) {
            is_zero_key = 0;
            break;
        }
    }
    if (is_zero_key) {
        append_output("Error: Symmetric key is zero (not properly generated). Please click 'Generate Keys' first.\r\n");
        return;
    }

    // 读取文件内容
    size_t file_len;
    unsigned char* file_data = read_file_all(filepath, &file_len);
    if (!file_data) {
        append_output("Failed to read file: %s\n", filepath);
        return;
    }

    append_output("=== File Sender Full Flow ===\r\n");
    append_output("Processing file: %s\n", filepath);

    // 计算文件摘要
    int hidx = (int)SendMessageA(hFileHashCombo, CB_GETCURSEL, 0, 0);
    char hashname[16] = "SHA256";
    if (hidx == 0) strcpy(hashname, "MD5"); else strcpy(hashname, "SHA256");

    unsigned char digest[32] = { 0 };
    unsigned int dlen = 0;
    if (strcmp(hashname, "MD5") == 0) {
        compute_md5_self(file_data, file_len, digest);
        dlen = 16;
    }
    else {
        compute_sha256_self(file_data, file_len, digest);
        dlen = 32;
    }

    // 签名：E(H(M), RKA)
    unsigned char* signature = NULL;
    unsigned int siglen = 0;
    //if (!rsa_sign_digest(g_own_rsa, digest, dlen, &signature, &siglen, hashname)) {
    //    append_output("Signature generation failed.\r\n");
    //    free(file_data);
    //    return;
    //}
    // 步骤1：从 g_own_rsa（自己的私钥）中提取 d 和 n
    const BIGNUM* own_d = NULL;
    const BIGNUM* own_n = NULL;
    RSA_get0_key(g_own_rsa, &own_n, NULL, &own_d);
    if (!own_d || !own_n) {
        append_output("RSA sign: Failed to extract d/n from own private key\n");
        // 原错误处理逻辑（释放 file_data、message 等）
        return;
    }

    // 步骤2：调用自主实现的 my_rsa_sign_digest（暂不处理 hashname，后续可补充）
    if (!my_rsa_sign_digest(own_d, own_n, digest, dlen, &signature, &siglen)) {
        append_output("Signature generation failed.\r\n");
        free(file_data);
        return;
    }

    // 拼接文件内容 || E(H(M), RKA)
    int total_len = (int)file_len + siglen;
    unsigned char* file_with_signature = (unsigned char*)malloc(total_len);
    if (!file_with_signature) {
        append_output("Memory allocation failed for file with signature.\r\n");
        free(file_data);
        free(signature);
        return;
    }
    memcpy(file_with_signature, file_data, file_len);
    memcpy(file_with_signature + file_len, signature, siglen);

    // 使用预先生成的对称密钥
    unsigned char keybuf[32] = { 0 };
    unsigned char ivbuf[16] = { 0 };
    memcpy(keybuf, g_generated_sym_key, 32);

    // 生成IV（仍然随机生成）
    if (RAND_bytes(ivbuf, 16) != 1) {
        append_output("RAND_bytes failed for IV generation.\r\n");
        free(file_data);
        free(signature);
        free(file_with_signature);
        return;
    }

    append_output("Using pre-generated symmetric key from Generate Keys.\r\n");

    // 对称加密 文件内容||E(H(M), RKA)
    unsigned char* encrypted_payload = NULL;
    int encrypted_payload_len = 0;
    if (!symmetric_encrypt(file_with_signature, total_len, keybuf, ivbuf, algo, &encrypted_payload, &encrypted_payload_len)) {
        append_output("Symmetric encryption failed.\r\n");
        free(file_data);
        free(signature);
        free(file_with_signature);
        return;
    }

    // RSA 加密对称密钥 K: E(K, UKB)
    int keylen_to_encrypt = (strcmp(algo, "AES") == 0) ? 32 : 8;
    unsigned char* encrypted_key = NULL;
    int encrypted_key_len = 0;
    //if (!rsa_encrypt_with_pubkey(g_peer_rsa, keybuf, keylen_to_encrypt, &encrypted_key, &encrypted_key_len)) {
    //    append_output("RSA encrypt symmetric key failed.\r\n");
    //    free(file_data);
    //    free(signature);
    //    free(file_with_signature);
    //    free(encrypted_payload);
    //    return;
    //}
    // 步骤1：从 g_peer_rsa（peer 的公钥）中提取 e 和 n
    const BIGNUM* peer_e = NULL;
    const BIGNUM* peer_n = NULL;
    RSA_get0_key(g_peer_rsa, &peer_n, &peer_e, NULL); // 解密用不到 d，传 NULL
    if (!peer_e || !peer_n) {
        append_output("RSA encrypt: Failed to extract e/n from peer public key\n");
        // 原错误处理逻辑（释放内存等）
        return;
    }

    // 步骤2：调用自主实现的 my_rsa_public_encrypt
    if (!my_rsa_public_encrypt(peer_e, peer_n, keybuf, keylen_to_encrypt, &encrypted_key, &encrypted_key_len)) {
        append_output("RSA encrypt symmetric key failed.\r\n");
        free(file_data);
        free(signature);
        free(file_with_signature);
        free(encrypted_payload);
        return;
    }
    // 保存输出文件
    char output_path[1024];

    // 保存加密的文件内容
    snprintf(output_path, sizeof(output_path), "%s.enc", filepath);
    if (!write_file_all(output_path, encrypted_payload, encrypted_payload_len)) {
        append_output("Failed to write encrypted file: %s\n", output_path);
    }
    else {
        append_output("Encrypted file saved: %s\n", output_path);
    }

    // 保存加密的对称密钥
    snprintf(output_path, sizeof(output_path), "%s.key", filepath);
    if (!write_file_all(output_path, encrypted_key, encrypted_key_len)) {
        append_output("Failed to write key file: %s\n", output_path);
    }
    else {
        append_output("Encrypted key saved: %s\n", output_path);
    }

    // 保存IV
    snprintf(output_path, sizeof(output_path), "%s.iv", filepath);
    if (!write_file_all(output_path, ivbuf, 16)) {
        append_output("Failed to write IV file: %s\n", output_path);
    }
    else {
        append_output("IV saved: %s\n", output_path);
    }

    append_output("=== End File Sender Full Flow ===\r\n");

    // 清理内存
    free(file_data);
    free(signature);
    free(file_with_signature);
    free(encrypted_payload);
    free(encrypted_key);
}

// File Mode 接收函数
static void receiver_full_flow_file(const char* filepath, const char* algo) {
    if (!g_own_rsa) {
        append_output("Receive failed: own private key not loaded.\n");
        return;
    }
    if (!g_peer_rsa) {
        append_output("Receive failed: peer public key not loaded.\n");
        return;
    }

    append_output("=== File Receiver Full Flow ===\n");

    // 读取发送方生成的文件
    char enc_file_path[1024];
    snprintf(enc_file_path, sizeof(enc_file_path), "%s.enc", filepath);
    size_t enc_payload_len;
    unsigned char* enc_payload = read_file_all(enc_file_path, &enc_payload_len);
    if (!enc_payload) {
        append_output("Receive failed: %s not found.\n", enc_file_path);
        return;
    }

    char key_file_path[1024];
    snprintf(key_file_path, sizeof(key_file_path), "%s.key", filepath);
    size_t enc_key_len;
    unsigned char* enc_key = read_file_all(key_file_path, &enc_key_len);
    if (!enc_key) {
        append_output("Receive failed: %s not found.\n", key_file_path);
        free(enc_payload);
        return;
    }

    char iv_file_path[1024];
    snprintf(iv_file_path, sizeof(iv_file_path), "%s.iv", filepath);
    size_t iv_len;
    unsigned char* iv_data = read_file_all(iv_file_path, &iv_len);
    if (!iv_data) {
        append_output("Receive failed: %s not found.\n", iv_file_path);
        free(enc_payload);
        free(enc_key);
        return;
    }

    // 1. 用RKB解密对称密钥：D(E(K, UKB), RKB) = K
    unsigned char* symkey = NULL;
    int symkey_len = 0;
    //if (!rsa_decrypt_with_privkey(g_own_rsa, enc_key, (int)enc_key_len, &symkey, &symkey_len)) {
    //    append_output("RSA decrypt symmetric key failed.\n");
    //    free(enc_payload);
    //    free(enc_key);
    //    free(iv_data);
    //    return;
    //}
    // 步骤1：从 g_own_rsa（自己的私钥）中提取 d 和 n
    const BIGNUM* own_d = NULL;
    const BIGNUM* own_n = NULL;
    RSA_get0_key(g_own_rsa, &own_n, NULL, &own_d); // 解密用不到 e，传 NULL
    if (!own_d || !own_n) {
        append_output("RSA decrypt: Failed to extract d/n from own private key\n");
        // 原错误处理逻辑（释放 enc_payload、enc_key 等）
        return;
    }

    // 步骤2：调用自主实现的 my_rsa_private_decrypt
    if (!my_rsa_private_decrypt(own_d, own_n, enc_key, (int)enc_key_len, &symkey, &symkey_len)) {
        append_output("RSA decrypt symmetric key failed.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        return;
    }

    // 2. 用K解密得到 文件内容||E(H(M), RKA)
    unsigned char keybuf[32];
    unsigned char ivbuf[16];
    memset(keybuf, 0, sizeof(keybuf));
    memset(ivbuf, 0, sizeof(ivbuf));

    if (strcmp(algo, "AES") == 0) {
        memcpy(keybuf, symkey, symkey_len > 32 ? 32 : symkey_len);
        memcpy(ivbuf, iv_data, iv_len > 16 ? 16 : iv_len);
    }
    else {
        memcpy(keybuf, symkey, symkey_len > 8 ? 8 : symkey_len);
        memcpy(ivbuf, iv_data, iv_len > 8 ? 8 : iv_len);
    }

    unsigned char* decrypted_data = NULL;
    int decrypted_len = 0;
    if (!symmetric_decrypt(enc_payload, (int)enc_payload_len, keybuf, ivbuf, algo, &decrypted_data, &decrypted_len)) {
        append_output("Symmetric decryption failed.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        free(symkey);
        return;
    }

    // 3. 分离 文件内容 和 E(H(M), RKA)
    int rsa_size = RSA_size(g_peer_rsa);
    if (decrypted_len <= rsa_size) {
        append_output("Decrypted data too short to contain file content and signature.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        free(symkey);
        free(decrypted_data);
        return;
    }

    int file_len = decrypted_len - rsa_size;
    unsigned char* file_content = (unsigned char*)malloc(file_len);
    unsigned char* signature = (unsigned char*)malloc(rsa_size);
    if (!file_content || !signature) {
        append_output("Memory allocation failed.\n");
        free(enc_payload);
        free(enc_key);
        free(iv_data);
        free(symkey);
        free(decrypted_data);
        free(file_content);
        free(signature);
        return;
    }

    memcpy(file_content, decrypted_data, file_len);
    memcpy(signature, decrypted_data + file_len, rsa_size);

    append_output("Decrypted file content (%d bytes)\n", file_len);

    // 4. 计算接收到的文件内容的摘要 H(M)
    int hidx = (int)SendMessageA(hFileHashCombo, CB_GETCURSEL, 0, 0);
    char hashname[16] = "SHA256";
    if (hidx == 0) strcpy(hashname, "MD5"); else strcpy(hashname, "SHA256");

    unsigned char computed_digest[32];
    unsigned int dlen = 0;

    if (strcmp(hashname, "MD5") == 0) {
        compute_md5_self(file_content, file_len, computed_digest);
        dlen = 16;
    }
    else {
        compute_sha256_self(file_content, file_len, computed_digest);
        dlen = 32;
    }

    // 5. 用UKA验证签名：D(E(H(M), RKA), UKA) = H(M)
    //int ok = rsa_verify_digest(g_peer_rsa, computed_digest, dlen, signature, rsa_size, hashname);
    // 步骤1：从 g_peer_rsa（peer 的公钥）中提取 e 和 n
    const BIGNUM* peer_e = NULL;
    const BIGNUM* peer_n = NULL;
    RSA_get0_key(g_peer_rsa, &peer_n, &peer_e, NULL);
    if (!peer_e || !peer_n) {
        append_output("RSA verify: Failed to extract e/n from peer public key\n");
        // 原错误处理逻辑（释放 message、signature 等）
        return;
    }

    // 步骤2：调用自主实现的 my_rsa_verify_digest（暂不处理 hashname）
    int ok = my_rsa_verify_digest(peer_e, peer_n, computed_digest, dlen, signature, rsa_size);

    append_output("Signature verification: %s\n", ok ? "OK" : "FAILED");

    if (ok) {
        append_output("The signature is valid. File authentication successful.\n");

        // 保存解密后的文件
        char output_path[1024];
        snprintf(output_path, sizeof(output_path), "%s.dec", filepath);
        if (!write_file_all(output_path, file_content, file_len)) {
            append_output("Failed to write decrypted file: %s\n", output_path);
        }
        else {
            append_output("Decrypted file saved: %s\n", output_path);
        }
    }
    else {
        append_output("The signature is invalid. File may have been tampered with.\n");
    }

    append_output("=== End File Receiver Full Flow ===\n");

    // 清理内存
    free(enc_payload);
    free(enc_key);
    free(iv_data);
    free(symkey);
    free(decrypted_data);
    free(file_content);
    free(signature);
}

LRESULT CALLBACK MainWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
    case WM_CREATE: {
        InitCommonControls();
        nStringControls = 0; nFileControls = 0;
        SetWindowLong(hwnd, GWL_STYLE, GetWindowLong(hwnd, GWL_STYLE) & ~WS_MAXIMIZEBOX);

        hTab = CreateWindowExW(0, WC_TABCONTROLW, L"",
            WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | TCS_FOCUSNEVER,
            10, 10, 800, 400, hwnd, (HMENU)NULL, hInst, NULL);

        TCITEMW tie;
        tie.mask = TCIF_TEXT;
        tie.pszText = (LPWSTR)L"String Mode";
        TabCtrl_InsertItem(hTab, 0, &tie);
        tie.pszText = (LPWSTR)L"File Mode";
        TabCtrl_InsertItem(hTab, 1, &tie);

        hOutputEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | ES_READONLY,
            10, 420, 800, 200, hwnd, (HMENU)IDC_OUTPUT_EDIT, hInst, NULL);

        // ==================== String Mode 控件 ====================
        HWND hAlgoLabel = CreateWindowW(L"STATIC", L"Algorithm:",
            WS_CHILD | WS_VISIBLE, 20, 50, 80, 20, hwnd, NULL, hInst, NULL);
        add_string_control(hAlgoLabel);

        hAlgoCombo = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            100, 50, 100, 200, hwnd, (HMENU)IDC_ALGO_COMBO, hInst, NULL);
        SendMessageW(hAlgoCombo, CB_ADDSTRING, 0, (LPARAM)L"AES");
        SendMessageW(hAlgoCombo, CB_ADDSTRING, 0, (LPARAM)L"DES");
        SendMessageW(hAlgoCombo, CB_SETCURSEL, 0, 0);
        add_string_control(hAlgoCombo);

        HWND hHashLabel = CreateWindowW(L"STATIC", L"Hash:",
            WS_CHILD | WS_VISIBLE, 230, 50, 80, 20, hwnd, NULL, hInst, NULL);
        add_string_control(hHashLabel);

        hHashCombo = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            310, 50, 100, 200, hwnd, (HMENU)IDC_HASH_COMBO, hInst, NULL);
        SendMessageW(hHashCombo, CB_ADDSTRING, 0, (LPARAM)L"MD5");
        SendMessageW(hHashCombo, CB_ADDSTRING, 0, (LPARAM)L"SHA256");
        SendMessageW(hHashCombo, CB_SETCURSEL, 1, 0);
        add_string_control(hHashCombo);

        HWND hStringPathLabel = CreateWindowW(L"STATIC", L"File Path:",
            WS_CHILD | WS_VISIBLE, 20, 80, 80, 20, hwnd, NULL, hInst, NULL);
        add_string_control(hStringPathLabel);

        hFilePathEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            100, 80, 200, 25, hwnd, (HMENU)IDC_FILEPATH_EDIT, hInst, NULL);  // 宽度从400改为300
        add_string_control(hFilePathEdit);

        hBrowseBtn = CreateWindowW(L"BUTTON", L"Browse...",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            330, 80, 80, 25, hwnd, (HMENU)IDC_BROWSE_BTN, hInst, NULL);  // x位置从430改为330
        add_string_control(hBrowseBtn);

        hInputEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            20, 120, 400, 180, hwnd, (HMENU)IDC_INPUT_EDIT, hInst, NULL);
        add_string_control(hInputEdit);

        // 对称密钥标签和编辑框
        hKeyLabel = CreateWindowW(L"STATIC", L"Sym Key:",
            WS_CHILD | WS_VISIBLE, 20, 310, 80, 20, hwnd, NULL, hInst, NULL);
        add_string_control(hKeyLabel);

        hKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            100, 310, 320, 25, hwnd, (HMENU)IDC_KEY_EDIT, hInst, NULL);
        add_string_control(hKeyEdit);
        // 添加p和q位数输入框（String Mode）
        HWND hPLabel = CreateWindowW(L"STATIC", L"p位数:",
            WS_CHILD | WS_VISIBLE, 20, 350, 60, 20, hwnd, NULL, hInst, NULL);
        add_string_control(hPLabel);

        hPEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"512",
            WS_CHILD | WS_VISIBLE | ES_NUMBER,
            80, 350, 60, 20, hwnd, (HMENU)IDC_P_EDIT, hInst, NULL);
        add_string_control(hPEdit);

        HWND hQLabel = CreateWindowW(L"STATIC", L"q位数:",
            WS_CHILD | WS_VISIBLE, 150, 350, 60, 20, hwnd, NULL, hInst, NULL);
        add_string_control(hQLabel);

        hQEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"512",
            WS_CHILD | WS_VISIBLE | ES_NUMBER,
            210, 350, 60, 20, hwnd, (HMENU)IDC_Q_EDIT, hInst, NULL);
        add_string_control(hQEdit);

        // 发送和接收按钮
        HWND hSendBtn = CreateWindowW(L"BUTTON", L"Send (Full Flow)",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 370, 160, 30, hwnd, (HMENU)IDM_SEND, hInst, NULL);
        add_string_control(hSendBtn);

        HWND hRecvBtn = CreateWindowW(L"BUTTON", L"Receive (Full Flow)",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            200, 370, 160, 30, hwnd, (HMENU)IDM_RECEIVE, hInst, NULL);
        add_string_control(hRecvBtn);

        // 右侧密钥管理区域
        hGenerateBtn = CreateWindowW(L"BUTTON", L"Generate Keys",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            450, 50, 140, 25, hwnd, (HMENU)IDM_GEN_RSA, hInst, NULL);
        add_string_control(hGenerateBtn);

        hLoadPubBtn = CreateWindowW(L"BUTTON", L"Load Peer PubKey",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            450, 80, 140, 25, hwnd, (HMENU)IDC_LOAD_PUB_BTN, hInst, NULL);
        add_string_control(hLoadPubBtn);

        hLoadPrivBtn = CreateWindowW(L"BUTTON", L"Load Own PrivKey",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            450, 110, 140, 25, hwnd, (HMENU)IDC_LOAD_PRIV_BTN, hInst, NULL);
        add_string_control(hLoadPrivBtn);

        hSavePubBtn = CreateWindowW(L"BUTTON", L"Save PubKey",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            450, 140, 140, 25, hwnd, (HMENU)IDC_SAVE_PUB_BTN, hInst, NULL);
        add_string_control(hSavePubBtn);

        hSavePrivBtn = CreateWindowW(L"BUTTON", L"Save PrivKey",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            450, 170, 140, 25, hwnd, (HMENU)IDC_SAVE_PRIV_BTN, hInst, NULL);
        add_string_control(hSavePrivBtn);

        HWND hPrivLabel = CreateWindowW(L"STATIC", L"Private Key:",
            WS_CHILD | WS_VISIBLE, 450, 200, 100, 20, hwnd, NULL, hInst, NULL);
        add_string_control(hPrivLabel);

        hRSAPrvEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            450, 220, 300, 70, hwnd, (HMENU)IDC_RSA_PRIV_EDIT, hInst, NULL);
        add_string_control(hRSAPrvEdit);

        HWND hPubLabel = CreateWindowW(L"STATIC", L"Public Key:",
            WS_CHILD | WS_VISIBLE, 450, 300, 100, 20, hwnd, NULL, hInst, NULL);
        add_string_control(hPubLabel);

        hRSAPubEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            450, 320, 300, 70, hwnd, (HMENU)IDC_RSA_PUB_EDIT, hInst, NULL);
        add_string_control(hRSAPubEdit);

        // ==================== File Mode 控件 ====================
        HWND hFilePathLabel2 = CreateWindowW(L"STATIC", L"File Path:",
            WS_CHILD | WS_VISIBLE, 20, 50, 80, 20, hwnd, NULL, hInst, NULL);
        add_file_control(hFilePathLabel2);

        hFilePathEdit2 = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            20, 70, 300, 25, hwnd, (HMENU)IDC_FILEPATH_EDIT2, hInst, NULL);  // 宽度从400改为300
        add_file_control(hFilePathEdit2);

        hBrowseBtn2 = CreateWindowW(L"BUTTON", L"Browse...",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            330, 70, 80, 25, hwnd, (HMENU)IDC_BROWSE_FileBTN, hInst, NULL);  // x位置从430改为330
        add_file_control(hBrowseBtn2);

        // 对称密钥区域
        HWND hFileKeyLabel = CreateWindowW(L"STATIC", L"Sym Key:",
            WS_CHILD | WS_VISIBLE, 20, 110, 80, 20, hwnd, NULL, hInst, NULL);
        add_file_control(hFileKeyLabel);

        hFileKeyEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            100, 110, 220, 25, hwnd, (HMENU)IDC_KEY_EDIT_FILE, hInst, NULL);  // 宽度从320改为220
        add_file_control(hFileKeyEdit);
        HWND hFilePLabel = CreateWindowW(L"STATIC", L"p位数:",
            WS_CHILD | WS_VISIBLE, 20, 190, 60, 20, hwnd, NULL, hInst, NULL);
        add_file_control(hFilePLabel);

        hFilePEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"512",
            WS_CHILD | WS_VISIBLE | ES_NUMBER,
            80, 190, 60, 20, hwnd, (HMENU)IDC_FILE_P_EDIT, hInst, NULL);
        add_file_control(hFilePEdit);

        HWND hFileQLabel = CreateWindowW(L"STATIC", L"q位数:",
            WS_CHILD | WS_VISIBLE, 150, 190, 60, 20, hwnd, NULL, hInst, NULL);
        add_file_control(hFileQLabel);

        hFileQEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"512",
            WS_CHILD | WS_VISIBLE | ES_NUMBER,
            210, 190, 60, 20, hwnd, (HMENU)IDC_FILE_Q_EDIT, hInst, NULL);
        add_file_control(hFileQEdit);
        // 文件操作按钮
        hFileSendBtn = CreateWindowW(L"BUTTON", L"Send",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            20, 150, 120, 30, hwnd, (HMENU)IDM_SEND_FILE, hInst, NULL);
        add_file_control(hFileSendBtn);

        hFileReceiveBtn = CreateWindowW(L"BUTTON", L"Receive",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            150, 150, 120, 30, hwnd, (HMENU)IDM_RECEIVE_FILE, hInst, NULL);
        add_file_control(hFileReceiveBtn);

        // 算法和哈希选择
        HWND hAlgoLabelFile = CreateWindowW(L"STATIC", L"Algorithm:",
            WS_CHILD | WS_VISIBLE, 20, 200, 80, 20, hwnd, NULL, hInst, NULL);
        add_file_control(hAlgoLabelFile);

        hFileAlgoCombo = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            20, 220, 100, 200, hwnd, (HMENU)IDC_ALGO_COMBO_FILE, hInst, NULL);
        SendMessageW(hFileAlgoCombo, CB_ADDSTRING, 0, (LPARAM)L"AES");
        SendMessageW(hFileAlgoCombo, CB_ADDSTRING, 0, (LPARAM)L"DES");
        SendMessageW(hFileAlgoCombo, CB_SETCURSEL, 0, 0);
        add_file_control(hFileAlgoCombo);

        HWND hHashLabelFile = CreateWindowW(L"STATIC", L"Hash:",
            WS_CHILD | WS_VISIBLE, 140, 200, 80, 20, hwnd, NULL, hInst, NULL);
        add_file_control(hHashLabelFile);

        hFileHashCombo = CreateWindowW(L"COMBOBOX", L"",
            WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST,
            140, 220, 100, 200, hwnd, (HMENU)IDC_HASH_COMBO_FILE, hInst, NULL);
        SendMessageW(hFileHashCombo, CB_ADDSTRING, 0, (LPARAM)L"MD5");
        SendMessageW(hFileHashCombo, CB_ADDSTRING, 0, (LPARAM)L"SHA256");
        SendMessageW(hFileHashCombo, CB_SETCURSEL, 1, 0);
        add_file_control(hFileHashCombo);

        // File Mode 右侧密钥管理区域
        hFileGenerateBtn = CreateWindowW(L"BUTTON", L"Generate Keys",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            600, 50, 140, 25, hwnd, (HMENU)IDM_GEN_RSA, hInst, NULL);
        add_file_control(hFileGenerateBtn);

        hFileLoadPubBtn = CreateWindowW(L"BUTTON", L"Load Peer PubKey",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            600, 80, 140, 25, hwnd, (HMENU)IDC_LOAD_PUB_BTN, hInst, NULL);
        add_file_control(hFileLoadPubBtn);

        hFileLoadPrivBtn = CreateWindowW(L"BUTTON", L"Load Own PrivKey",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            600, 110, 140, 25, hwnd, (HMENU)IDC_LOAD_PRIV_BTN, hInst, NULL);
        add_file_control(hFileLoadPrivBtn);

        hFileSavePubBtn = CreateWindowW(L"BUTTON", L"Save PubKey",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            600, 140, 140, 25, hwnd, (HMENU)IDC_SAVE_PUB_BTN, hInst, NULL);
        add_file_control(hFileSavePubBtn);

        hFileSavePrivBtn = CreateWindowW(L"BUTTON", L"Save PrivKey",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            600, 170, 140, 25, hwnd, (HMENU)IDC_SAVE_PRIV_BTN, hInst, NULL);
        add_file_control(hFileSavePrivBtn);

        hFilePrivLabel = CreateWindowW(L"STATIC", L"Private Key:",
            WS_CHILD | WS_VISIBLE, 450, 200, 100, 20, hwnd, NULL, hInst, NULL);
        add_file_control(hFilePrivLabel);

        hFileRSAPrvEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            450, 220, 300, 70, hwnd, (HMENU)IDC_RSA_PRIV_EDIT, hInst, NULL);
        add_file_control(hFileRSAPrvEdit);

        hFilePubLabel = CreateWindowW(L"STATIC", L"Public Key:",
            WS_CHILD | WS_VISIBLE, 450, 300, 100, 20, hwnd, NULL, hInst, NULL);
        add_file_control(hFilePubLabel);

        hFileRSAPubEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | ES_LEFT | ES_MULTILINE | ES_AUTOVSCROLL | WS_VSCROLL,
            450, 320, 300, 70, hwnd, (HMENU)IDC_RSA_PUB_EDIT, hInst, NULL);
        add_file_control(hFileRSAPubEdit);
        // 调整File Mode其他控件位置
        MoveWindow(hFileSendBtn, 20, 275, 120, 30, TRUE);
        MoveWindow(hFileReceiveBtn, 140, 275, 120, 30, TRUE);
        MoveWindow(hAlgoLabelFile, 20, 230, 80, 20, TRUE);
        MoveWindow(hFileAlgoCombo, 20, 250, 100, 200, TRUE);
        MoveWindow(hHashLabelFile, 140, 230, 80, 20, TRUE);
        MoveWindow(hFileHashCombo, 140, 250, 100, 200, TRUE);

        show_tab_controls(0);
        SetWindowTextA(hOutputEdit, "程序分为String Mode和File Mode两种模式。整个中间过程和中间值可以通过下方的output窗口查看\r\n"
            "整个过程中使用的RSA、AES、DES、MD5和SHA256等算法都是自己实现的，没有调用外部包\r\n"
            "在String Mode中：\r\n"
            "\t1、可以通过“Algorithm：”选择对称加密算法，通过“Hash：”选择哈希算法\r\n"
            "\t2、左侧空白部分用于输入需要传输的信息\r\n"
            "\t3、可以通过【Browse...】按钮选择.txt文件，显示在下方的需要传输的内容区域。注意：只能英文路径！！！\r\n"
            "\t4、在素数p和q的位数栏目中可以指定p和q的位数（p/q位数限制在64到4096中）\r\n"
            "\t5、【Generate Keys】按钮用于自动生成对称密钥和非对称加密算法RSA的公私钥，并输出在【Sym Key】【Private Key】【Public Key】的窗口中\r\n"
            "\t6、【Load Peer PubKey】按钮用于导入对方的公钥\r\n"
            "\t7、【Load Own PrivKey】按钮用于导入自己的私钥\r\n"
            "\t8、【Save PubKey】按钮用于保存【Generate Keys】按钮生成的非对称密码的公钥\r\n"
            "\t9、【Save PrivKey】按钮用于保存【Generate Keys】按钮生成的非对称密码的私钥\r\n"
            "\t10、通过【Send】【Receive】按钮进行发送和接收操作\r\n"
            "在File Mode中：\r\n"
            "\t1、可以通过【Browse】按钮导入需要发送的文件---注意路径应该为英文路径！！！\r\n"
            "\t2、其他按钮和编辑框的功能与String Mode相同\r\n"
            "操作流程：\r\n"
            "\t1、通过“Algorithm：”选择对称加密算法，通过“Hash：”选择哈希算法，在素数p和q的位数栏目中指定p和q的位数\r\n"
            "\t2、左侧空白部分输入需要传输的信息（在File Mode中则选择需要传输的文件）\r\n"
            "\t3、按下【Generate Keys】按钮生成对称密钥和非对称加密算法RSA的公私钥\r\n"
            "\t4、分别按下【Save PubKey】和【Save PrivKey】按钮用于保存非对称密码的公私钥\r\n"
            "\t5、上述步骤3和4执行两次得到A和B的公私钥后，按下【Load Peer PubKey】按钮导入B的公钥，按下【Load Own PrivKey】按钮导入A的私钥\r\n"
            "\t6、A按下【Send】按钮发送消息到B，得到相关的加密文件等\r\n"
            "\t7、按下【Load Peer PubKey】按钮导入A的公钥，按下【Load Own PrivKey】按钮导入B的私钥\r\n"
            "\t8、B按下【Receive】按钮接收消息，得到解密后的文件\r\n"
            "\r\n"
            "整个中间过程和中间值可以通过下方的output窗口查看\r\n"
            "程序启动。请选择操作并点击对应按钮。\r\n");
        break;
    }

    case WM_GETMINMAXINFO: {
        MINMAXINFO* mmi = (MINMAXINFO*)lParam;
        mmi->ptMinTrackSize.x = 850;  // 最小宽度
        mmi->ptMinTrackSize.y = 650;  // 最小高度
        return 0;
    }

    case WM_SIZE: {
        g_windowWidth = LOWORD(lParam);
        g_windowHeight = HIWORD(lParam);

        // 调整p、q位数输入框位置
        int stringModeY = 350;  // 根据实际布局调整
        int fileModeY = 190;    // 根据实际布局调整
        // 计算可用区域
        int margin = 10;
        int outputHeight = 200;
        int outputTop = g_windowHeight - outputHeight - margin;

        // 调整标签控件大小
        MoveWindow(hTab, margin, margin, g_windowWidth - 2 * margin, 400, TRUE);

        // 调整输出文本框大小
        MoveWindow(hOutputEdit, margin, outputTop, g_windowWidth - 2 * margin, outputHeight, TRUE);

        // 调整右侧区域控件宽度
        int rightWidth = g_windowWidth - 470;
        if (rightWidth < 300) rightWidth = 300;

        // String Mode 控件调整
        MoveWindow(hRSAPrvEdit, 450, 220, rightWidth, 70, TRUE);
        MoveWindow(hRSAPubEdit, 450, 320, rightWidth, 70, TRUE);

        // File Mode 控件调整 - 更新布局计算
        int fileInputWidth = g_windowWidth - 470;  // 为右侧区域留出更多空间
        if (fileInputWidth < 300) fileInputWidth = 300;

        // File Mode 右侧区域
        MoveWindow(hFileRSAPrvEdit, 450, 220, rightWidth, 70, TRUE);
        MoveWindow(hFileRSAPubEdit, 450, 320, rightWidth, 70, TRUE);
        if (hPEdit && hQEdit) {
            MoveWindow(hPEdit, 80, stringModeY, 60, 20, TRUE);
            MoveWindow(hQEdit, 210, stringModeY, 60, 20, TRUE);
        }

        if (hFilePEdit && hFileQEdit) {
            MoveWindow(hFilePEdit, 80, fileModeY, 60, 20, TRUE);
            MoveWindow(hFileQEdit, 210, fileModeY, 60, 20, TRUE);
        }

        InvalidateRect(hwnd, NULL, TRUE);
        break;
    }

    case WM_NOTIFY: {
        NMHDR* nmhdr = (NMHDR*)lParam;
        if (nmhdr->hwndFrom == hTab && nmhdr->code == TCN_SELCHANGE) {
            int selectedTab = TabCtrl_GetCurSel(hTab);
            show_tab_controls(selectedTab);
            append_output("Tab changed to: %d\n", selectedTab);
        }
        break;
    }

    case WM_COMMAND: {
        int id = LOWORD(wParam);
        int event = HIWORD(wParam);

        if (event != BN_CLICKED) {
            break;
        }

        append_output("Button clicked: ID=%d\n", id);

        switch (id) {
            // 在 Generate Keys 按钮处理中设置密钥生成标志
        case IDM_GEN_RSA: {
            // 获取p和q的位数
            char p_bits_str[16] = { 0 };
            char q_bits_str[16] = { 0 };
            int p_bits = 512, q_bits = 512;  // 默认值

            // 根据当前标签页获取对应的输入框
            int selectedTab = TabCtrl_GetCurSel(hTab);
            if (selectedTab == 0) {  // String Mode
                if (hPEdit) {
                    GetWindowTextA(hPEdit, p_bits_str, sizeof(p_bits_str));
                    append_output("String Mode - p bits: %s\n", p_bits_str);
                }
                if (hQEdit) {
                    GetWindowTextA(hQEdit, q_bits_str, sizeof(q_bits_str));
                    append_output("String Mode - q bits: %s\n", q_bits_str);
                }
            }
            else {  // File Mode
                if (hFilePEdit) {
                    GetWindowTextA(hFilePEdit, p_bits_str, sizeof(p_bits_str));
                    append_output("File Mode - p bits: %s\n", p_bits_str);
                }
                if (hFileQEdit) {
                    GetWindowTextA(hFileQEdit, q_bits_str, sizeof(q_bits_str));
                    append_output("File Mode - q bits: %s\n", q_bits_str);
                }
            }

            // 转换为整数
            p_bits = atoi(p_bits_str);
            q_bits = atoi(q_bits_str);

            // 调试信息：显示转换后的值
            append_output("Parsed p_bits=%d, q_bits=%d\n", p_bits, q_bits);

            // 验证输入
            if (p_bits < 64 || p_bits > 4096 || q_bits < 64 || q_bits > 4096) {
                append_output("Error: p and q bits must be between 64 and 4096\n");
                break;
            }

            append_output("Generating RSA with p=%d bits, q=%d bits...\n", p_bits, q_bits);

            if (!generate_rsa_keypair_with_primes(p_bits, q_bits)) {
                append_output("RSA generation failed.\n");
            }
            else {
                append_output("RSA key pair generated successfully.\n");

                // 显示对称密钥
                char* sym_key_hex = bin_to_hex(g_generated_sym_key, 32);
                if (sym_key_hex) {
                    SetWindowTextA(hKeyEdit, sym_key_hex);
                    SetWindowTextA(hFileKeyEdit, sym_key_hex);
                    append_output("Symmetric key generated and displayed.\n");
                    free(sym_key_hex);
                }
            }
            break;
        }
        case IDM_SEND: {
            append_output("Send (full hybrid) clicked.\n");
            char algo[16] = "AES";
            int aidx = (int)SendMessageA(hAlgoCombo, CB_GETCURSEL, 0, 0);
            if (aidx == 0) strcpy(algo, "AES"); else strcpy(algo, "DES");
            sender_full_flow_string(algo);
            break;
        }
        case IDM_RECEIVE: {
            append_output("Receive (full hybrid) clicked.\n");
            char algo[16] = "AES";
            int aidx = (int)SendMessageA(hAlgoCombo, CB_GETCURSEL, 0, 0);
            if (aidx == 0) strcpy(algo, "AES"); else strcpy(algo, "DES");
            receiver_full_flow_string(algo);
            break;
        }
        case IDM_SEND_FILE: {
            append_output("File Send clicked.\n");
            char filepath[1024];
            GetWindowTextA(hFilePathEdit2, filepath, sizeof(filepath));
            if (strlen(filepath) == 0) {
                append_output("Please select a file first.\n");
                break;
            }
            char algo[16] = "AES";
            int aidx = (int)SendMessageA(hFileAlgoCombo, CB_GETCURSEL, 0, 0);
            if (aidx == 0) strcpy(algo, "AES"); else strcpy(algo, "DES");
            sender_full_flow_file(filepath, algo);
            break;
        }
        case IDM_RECEIVE_FILE: {
            append_output("File Receive clicked.\n");
            char filepath[1024];
            GetWindowTextA(hFilePathEdit2, filepath, sizeof(filepath));
            if (strlen(filepath) == 0) {
                append_output("Please select a file first.\n");
                break;
            }
            char algo[16] = "AES";
            int aidx = (int)SendMessageA(hFileAlgoCombo, CB_GETCURSEL, 0, 0);
            if (aidx == 0) strcpy(algo, "AES"); else strcpy(algo, "DES");
            receiver_full_flow_file(filepath, algo);
            break;
        }
        case IDC_LOAD_PRIV_BTN: {
            append_output("Loading own private key...\n");
            char path[1024];
            if (open_file_dialog(path, sizeof(path))) {
                if (!load_private_key_manual(path)) append_output("Failed to load private key from %s\n", path);
            }
            break;
        }
        case IDC_LOAD_PUB_BTN: {
            append_output("Loading peer public key...\n");
            char path[1024];
            if (open_file_dialog(path, sizeof(path))) {
                if (!load_public_key_manual(path)) append_output("Failed to load peer public key from %s\n", path);
            }
            break;
        }
        case IDC_BROWSE_BTN: {
            append_output("Browsing for file...\n");
            char path[1024];
            if (open_file_dialog(path, sizeof(path))) {
                wchar_t wpath[1024];
                MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 1024);
                SetWindowTextW(hFilePathEdit, wpath);
                append_output("Selected file: %s\n", path);

                // 检查当前标签页，如果是String Mode则读取文件内容
                int selectedTab = TabCtrl_GetCurSel(hTab);
                if (selectedTab == 0) { // String Mode
                    // 检查文件扩展名是否为.txt
                    const char* ext = strrchr(path, '.');
                    if (ext && _stricmp(ext, ".txt") == 0) {
                        // 读取文件内容
                        size_t file_len;
                        unsigned char* file_data = read_file_all(path, &file_len);
                        if (file_data) {
                            // 检查文件内容是否符合要求（主要是文本内容）
                            int is_valid_text = 1;
                            for (size_t i = 0; i < file_len; i++) {
                                // 检查是否为可打印字符或常见控制字符
                                if (file_data[i] < 0x20 && file_data[i] != '\r' && file_data[i] != '\n' && file_data[i] != '\t') {
                                    is_valid_text = 0;
                                    break;
                                }
                            }

                            if (is_valid_text) {
                                // 将文件内容转换为宽字符并显示在输入框中
                                int wlen = MultiByteToWideChar(CP_UTF8, 0, (char*)file_data, (int)file_len, NULL, 0);
                                if (wlen > 0) {
                                    wchar_t* wbuf = (wchar_t*)malloc((wlen + 1) * sizeof(wchar_t));
                                    if (wbuf) {
                                        MultiByteToWideChar(CP_UTF8, 0, (char*)file_data, (int)file_len, wbuf, wlen);
                                        wbuf[wlen] = 0;
                                        SetWindowTextW(hInputEdit, wbuf);
                                        free(wbuf);
                                        append_output("File content loaded into input edit.\n");
                                    }
                                }
                            }
                            else {
                                append_output("Error: File contains binary data. Only text files are supported in String Mode.\n");
                            }
                            free(file_data);
                        }
                        else {
                            append_output("Error: Failed to read file.\n");
                        }
                    }
                    else {
                        append_output("Error: Only .txt files are supported in String Mode.\n");
                    }
                }
            }
            break;
        }
        case IDC_BROWSE_FileBTN: {
            append_output("Browsing for file...\n");
            char path[1024];
            if (open_file_dialog(path, sizeof(path))) {
                wchar_t wpath[1024];
                MultiByteToWideChar(CP_UTF8, 0, path, -1, wpath, 1024);
                SetWindowTextW(hFilePathEdit2, wpath);
                append_output("Selected file: %s\n", path);
            }
            break;
        }
        case IDC_SAVE_PRIV_BTN: {
            append_output("Saving private key...\n");
            save_privkey_to_file_dialog();
            break;
        }
        case IDC_SAVE_PUB_BTN: {
            append_output("Saving public key...\n");
            save_pubkey_to_file_dialog();
            break;
        }
        default:
            append_output("Unhandled button ID: %d\n", id);
            break;
        }
        break;
    }

    case WM_DESTROY:
        if (g_own_rsa) { RSA_free(g_own_rsa); g_own_rsa = NULL; }
        if (g_peer_rsa) { RSA_free(g_peer_rsa); g_peer_rsa = NULL; }
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProcW(hwnd, msg, wParam, lParam);
    }
    return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    hInst = hInstance;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();
    RAND_load_file(NULL, 0);

    WNDCLASSW wc = { 0 };
    wc.lpfnWndProc = MainWndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"CryptoToolFullFlowClass";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&wc);

    hMainWnd = CreateWindowExW(0, L"CryptoToolFullFlowClass", L"加密签名工具 - FullFlow (PEM save/load)",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, g_windowWidth, g_windowHeight, NULL, NULL, hInstance, NULL);

    if (!hMainWnd) {
        MessageBoxW(NULL, L"窗口创建失败!", L"错误", MB_ICONERROR);
        return 1;
    }

    ShowWindow(hMainWnd, nCmdShow);
    UpdateWindow(hMainWnd);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    return (int)msg.wParam;
}