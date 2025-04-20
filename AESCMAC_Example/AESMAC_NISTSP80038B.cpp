//
// This implementation of CMAC is based on NIST SP 800-38B,
// “Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication”.
// It uses AES-128 as the underlying block cipher.
//
// Steps:
//  1. Generate subkeys K1 and K2 from key K by encrypting a 0-block,
//     then left-shifting and conditionally XORing with Rb (for AES, Rb = 0x87).
//  2. Format the input message M: partition M into 16-byte blocks;
//     if the last block is complete, XOR it with K1, else pad (with 0x80 followed by zeros)
//     and XOR with K2.
//  3. Compute C0 = 0^128, then for i = 1 to n, compute Ci = AES_Encrypt( Ci-1 + Mi ).
//  4. The MAC T is the most-significant Tlen bits of Cn.
// 
// For demonstration, the full MAC (128 bits) is output. 
// To truncate the MAC to a smaller bit-length, change the Tlen parameter.

#include <cstring>
#include <iostream>
#include <iomanip>
#include <string>


//#define TEST_MAC_1
//#define TEST_MAC_2
#define TEST_MAC_3
//#define TEST_CRYPTO


// Define a byte type.
using byte = uint8_t;

// ---------------------- AES-128 Implementation ----------------------

// AES S-box (FIPS 197)
static const byte sbox[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

// Round constants for key expansion
static const byte Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08,
    0x10, 0x20, 0x40, 0x80, 0x1B,
    0x36
};

// Multiply by 2 in GF(2^8)
static inline byte xtime(byte x) 
{
    return (byte)((x << 1) ^ ((x & 0x80) ? 0x1b : 0));
}

// Expands a 16-byte AES key into a 176-byte round key array.
static void KeyExpansion(const byte key[16], byte roundKeys[176]) 
{
    memcpy(roundKeys, key, 16);
    int bytesGenerated = 16;
    int rconIteration = 1;
    byte temp[4];

    while (bytesGenerated < 176) 
    {
        for (int i = 0; i < 4; i++)
            temp[i] = roundKeys[bytesGenerated - 4 + i];

        if (bytesGenerated % 16 == 0) {
            // RotWord: cyclic left shift.
            byte t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // SubWord: apply the S-box.
            for (int i = 0; i < 4; i++)
                temp[i] = sbox[temp[i]];
            // XOR with round constant.
            temp[0] ^= Rcon[rconIteration];
            rconIteration++;
        }
        for (int i = 0; i < 4; i++)
        {
            roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 16] ^ temp[i];
            bytesGenerated++;
        }
    }
}

// AddRoundKey: XORs the state with the round key.
static void AddRoundKey(byte state[4][4], const byte roundKey[16]) 
{
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] ^= roundKey[c * 4 + r]; // Column-major order.
}

// SubBytes: applies the S-box to every byte of the state.
static void SubBytes(byte state[4][4]) 
{
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            state[r][c] = sbox[state[r][c]];
}

// ShiftRows: cyclically shifts each row of the state to the left by its row index.
static void ShiftRows(byte state[4][4])
{
    byte temp[4];
    // Row 1 shift by 1.
    temp[0] = state[1][0]; temp[1] = state[1][1];
    temp[2] = state[1][2]; temp[3] = state[1][3];
    state[1][0] = temp[1]; state[1][1] = temp[2];
    state[1][2] = temp[3]; state[1][3] = temp[0];

    // Row 2 shift by 2.
    temp[0] = state[2][0]; temp[1] = state[2][1];
    temp[2] = state[2][2]; temp[3] = state[2][3];
    state[2][0] = temp[2]; state[2][1] = temp[3];
    state[2][2] = temp[0]; state[2][3] = temp[1];

    // Row 3 shift by 3 (or right by 1).
    temp[0] = state[3][0]; temp[1] = state[3][1];
    temp[2] = state[3][2]; temp[3] = state[3][3];
    state[3][0] = temp[3]; state[3][1] = temp[0];
    state[3][2] = temp[1]; state[3][3] = temp[2];
}

// MixColumns: mixes the columns of the state.
static void MixColumns(byte state[4][4]) 
{
    for (int c = 0; c < 4; c++) 
    {
        byte a0 = state[0][c];
        byte a1 = state[1][c];
        byte a2 = state[2][c];
        byte a3 = state[3][c];
        byte r0 = xtime(a0) ^ (a1 ^ xtime(a1)) ^ a2 ^ a3;
        byte r1 = a0 ^ xtime(a1) ^ (a2 ^ xtime(a2)) ^ a3;
        byte r2 = a0 ^ a1 ^ xtime(a2) ^ (a3 ^ xtime(a3));
        byte r3 = (a0 ^ xtime(a0)) ^ a1 ^ a2 ^ xtime(a3);
        state[0][c] = r0;
        state[1][c] = r1;
        state[2][c] = r2;
        state[3][c] = r3;
    }
}

// Encrypts a single 16-byte block using AES-128.
static void AES_Encrypt_Block(const byte in[16], byte out[16], const byte roundKeys[176])
{
    byte state[4][4];
    // Copy input into state (column-major order).
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            state[r][c] = in[c * 4 + r];

    AddRoundKey(state, roundKeys);

    for (int round = 1; round <= 9; round++) 
    {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, roundKeys + round * 16);
    }

    // Final round (without MixColumns).
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, roundKeys + 10 * 16);

    // Copy state to output.
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            out[c * 4 + r] = state[r][c];
}

// ---------------------- CMAC Implementation ----------------------

// LeftShiftBlock: left shifts a 16-byte block by one bit.
static void LeftShiftBlock(const byte in[16], byte out[16]) 
{
    byte carry = 0;
    for (int i = 15; i >= 0; i--) 
    {
        out[i] = (in[i] << 1) | carry;
        carry = (in[i] & 0x80) ? 1 : 0;
    }
}

// XorBlocks: XORs two 16-byte blocks (out = a xor b).
static void XorBlocks(const byte a[16], const byte b[16], byte out[16]) 
{
    for (int i = 0; i < 16; i++)
        out[i] = a[i] ^ b[i];
}

// GenerateSubkeys: Implements the subkey generation (Section 6.1 of NIST SP 800-38B).
// For AES-128 (b = 128), the constant Rb is 0x87.
static void GenerateSubkeys(const byte key[16], byte K1[16], byte K2[16]) 
{
    byte roundKeys[176];
    KeyExpansion(key, roundKeys);
    byte L[16] = { 0 };
    byte zeroBlock[16] = { 0 };
    // Step 1: L = CIPHK(0^128)
    AES_Encrypt_Block(zeroBlock, L, roundKeys);

    byte tmp[16];
    // Step 2: Compute K1 = L << 1; if MSB(L)==1, then K1 = (L << 1) + Rb.
    LeftShiftBlock(L, tmp);
    if (L[0] & 0x80)
    {
        tmp[15] ^= 0x87; // Rb for AES-128.
    }
    memcpy(K1, tmp, 16);

    // Step 3: Compute K2 = K1 << 1; if MSB(K1)==1, then K2 = (K1 << 1) + Rb.
    LeftShiftBlock(K1, tmp);
    if (K1[0] & 0x80) 
    {
        tmp[15] ^= 0x87;
    }
    memcpy(K2, tmp, 16);
}

// CMAC: Computes the CMAC of message M using key K.
// Tlen is the desired output MAC length in bits (Tlen ≤ 128).
// This follows the steps in Section 6.2 of NIST SP 800-38B.
void CMAC(const byte key[16], const byte* message, size_t messageLen, int Tlen, byte mac[16]) 
{
    // 1. Generate subkeys K1 and K2.
    byte K1[16], K2[16];
    GenerateSubkeys(key, K1, K2);

    // 2. Let n = ceil(messageLen / 128). If message is empty, set n = 1.
    size_t n = (messageLen + 15) / 16;
    bool complete;
    if (messageLen == 0) 
    {
        n = 1;
        complete = false;
    }
    else 
    {
        complete = (messageLen % 16 == 0);
    }

    // 3. Prepare the last block.
    byte M_last[16] = { 0 };
    if (complete) 
    {
        // If the last block is complete, set M_last = Mn xor K1.
        memcpy(M_last, message + (n - 1) * 16, 16);
        XorBlocks(M_last, K1, M_last);
    }
    else
    {
        // Otherwise, pad the last block: append '1' bit (0x80) then zeros,
        // and set M_last = (Mn* || padding) + K2.
        size_t rem = messageLen % 16;
        memset(M_last, 0, 16);
        if (rem > 0) 
        {
            memcpy(M_last, message + (n - 1) * 16, rem);
        }
        M_last[rem] = 0x80;
        XorBlocks(M_last, K2, M_last);
    }

    // 4. Initialize C0 = 0^128.
    byte X[16] = { 0 };
    byte Y[16];
    byte block[16];

    // Precompute round keys for AES.
    byte roundKeys[176];
    KeyExpansion(key, roundKeys);

    // 5. For i = 1 to n-1, compute Ci = CIPHK(Ci-1 + Mi).
    for (size_t i = 0; i < n - 1; i++) 
    {
        memcpy(block, message + i * 16, 16);
        XorBlocks(X, block, Y);
        AES_Encrypt_Block(Y, X, roundKeys);
    }
    // 6. Process the last block.
    XorBlocks(X, M_last, Y);
    AES_Encrypt_Block(Y, X, roundKeys);

    // X now holds the full 128-bit MAC.
    memcpy(mac, X, 16);

    // 7. If Tlen < 128, truncate the MAC to its Tlen most significant bits.
    // (For simplicity, this implementation assumes Tlen is a multiple of 8;
    // if not, the last byte is masked appropriately.)
    int fullBytes = Tlen / 8;
    int remBits = Tlen % 8;
    if (Tlen < 128)
    {
        for (int i = fullBytes; i < 16; i++)
        {
            mac[i] = 0;
        }
        if (remBits != 0 && fullBytes < 16) 
        {
            mac[fullBytes] &= (0xFF << (8 - remBits));
        }
    }
}

// ---------------------- Main Demo ----------------------
int main() 
{
    // Example key (AES-128): 000102030405060708090a0b0c0d0e0f
    byte key[16]       = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    byte key1[16]      = { 0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01,0x00,0x01 };
    byte key2[16]      = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
    byte key3[16]      = { 0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c };

    byte plaintext[16] = { 0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff };
    byte Message1[16]  = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a };
    byte Message2[64]  = { 0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                           0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51,
                           0x30,0xc8,0x1c,0x46,0xa3,0x5c,0xe4,0x11,0xe5,0xfb,0xc1,0x19,0x1a,0x0a,0x52,0xef,
                           0xf6,0x9f,0x24,0x45,0xdf,0x4f,0x9b,0x17,0xad,0x2b,0x41,0x7b,0xe6,0x6c,0x37,0x10 };
    byte Message3[58]  = { 0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
                           0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
                           0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 
                           0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
    
    byte fullMAC[16];

    // Desired MAC length in bits. (Set Tlen = 128 for full MAC, or a smaller value to truncate.)
    int Trunclen = 53;  // Change, for example, to 64 or 53 as needed.

#ifdef TEST_MAC_1
    // Example message.
    std::string msg = "The quick brown fox jumps over the lazy dog";
    size_t msgLen = msg.size();

    CMAC(key, reinterpret_cast<const byte*>(msg.c_str()), msgLen, Tlen, fullMAC);

    std::cout << "CMAC (truncated to " << Tlen << " bits): ";
    for (int i = 0; i < 16; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << (int)fullMAC[i];
    }
#endif
    

#ifdef TEST_MAC_2
    CMAC(key1, Message1, 16, Trunclen, fullMAC);
    std::cout << "Full AES-CMAC (128-bit) = ";
    for (int i = 0; i < 16; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)fullMAC[i];
    }
    std::cout << std::endl;
#endif // TEST_MAC_2


#ifdef TEST_MAC_3
    CMAC(key1, Message3, 58, Trunclen, fullMAC);
    std::cout << "Full AES-CMAC (128-bit) = ";
    for (int i = 0; i < 16; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)fullMAC[i];
    }
    std::cout << std::endl;
#endif // TEST_MAC_3


    std::cout << std::endl;

    return 0;
}
