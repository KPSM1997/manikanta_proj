#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>

// Constants for SHA-256
const unsigned int K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// SHA-256 Functions
unsigned int ROTR(unsigned int a, unsigned int b) {
    return (a >> b) | (a << (32 - b));
}

unsigned int CH(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (~x & z);
}

unsigned int MAJ(unsigned int x, unsigned int y, unsigned int z) {
    return (x & y) ^ (x & z) ^ (y & z);
}

unsigned int EP0(unsigned int x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

unsigned int EP1(unsigned int x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

unsigned int SIG0(unsigned int x) {
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

unsigned int SIG1(unsigned int x) {
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

void SHA256Transform(unsigned int state[8], const unsigned char data[64]) {
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void SHA256Init(unsigned int state[8]) {
    state[0] = 0x6a09e667;
    state[1] = 0xbb67ae85;
    state[2] = 0x3c6ef372;
    state[3] = 0xa54ff53a;
    state[4] = 0x510e527f;
    state[5] = 0x9b05688c;
    state[6] = 0x1f83d9ab;
    state[7] = 0x5be0cd19;
}

void SHA256Update(unsigned int state[8], const unsigned char data[], unsigned int len, unsigned long long& bitlen, unsigned char buffer[64], unsigned int& data_len) {
    bitlen += len * 8;  // Add length of data in bits to the total bit length

    unsigned int i = 0;

    // If there's leftover data in buffer, try to fill it up
    if (data_len > 0) {
        while (i < len && data_len < 64) {
            buffer[data_len++] = data[i++];
        }

        if (data_len == 64) {
            SHA256Transform(state, buffer);
            data_len = 0;
        }
    }

    // Process as many 64-byte chunks as possible directly from input
    while (i + 63 < len) {
        SHA256Transform(state, &data[i]);
        i += 64;
    }

    // Copy remaining data into buffer
    while (i < len) {
        buffer[data_len++] = data[i++];
    }
}

void SHA256Final(unsigned int state[8], unsigned char hash[32], unsigned long long bitlen, unsigned char buffer[64], unsigned int data_len) {
    // Append the 0x80 padding byte
    buffer[data_len++] = 0x80;

    // Pad the buffer with zeros if there is not enough space to store the bit length
    if (data_len > 56) {
        std::memset(buffer + data_len, 0, 64 - data_len);
        SHA256Transform(state, buffer);
        data_len = 0;
    }

    // Pad remaining bytes with zeros, leaving space for bit length
    std::memset(buffer + data_len, 0, 56 - data_len);

    // Append the total bit length to the last 8 bytes
    for (int i = 7; i >= 0; --i) {
        buffer[63 - i] = (bitlen >> (i * 8)) & 0xFF;
    }

    SHA256Transform(state, buffer);

    // Convert the state to the final hash value
    for (int i = 0; i < 8; ++i) {
        hash[i * 4] = (state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = state[i] & 0xFF;
    }
}

// Helper function to get the content of a file
std::string getFileContent(const std::string& fileName) {
    std::ifstream file(fileName);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    std::string fileName = "MANIKANTA_PROJ.txt";  // File name

    std::string fileContent = getFileContent(fileName);  // Reading file content

    unsigned int state[8];
    SHA256Init(state);

    const unsigned char* data = reinterpret_cast<const unsigned char*>(fileContent.c_str());
    unsigned int len = fileContent.size();

    unsigned long long bitlen = 0;  // To track the total bit length

    unsigned char buffer[64];  // Buffer for partial blocks
    unsigned int data_len = 0;  // Length of partial data
    SHA256Update(state, data, len, bitlen, buffer, data_len);

    unsigned char hash[32];
    SHA256Final(state, hash, bitlen, buffer, data_len);

    std::cout << "SHA-256 hash: ";
    for (int i = 0; i < 32; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::endl;

    return 0;
}
