#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <vector>

#ifdef CYPRESS_32_BIT
typedef uint32_t WordType;
#define HEX_DIGITS_IN_WORD 8
#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))
#define HALFROUND32(a, b, c, d) \
    {                           \
        a += b;                 \
        d ^= a;                 \
        d = ROTL32(d, 16);      \
        c += d;                 \
        b ^= c;                 \
        b = ROTL32(b, 12);      \
        a += b;                 \
        d ^= a;                 \
        d = ROTL32(d, 8);       \
        c += d;                 \
        b ^= c;                 \
        b = ROTL32(b, 7);       \
    }
#define NUM_OF_ROUNDS 10
#else
typedef uint64_t WordType;
#define HEX_DIGITS_IN_WORD 16
#define ROTL64(v, n) ((v) << (n)) | ((v) >> (64 - (n)))
#define HALFROUND64(a, b, c, d) \
    {                           \
        a += b;                 \
        d ^= a;                 \
        d = ROTL64(d, 32);      \
        c += d;                 \
        b ^= c;                 \
        b = ROTL64(b, 24);      \
        a += b;                 \
        d ^= a;                 \
        d = ROTL64(d, 16);      \
        c += d;                 \
        b ^= c;                 \
        b = ROTL64(b, 15);      \
    }
#define NUM_OF_ROUNDS 14
#endif

template <typename ARR>
void halfround(ARR& arr) {
#ifdef CYPRESS_32_BIT
    HALFROUND32(arr[0], arr[1], arr[2], arr[3]);
#else
    HALFROUND64(arr[0], arr[1], arr[2], arr[3]);
#endif
    
}

template <typename ARR1, typename ARR2>
void perCoordAddRtoL(ARR1& a, const ARR2& b, int len) {
    for (int i = 0; i < len; ++i) {
        a[i] += b[i];
    }
}

template <typename ARR1, typename ARR2>
void perCoordXorRtoL(ARR1& a, const ARR2& b, int len) {
    for (int i = 0; i < len; ++i) {
        a[i] ^= b[i];
    }
}

template <typename ARR1, typename ARR2>
void assignFromArray(ARR1& a, const ARR2& b, int len, int leftArrShift = 0, int rightArrShift = 0) {
    for (int i = 0; i < len; ++i) {
        a[leftArrShift + i] = b[i + rightArrShift];
    }
}

std::array<WordType, 4> genAuxiliaryKey(const std::array<WordType, 8>& masterKey) {
    std::array<WordType, 4> state{0, 0, 0, 0};
    std::array<WordType, 4> Kl{
        masterKey[0],
        masterKey[1],
        masterKey[2],
        masterKey[3],
    };
    std::array<WordType, 4> Kr{
        masterKey[4],
        masterKey[5],
        masterKey[6],
        masterKey[7],
    };

    perCoordAddRtoL(state, Kl, 4);
    state[3] ^= 1;
    halfround(state);
    halfround(state);

    perCoordAddRtoL(state, Kr, 4);
    halfround(state);
    halfround(state);

    perCoordXorRtoL(state, Kl, 4);
    halfround(state);
    halfround(state);

    return state;
}

std::array<std::array<WordType, 4>, NUM_OF_ROUNDS> genRoundKeys(const std::array<WordType, 4>& auxKey,
                                                     const std::array<WordType, 8>& masterKey) {
    std::array<std::array<WordType, 4>, NUM_OF_ROUNDS> roundKeys;

#ifdef CYPRESS_32_BIT
    std::array<WordType, 4> tmv{0x000F000F, 0x000F000F, 0x000F000F, 0x000F000F};
#else
    std::array<WordType, 4> tmv{0x000F000F000F000F, 0x000F000F000F000F, 0x000F000F000F000F, 0x000F000F000F000F};
#endif

    std::array<WordType, 4> state{0, 0, 0, 0};
    std::array<WordType, 4> K;

    auto ROTLKey = [](std::array<WordType, 8>& key) {
        auto tmp = key[7];
        for (int i = 1; i < 8; ++i) {
            key[i] = key[i - 1];
        }
        key[0] = tmp;
    };

    auto roundInitData = masterKey;
    for (int i = 0; i <= NUM_OF_ROUNDS-2; i += 2) {
        auto genRoundKey = [&]() {
            K = auxKey;
            perCoordAddRtoL(K, tmv, 4);
            perCoordAddRtoL(state, K, 4);
            halfround(state);
            halfround(state);
            perCoordXorRtoL(state, K, 4);
            halfround(state);
            halfround(state);
            perCoordAddRtoL(state, K, 4);
            return state;
        };

        assignFromArray(state, roundInitData, 4);
        roundKeys[i] = genRoundKey();
        std::for_each(tmv.begin(), tmv.end(), [](WordType& el) { el <<= 1; });

        assignFromArray(state, roundInitData, 4, 0, 4);
        roundKeys[i + 1] = genRoundKey();
        std::for_each(tmv.begin(), tmv.end(), [](WordType& el) { el <<= 1; });
        ROTLKey(roundInitData);
    }
    return roundKeys;
}

std::array<WordType, 8> encryptBlock(const std::array<WordType, 8>& plainText,
                                     const std::array<std::array<WordType, 4>, NUM_OF_ROUNDS> roundKeys) {
    std::array<WordType, 8> cipherText;

    std::array<WordType, 4> L, R;
    std::array<WordType, 4> tmp;

    assignFromArray(L, plainText, 4);
    assignFromArray(R, plainText, 4, 0, 4);

    for (int i = 0; i < NUM_OF_ROUNDS; ++i) {
        assignFromArray(tmp, L, 4);
        perCoordXorRtoL(L, roundKeys[i], 4);
        halfround(L);
        halfround(L);
        perCoordXorRtoL(L, R, 4);
        assignFromArray(R, tmp, 4);
    }

    assignFromArray(cipherText, L, 4);
    assignFromArray(cipherText, R, 4, 4, 0);
    return cipherText;
}

std::array<WordType, 8> decryptBlock(const std::array<WordType, 8>& cipherText,
                                     const std::array<std::array<WordType, 4>, NUM_OF_ROUNDS> roundKeys) {
    std::array<WordType, 8> decryptedText;

    std::array<WordType, 4> L, R;
    std::array<WordType, 4> tmp;

    assignFromArray(L, cipherText, 4);
    assignFromArray(R, cipherText, 4, 0, 4);

    for (int i = 0; i < NUM_OF_ROUNDS; ++i) {
        assignFromArray(tmp, R, 4);
        perCoordXorRtoL(R, roundKeys[NUM_OF_ROUNDS - 1 - i], 4);
        halfround(R);
        halfround(R);
        perCoordXorRtoL(R, L, 4);
        assignFromArray(L, tmp, 4);
    }

    assignFromArray(decryptedText, L, 4);
    assignFromArray(decryptedText, R, 4, 4, 0);
    return decryptedText;
}

std::vector<WordType> encryptData(const std::vector<WordType> data,
                                  const std::array<std::array<WordType, 4>, NUM_OF_ROUNDS> roundKeys) {
    std::vector<WordType> cipherText;
    cipherText.reserve(data.size());

    // iterate through blocks
    for (int i = 0; i < data.size(); i += 8) {
        // value initialization will fill array with zeros
        std::array<WordType, 8> blockOfPlainText{};
        auto nonZeroWordsInBlock = data.size() - i < 8 ? (data.size() % 8) : 8;

        //std::cout << "iter block = " << i << ", nzwib = " << nonZeroWordsInBlock << '\n';
        // iterate through words in block
        for (int j = 0; j < nonZeroWordsInBlock; ++j) {
        	//std::cout << "data = " << data[i+j] << '\n';
            blockOfPlainText[j] = data[i + j];
        }

        auto cipheredBlock = encryptBlock(blockOfPlainText, roundKeys);

        std::for_each(std::begin(cipheredBlock), std::end(cipheredBlock), [&cipherText](WordType cipheredWord) {
            cipherText.push_back(cipheredWord);
        });
    }

    return cipherText;
}

// after encryption vec size will be devisible by 8
std::vector<WordType> decryptData(const std::vector<WordType> cipherText,
                                  const std::array<std::array<WordType, 4>, NUM_OF_ROUNDS> roundKeys) {
    std::vector<WordType> data;
    data.reserve(cipherText.size());

    // iterate through blocks
    for (int i = 0; i < cipherText.size(); i += 8) {
        // value initialization will fill array with zeros
        std::array<WordType, 8> blockOfCipherText{};

        // iterate through words in block
        for (int j = 0; j < 8; ++j) {
            blockOfCipherText[j] = cipherText[i + j];
        }

        auto decryptedBlock = decryptBlock(blockOfCipherText, roundKeys);

        std::for_each(std::begin(decryptedBlock), std::end(decryptedBlock), [&data](WordType decryptedWord) {
            data.push_back(decryptedWord);
        });
    }

    return data;
}