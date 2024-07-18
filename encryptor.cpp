#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <memory> // Used for std::unique_ptr
#include <openssl/pem.h>
#include <openssl/err.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iterator>

struct ECKeyDeleter {
    void operator()(EC_KEY* p) const { EC_KEY_free(p); }
};
using UniqueECKey = std::unique_ptr<EC_KEY, ECKeyDeleter>;

class EncryptionManager {
public:
    UniqueECKey generate_key_pair() {
        UniqueECKey eckey(EC_KEY_new_by_curve_name(NID_secp256k1));
        if (!eckey || !EC_KEY_generate_key(eckey.get())) {
            throw std::runtime_error("Error generating EC key");
        }
        return eckey;
    }

    void save_private_key(const std::string& filename, const UniqueECKey& ec_key) {
        BIO* out = BIO_new_file(filename.c_str(), "w");
        if (!out || !PEM_write_bio_ECPrivateKey(out, ec_key.get(), EVP_aes_256_cbc(), nullptr, 0, nullptr, nullptr)) {
            std::cerr << "Error writing private key to file" << std::endl;
        }
        BIO_free(out);
    }

    void save_public_key(const std::string& filename, const UniqueECKey& ec_key) {
        BIO* out = BIO_new_file(filename.c_str(), "w");
        if (!out || !PEM_write_bio_EC_PUBKEY(out, ec_key.get())) {
            std::cerr << "Error writing public key to file" << std::endl;
        }
        BIO_free(out);
    }

    UniqueECKey load_private_key(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "rb");
        UniqueECKey ecKey(PEM_read_ECPrivateKey(file, nullptr, nullptr, nullptr));
        fclose(file);
        if (!ecKey) {
            throw std::runtime_error("Error loading private key");
        }
        return ecKey;
    }

    UniqueECKey load_public_key(const std::string& filename) {
        FILE* file = fopen(filename.c_str(), "rb");
        UniqueECKey ecKey(PEM_read_EC_PUBKEY(file, nullptr, nullptr, nullptr));
        fclose(file);
        if (!ecKey) {
            throw std::runtime_error("Error loading public key");
        }
        return ecKey;
    }

    std::vector<uint8_t> encrypt_data(EC_KEY* pubkey, const std::vector<uint8_t>& plaintext) {
        EVP_PKEY* peerkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(peerkey, pubkey);

        EVP_PKEY_CTX* ctx;
        if (!(ctx = EVP_PKEY_CTX_new(peerkey, nullptr))) {
            throw std::runtime_error("Error creating PKEY context");
        }

        if (EVP_PKEY_encrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peerkey);
            throw std::runtime_error("Error initializing encryption");
        }

        size_t outlen;
        if (EVP_PKEY_encrypt(ctx, nullptr, &outlen, plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peerkey);
            throw std::runtime_error("Error getting encryption length");
        }

        std::vector<uint8_t> ciphertext(outlen);
        if (EVP_PKEY_encrypt(ctx, ciphertext.data(), &outlen, plaintext.data(), plaintext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(peerkey);
            throw std::runtime_error("Error encrypting data");
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(peerkey);

        return ciphertext;
    }

    std::vector<uint8_t> decrypt_data(EC_KEY* privkey, const std::vector<uint8_t>& ciphertext) {
        if (ciphertext.empty()) {
            throw std::invalid_argument("Empty ciphertext provided");
        }

        EVP_PKEY *ownkey = EVP_PKEY_new();
        EVP_PKEY_assign_EC_KEY(ownkey, privkey);

        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(ownkey, nullptr);
        if (!ctx) {
            EVP_PKEY_free(ownkey);
            throw std::runtime_error("Error creating PKEY context");
        }

        if (EVP_PKEY_decrypt_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(ownkey);
            throw std::runtime_error("Error initializing decryption");
        }

        size_t outlen;
        if (EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(ownkey);
            throw std::runtime_error("Error getting decryption length");
        }

        std::vector<uint8_t> plaintext(outlen);
        if (EVP_PKEY_decrypt(ctx, plaintext.data(), &outlen, ciphertext.data(), ciphertext.size()) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            EVP_PKEY_free(ownkey);
            throw std::runtime_error("Error decrypting data");
        }

        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(ownkey);

        return plaintext;
    }
};

void save_to_file(const std::string& filename, const std::vector<uint8_t>& data) {
    std::ofstream file(filename, std::ios::binary);
    std::copy(data.begin(), data.end(), std::ostreambuf_iterator<char>(file));
}

std::vector<uint8_t> load_from_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

int main() {
    try {
        OpenSSL_add_all_algorithms();
        ERR_load_BIO_strings();
        ERR_load_crypto_strings();

        EncryptionManager encryptionManager;

        // Generate key pair
        UniqueECKey keyPair = encryptionManager.generate_key_pair();

        // Save keys to files
        encryptionManager.save_private_key("private_key.pem", keyPair);
        encryptionManager.save_public_key("public_key.pem", keyPair);

        // Load public key
        UniqueECKey publicKey = encryptionManager.load_public_key("public_key.pem");

        // Load plaintext from file
        std::vector<uint8_t> plaintext = load_from_file("plaintext.txt");

        // Encrypt data
        std::vector<uint8_t> ciphertext = encryptionManager.encrypt_data(publicKey.get(), plaintext);
        save_to_file("ciphertext.bin", ciphertext);

        // Load private key
        UniqueECKey privateKey = encryptionManager.load_private_key("private_key.pem");

        // Load ciphertext from file
        std::vector<uint8_t> loadedCiphertext = load_from_file("ciphertext.bin");

        // Decrypt data
        std::vector<uint8_t> decrypted = encryptionManager.decrypt_data(privateKey.get(), loadedCiphertext);
        save_to_file("decrypted.txt", decrypted);

        std::cout << "Encryption and decryption completed successfully." << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Caught exception: " << e.what() << std::endl;
        ERR_print_errors_fp(stderr);
        return 1;
    }

    return 0;
}
