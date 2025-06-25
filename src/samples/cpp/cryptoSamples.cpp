#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <fstream>

// --- Hashing ---

std::string hashSHA256_latest(const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr);
    EVP_DigestUpdate(ctx, data.c_str(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    return std::string((char*)hash, len);
}

std::string hashMD5_old(const std::string& data) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int len;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, data.c_str(), data.size());
    EVP_DigestFinal_ex(ctx, hash, &len);
    EVP_MD_CTX_free(ctx);
    return std::string((char*)hash, len);
}

// --- Symmetric Encryption/Decryption (AES-256-CBC) ---

std::vector<unsigned char> symmetricEncrypt_latest(const std::string& plaintext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
    int len, ciphertext_len = 0;
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char*)plaintext.c_str(), plaintext.size());
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(ciphertext_len);
    return ciphertext;
}

std::string symmetricDecrypt_latest(const std::vector<unsigned char>& ciphertext, const unsigned char* key, const unsigned char* iv) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len, plaintext_len = 0;
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size());
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);
    return std::string((char*)plaintext.data(), plaintext_len);
}

// --- Asymmetric Encryption/Decryption (RSA) ---

std::vector<unsigned char> asymmetricEncrypt_latest(const std::string& plaintext, EVP_PKEY* pubkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pubkey, nullptr);
    EVP_PKEY_encrypt_init(ctx);
    size_t outlen;
    EVP_PKEY_encrypt(ctx, nullptr, &outlen, (unsigned char*)plaintext.c_str(), plaintext.size());
    std::vector<unsigned char> out(outlen);
    EVP_PKEY_encrypt(ctx, out.data(), &outlen, (unsigned char*)plaintext.c_str(), plaintext.size());
    EVP_PKEY_CTX_free(ctx);
    out.resize(outlen);
    return out;
}

std::string asymmetricDecrypt_latest(const std::vector<unsigned char>& ciphertext, EVP_PKEY* privkey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privkey, nullptr);
    EVP_PKEY_decrypt_init(ctx);
    size_t outlen;
    EVP_PKEY_decrypt(ctx, nullptr, &outlen, ciphertext.data(), ciphertext.size());
    std::vector<unsigned char> out(outlen);
    EVP_PKEY_decrypt(ctx, out.data(), &outlen, ciphertext.data(), ciphertext.size());
    EVP_PKEY_CTX_free(ctx);
    return std::string((char*)out.data(), outlen);
}

// --- Certificate Related ---

// Load X509 certificate from file
X509* loadCertificate(const char* certPath) {
    FILE* fp = fopen(certPath, "r");
    if (!fp) return nullptr;
    X509* cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return cert;
}

// Load private key from file
EVP_PKEY* loadPrivateKey(const char* keyPath) {
    FILE* fp = fopen(keyPath, "r");
    if (!fp) return nullptr;
    EVP_PKEY* pkey = PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr);
    fclose(fp);
    return pkey;
}

// Sign data with private key
std::vector<unsigned char> signDataWithPrivateKey(const std::string& data, EVP_PKEY* privkey) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privkey);
    EVP_DigestSignUpdate(ctx, data.c_str(), data.size());
    size_t siglen;
    EVP_DigestSignFinal(ctx, nullptr, &siglen);
    std::vector<unsigned char> sig(siglen);
    EVP_DigestSignFinal(ctx, sig.data(), &siglen);
    EVP_MD_CTX_free(ctx);
    sig.resize(siglen);
    return sig;
}

// Verify signature with public key
bool verifySignatureWithPublicKey(const std::string& data, const std::vector<unsigned char>& sig, EVP_PKEY* pubkey) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, pubkey);
    EVP_DigestVerifyUpdate(ctx, data.c_str(), data.size());
    int ret = EVP_DigestVerifyFinal(ctx, sig.data(), sig.size());
    EVP_MD_CTX_free(ctx);
    return ret == 1;
}

// Create a self-signed certificate
bool createSelfSignedCertificate(const char* certPath, const char* keyPath, int days = 365) {
    EVP_PKEY* pkey = EVP_PKEY_new();
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    // Use RSA_generate_key_ex instead of deprecated RSA_generate_key
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);
    BN_free(bn);
    EVP_PKEY_assign_RSA(pkey, rsa);

    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 60L*60L*24L*days);
    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*)"Example Org", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"example.org", -1, -1, 0);

    X509_set_issuer_name(x509, name);

    X509_sign(x509, pkey, EVP_sha256());

    FILE* f = fopen(certPath, "wb");
    if (!f) return false;
    PEM_write_X509(f, x509);
    fclose(f);

    f = fopen(keyPath, "wb");
    if (!f) return false;
    PEM_write_PrivateKey(f, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(f);

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return true;
}

void printHex(const std::string& label, const std::string& data) {
    std::cout << label;
    for (unsigned char c : data) {
        printf("%02x", c);
    }
    std::cout << std::endl;
}

void printHexVec(const std::string& label, const std::vector<unsigned char>& data) {
    std::cout << label;
    for (unsigned char c : data) {
        printf("%02x", c);
    }
    std::cout << std::endl;
}

// --- More Crypto Examples: Good and Bad Practices ---

void badSymmetricExample() {
    // BAD: Hardcoded key and IV (should never be done in production)
    unsigned char key[32];
    unsigned char iv[16];
    // Use memcpy to copy string literals into the arrays (avoid initializer-string too long error)
    const char* key_str = "0123456789abcdef0123456789abcdef"; // 32 bytes
    const char* iv_str  = "abcdef9876543210";                 // 16 bytes
    memcpy(key, key_str, 32);
    memcpy(iv, iv_str, 16);
    std::string plaintext = "Sensitive data";
    auto ciphertext = symmetricEncrypt_latest(plaintext, key, iv);
    std::string decrypted = symmetricDecrypt_latest(ciphertext, key, iv);
    printHexVec("[BAD] AES-256 Encrypted: ", ciphertext);
    std::cout << "[BAD] AES-256 Decrypted: " << decrypted << std::endl;
}

void badHashExample() {
    std::string password = "password123";
    std::string hash = hashMD5_old(password);
    printHex("[BAD] MD5 password hash: ", hash);
}

void goodHashExample() {
    const char* password = "password123";
    unsigned char salt[16];
    RAND_bytes(salt, sizeof(salt));
    unsigned char hash[32];
    PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt), 100000, EVP_sha256(), sizeof(hash), hash);
    std::cout << "[GOOD] PBKDF2-SHA256 password hash: ";
    for (int i = 0; i < 32; ++i) printf("%02x", hash[i]);
    std::cout << std::endl;
}

void badNoCheckExample() {
    unsigned char key[32], iv[16];
    RAND_bytes(key, sizeof(key)); // Should check return value!
    RAND_bytes(iv, sizeof(iv));   // Should check return value!
    std::string plaintext = "data";
    auto ciphertext = symmetricEncrypt_latest(plaintext, key, iv);
    std::string decrypted = symmetricDecrypt_latest(ciphertext, key, iv);
    printHexVec("[BAD] No check AES-256 Encrypted: ", ciphertext);
    std::cout << "[BAD] No check AES-256 Decrypted: " << decrypted << std::endl;
}

void goodCheckExample() {
    unsigned char key[32], iv[16];
    if (RAND_bytes(key, sizeof(key)) != 1 || RAND_bytes(iv, sizeof(iv)) != 1) {
        std::cerr << "[GOOD] Random generation failed!" << std::endl;
        return;
    }
    std::string plaintext = "data";
    auto ciphertext = symmetricEncrypt_latest(plaintext, key, iv);
    std::string decrypted = symmetricDecrypt_latest(ciphertext, key, iv);
    printHexVec("[GOOD] Checked AES-256 Encrypted: ", ciphertext);
    std::cout << "[GOOD] Checked AES-256 Decrypted: " << decrypted << std::endl;
}

void badSelfSignedCertExample() {
    bool ok = createSelfSignedCertificate("bad_cert.pem", "bad_key.pem");
    std::cout << "[BAD] Self-signed certificate created: " << (ok ? "yes" : "no") << std::endl;
}

void goodSelfSignedCertExample() {
    bool ok = createSelfSignedCertificate("good_cert.pem", "good_key.pem");
    std::cout << "[GOOD] Self-signed certificate created for dev/test: " << (ok ? "yes" : "no") << std::endl;
}

// Example usage (not for production, just for demonstration)
void example() {
    // Hashing
    std::string data = "hello";
    std::string sha256 = hashSHA256_latest(data);
    std::string md5 = hashMD5_old(data);
    printHex("SHA256: ", sha256);
    printHex("MD5: ", md5);

    // Symmetric
    unsigned char key[32], iv[16];
    RAND_bytes(key, sizeof(key));
    RAND_bytes(iv, sizeof(iv));
    auto enc = symmetricEncrypt_latest(data, key, iv);
    std::string dec = symmetricDecrypt_latest(enc, key, iv);
    printHexVec("AES-256-CBC Encrypted: ", enc);
    std::cout << "AES-256-CBC Decrypted: " << dec << std::endl;

    // Asymmetric
    createSelfSignedCertificate("cert.pem", "key.pem");
    EVP_PKEY* priv = loadPrivateKey("key.pem");
    X509* cert = loadCertificate("cert.pem");
    EVP_PKEY* pub = X509_get_pubkey(cert);
    auto rsa_enc = asymmetricEncrypt_latest(data, pub);
    std::string rsa_dec = asymmetricDecrypt_latest(rsa_enc, priv);
    printHexVec("RSA Encrypted: ", rsa_enc);
    std::cout << "RSA Decrypted: " << rsa_dec << std::endl;

    // Signing
    auto sig = signDataWithPrivateKey(data, priv);
    printHexVec("Signature: ", sig);
    bool valid = verifySignatureWithPublicKey(data, sig, pub);
    std::cout << "Signature valid: " << (valid ? "yes" : "no") << std::endl;

    // --- More Crypto Examples ---
    badSymmetricExample();
    badHashExample();
    goodHashExample();
    badNoCheckExample();
    goodCheckExample();
    badSelfSignedCertExample();
    goodSelfSignedCertExample();

    // Cleanup
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    X509_free(cert);
}

int main() {
    example();
    return 0;
}