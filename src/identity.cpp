#include "pm/encryption/identity.hpp"

#include <sodium.h>

static_assert(crypto_sign_PUBLICKEYBYTES == 32);
static_assert(crypto_sign_SECRETKEYBYTES == 64);
static_assert(crypto_sign_SEEDBYTES == 32);
static_assert(crypto_sign_BYTES == 64);

namespace pm::encryption {
namespace {

void wipe(void* data, std::size_t size) {
    if (data && size)
        sodium_memzero(data, size);
}

bool init_crypto(Error& err) {
    if (sodium_init() < 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "libsodium initialization failed");
        return false;
    }
    return true;
}

} // namespace

Identity::Identity() = default;

Identity::~Identity() {
    wipe(secret_.data(), secret_.size());
}

Identity::Identity(Identity&& other) noexcept
    : public_(other.public_), secret_(other.secret_), valid_(other.valid_) {
    wipe(other.secret_.data(), other.secret_.size());
    other.public_.fill(0);
    other.valid_ = false;
}

Identity& Identity::operator=(Identity&& other) noexcept {
    if (this == &other)
        return *this;
    wipe(secret_.data(), secret_.size());
    public_ = other.public_;
    secret_ = other.secret_;
    valid_ = other.valid_;
    wipe(other.secret_.data(), other.secret_.size());
    other.public_.fill(0);
    other.valid_ = false;
    return *this;
}

Identity Identity::generate(Error& err) {
    err = {};
    Identity out;
    if (!init_crypto(err))
        return out;
    if (crypto_sign_keypair(out.public_.data(), out.secret_.data()) != 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "identity key generation failed");
        return out;
    }
    out.valid_ = true;
    return out;
}

Identity Identity::from_seed(const Seed& seed, Error& err) {
    err = {};
    Identity out;
    if (!init_crypto(err))
        return out;
    if (crypto_sign_seed_keypair(out.public_.data(), out.secret_.data(), seed.data()) != 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "seeded identity generation failed");
        return out;
    }
    out.valid_ = true;
    return out;
}

Error Identity::sign(std::span<const std::uint8_t> message, Signature& signature) const {
    signature.fill(0);
    if (!valid_)
        return Error::make(ErrorCode::InvalidArgument, "identity is invalid");
    unsigned long long written = 0;
    if (crypto_sign_detached(signature.data(), &written,
                             message.empty() ? nullptr : message.data(),
                             static_cast<unsigned long long>(message.size()),
                             secret_.data()) != 0
        || written != signature.size()) {
        signature.fill(0);
        return Error::make(ErrorCode::CryptoUnavailable, "identity signature failed");
    }
    return {};
}

Error Identity::verify(const IdentityPublic& public_key,
                       std::span<const std::uint8_t> message,
                       std::span<const std::uint8_t> signature) {
    Error err;
    if (!init_crypto(err))
        return err;
    IdentityPublic zero{};
    if (sodium_memcmp(public_key.data(), zero.data(), public_key.size()) == 0)
        return Error::make(ErrorCode::InvalidArgument, "identity public key is empty");
    if (signature.size() != k_signature_bytes)
        return Error::make(ErrorCode::BadSignature, "identity signature length is invalid");
    if (crypto_sign_verify_detached(signature.data(),
                                    message.empty() ? nullptr : message.data(),
                                    static_cast<unsigned long long>(message.size()),
                                    public_key.data()) != 0)
        return Error::make(ErrorCode::BadSignature, "identity signature verification failed");
    return {};
}

} // namespace pm::encryption
