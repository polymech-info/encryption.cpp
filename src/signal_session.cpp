#include "pm/encryption/signal_session.hpp"

#if PM_ENCRYPTION_LIBSIGNAL

#include "pm_signal.h"

namespace pm::encryption {
namespace {

Error from_code(int code) {
    switch (code) {
    case PM_SIGNAL_OK:
        return {};
    case PM_SIGNAL_INVALID:
        return Error::make(ErrorCode::InvalidArgument, "signal request is invalid");
    case PM_SIGNAL_NO_SESSION:
        return Error::make(ErrorCode::UnexpectedState, "signal session is not established");
    case PM_SIGNAL_UNTRUSTED:
        return Error::make(ErrorCode::IdentityMismatch, "signal identity is not trusted");
    case PM_SIGNAL_DECRYPT:
        return Error::make(ErrorCode::AuthenticationFailed, "signal message failed authentication");
    default:
        return Error::make(ErrorCode::CryptoUnavailable, "signal session operation failed");
    }
}

} // namespace

SignalEndpoint::SignalEndpoint() = default;

SignalEndpoint::~SignalEndpoint() {
    pm_signal_endpoint_destroy(static_cast<PmSignalEndpoint*>(endpoint_));
}

SignalEndpoint::SignalEndpoint(SignalEndpoint&& other) noexcept
    : endpoint_(other.endpoint_), name_(std::move(other.name_)) {
    other.endpoint_ = nullptr;
}

SignalEndpoint& SignalEndpoint::operator=(SignalEndpoint&& other) noexcept {
    if (this == &other)
        return *this;
    pm_signal_endpoint_destroy(static_cast<PmSignalEndpoint*>(endpoint_));
    endpoint_ = other.endpoint_;
    name_ = std::move(other.name_);
    other.endpoint_ = nullptr;
    return *this;
}

SignalEndpoint SignalEndpoint::open(std::string name, Error& err) {
    err = {};
    SignalEndpoint out;
    PmSignalEndpoint* endpoint = nullptr;
    const int code = pm_signal_endpoint_create(
        reinterpret_cast<const std::uint8_t*>(name.data()), name.size(), &endpoint);
    if (code != PM_SIGNAL_OK || endpoint == nullptr) {
        err = from_code(code == PM_SIGNAL_OK ? PM_SIGNAL_CRYPTO : code);
        return {};
    }
    out.endpoint_ = endpoint;
    out.name_ = std::move(name);
    return out;
}

Error SignalEndpoint::export_bundle(std::vector<std::uint8_t>& bundle, bool include_onetime) {
    bundle.clear();
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "signal endpoint is invalid");
    std::uint8_t* bytes = nullptr;
    std::size_t len = 0;
    const int code = pm_signal_export_bundle(
        static_cast<PmSignalEndpoint*>(endpoint_), include_onetime ? 1 : 0, &bytes, &len);
    if (code != PM_SIGNAL_OK) {
        pm_signal_free(bytes);
        return from_code(code);
    }
    bundle.assign(bytes, bytes + len);
    pm_signal_free(bytes);
    return {};
}

Error SignalEndpoint::initiate(std::string_view peer, std::span<const std::uint8_t> bundle) {
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "signal endpoint is invalid");
    return from_code(pm_signal_initiate(
        static_cast<PmSignalEndpoint*>(endpoint_),
        reinterpret_cast<const std::uint8_t*>(peer.data()), peer.size(),
        bundle.data(), bundle.size()));
}

Error SignalEndpoint::encrypt(std::string_view peer, std::span<const std::uint8_t> plaintext,
                              std::vector<std::uint8_t>& ciphertext) {
    ciphertext.clear();
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "signal endpoint is invalid");
    std::uint8_t* bytes = nullptr;
    std::size_t len = 0;
    const int code = pm_signal_encrypt(
        static_cast<PmSignalEndpoint*>(endpoint_),
        reinterpret_cast<const std::uint8_t*>(peer.data()), peer.size(),
        plaintext.data(), plaintext.size(), &bytes, &len);
    if (code != PM_SIGNAL_OK) {
        pm_signal_free(bytes);
        return from_code(code);
    }
    ciphertext.assign(bytes, bytes + len);
    pm_signal_free(bytes);
    return {};
}

Error SignalEndpoint::decrypt(std::string_view peer, std::span<const std::uint8_t> ciphertext,
                              std::vector<std::uint8_t>& plaintext) {
    plaintext.clear();
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "signal endpoint is invalid");
    std::uint8_t* bytes = nullptr;
    std::size_t len = 0;
    const int code = pm_signal_decrypt(
        static_cast<PmSignalEndpoint*>(endpoint_),
        reinterpret_cast<const std::uint8_t*>(peer.data()), peer.size(),
        ciphertext.data(), ciphertext.size(), &bytes, &len);
    if (code != PM_SIGNAL_OK) {
        pm_signal_free(bytes);
        return from_code(code);
    }
    plaintext.assign(bytes, bytes + len);
    pm_signal_free(bytes);
    return {};
}

} // namespace pm::encryption

#endif
