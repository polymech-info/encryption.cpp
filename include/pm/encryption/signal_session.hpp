#pragma once

#include "pm/encryption/features.hpp"

#if PM_ENCRYPTION_LIBSIGNAL

#include "pm/encryption/channel.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace pm::encryption {

/**
 * One device's Signal session state.
 *
 * The ciphertext is produced by upstream libsignal: PQXDH for the first
 * message, then the Triple Ratchet. This type does not implement either
 * protocol. The host serializes calls. History lives in the session state
 * held by the adapter, not in a single channel key.
 */
class SignalEndpoint {
public:
    SignalEndpoint();
    ~SignalEndpoint();
    SignalEndpoint(SignalEndpoint&& other) noexcept;
    SignalEndpoint& operator=(SignalEndpoint&& other) noexcept;
    SignalEndpoint(const SignalEndpoint&) = delete;
    SignalEndpoint& operator=(const SignalEndpoint&) = delete;

    static SignalEndpoint open(std::string name, Error& err);

    bool valid() const noexcept { return endpoint_ != nullptr; }
    const std::string& name() const noexcept { return name_; }

    Error export_bundle(std::vector<std::uint8_t>& bundle, bool include_onetime = true);
    Error initiate(std::string_view peer, std::span<const std::uint8_t> bundle);
    Error encrypt(std::string_view peer, std::span<const std::uint8_t> plaintext,
                  std::vector<std::uint8_t>& ciphertext);
    Error decrypt(std::string_view peer, std::span<const std::uint8_t> ciphertext,
                  std::vector<std::uint8_t>& plaintext);

private:
    void* endpoint_ = nullptr;
    std::string name_;
};

} // namespace pm::encryption

#endif
