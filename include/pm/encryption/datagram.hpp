#pragma once

#include "pm/encryption/replay.hpp"

#include <string>
#include <vector>

namespace pm::encryption {

inline constexpr std::size_t k_flow_id_max = 32;
inline constexpr std::size_t k_flow_scope_max = 64;
inline constexpr std::size_t k_datagram_max_plaintext = 64U * 1024U;
inline constexpr int k_datagram_replay_window = 64;

/**
 * Key for one datagram flow.
 *
 * The id, scope, and epoch are bound into every frame. The key does not
 * record a content type. generate() is the one object that may seal.
 * from_wrap() opens that sender's packets and cannot seal. A restart does
 * not restore the send counter. Holding a previous epoch still opens it.
 * Nothing here expires a key because a member left.
 */
class FlowKey {
public:
    FlowKey();
    ~FlowKey();
    FlowKey(FlowKey&& other) noexcept;
    FlowKey& operator=(FlowKey&& other) noexcept;
    FlowKey(const FlowKey&) = delete;
    FlowKey& operator=(const FlowKey&) = delete;

    static FlowKey generate(std::span<const std::uint8_t> id, std::span<const std::uint8_t> scope,
                            std::uint32_t epoch, Error& err);
    static FlowKey from_wrap(std::span<const std::uint8_t> wrap, Error& err);

    Error write_wrap(std::vector<std::uint8_t>& out) const;
    bool valid() const noexcept { return valid_; }
    std::uint32_t epoch() const noexcept { return epoch_; }
    const std::vector<std::uint8_t>& id() const noexcept { return id_; }
    const std::vector<std::uint8_t>& scope() const noexcept { return scope_; }

private:
    friend class DatagramSender;
    friend class DatagramReceiver;
    friend class SecureFlow;
    friend class SecureEndpoint;

    FlowKey clone() const;
    void wipe() noexcept;

    std::array<std::uint8_t, 32> key_{};
    std::vector<std::uint8_t> id_;
    std::vector<std::uint8_t> scope_;
    std::uint32_t epoch_ = 0;
    bool sendable_ = false;
    bool valid_ = false;
};

class DatagramSender {
public:
    DatagramSender();
    ~DatagramSender();
    DatagramSender(DatagramSender&& other) noexcept;
    DatagramSender& operator=(DatagramSender&& other) noexcept;
    DatagramSender(const DatagramSender&) = delete;
    DatagramSender& operator=(const DatagramSender&) = delete;

    static DatagramSender adopt(FlowKey key, Error& err);
    bool valid() const noexcept { return key_.valid(); }
    std::uint32_t epoch() const noexcept { return key_.epoch(); }

    Error seal(std::span<const std::uint8_t> payload, std::uint32_t timestamp_ms,
               std::vector<std::uint8_t>& packet);

private:
    FlowKey key_;
    std::uint64_t next_ = 0;
};

class DatagramReceiver {
public:
    DatagramReceiver();
    ~DatagramReceiver();
    DatagramReceiver(DatagramReceiver&& other) noexcept;
    DatagramReceiver& operator=(DatagramReceiver&& other) noexcept;
    DatagramReceiver(const DatagramReceiver&) = delete;
    DatagramReceiver& operator=(const DatagramReceiver&) = delete;

    static DatagramReceiver adopt(FlowKey key, Error& err);
    bool valid() const noexcept { return key_.valid(); }
    std::uint32_t epoch() const noexcept { return key_.epoch(); }

    Error open(std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& payload,
               std::uint32_t& timestamp_ms, std::uint64_t& sequence);

private:
    FlowKey key_;
    ReplayWindow window_{ReplayWindow::Rule::AnySequenceThenWindow, k_datagram_replay_window};
};

Error datagram_id(std::span<const std::uint8_t> packet, std::vector<std::uint8_t>& id);

} // namespace pm::encryption
