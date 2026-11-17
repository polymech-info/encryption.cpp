#pragma once

#include "pm/encryption/datagram.hpp"

namespace pm::encryption {

enum class Delivery : std::uint8_t {
    Datagram = 1,
    Reliable = 2,
    Durable = 3,
};

struct FlowOptions {
    Delivery delivery = Delivery::Datagram;
    std::vector<std::uint8_t> id;
    std::vector<std::uint8_t> scope;
    std::uint32_t epoch = 1;
};

/**
 * One opened flow. seal and open take opaque bytes.
 *
 * This endpoint currently opens datagram flows. Reliable messages stay on
 * SecureChannel. Durable objects stay on the file envelope. Asking for either
 * through open_flow fails. It does not fall back to a datagram.
 *
 * open_flow keeps the only send counter. accept installs a receiver.
 * rekey is the sender's next epoch and returns a wrap. accept_next moves a
 * receiver forward and refuses an epoch that is not newer. A peer that keeps
 * the previous object can still open the previous epoch. close wipes this
 * object only. A process that restarts has no counter to resume.
 */
class SecureFlow {
public:
    SecureFlow();
    ~SecureFlow();
    SecureFlow(SecureFlow&& other) noexcept;
    SecureFlow& operator=(SecureFlow&& other) noexcept;
    SecureFlow(const SecureFlow&) = delete;
    SecureFlow& operator=(const SecureFlow&) = delete;

    static SecureFlow accept(std::span<const std::uint8_t> wrap, Error& err);

    bool valid() const noexcept { return retained_.valid() && receiver_.valid(); }
    bool can_send() const noexcept { return sender_.valid(); }
    Delivery delivery() const noexcept { return Delivery::Datagram; }
    std::uint32_t epoch() const noexcept { return retained_.epoch(); }

    Error seal(std::span<const std::uint8_t> plaintext, std::vector<std::uint8_t>& ciphertext);
    Error open(std::span<const std::uint8_t> ciphertext, std::vector<std::uint8_t>& plaintext);
    Error export_key(std::vector<std::uint8_t>& wrap) const;
    Error rekey(std::vector<std::uint8_t>& wrap);
    Error accept_next(std::span<const std::uint8_t> wrap);
    void close();

private:
    friend class SecureEndpoint;

    DatagramSender sender_;
    DatagramReceiver receiver_;
    FlowKey retained_;
};

class SecureEndpoint {
public:
    SecureEndpoint() = default;

    static SecureEndpoint open(Error& err);
    SecureFlow open_flow(const FlowOptions& options, Error& err) const;
};

} // namespace pm::encryption
