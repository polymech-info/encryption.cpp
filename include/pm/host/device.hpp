#pragma once

#include "pm/encryption/datagram.hpp"
#include "pm/room/pairing.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace pm::host {

/**
 * In-package stand-in for the desktop or phone media host.
 *
 * The test pushes already-encoded frames in. The host seals them onto a
 * loopback plane and the other host renders them. This is not a microphone,
 * a codec, or a WebRTC transport. The room broker is not the plane.
 */
enum class Source : std::uint8_t {
    Microphone = 1,
    Camera = 2,
};

inline constexpr std::string_view k_microphone_flow = "mic";
inline constexpr std::string_view k_camera_flow = "cam";

struct Rendered {
    Source source = Source::Microphone;
    std::uint32_t generation = 0;
    std::uint64_t sequence = 0;
    std::uint32_t timestamp_ms = 0;
    std::vector<std::uint8_t> payload;
};

class Device {
public:
    Device();
    ~Device();
    Device(Device&& other) noexcept;
    Device& operator=(Device&& other) noexcept;
    Device(const Device&) = delete;
    Device& operator=(const Device&) = delete;

    pm::encryption::Error open(std::string name, std::uint32_t grants);
    const std::string& name() const noexcept { return name_; }
    bool valid() const noexcept { return !name_.empty(); }

    pm::encryption::Error install_send(pm::encryption::FlowKey key);
    pm::encryption::Error install_recv(pm::encryption::FlowKey key);
    void set_muted(Source source, bool muted);

    pm::encryption::Error capture(Source source, std::uint32_t timestamp_ms,
                                  std::span<const std::uint8_t> encoded);
    pm::encryption::Error publish(std::vector<std::vector<std::uint8_t>>& plane);
    pm::encryption::Error render(std::span<const std::uint8_t> packet);

    std::size_t published() const noexcept { return published_; }
    std::size_t muted_dropped() const noexcept { return muted_dropped_; }
    const std::vector<Rendered>& rendered() const noexcept { return rendered_; }

private:
    struct Captured {
        Source source = Source::Microphone;
        std::uint32_t timestamp_ms = 0;
        std::vector<std::uint8_t> encoded;
    };

    bool granted(Source source) const noexcept;

    std::string name_;
    std::uint32_t grants_ = 0;
    bool audio_muted_ = false;
    bool video_muted_ = false;
    std::uint32_t audio_generation_ = 0;
    std::uint32_t video_generation_ = 0;
    std::size_t published_ = 0;
    std::size_t muted_dropped_ = 0;
    std::vector<Captured> queue_;
    std::vector<Rendered> rendered_;
    pm::encryption::DatagramSender audio_tx_;
    pm::encryption::DatagramReceiver audio_rx_;
    pm::encryption::DatagramSender video_tx_;
    pm::encryption::DatagramReceiver video_rx_;
};

} // namespace pm::host
