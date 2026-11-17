#include "pm/host/device.hpp"

#include <cstring>
#include <utility>

namespace pm::host {
namespace {

using pm::encryption::Error;
using pm::encryption::ErrorCode;

constexpr std::size_t k_queue_cap = 32;

bool flow_is(const pm::encryption::FlowKey& key, std::string_view name) {
    const auto& id = key.id();
    return id.size() == name.size() && std::memcmp(id.data(), name.data(), name.size()) == 0;
}

} // namespace

Device::Device() = default;
Device::~Device() = default;

Device::Device(Device&& other) noexcept
    : name_(std::move(other.name_)),
      grants_(other.grants_),
      audio_muted_(other.audio_muted_),
      video_muted_(other.video_muted_),
      audio_generation_(other.audio_generation_),
      video_generation_(other.video_generation_),
      published_(other.published_),
      muted_dropped_(other.muted_dropped_),
      queue_(std::move(other.queue_)),
      rendered_(std::move(other.rendered_)),
      audio_tx_(std::move(other.audio_tx_)),
      audio_rx_(std::move(other.audio_rx_)),
      video_tx_(std::move(other.video_tx_)),
      video_rx_(std::move(other.video_rx_)) {
    other.grants_ = 0;
    other.published_ = 0;
    other.muted_dropped_ = 0;
    other.audio_generation_ = 0;
    other.video_generation_ = 0;
}

Device& Device::operator=(Device&& other) noexcept {
    if (this == &other)
        return *this;
    name_ = std::move(other.name_);
    grants_ = other.grants_;
    audio_muted_ = other.audio_muted_;
    video_muted_ = other.video_muted_;
    audio_generation_ = other.audio_generation_;
    video_generation_ = other.video_generation_;
    published_ = other.published_;
    muted_dropped_ = other.muted_dropped_;
    queue_ = std::move(other.queue_);
    rendered_ = std::move(other.rendered_);
    audio_tx_ = std::move(other.audio_tx_);
    audio_rx_ = std::move(other.audio_rx_);
    video_tx_ = std::move(other.video_tx_);
    video_rx_ = std::move(other.video_rx_);
    other.grants_ = 0;
    other.published_ = 0;
    other.muted_dropped_ = 0;
    other.audio_generation_ = 0;
    other.video_generation_ = 0;
    return *this;
}

bool Device::granted(Source source) const noexcept {
    const std::uint32_t bit = source == Source::Microphone ? pm::room::k_grant_audio : pm::room::k_grant_video;
    return (grants_ & bit) != 0;
}

Error Device::open(std::string name, std::uint32_t grants) {
    if (name.empty() || name.size() > 128)
        return Error::make(ErrorCode::InvalidArgument, "host name is empty or too long");
    name_ = std::move(name);
    grants_ = grants;
    return {};
}

Error Device::install_send(pm::encryption::FlowKey key) {
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "host is not open");
    Error err;
    const auto epoch = key.epoch();
    const bool microphone = flow_is(key, k_microphone_flow);
    const bool camera = flow_is(key, k_camera_flow);
    if (!microphone && !camera)
        return Error::make(ErrorCode::InvalidArgument, "host flow id is not installed on this device");
    if (microphone) {
        audio_tx_ = pm::encryption::DatagramSender::adopt(std::move(key), err);
        if (!err)
            audio_generation_ = epoch;
        return err;
    }
    video_tx_ = pm::encryption::DatagramSender::adopt(std::move(key), err);
    if (!err)
        video_generation_ = epoch;
    return err;
}

Error Device::install_recv(pm::encryption::FlowKey key) {
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "host is not open");
    Error err;
    const auto epoch = key.epoch();
    const bool microphone = flow_is(key, k_microphone_flow);
    const bool camera = flow_is(key, k_camera_flow);
    if (!microphone && !camera)
        return Error::make(ErrorCode::InvalidArgument, "host flow id is not installed on this device");
    if (microphone) {
        audio_rx_ = pm::encryption::DatagramReceiver::adopt(std::move(key), err);
        if (!err)
            audio_generation_ = epoch;
        return err;
    }
    video_rx_ = pm::encryption::DatagramReceiver::adopt(std::move(key), err);
    if (!err)
        video_generation_ = epoch;
    return err;
}

void Device::set_muted(Source source, bool muted) {
    if (source == Source::Microphone)
        audio_muted_ = muted;
    else
        video_muted_ = muted;
}

Error Device::capture(Source source, std::uint32_t timestamp_ms, std::span<const std::uint8_t> encoded) {
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "host is not open");
    if (source != Source::Microphone && source != Source::Camera)
        return Error::make(ErrorCode::InvalidArgument, "host capture source is invalid");
    if (encoded.empty() || encoded.size() > pm::encryption::k_datagram_max_plaintext)
        return Error::make(ErrorCode::InvalidArgument, "host capture is empty or over 64 KiB");
    if (queue_.size() >= k_queue_cap)
        return Error::make(ErrorCode::InvalidArgument, "host capture queue is full");
    queue_.push_back(Captured{source, timestamp_ms, std::vector<std::uint8_t>(encoded.begin(), encoded.end())});
    return {};
}

Error Device::publish(std::vector<std::vector<std::uint8_t>>& plane) {
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "host is not open");
    for (const Captured& item : queue_) {
        if (!granted(item.source))
            return Error::make(ErrorCode::InvalidArgument, "host has no grant for that capture source");
        const bool muted = item.source == Source::Microphone ? audio_muted_ : video_muted_;
        if (muted)
            continue;
        const bool ready = item.source == Source::Microphone ? audio_tx_.valid() : video_tx_.valid();
        if (!ready)
            return Error::make(ErrorCode::UnexpectedState, "host has no send key for that capture source");
    }
    for (std::size_t i = 0; i < queue_.size(); ++i) {
        Captured& item = queue_[i];
        const bool muted = item.source == Source::Microphone ? audio_muted_ : video_muted_;
        if (muted) {
            ++muted_dropped_;
            continue;
        }
        std::vector<std::uint8_t> packet;
        Error err = item.source == Source::Microphone
            ? audio_tx_.seal(item.encoded, item.timestamp_ms, packet)
            : video_tx_.seal(item.encoded, item.timestamp_ms, packet);
        if (err) {
            std::vector<Captured> held;
            held.push_back(std::move(item));
            for (std::size_t j = i + 1; j < queue_.size(); ++j)
                held.push_back(std::move(queue_[j]));
            queue_ = std::move(held);
            return err;
        }
        plane.push_back(std::move(packet));
        ++published_;
    }
    queue_.clear();
    return {};
}

Error Device::render(std::span<const std::uint8_t> packet) {
    if (!valid())
        return Error::make(ErrorCode::InvalidArgument, "host is not open");
    std::vector<std::uint8_t> flow;
    if (Error label = pm::encryption::datagram_id(packet, flow))
        return label;
    const bool microphone = flow.size() == k_microphone_flow.size()
        && std::memcmp(flow.data(), k_microphone_flow.data(), flow.size()) == 0;
    const bool camera = flow.size() == k_camera_flow.size()
        && std::memcmp(flow.data(), k_camera_flow.data(), flow.size()) == 0;
    if (!microphone && !camera)
        return Error::make(ErrorCode::InvalidFrame, "host has no flow for that datagram");
    std::vector<std::uint8_t> payload;
    std::uint32_t timestamp = 0;
    std::uint64_t sequence = 0;
    Error err = microphone ? audio_rx_.open(packet, payload, timestamp, sequence)
                           : video_rx_.open(packet, payload, timestamp, sequence);
    if (err)
        return err;
    rendered_.push_back(Rendered{
        microphone ? Source::Microphone : Source::Camera,
        microphone ? audio_generation_ : video_generation_,
        sequence,
        timestamp,
        std::move(payload),
    });
    return {};
}

} // namespace pm::host
