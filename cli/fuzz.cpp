#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/features.hpp"
#include "pm/encryption/file.hpp"

#include <iostream>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <functional>
#include <utility>
#include <vector>

#if PM_ENCRYPTION_LIVE_SESSION
#include "pm/encryption/handshake.hpp"
#endif

namespace pm::encryption::cli {
namespace {

void mutate(const std::vector<std::uint8_t>& original,
            const std::function<void(const std::vector<std::uint8_t>&)>& feed) {
    if (original.empty())
        return;
    std::vector<std::uint8_t> buf = original;
    for (std::size_t i = 0; i < buf.size(); ++i) {
        buf[i] = static_cast<std::uint8_t>(buf[i] ^ (1u << (i % 8)));
        feed(buf);
        buf[i] = static_cast<std::uint8_t>(buf[i] ^ (1u << (i % 8)));
    }
    const std::size_t step = std::max<std::size_t>(1, buf.size() / 16);
    for (std::size_t n = 0; n < buf.size(); n += step)
        feed(std::vector<std::uint8_t>(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n)));
    buf.push_back(0x5a);
    feed(buf);
    feed({});
    feed(std::vector<std::uint8_t>(64, 0xff));
}

#if PM_ENCRYPTION_LIVE_SESSION

bool make_pair(Handshake& initiator, Handshake& responder, Error& err) {
    Seed identity_i{};
    Seed identity_r{};
    Seed ephemeral_i{};
    Seed ephemeral_r{};
    for (std::size_t i = 0; i < identity_i.size(); ++i) {
        identity_i[i] = static_cast<std::uint8_t>(i + 1);
        identity_r[i] = static_cast<std::uint8_t>(0x40 + i);
        ephemeral_i[i] = static_cast<std::uint8_t>(0x10 + i);
        ephemeral_r[i] = static_cast<std::uint8_t>(0xc0 + i);
    }
    auto left = Identity::from_seed(identity_i, err);
    auto right = Identity::from_seed(identity_r, err);
    auto left_ephemeral = KeyPair::from_seed(ephemeral_i, err);
    auto right_ephemeral = KeyPair::from_seed(ephemeral_r, err);
    if (err)
        return false;
    const auto left_public = left.public_key();
    const auto right_public = right.public_key();
    initiator = Handshake::initiator(std::move(left), right_public, "fuzz-v1",
                                     std::move(left_ephemeral), test_session(), err);
    responder = Handshake::responder(std::move(right), left_public, "fuzz-v1",
                                     std::move(right_ephemeral), err);
    return !err;
}

#endif

} // namespace

int run_fuzz() {
    Error err;
    int trials = 0;
    int accepted = 0;

#if PM_ENCRYPTION_LIVE_SESSION
    Handshake initiator;
    Handshake responder;
    if (!make_pair(initiator, responder, err)) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    std::vector<std::uint8_t> message_1;
    std::vector<std::uint8_t> message_2;
    std::vector<std::uint8_t> message_3;
    if (initiator.write_message(message_1) || responder.read_message(message_1)
        || responder.write_message(message_2) || initiator.read_message(message_2)
        || initiator.write_message(message_3) || responder.read_message(message_3)) {
        std::cout << error_json(Error::make(ErrorCode::UnexpectedState, "fuzz handshake setup failed")).dump()
                  << "\n";
        return 1;
    }
    auto send = initiator.take_channel(err);
    auto recv = responder.take_channel(err);
    std::vector<std::uint8_t> frame;
    std::vector<std::uint8_t> opened;
    if (err || send.seal(bytes_of("fuzz"), "text/plain", frame)) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    mutate(frame, [&](const std::vector<std::uint8_t>& sample) {
        ++trials;
        opened.clear();
        if (!recv.open(sample, "text/plain", opened) || !opened.empty())
            ++accepted;
    });
    mutate(message_2, [&](const std::vector<std::uint8_t>& sample) {
        ++trials;
        Handshake peer_i;
        Handshake peer_r;
        Error local;
        if (!make_pair(peer_i, peer_r, local))
            return;
        std::vector<std::uint8_t> first;
        if (peer_i.write_message(first) || peer_r.read_message(first))
            return;
        if (!peer_i.read_message(sample))
            ++accepted;
    });
    mutate(message_3, [&](const std::vector<std::uint8_t>& sample) {
        ++trials;
        Handshake peer_i;
        Handshake peer_r;
        Error local;
        if (!make_pair(peer_i, peer_r, local))
            return;
        std::vector<std::uint8_t> first;
        std::vector<std::uint8_t> second;
        if (peer_i.write_message(first) || peer_r.read_message(first) || peer_r.write_message(second)
            || peer_i.read_message(second))
            return;
        if (!peer_r.read_message(sample))
            ++accepted;
    });
    mutate(message_1, [&](const std::vector<std::uint8_t>& sample) {
        ++trials;
        Handshake peer_i;
        Handshake peer_r;
        Error local;
        if (!make_pair(peer_i, peer_r, local))
            return;
        peer_r.read_message(sample);
    });
#else
    (void)err;
#endif

    Seed signer{};
    Seed sender_seed{};
    Seed recipient_seed{};
    signer.fill(0x11);
    sender_seed.fill(0x22);
    recipient_seed.fill(0x33);
    auto signer_id = Identity::from_seed(signer, err);
    auto sender_file = FileKey::from_seed(sender_seed, err);
    auto recipient_saved = FileKey::from_seed(recipient_seed, err);
    FileId transfer{};
    FileId room{};
    transfer.fill(0x44);
    room.fill(0x55);
    const PublicKey recipients[] = {recipient_saved.public_key()};
    FileOffer offer;
    if (!err)
        err = create_file_offer(signer_id, sender_file, transfer, room, "fuzz.bin",
                                "application/octet-stream", bytes_of("fuzz-file"), 4, recipients, offer);
    std::vector<std::uint8_t> offer_blob;
    if (!err)
        err = encode_file_offer(offer, offer_blob);
    if (err) {
        std::cout << error_json(err).dump() << "\n";
        return 1;
    }
    const auto manifest = offer.manifest;
    const auto seals = offer.seals;
    const auto chunk0 = offer.chunks.empty() ? std::vector<std::uint8_t>{} : offer.chunks[0];
    mutate(offer_blob, [&](const std::vector<std::uint8_t>& sample) {
        ++trials;
        FileOffer decoded;
        Error decoded_err = decode_file_offer(sample, decoded);
        if (decoded_err)
            return;
        Error open_err;
        auto inbox = FileInbox::open(FileKey::from_seed(recipient_seed, open_err), decoded.manifest,
                                     decoded.seals, open_err);
        if (!open_err && inbox.valid())
            ++accepted;
    });
    if (!chunk0.empty()) {
        mutate(chunk0, [&](const std::vector<std::uint8_t>& sample) {
            ++trials;
            Error open_err;
            auto inbox = FileInbox::open(FileKey::from_seed(recipient_seed, open_err), manifest, seals, open_err);
            if (open_err)
                return;
            if (!inbox.accept(0, sample))
                ++accepted;
        });
    }

    const bool ok = accepted == 0 && trials > 0;
    std::cout << nlohmann::json{{"ok", ok},
                                {"schema", "pm.encryption.fuzz.v1"},
                                {"trials", trials},
                                {"accepted", accepted},
                                {"handshake", static_cast<bool>(PM_ENCRYPTION_LIVE_SESSION)},
                                {"frame", static_cast<bool>(PM_ENCRYPTION_LIVE_SESSION)},
                                {"file", true}}
                     .dump()
              << "\n";
    return ok ? 0 : 1;
}

} // namespace pm::encryption::cli
