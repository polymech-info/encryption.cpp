#include "support.hpp"

#include "pm/encryption/features.hpp"
#include "pm/encryption/handshake.hpp"

#include <utility>

namespace pm::encryption::cli {

void run_handshake_checks(Check& check) {
    Error err;
    Seed identity_i{};
    Seed identity_r{};
    Seed identity_x{};
    Seed ephemeral_i{};
    Seed ephemeral_r{};
    for (std::size_t i = 0; i < identity_i.size(); ++i) {
        identity_i[i] = static_cast<std::uint8_t>(i + 1);
        identity_r[i] = static_cast<std::uint8_t>(0x40U + i);
        identity_x[i] = static_cast<std::uint8_t>(0x80U + i);
        ephemeral_i[i] = static_cast<std::uint8_t>(0x10U + i);
        ephemeral_r[i] = static_cast<std::uint8_t>(0xc0U + i);
    }

    auto make_pair = [&](std::string context, Handshake& initiator, Handshake& responder) {
        auto left = Identity::from_seed(identity_i, err);
        if (err)
            return false;
        auto right = Identity::from_seed(identity_r, err);
        if (err)
            return false;
        auto left_ephemeral = KeyPair::from_seed(ephemeral_i, err);
        if (err)
            return false;
        auto right_ephemeral = KeyPair::from_seed(ephemeral_r, err);
        if (err)
            return false;
        const auto left_public = left.public_key();
        const auto right_public = right.public_key();
        initiator = Handshake::initiator(std::move(left), right_public, context,
                                         std::move(left_ephemeral), test_session(), err);
        if (err)
            return false;
        responder = Handshake::responder(std::move(right), left_public, std::move(context),
                                         std::move(right_ephemeral), err);
        return !err;
    };

    {
        auto same = Identity::from_seed(identity_i, err);
        auto again = Identity::from_seed(identity_i, err);
        auto ephemeral = KeyPair::from_seed(ephemeral_i, err);
        auto rejected = Handshake::initiator(
            std::move(same), again.public_key(), "same-device", std::move(ephemeral),
            test_session(), err);
        check(err.code == ErrorCode::InvalidArgument && !rejected.complete(),
              "reject a handshake with one identity on both ends", error_code_name(err.code));
    }

    Handshake initiator;
    Handshake responder;
    check(make_pair("wifi-room", initiator, responder), "create pinned handshake", err.message);
    std::vector<std::uint8_t> first;
    std::vector<std::uint8_t> second;
    std::vector<std::uint8_t> third;
    auto wrote_first = initiator.write_message(first);
    auto read_first = responder.read_message(first);
    auto wrote_second = responder.write_message(second);
    auto read_second = initiator.read_message(second);
    auto wrote_third = initiator.write_message(third);
    auto read_third = responder.read_message(third);
    const bool finished = !wrote_first && !read_first && !wrote_second && !read_second
        && !wrote_third && !read_third && initiator.complete() && responder.complete();
    check(finished, "complete mutual identity handshake",
          wrote_first.message + read_first.message + wrote_second.message + read_second.message
              + wrote_third.message + read_third.message);
    auto left = initiator.take_channel(err);
    auto right = responder.take_channel(err);
    std::vector<std::uint8_t> frame;
    std::vector<std::uint8_t> opened;
    const auto body = bytes_of("hello identity");
    auto sealed = left.seal(body, "application/octet-stream", frame);
    auto unsealed = right.open(frame, "application/octet-stream", opened);
    check(finished && !err && !sealed && !unsealed && opened == body,
          "handshake channel round-trips payload bytes", unsealed.message);
    Error second_take;
    auto discarded = initiator.take_channel(second_take);
    check(second_take.code == ErrorCode::UnexpectedState && !discarded.valid(),
          "channel can be taken once", error_code_name(second_take.code));

    {
        Handshake sender;
        Handshake receiver;
        check(make_pair("wifi-room", sender, receiver), "rebuild handshake for tamper", err.message);
        std::vector<std::uint8_t> message;
        sender.write_message(message);
        receiver.read_message(message);
        receiver.write_message(message);
        message.back() ^= 0x01;
        err = sender.read_message(message);
        check(err.code == ErrorCode::BadSignature, "reject a modified handshake signature",
              error_code_name(err.code));
    }
    {
        Handshake sender;
        Handshake receiver;
        make_pair("wifi-room", sender, receiver);
        std::vector<std::uint8_t> message;
        sender.write_message(message);
        message[4] = 9;
        err = receiver.read_message(message);
        check(err.code == ErrorCode::UnsupportedVersion, "reject a handshake version change",
              error_code_name(err.code));
    }
    {
        Handshake sender;
        Handshake receiver;
        make_pair("wifi-room", sender, receiver);
        std::vector<std::uint8_t> message;
        sender.write_message(message);
        auto local = Identity::from_seed(identity_r, err);
        auto stranger = Identity::from_seed(identity_x, err);
        auto ephemeral = KeyPair::from_seed(ephemeral_r, err);
        auto wrong_peer = Handshake::responder(
            std::move(local), stranger.public_key(), "wifi-room", std::move(ephemeral), err);
        err = wrong_peer.read_message(message);
        check(err.code == ErrorCode::IdentityMismatch, "reject an unpinned initiator identity",
              error_code_name(err.code));
    }
    {
        auto left_id = Identity::from_seed(identity_i, err);
        auto right_id = Identity::from_seed(identity_r, err);
        auto left_ephemeral = KeyPair::from_seed(ephemeral_i, err);
        auto right_ephemeral = KeyPair::from_seed(ephemeral_r, err);
        const auto left_public = left_id.public_key();
        const auto right_public = right_id.public_key();
        auto sender = Handshake::initiator(
            std::move(left_id), right_public, "context-a", std::move(left_ephemeral),
            test_session(), err);
        auto receiver = Handshake::responder(
            std::move(right_id), left_public, "context-b", std::move(right_ephemeral), err);
        std::vector<std::uint8_t> message;
        sender.write_message(message);
        receiver.read_message(message);
        receiver.write_message(message);
        err = sender.read_message(message);
        check(err.code == ErrorCode::BadSignature, "bind the caller context into the signature",
              error_code_name(err.code));
    }
    {
        Handshake sender;
        make_pair("wifi-room", sender, responder);
        std::vector<std::uint8_t> message;
        sender.write_message(message);
        err = sender.write_message(message);
        check(err.code == ErrorCode::UnexpectedState, "reject a handshake write from the wrong state",
              error_code_name(err.code));
    }

#if PM_ENCRYPTION_UNAUTHENTICATED_KX
    {
        Handshake sender;
        Handshake receiver;
        make_pair("wifi-room", sender, receiver);
        std::vector<std::uint8_t> message;
        sender.write_message(message);
        receiver.read_message(message);
        receiver.write_message(message);
        sender.read_message(message);
        sender.write_message(message);
        receiver.read_message(message);
        auto channel = sender.take_channel(err);
        channel.seal(bytes_of("bound"), "application/octet-stream", frame);
        auto raw_ephemeral = KeyPair::from_seed(ephemeral_r, err);
        auto peer_keys = KeyPair::from_seed(ephemeral_i, err);
        const auto peer_ephemeral = peer_keys.public_key();
        auto raw = SecureChannel::responder(
            std::move(raw_ephemeral), peer_ephemeral, test_session(), "not-the-transcript", err);
        err = raw.open(frame, "application/octet-stream", opened);
        check(err.code == ErrorCode::AuthenticationFailed,
              "raw key agreement cannot open a handshake frame", error_code_name(err.code));
    }
#endif
}

} // namespace pm::encryption::cli
