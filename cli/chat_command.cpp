#include "commands.hpp"
#include "support.hpp"

#include "pm/encryption/text_session.hpp"
#include "pm/room/broker.hpp"
#include "pm/room/text_room.hpp"

#include <sodium.h>

#include <cstring>
#include <iostream>
#include <string_view>
#include <vector>

namespace pm::encryption::cli {
namespace {

constexpr const char* k_schema = "pm.encryption.chat.v1";
constexpr std::string_view k_context = "tanit-chat|policy-v1";

nlohmann::json chat_failure(const char* code, std::string error) {
    return {{"ok", false}, {"schema", k_schema}, {"code", code}, {"error", std::move(error)}};
}

Identity keyed(std::uint8_t tag, Error& err) {
    Seed seed{};
    seed.fill(tag);
    return Identity::from_seed(seed, err);
}

bool contains_text(std::span<const std::uint8_t> hay, std::string_view needle) {
    if (needle.empty() || hay.size() < needle.size())
        return false;
    for (std::size_t i = 0; i + needle.size() <= hay.size(); ++i) {
        if (std::memcmp(hay.data() + i, needle.data(), needle.size()) == 0)
            return true;
    }
    return false;
}

PolicyId parse_policy(const std::string& name, bool& known) {
    known = true;
    if (name == "live")
        return PolicyId::LiveSession;
    if (name == "signal")
        return PolicyId::Signal;
    if (name == "unauthenticated-kx")
        return PolicyId::UnauthenticatedKx;
    if (name == "mls")
        return PolicyId::Mls;
    known = false;
    return PolicyId::LiveSession;
}

struct Party {
    Identity id;
    pm::room::TextRoom room;
    std::string signal_name;
};

} // namespace

int run_chat(const std::string& policy_name, const std::string& text, LogSink& log) {
    bool known = false;
    const PolicyId policy = parse_policy(policy_name, known);
    if (!known) {
        std::cout << chat_failure("invalid_argument", "chat policy is unknown").dump() << "\n";
        return 2;
    }
    if (text.empty() || text.size() > k_text_max_plaintext) {
        std::cout << chat_failure("invalid_argument", "chat text is empty or over 12288 bytes").dump() << "\n";
        return text.empty() ? 2 : 1;
    }

    Error err;
    Identity probe_a = keyed(0xA1, err);
    Identity probe_b = keyed(0xB2, err);
    TextSession refused;
    const Error unauth = TextSession::open(PolicyId::UnauthenticatedKx, EndpointRole::Initiator, probe_a,
                                           probe_b.public_key(), std::string(k_context), {}, {}, refused);
    const Error mls = TextSession::open(PolicyId::Mls, EndpointRole::Initiator, probe_a, probe_b.public_key(),
                                        std::string(k_context), {}, {}, refused);
    if (policy == PolicyId::UnauthenticatedKx || policy == PolicyId::Mls) {
        const Error& refused_policy = policy == PolicyId::Mls ? mls : unauth;
        log_warn(log, "chat", refused_policy.message);
        std::cout << chat_failure(error_code_name(refused_policy.code), refused_policy.message).dump() << "\n";
        return 1;
    }
    if (!policy_enabled(policy)) {
        std::cout << chat_failure("unexpected_state", "chat policy is not compiled").dump() << "\n";
        return 1;
    }

    Party alice;
    Party bob;
    Party carol;
    alice.signal_name = "alice";
    bob.signal_name = "bob";
    carol.signal_name = "carol";
    alice.id = keyed(0xA1, err);
    bob.id = keyed(0xB2, err);
    carol.id = keyed(0xC3, err);
    if (!err)
        err = pm::room::TextRoom::open(policy, alice.id, std::string(k_context), alice.signal_name, alice.room);
    if (!err)
        err = pm::room::TextRoom::open(policy, bob.id, std::string(k_context), bob.signal_name, bob.room);
    if (!err)
        err = pm::room::TextRoom::open(policy, carol.id, std::string(k_context), carol.signal_name, carol.room);
    if (!err)
        err = alice.room.add_peer(bob.id.public_key(), bob.signal_name);
    if (!err)
        err = alice.room.add_peer(carol.id.public_key(), carol.signal_name);
    if (!err)
        err = bob.room.add_peer(alice.id.public_key(), alice.signal_name);
    if (!err)
        err = carol.room.add_peer(alice.id.public_key(), alice.signal_name);

    auto room_id = random_session_id(err);
    pm::room::Broker broker;
    pm::room::Room room;
    if (!err)
        err = broker.create_room(alice.id, room_id, room);
    pm::room::Invite invite;
    if (!err)
        err = broker.invite(alice.id, room_id, bob.id.public_key(), pm::room::k_grant_chat, invite);
    if (!err)
        err = broker.join(bob.id, invite, room);
    if (!err)
        err = broker.invite(alice.id, room_id, carol.id.public_key(), pm::room::k_grant_chat, invite);
    if (!err)
        err = broker.join(carol.id, invite, room);

    auto hop = [&](Party& from, const IdentityPublic& to_id, Party& to) {
        if (err || !from.room.wants_pull(to_id))
            return;
        std::vector<std::uint8_t> frame;
        err = from.room.pull(to_id, frame);
        pm::room::Envelope envelope;
        if (!err)
            err = broker.post(from.id, room_id, frame, envelope);
        if (!err)
            err = to.room.push(from.id.public_key(), envelope.frame);
    };

    for (int step = 0; !err && step < 16; ++step) {
        const bool done = alice.room.ready(bob.id.public_key()) && bob.room.ready(alice.id.public_key())
            && alice.room.ready(carol.id.public_key()) && carol.room.ready(alice.id.public_key());
        if (done)
            break;
        hop(alice, bob.id.public_key(), bob);
        hop(bob, alice.id.public_key(), alice);
        hop(alice, carol.id.public_key(), carol);
        hop(carol, alice.id.public_key(), alice);
    }

    const bool setup = !err && alice.room.ready(bob.id.public_key()) && bob.room.ready(alice.id.public_key())
        && alice.room.ready(carol.id.public_key()) && carol.room.ready(alice.id.public_key());

    auto deliver = [&](Party& from, Party& to, std::vector<std::uint8_t>& posted) {
        posted.clear();
        if (err)
            return;
        err = from.room.seal(to.id.public_key(),
                             {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()}, posted);
        pm::room::Envelope envelope;
        if (!err)
            err = broker.post(from.id, room_id, posted, envelope);
        if (!err)
            posted = envelope.frame;
        std::vector<std::uint8_t> opened;
        if (!err)
            err = to.room.open_frame(from.id.public_key(), posted, opened);
        if (!err && (opened.size() != text.size() || std::memcmp(opened.data(), text.data(), text.size()) != 0))
            err = Error::make(ErrorCode::AuthenticationFailed, "opened text does not match");
    };

    std::vector<std::uint8_t> first;
    std::vector<std::uint8_t> for_alice;
    IdentityPublic sender_for_alice{};
    if (setup) {
        const bool alice_starts = TextSession::role_for(alice.id.public_key(), bob.id.public_key())
            == EndpointRole::Initiator;
        if (alice_starts) {
            deliver(alice, bob, first);
            if (!err)
                deliver(bob, alice, for_alice);
            sender_for_alice = bob.id.public_key();
        } else {
            deliver(bob, alice, for_alice);
            sender_for_alice = bob.id.public_key();
        }
    }

    std::vector<std::uint8_t> ignored;
    Error wrong_session;
    Error wrong_address;
    bool plaintext_hidden = false;
    if (!err && setup && !for_alice.empty()) {
        plaintext_hidden = !contains_text(for_alice, text) && (first.empty() || !contains_text(first, text));
        wrong_session = alice.room.open_frame(carol.id.public_key(), for_alice, ignored);
        wrong_address = carol.room.open_frame(sender_for_alice, for_alice, ignored);
    }

    const auto session_rejected = [](ErrorCode code) {
        return code == ErrorCode::AuthenticationFailed || code == ErrorCode::WrongDirection
            || code == ErrorCode::WrongSession || code == ErrorCode::IdentityMismatch;
    };
    const bool opened = !err && setup && plaintext_hidden && session_rejected(wrong_session.code)
        && wrong_address.code == ErrorCode::NotRecipient && alice.room.peers() == 2 && room.members.size() == 3;
    log_info(log, "chat", opened ? "passed" : std::string_view{err.message});
    std::cout << nlohmann::json{
                     {"ok", opened},
                     {"schema", k_schema},
                     {"policy", policy_id_name(policy)},
                     {"api", "text-session"},
                     {"socket", false},
                     {"hosts", "desktop-android"},
                     {"peers", alice.room.peers()},
                     {"members", room.members.size()},
                     {"shared_key", false},
                     {"pairwise", true},
                     {"relayed", opened},
                     {"broker_sees_plaintext", !plaintext_hidden},
                     {"other_session_rejected", session_rejected(wrong_session.code)},
                     {"other_device_rejected", wrong_address.code == ErrorCode::NotRecipient},
                     {"unauthenticated_refused", unauth.code == ErrorCode::InvalidArgument},
                     {"mls_refused", mls.code == ErrorCode::InvalidArgument},
                     {"signal_bound_to_device", false},
                     {"channel_key", policy == PolicyId::LiveSession ? "one-for-process" : "ratchet"},
                     {"error", opened ? "" : (err ? err.message : wrong_session.message)},
                 }
                     .dump()
              << "\n";
    return opened ? 0 : 1;
}

} // namespace pm::encryption::cli
