#include "pm/room/pairing.hpp"

#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace pm::room {
namespace {

using pm::encryption::Error;
using pm::encryption::ErrorCode;
using pm::encryption::IdentityPublic;

constexpr char k_offer_domain[] = "pm.room.pair.offer.v1";
constexpr char k_accept_domain[] = "pm.room.pair.accept.v1";
constexpr char k_fingerprint_domain[] = "pm.room.pair.fingerprint.v1";

void append(std::vector<std::uint8_t>& out, std::span<const std::uint8_t> bytes) {
    out.insert(out.end(), bytes.begin(), bytes.end());
}

std::vector<std::uint8_t> offer_bytes(const PairOffer& offer) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), k_offer_domain, k_offer_domain + sizeof(k_offer_domain) - 1);
    append(out, offer.pairing_id);
    append(out, offer.initiator);
    return out;
}

std::vector<std::uint8_t> accept_bytes(const PairAccept& accept) {
    std::vector<std::uint8_t> out;
    out.insert(out.end(), k_accept_domain, k_accept_domain + sizeof(k_accept_domain) - 1);
    append(out, accept.pairing_id);
    append(out, accept.initiator);
    append(out, accept.responder);
    return out;
}

bool zero_id(const Id& id) {
    return sodium_is_zero(id.data(), id.size()) == 1;
}

} // namespace

pm::encryption::Error create_offer(const pm::encryption::Identity& initiator, const Id& pairing_id,
                                   PairOffer& out) {
    out = {};
    if (!initiator.valid() || zero_id(pairing_id))
        return Error::make(ErrorCode::InvalidArgument, "pairing offer needs an identity and an id");
    out.pairing_id = pairing_id;
    out.initiator = initiator.public_key();
    return initiator.sign(offer_bytes(out), out.signature);
}

pm::encryption::Error verify_offer(const PairOffer& offer) {
    if (zero_id(offer.pairing_id))
        return Error::make(ErrorCode::InvalidArgument, "pairing id is empty");
    return pm::encryption::Identity::verify(offer.initiator, offer_bytes(offer), offer.signature);
}

Fingerprint fingerprint_of(const IdentityPublic& first, const IdentityPublic& second, const Id& pairing_id,
                           pm::encryption::Error& err) {
    Fingerprint out{};
    err = {};
    if (sodium_init() < 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "libsodium initialization failed");
        return out;
    }
    IdentityPublic low = first;
    IdentityPublic high = second;
    if (sodium_memcmp(low.data(), high.data(), low.size()) > 0)
        std::swap(low, high);
    std::vector<std::uint8_t> body;
    body.insert(body.end(), k_fingerprint_domain, k_fingerprint_domain + sizeof(k_fingerprint_domain) - 1);
    append(body, pairing_id);
    append(body, low);
    append(body, high);
    std::array<std::uint8_t, 32> hash{};
    if (crypto_generichash(hash.data(), hash.size(), body.data(),
                           static_cast<unsigned long long>(body.size()), nullptr, 0) != 0) {
        err = Error::make(ErrorCode::CryptoUnavailable, "pairing fingerprint failed");
        return out;
    }
    std::copy_n(hash.begin(), out.size(), out.begin());
    return out;
}

pm::encryption::Error accept_offer(const pm::encryption::Identity& responder, const PairOffer& offer,
                                   PairAccept& out) {
    out = {};
    if (Error err = verify_offer(offer))
        return err;
    if (!responder.valid())
        return Error::make(ErrorCode::InvalidArgument, "pairing responder is invalid");
    if (sodium_memcmp(responder.public_key().data(), offer.initiator.data(), offer.initiator.size()) == 0)
        return Error::make(ErrorCode::InvalidArgument, "a device cannot pair with itself");
    out.pairing_id = offer.pairing_id;
    out.initiator = offer.initiator;
    out.responder = responder.public_key();
    return responder.sign(accept_bytes(out), out.signature);
}

pm::encryption::Error confirm_pairing(const pm::encryption::Identity& initiator, const PairAccept& accept,
                                      const Fingerprint& peer_displayed, PairedDevice& out) {
    out = {};
    if (!initiator.valid())
        return Error::make(ErrorCode::InvalidArgument, "pairing initiator is invalid");
    if (sodium_memcmp(accept.initiator.data(), initiator.public_key().data(), accept.initiator.size()) != 0)
        return Error::make(ErrorCode::IdentityMismatch, "pairing accept names a different initiator");
    if (Error err = pm::encryption::Identity::verify(accept.responder, accept_bytes(accept), accept.signature))
        return err;
    Error err;
    const Fingerprint local = fingerprint_of(accept.initiator, accept.responder, accept.pairing_id, err);
    if (err)
        return err;
    if (sodium_memcmp(local.data(), peer_displayed.data(), local.size()) != 0)
        return Error::make(ErrorCode::AuthenticationFailed,
                           "pairing fingerprint does not match the other device");
    out.peer = accept.responder;
    out.pairing_id = accept.pairing_id;
    out.trust = Trust::Paired;
    out.grants = k_grant_chat;
    return {};
}

} // namespace pm::room
