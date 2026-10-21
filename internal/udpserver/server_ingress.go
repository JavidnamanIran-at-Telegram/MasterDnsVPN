// ==============================================================================
// MasterDnsVPN
// Author: MasterkinG32
// Github: https://github.com/masterking32
// Year: 2026
// ==============================================================================

package udpserver

import (
	"errors"
	"fmt"
	"time"

	DnsParser "masterdnsvpn-go/internal/dnsparser"
	domainMatcher "masterdnsvpn-go/internal/domainmatcher"
	Enums "masterdnsvpn-go/internal/enums"
	VpnProto "masterdnsvpn-go/internal/vpnproto"
)

func (s *Server) handlePacket(packet []byte) []byte {
	parsed, err := DnsParser.ParseDNSRequestLite(packet)
	if err != nil {
		if errors.Is(err, DnsParser.ErrNotDNSRequest) || errors.Is(err, DnsParser.ErrPacketTooShort) {
			return nil
		}

		return s.buildNoDataResponseLogged(packet, "request-parse-failed")
	}

	return s.handleParsedPacket(packet, parsed, nil)
}

func (s *Server) handleParsedPacket(packet []byte, parsed DnsParser.LitePacket, err error) []byte {
	if err != nil || parsed.Header.QR != 0 {
		return nil
	}

	if !parsed.HasQuestion {
		return s.buildNoDataResponseLogged(packet, "request-has-no-question")
	}

	decision := s.domainMatcher.Match(parsed)
	switch decision.Action {
	case domainMatcher.ActionProcess:
		response := s.handleTunnelCandidate(packet, parsed, decision)
		if response != nil {
			return response
		}

		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-process-failed")
	case domainMatcher.ActionFormatError:
		return s.buildFormatErrorResponseLiteLogged(packet, parsed, decision.Reason)
	case domainMatcher.ActionNoData:
		if decision.Reason == "unauthorized-domain" {
			return s.buildNameErrorResponseLiteLogged(packet, parsed, decision.Reason)
		}
		return s.buildNoDataResponseLiteLogged(packet, parsed, decision.Reason)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, "domain-match-unknown-action")
	}
}
func (s *Server) handleTunnelCandidate(packet []byte, parsed DnsParser.LitePacket, decision domainMatcher.Decision) []byte {
	// With per-member identity on, the label directly above the zone is the
	// member's token and is not part of the payload. An absent or unknown
	// token is refused here, before any session exists - that refusal is the
	// whole of the metering boundary.
	tunnelLabels := decision.Labels
	rememberMember := func(uint32) {}
	if MemberIdentityEnabled() {
		payload, token, ok := splitMemberToken(decision.RequestName, decision.BaseDomain, tunnelLabels)
		if !ok {
			return s.buildNoDataResponseLiteLogged(packet, parsed, "member-token-missing")
		}
		account, authorized := authorizeMember(token)
		if !authorized {
			return s.buildNoDataResponseLiteLogged(packet, parsed, "member-token-unknown")
		}
		tunnelLabels = payload
		rememberMember = func(sessionID uint32) { rememberMemberSession(sessionID, account) }
	}

	vpnPacket, err := VpnProto.ParseInflatedFromLabels(tunnelLabels, s.codec)
	if err != nil {
		return s.buildNoDataResponseLiteLogged(packet, parsed, "vpn-proto-parse-failed")
	}

	// Only the first packets of a session carry a name we parsed, so bind the
	// session id to the member now; later streams are charged from that.
	rememberMember(uint32(vpnPacket.SessionID))

	if vpnPacket.PacketType == Enums.PACKET_SESSION_CLOSE {
		forgetMemberSession(uint32(vpnPacket.SessionID))
		s.handleSessionCloseNotice(vpnPacket, time.Now())
		return s.buildNoDataResponseLiteLogged(packet, parsed, "session-close-notice")
	}

	if !isPreSessionRequestType(vpnPacket.PacketType) {
		validation := s.validatePostSessionPacket(packet, decision.RequestName, vpnPacket)
		if !validation.ok {
			return validation.response
		}

		if !s.handlePostSessionPacket(vpnPacket, validation.record) {
			return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("post-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
		}

		return s.serveQueuedOrPong(packet, decision.RequestName, validation.record, time.Now())
	}

	switch vpnPacket.PacketType {
	case Enums.PACKET_MTU_UP_REQ:
		return s.handleMTUUpRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_MTU_DOWN_REQ:
		return s.handleMTUDownRequest(packet, parsed, decision, vpnPacket)
	case Enums.PACKET_SESSION_INIT:
		return s.handleSessionInitRequest(packet, decision, vpnPacket)
	default:
		return s.buildNoDataResponseLiteLogged(packet, parsed, fmt.Sprintf("pre-session-unhandled-%s", Enums.PacketTypeName(vpnPacket.PacketType)))
	}
}
