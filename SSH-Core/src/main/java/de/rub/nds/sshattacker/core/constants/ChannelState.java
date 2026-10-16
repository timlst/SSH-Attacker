/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.constants;

/**
 * The lifecycle of a channel (RFC 4254, sections 5.1 and 5.3), seen from the local side.
 *
 * <p>A channel whose open is rejected by either side is dropped instead of getting a state of its
 * own.
 */
public enum ChannelState {
    /** We sent SSH_MSG_CHANNEL_OPEN and are waiting for the peer to confirm or reject it. */
    OPEN_SENT,
    /** The peer sent SSH_MSG_CHANNEL_OPEN, and we have not confirmed or rejected it yet. */
    OPEN_RECEIVED,
    /** The open was confirmed, and neither side sent SSH_MSG_CHANNEL_CLOSE yet. */
    OPEN,
    /** We sent SSH_MSG_CHANNEL_CLOSE and are waiting for the peer's. */
    CLOSE_SENT,
    /** The peer sent SSH_MSG_CHANNEL_CLOSE, and we have not sent ours yet. */
    CLOSE_RECEIVED,
    /** Both sides sent SSH_MSG_CHANNEL_CLOSE. */
    CLOSED
}
