/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection;

import de.rub.nds.modifiablevariable.ModifiableVariableFactory;
import de.rub.nds.modifiablevariable.integer.ModifiableInteger;
import de.rub.nds.sshattacker.core.constants.ChannelState;
import de.rub.nds.sshattacker.core.constants.ChannelType;
import java.io.Serializable;

public class Channel implements Serializable {

    private ChannelType channelType;
    private ModifiableInteger localChannelId;
    private ModifiableInteger localWindowSize;
    private ModifiableInteger localPacketSize;

    private ModifiableInteger remoteChannelId;
    private ModifiableInteger remoteWindowSize;
    private ModifiableInteger remotePacketSize;

    /**
     * Channels created from the defaults are assumed to be established. The open handshake sets
     * {@link ChannelState#OPEN_SENT} or {@link ChannelState#OPEN_RECEIVED} explicitly.
     */
    private ChannelState state = ChannelState.OPEN;

    public Channel() {
        super();
    }

    public Channel(
            ChannelType channelType,
            Integer localChannelId,
            Integer localWindowSize,
            Integer localPacketSize) {
        super();
        this.channelType = channelType;
        setLocalChannelId(localChannelId);
        setLocalWindowSize(localWindowSize);
        setLocalPacketSize(localPacketSize);
    }

    public Channel(
            ChannelType channelType,
            ModifiableInteger localChannelId,
            ModifiableInteger localWindowSize,
            ModifiableInteger localPacketSize) {
        super();
        this.channelType = channelType;
        this.localChannelId = localChannelId;
        this.localWindowSize = localWindowSize;
        this.localPacketSize = localPacketSize;
    }

    public Channel(
            ChannelType channelType,
            Integer localChannelId,
            Integer localWindowSize,
            Integer localPacketSize,
            Integer remoteChannelId,
            Integer remoteWindowSize,
            Integer remotePacketSize) {
        super();
        this.channelType = channelType;
        setLocalChannelId(localChannelId);
        setLocalWindowSize(localWindowSize);
        setLocalPacketSize(localPacketSize);
        setRemoteChannelId(remoteChannelId);
        setRemoteWindowSize(remoteWindowSize);
        setRemotePacketSize(remotePacketSize);
    }

    public ChannelType getChannelType() {
        return channelType;
    }

    public void setChannelType(ChannelType channelType) {
        this.channelType = channelType;
    }

    public ModifiableInteger getLocalPacketSize() {
        return localPacketSize;
    }

    public void setLocalPacketSize(ModifiableInteger localPacketSize) {
        this.localPacketSize = localPacketSize;
    }

    public void setLocalPacketSize(Integer localPacketSize) {
        this.localPacketSize =
                ModifiableVariableFactory.safelySetValue(this.localPacketSize, localPacketSize);
    }

    public ChannelState getState() {
        return state;
    }

    public void setState(ChannelState state) {
        this.state = state;
    }

    /**
     * @return Whether the open was confirmed and no side sent SSH_MSG_CHANNEL_CLOSE yet
     */
    public boolean isOpen() {
        return state == ChannelState.OPEN;
    }

    /** Records that we sent SSH_MSG_CHANNEL_CLOSE. */
    public void closeSent() {
        state =
                state == ChannelState.CLOSE_RECEIVED
                        ? ChannelState.CLOSED
                        : ChannelState.CLOSE_SENT;
    }

    /** Records that the peer sent SSH_MSG_CHANNEL_CLOSE. */
    public void closeReceived() {
        state =
                state == ChannelState.CLOSE_SENT
                        ? ChannelState.CLOSED
                        : ChannelState.CLOSE_RECEIVED;
    }

    public ModifiableInteger getLocalWindowSize() {
        return localWindowSize;
    }

    public void setLocalWindowSize(ModifiableInteger localWindowSize) {
        this.localWindowSize = localWindowSize;
    }

    public void setLocalWindowSize(Integer localWindowSize) {
        this.localWindowSize =
                ModifiableVariableFactory.safelySetValue(this.localWindowSize, localWindowSize);
    }

    public ModifiableInteger getLocalChannelId() {
        return localChannelId;
    }

    public void setLocalChannelId(ModifiableInteger localChannelId) {
        this.localChannelId = localChannelId;
    }

    public void setLocalChannelId(Integer localChannelId) {
        this.localChannelId =
                ModifiableVariableFactory.safelySetValue(this.localChannelId, localChannelId);
    }

    public ModifiableInteger getRemoteChannelId() {
        return remoteChannelId;
    }

    public void setRemoteChannelId(ModifiableInteger remoteChannelId) {
        this.remoteChannelId = remoteChannelId;
    }

    public void setRemoteChannelId(Integer remoteChannelId) {
        this.remoteChannelId =
                ModifiableVariableFactory.safelySetValue(this.remoteChannelId, remoteChannelId);
    }

    public ModifiableInteger getRemotePacketSize() {
        return remotePacketSize;
    }

    public void setRemotePacketSize(ModifiableInteger remotePacketSize) {
        this.remotePacketSize = remotePacketSize;
    }

    public void setRemotePacketSize(Integer remotePacketSize) {
        this.remotePacketSize =
                ModifiableVariableFactory.safelySetValue(this.remotePacketSize, remotePacketSize);
    }

    public ModifiableInteger getRemoteWindowSize() {
        return remoteWindowSize;
    }

    public void setRemoteWindowSize(ModifiableInteger remoteWindowSize) {
        this.remoteWindowSize = remoteWindowSize;
    }

    public void setRemoteWindowSize(Integer remoteWindowSize) {
        this.remoteWindowSize =
                ModifiableVariableFactory.safelySetValue(this.remoteWindowSize, remoteWindowSize);
    }

    @Override
    public String toString() {
        return "\n"
                + "Channel{"
                + "\n"
                + " channelType: "
                + channelType
                + "\n"
                + " localChannelId: "
                + localChannelId.getValue()
                + "\n"
                + " localWindowSize: "
                + localWindowSize.getValue()
                + "\n"
                + " localPacketSize: "
                + localPacketSize.getValue()
                + "\n"
                + " remoteChannelId: "
                + remoteChannelId.getValue()
                + "\n"
                + " remoteWindowSize: "
                + remoteWindowSize.getValue()
                + "\n"
                + " remotePacketSize: "
                + remotePacketSize.getValue()
                + "\n"
                + " state: "
                + state
                + "\n"
                + '}';
    }
}
