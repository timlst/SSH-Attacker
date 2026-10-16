/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection;

import de.rub.nds.sshattacker.core.constants.ChannelState;
import de.rub.nds.sshattacker.core.constants.ChannelType;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.*;
import java.util.stream.IntStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Keeps track of the channels of a connection, both the ones we open and the ones the peer opens.
 *
 * <p>Channels are stored by their local id only: every channel message the peer sends names the
 * channel by our id, and every message we send takes the peer's id from the channel. Whether an
 * open is still pending is recorded in the channel's {@link ChannelState}. The map keeps the order
 * in which channels were added, so the peer's opens are answered oldest first.
 */
public class ChannelManager {

    private static final Logger LOGGER = LogManager.getLogger();

    private final SshContext context;

    /**
     * Maps local channel id to the channel object, in the order they were added Requested but not
     * yet confirmed channels are included, with state {@link ChannelState#OPEN_RECEIVED} or {@link
     * ChannelState#OPEN_SENT}.
     */
    private final LinkedHashMap<Integer, Channel> channels = new LinkedHashMap<>();

    /** Local ids of the channels with a peer request that wants a reply, oldest first. */
    private final Deque<Integer> channelsAwaitingReply = new ArrayDeque<>();

    /**
     * Local id of the channel explicitly selected for outgoing messages that do not name one, or
     * null to fall back to the most recently opened channel. Moved by the channel selection
     * symbols.
     */
    private Integer selectedChannelId = null;

    public ChannelManager(SshContext context) {
        super();
        this.context = context;
    }

    /** Selects the first channel in open order, if any. */
    public void selectFirstChannel() {
        Iterator<Integer> it = channels.keySet().iterator();
        selectedChannelId = it.hasNext() ? it.next() : null;
    }

    /** Moves the selection to the next channel in open order, wrapping around. */
    public void selectNextChannel() {
        moveSelection(1);
    }

    /** Moves the selection to the previous channel in open order, wrapping around. */
    public void selectPreviousChannel() {
        moveSelection(-1);
    }

    private void moveSelection(int delta) {
        List<Integer> ids = new ArrayList<>(channels.keySet());
        if (ids.isEmpty()) {
            selectedChannelId = null;
            return;
        }
        int idx = selectedChannelId == null ? -1 : ids.indexOf(selectedChannelId);
        if (idx < 0) {
            // No (or stale) selection: next/first picks the first channel, previous the last.
            selectedChannelId = delta >= 0 ? ids.get(0) : ids.get(ids.size() - 1);
        } else {
            selectedChannelId = ids.get(Math.floorMod(idx + delta, ids.size()));
        }
    }

    private Channel selectedChannel() {
        return selectedChannelId == null ? null : channels.get(selectedChannelId);
    }

    /**
     * @return The channels by their local id, in the order they were added
     */
    public Map<Integer, Channel> getChannels() {
        return channels;
    }

    /**
     * @return The lowest local channel id that is not in use
     */
    public int findUnusedChannelId() {
        return IntStream.iterate(0, i -> i + 1)
                .filter(i -> !channels.containsKey(i))
                .findFirst()
                .orElseThrow(); // should never occur with infinite stream
    }

    /**
     * Registers a channel the peer opened, under a fresh local id. It stays in {@link
     * ChannelState#OPEN_RECEIVED} until we confirm or reject it.
     */
    public void handleChannelOpenMessage(ChannelOpenMessage<?> message) {
        int remoteChannelId = message.getSenderChannelId().getValue();
        // The peer's id of a channel we opened is only known once the peer confirmed it
        if (channels.values().stream()
                .anyMatch(
                        channel ->
                                channel.getState() != ChannelState.OPEN_SENT
                                        && channel.getRemoteChannelId().getValue()
                                                == remoteChannelId)) {
            LOGGER.warn(
                    "Peer opened a channel with id {}, which it already uses for another channel. Tracking it as a separate channel anyway.",
                    remoteChannelId);
        }
        Channel channel = createNewChannelFromDefaults(remoteChannelId);
        channel.setChannelType(ChannelType.fromName(message.getChannelType().getValue()));
        channel.setRemoteWindowSize(message.getInitialWindowSize());
        channel.setRemotePacketSize(message.getMaximumPacketSize());
        channel.setState(ChannelState.OPEN_RECEIVED);
    }

    /**
     * @return The oldest channel the peer opened that we neither confirmed nor rejected yet
     */
    public Optional<Channel> nextUnansweredIncomingOpen() {
        return channels.values().stream()
                .filter(channel -> channel.getState() == ChannelState.OPEN_RECEIVED)
                .findFirst();
    }

    /**
     * Guesses the channel a message is meant for, if it does not name one: the most recently added
     * open channel, or else the most recently added channel at all.
     */
    public Optional<Channel> guessChannel() {
        Channel selected = selectedChannel();
        if (selected != null) {
            return Optional.of(selected);
        }
        Channel lastChannel = null;
        Channel lastOpenChannel = null;
        for (Channel channel : channels.values()) {
            lastChannel = channel;
            if (channel.isOpen()) {
                lastOpenChannel = channel;
            }
        }
        return Optional.ofNullable(lastOpenChannel != null ? lastOpenChannel : lastChannel);
    }

    /** Records that the peer sent a channel request that wants a reply. */
    public void addToChannelRequestResponseQueue(ChannelMessage<?> message) {
        channelsAwaitingReply.add(message.getRecipientChannelId().getValue());
    }

    /**
     * Takes the channel of the oldest peer request that still awaits our reply.
     *
     * <p>If the peer sent that request on a channel that does not exist (anymore), the reply goes
     * to the id the peer named: the returned channel is created from the defaults with that id as
     * local and remote id, but not added to the channel map.
     */
    public Optional<Channel> takeChannelAwaitingReply() {
        Integer localChannelId = channelsAwaitingReply.pollFirst();
        if (localChannelId == null) {
            return Optional.empty();
        }
        Channel channel = channels.get(localChannelId);
        if (channel == null) {
            LOGGER.warn(
                    "Peer request on channel with id {} awaits a reply, but no such channel exists. Replying to that id.",
                    localChannelId);
            channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
            channel.setLocalChannelId(localChannelId);
            channel.setRemoteChannelId(localChannelId);
        }
        return Optional.of(channel);
    }

    /**
     * Create a new channel from the configured defaults and add it to the channel map.
     *
     * @param localChannelId the local channel ID
     * @param remoteChannelId the remote channel ID
     * @return the created channel
     */
    public Channel createNewChannelFromDefaults(int localChannelId, int remoteChannelId) {
        Channel channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
        channel.setLocalChannelId(localChannelId);
        channel.setRemoteChannelId(remoteChannelId);
        channels.put(localChannelId, channel);
        return channel;
    }

    /**
     * Create a new channel from the configured defaults and add it to the channel map.
     *
     * <p>This is a convenience method that selects the next free local channel ID automatically.
     *
     * @param remoteChannelId the remote channel ID
     * @return the created channel
     */
    public Channel createNewChannelFromDefaults(int remoteChannelId) {
        int localChannelId = findUnusedChannelId();
        return createNewChannelFromDefaults(localChannelId, remoteChannelId);
    }
}
