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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelSuccessMessage;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.util.*;
import java.util.stream.IntStream;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Keeps track of the channels of a connection, both the ones we open and the ones the peer opens.
 *
 *<p>Channels are stored in a map by their local id, accessible via {@link #getChannels}.
 * Each channel maintains its lifecycle in the {@link ChannelState} enum.
 * The ChannelManager separately tracks a fallback channel for cases in which sent messages do not reference a channel.
 *
 * It also keeps track of unanswered channel requests, which replaces the fallback channel for messages like {@link ChannelSuccessMessage} and {@link ChannelFailureMessage} that are replies to a peer request.
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

    /** The channel messages that name none go to; null only while there are no channels. */
    private Channel fallbackGuess = null;

    public ChannelManager(SshContext context) {
        super();
        this.context = context;
    }

    /**
     * Selects the channel messages that name none go to. It need not be in the channel map, e.g. a
     * channel that was removed already.
     */
    public void select(Channel channel) {
        fallbackGuess = channel;
    }

    /**
     * @return The channels by their local id, in the order they were added; read-only, use {@link
     *     #addChannel} and {@link #removeChannel} to change them
     */
    public Map<Integer, Channel> getChannels() {
        return Collections.unmodifiableMap(channels);
    }

    /** Adds a channel under its local id and selects it. */
    public void addChannel(Channel channel) {
        channels.put(channel.getLocalChannelId().getValue(), channel);
        fallbackGuess = channel;
    }

    /**
     * Removes a channel, if present. If it was selected, the most recently added remaining channel
     * is selected instead.
     */
    public void removeChannel(int localChannelId) {
        Channel removed = channels.remove(localChannelId);
        if (removed != null && fallbackGuess == removed) {
            fallbackGuess = null;
            for (Channel channel : channels.values()) {
                fallbackGuess = channel;
            }
        }
    }

    /**
     * Removes the given channel if it is still the one in the map under its local id: a no-op for a
     * channel that was removed already, whose local id a new channel may have taken over since.
     */
    public void removeChannel(Channel channel) {
        int localChannelId = channel.getLocalChannelId().getValue();
        if (channels.get(localChannelId) == channel) {
            removeChannel(localChannelId);
        }
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
        // Complete before adding it, so that addChannel sees a pending peer open
        Channel channel = context.getConfig().getChannelDefaults().newChannelFromDefaults();
        channel.setLocalChannelId(findUnusedChannelId());
        channel.setRemoteChannelId(remoteChannelId);
        channel.setChannelType(ChannelType.fromName(message.getChannelType().getValue()));
        channel.setRemoteWindowSize(message.getInitialWindowSize());
        channel.setRemotePacketSize(message.getMaximumPacketSize());
        channel.setState(ChannelState.OPEN_RECEIVED);
        addChannel(channel);
    }

    /** Records that we confirm a channel, usually one the peer opened. */
    public void confirmChannel(Channel channel) {
        channel.setState(ChannelState.OPEN);
    }

    /**
     * Called after the peer confirmed a channel, usually one we opened: the peer's id for it is
     * known from now on. Does nothing by default.
     */
    public void confirmedByPeer(Channel channel) {}

    /**
     * @return The oldest channel the peer opened that we neither confirmed nor rejected yet
     */
    public Optional<Channel> nextUnansweredIncomingOpen() {
        return channels.values().stream()
                .filter(channel -> channel.getState() == ChannelState.OPEN_RECEIVED)
                .findFirst();
    }

    /**
     * @return The channel a message goes to if it does not name one: the selected channel, empty if
     *     there is none
     */
    public Optional<Channel> guessChannel() {
        return Optional.ofNullable(fallbackGuess);
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
        addChannel(channel);
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
