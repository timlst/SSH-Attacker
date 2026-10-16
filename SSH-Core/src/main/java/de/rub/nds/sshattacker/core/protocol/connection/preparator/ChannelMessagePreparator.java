/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.ChannelState;
import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.common.SshMessagePreparator;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.ChannelManager;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public abstract class ChannelMessagePreparator<T extends ChannelMessage<T>>
        extends SshMessagePreparator<T> {

    private static final Logger LOGGER = LogManager.getLogger();

    protected Channel channel;

    protected ChannelMessagePreparator(Chooser chooser, T message, MessageIdConstant messageId) {
        super(chooser, message, messageId);
    }

    @Override
    public final void prepareMessageSpecificContents() {
        prepareChannel();
        prepareChannelMessageSpecificContents();
    }

    private void prepareChannel() {
        ChannelManager channelManager = chooser.getContext().getChannelManager();
        Integer configSenderChannelId = getObject().getConfigSenderChannelId();
        if (configSenderChannelId != null) {
            channel = channelManager.getChannels().get(configSenderChannelId);
            if (channel == null) {
                LOGGER.warn(
                        "About to prepare channel message for channel with local id {}, but no such channel exists. Creating a new one from defaults with this id as local and remote id.",
                        configSenderChannelId);
                channel =
                        channelManager.createNewChannelFromDefaults(
                                configSenderChannelId, configSenderChannelId);
            }
        } else {
            channel =
                    guessChannel()
                            .orElseGet(
                                    () -> {
                                        LOGGER.warn(
                                                "About to prepare channel message, but no channel was found or guessed. Creating a new one from defaults.");
                                        return channelManager.createNewChannelFromDefaults(0);
                                    });
        }

        if (!isExpectedState(channel.getState())) {
            int localChannelId = channel.getLocalChannelId().getValue();
            LOGGER.warn(
                    "About to prepare channel message for channel with local id {}, but channel is in state {}. Continuing anyway.",
                    localChannelId,
                    channel.getState());
        }
        getObject().setRecipientChannelId(channel.getRemoteChannelId());
    }

    /**
     * Guesses the channel of a message that does not name one explicitly.
     *
     * @return The guessed channel, or empty to create a new one from the defaults
     */
    protected Optional<Channel> guessChannel() {
        return chooser.getContext().getChannelManager().guessChannel();
    }

    /**
     * @return Whether the message may be sent on a channel in the given state without a warning
     */
    protected boolean isExpectedState(ChannelState state) {
        return state == ChannelState.OPEN;
    }

    protected abstract void prepareChannelMessageSpecificContents();
}
