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
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenConfirmationMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class ChannelOpenConfirmationMessagePreparator
        extends SshMessagePreparator<ChannelOpenConfirmationMessage> {

    private static final Logger LOGGER = LogManager.getLogger();

    public ChannelOpenConfirmationMessagePreparator(
            Chooser chooser, ChannelOpenConfirmationMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
    }

    @Override
    public void prepareMessageSpecificContents() {
        ChannelManager channelManager = chooser.getContext().getChannelManager();
        Optional<Channel> guessedChannel =
                Optional.ofNullable(getObject().getConfigSenderChannelId())
                        .map(channelManager.getChannels()::get)
                        .or(channelManager::nextUnansweredIncomingOpen)
                        .or(channelManager::guessChannel);
        if (guessedChannel.isEmpty()) {
            LOGGER.error("Failed to guess channel, setting sender and receiver channel IDs to 0!");
            getObject().setSenderChannelId(0);
            getObject().setRecipientChannelId(0);
            getObject()
                    .setInitialWindowSize(
                            chooser.getConfig().getChannelDefaults().getLocalWindowSize());
            getObject()
                    .setMaximumPacketSize(
                            chooser.getConfig().getChannelDefaults().getLocalPacketSize());
            return;
        }

        Channel channel = guessedChannel.get();
        if (channel.getState() != ChannelState.OPEN_RECEIVED) {
            LOGGER.warn(
                    "Channel with id {} is in state {}, sending ChannelOpenConfirmationMessage anyway.",
                    channel.getLocalChannelId().getValue(),
                    channel.getState());
        }
        channel.setState(ChannelState.OPEN);
        getObject().setSenderChannelId(channel.getLocalChannelId().getValue());
        getObject().setRecipientChannelId(channel.getRemoteChannelId().getValue());
        getObject().setInitialWindowSize(channel.getLocalWindowSize().getValue());
        getObject().setMaximumPacketSize(channel.getLocalPacketSize().getValue());
    }
}
