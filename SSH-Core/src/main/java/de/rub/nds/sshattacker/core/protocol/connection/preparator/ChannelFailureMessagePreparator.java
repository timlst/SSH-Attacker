/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection.preparator;

import de.rub.nds.sshattacker.core.constants.MessageIdConstant;
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelFailureMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;

public class ChannelFailureMessagePreparator
        extends ChannelMessagePreparator<ChannelFailureMessage> {

    public ChannelFailureMessagePreparator(Chooser chooser, ChannelFailureMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_FAILURE);
    }

    @Override
    protected Optional<Channel> guessChannel() {
        // Answer the oldest request of the peer that wants a reply
        return chooser.getContext()
                .getChannelManager()
                .takeChannelAwaitingReply()
                .or(super::guessChannel);
    }

    @Override
    protected void prepareChannelMessageSpecificContents() {}
}
