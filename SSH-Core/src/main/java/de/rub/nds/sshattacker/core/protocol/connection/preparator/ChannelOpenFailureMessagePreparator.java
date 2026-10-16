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
import de.rub.nds.sshattacker.core.protocol.connection.Channel;
import de.rub.nds.sshattacker.core.protocol.connection.message.ChannelOpenFailureMessage;
import de.rub.nds.sshattacker.core.workflow.chooser.Chooser;
import java.util.Optional;

public class ChannelOpenFailureMessagePreparator
        extends ChannelMessagePreparator<ChannelOpenFailureMessage> {

    public ChannelOpenFailureMessagePreparator(Chooser chooser, ChannelOpenFailureMessage message) {
        super(chooser, message, MessageIdConstant.SSH_MSG_CHANNEL_OPEN_FAILURE);
    }

    @Override
    protected Optional<Channel> guessChannel() {
        return chooser.getContext()
                .getChannelManager()
                .nextUnansweredIncomingOpen()
                .or(super::guessChannel);
    }

    @Override
    protected boolean isExpectedState(ChannelState state) {
        return state == ChannelState.OPEN_RECEIVED;
    }

    @Override
    public void prepareChannelMessageSpecificContents() {
        // A rejected channel never existed, so its local id is free again
        if (channel.getState() == ChannelState.OPEN_RECEIVED) {
            chooser.getContext().getChannels().remove(channel.getLocalChannelId().getValue());
        }
        // TODO dummy values for fuzzing
        getObject().setReasonCode(Integer.MAX_VALUE);
        getObject().setReason("", true);
        getObject().setLanguageTag("", true);
    }
}
