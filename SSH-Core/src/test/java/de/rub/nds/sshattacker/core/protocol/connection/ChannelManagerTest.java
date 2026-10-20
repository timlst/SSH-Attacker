/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2026 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.protocol.connection;

import static org.junit.jupiter.api.Assertions.*;

import de.rub.nds.sshattacker.core.constants.ChannelState;
import de.rub.nds.sshattacker.core.protocol.common.ProtocolMessage;
import de.rub.nds.sshattacker.core.protocol.connection.message.*;
import de.rub.nds.sshattacker.core.state.SshContext;
import org.junit.jupiter.api.Test;

/**
 * Scenario tests for channel management in both directions, driven through the real handlers and
 * preparators.
 */
public class ChannelManagerTest {

    private static void send(SshContext ctx, ProtocolMessage<?> m) {
        m.getHandler(ctx).getPreparator().prepare();
    }

    private static void receive(SshContext ctx, ProtocolMessage<?> m) {
        m.getHandler(ctx).adjustContext();
    }

    private static <T extends ChannelOpenMessage<T>> T peerOpen(T m, int id, String type) {
        m.setSenderChannelId(id);
        m.setChannelType(type, true);
        m.setInitialWindowSize(1000 + id);
        m.setMaximumPacketSize(2000 + id);
        return m;
    }

    @Test
    public void peerOpensTwoWeConfirmBoth() {
        SshContext ctx = new SshContext();
        receive(ctx, peerOpen(new ChannelOpenSessionMessage(), 7, "session"));
        receive(ctx, peerOpen(new ChannelOpenSessionMessage(), 9, "session"));
        ChannelOpenConfirmationMessage c1 = new ChannelOpenConfirmationMessage();
        ChannelOpenConfirmationMessage c2 = new ChannelOpenConfirmationMessage();
        send(ctx, c1);
        send(ctx, c2);
        assertEquals(7, c1.getRecipientChannelId().getValue());
        assertEquals(0, c1.getSenderChannelId().getValue());
        assertEquals(9, c2.getRecipientChannelId().getValue());
        assertEquals(1, c2.getSenderChannelId().getValue());
        assertTrue(ctx.getChannels().get(0).isOpen());
        assertTrue(ctx.getChannels().get(1).isOpen());
        assertEquals(1007, ctx.getChannels().get(0).getRemoteWindowSize().getValue());
    }

    @Test
    public void weOpenTwoPeerConfirmsSecond() {
        SshContext ctx = new SshContext();
        ChannelOpenSessionMessage o1 = new ChannelOpenSessionMessage();
        ChannelOpenSessionMessage o2 = new ChannelOpenSessionMessage();
        send(ctx, o1);
        send(ctx, o2);
        assertEquals(0, o1.getSenderChannelId().getValue());
        assertEquals(1, o2.getSenderChannelId().getValue());
        assertEquals(ChannelState.OPEN_SENT, ctx.getChannels().get(1).getState());

        ChannelOpenConfirmationMessage conf = new ChannelOpenConfirmationMessage();
        conf.setRecipientChannelId(1);
        conf.setSenderChannelId(42);
        conf.setInitialWindowSize(100);
        conf.setMaximumPacketSize(200);
        receive(ctx, conf);
        assertTrue(ctx.getChannels().get(1).isOpen());
        assertEquals(42, ctx.getChannels().get(1).getRemoteChannelId().getValue());
        assertEquals(ChannelState.OPEN_SENT, ctx.getChannels().get(0).getState());

        ChannelOpenFailureMessage fail = new ChannelOpenFailureMessage();
        fail.setRecipientChannelId(0);
        receive(ctx, fail);
        assertNull(ctx.getChannels().get(0));

        ChannelDataMessage data = new ChannelDataMessage();
        send(ctx, data);
        assertEquals(42, data.getRecipientChannelId().getValue());
    }

    @Test
    public void bothDirectionsAndReplies() {
        SshContext ctx = new SshContext();
        // we open channel 0, peer confirms as 5
        send(ctx, new ChannelOpenSessionMessage());
        ChannelOpenConfirmationMessage conf = new ChannelOpenConfirmationMessage();
        conf.setRecipientChannelId(0);
        conf.setSenderChannelId(5);
        conf.setInitialWindowSize(100);
        conf.setMaximumPacketSize(200);
        receive(ctx, conf);
        // peer opens its own channel 3 -> our local 1; we confirm
        receive(ctx, peerOpen(new ChannelOpenX11Message(), 3, "x11"));
        ChannelOpenConfirmationMessage ours = new ChannelOpenConfirmationMessage();
        send(ctx, ours);
        assertEquals(3, ours.getRecipientChannelId().getValue());
        assertEquals(1, ours.getSenderChannelId().getValue());

        // peer sends a request with want_reply on our channel 0, then we send data first
        ChannelRequestExecMessage req = new ChannelRequestExecMessage();
        req.setRecipientChannelId(0);
        req.setWantReply(true);
        receive(ctx, req);
        ChannelDataMessage data = new ChannelDataMessage();
        send(ctx, data);
        ChannelSuccessMessage ok = new ChannelSuccessMessage();
        send(ctx, ok);
        assertEquals(5, ok.getRecipientChannelId().getValue(), "reply goes to channel 0's peer id");

        // peer closes channel 1 (our id), we answer
        ChannelCloseMessage close = new ChannelCloseMessage();
        close.setRecipientChannelId(1);
        receive(ctx, close);
        assertEquals(ChannelState.CLOSE_RECEIVED, ctx.getChannels().get(1).getState());
        ChannelCloseMessage ourClose = new ChannelCloseMessage();
        ourClose.setConfigSenderChannelId(1);
        send(ctx, ourClose);
        assertEquals(3, ourClose.getRecipientChannelId().getValue());
        assertNull(ctx.getChannels().get(1));
    }

    @Test
    public void peerOpenRejected() {
        SshContext ctx = new SshContext();
        receive(ctx, peerOpen(new ChannelOpenSessionMessage(), 7, "session"));
        ChannelOpenFailureMessage f = new ChannelOpenFailureMessage();
        send(ctx, f);
        assertEquals(7, f.getRecipientChannelId().getValue());
        assertTrue(ctx.getChannels().isEmpty());
    }

    @Test
    public void unknownChannelType() {
        SshContext ctx = new SshContext();
        receive(ctx, peerOpen(new ChannelOpenUnknownMessage(), 7, "foo@example.com"));
        assertDoesNotThrow(() -> ctx.getChannels().get(0).toString());
    }

    @Test
    public void explicitChannelIdNotYetKnown() {
        SshContext ctx = new SshContext();
        receive(ctx, peerOpen(new ChannelOpenSessionMessage(), 7, "session"));
        send(ctx, new ChannelOpenConfirmationMessage());
        ChannelDataMessage d1 = new ChannelDataMessage();
        d1.setConfigSenderChannelId(5);
        send(ctx, d1);
        ChannelDataMessage d2 = new ChannelDataMessage();
        d2.setConfigSenderChannelId(5);
        send(ctx, d2);
        assertEquals(2, ctx.getChannels().size(), "same explicit id should reuse one channel");
        assertEquals(5, d1.getRecipientChannelId().getValue());
        assertEquals(5, d2.getRecipientChannelId().getValue());
    }

    @Test
    public void dataAndEofOnUnknownChannelAreIgnored() {
        SshContext ctx = new SshContext();
        ChannelDataMessage data = new ChannelDataMessage();
        data.setRecipientChannelId(9);
        assertDoesNotThrow(() -> receive(ctx, data));
        ChannelEofMessage eof = new ChannelEofMessage();
        eof.setRecipientChannelId(9);
        assertDoesNotThrow(() -> receive(ctx, eof));
        assertTrue(ctx.getChannels().isEmpty());
    }

    @Test
    public void requestOnUnknownChannelIsAnsweredOnThatId() {
        SshContext ctx = new SshContext();
        receive(ctx, peerOpen(new ChannelOpenSessionMessage(), 7, "session"));
        send(ctx, new ChannelOpenConfirmationMessage());
        ChannelRequestExecMessage req = new ChannelRequestExecMessage();
        req.setRecipientChannelId(9);
        req.setWantReply(true);
        receive(ctx, req);
        ChannelSuccessMessage ok = new ChannelSuccessMessage();
        send(ctx, ok);
        // channel 9 does not exist, so the reply goes to the id the peer named
        assertEquals(9, ok.getRecipientChannelId().getValue());
        assertNull(ctx.getChannels().get(9), "the reply must not register a channel");
    }

    @Test
    public void confirmationForUnrequestedChannelCreatesIt() {
        SshContext ctx = new SshContext();
        ChannelOpenConfirmationMessage conf = new ChannelOpenConfirmationMessage();
        conf.setRecipientChannelId(4);
        conf.setSenderChannelId(11);
        conf.setInitialWindowSize(100);
        conf.setMaximumPacketSize(200);
        receive(ctx, conf);
        Channel channel = ctx.getChannels().get(4);
        assertNotNull(channel);
        assertEquals(ChannelState.OPEN, channel.getState());
        assertEquals(11, channel.getRemoteChannelId().getValue());
        ChannelDataMessage data = new ChannelDataMessage();
        send(ctx, data);
        assertEquals(11, data.getRecipientChannelId().getValue());
    }

    @Test
    public void confirmationForPeerOpenedChannelOverwritesRemoteId() {
        SshContext ctx = new SshContext();
        receive(ctx, peerOpen(new ChannelOpenSessionMessage(), 7, "session"));
        ChannelOpenConfirmationMessage conf = new ChannelOpenConfirmationMessage();
        conf.setRecipientChannelId(0);
        conf.setSenderChannelId(8);
        conf.setInitialWindowSize(100);
        conf.setMaximumPacketSize(200);
        receive(ctx, conf);
        // Current behaviour: accepted without a state check
        assertEquals(ChannelState.OPEN, ctx.getChannels().get(0).getState());
        assertEquals(8, ctx.getChannels().get(0).getRemoteChannelId().getValue());
    }

    /** Opens a channel from our side and has the peer confirm it with the given remote id. */
    private static void openAndConfirm(SshContext ctx, int remoteId) {
        int localId = ctx.getChannelManager().findUnusedChannelId(); // the id the open will take
        send(ctx, new ChannelOpenSessionMessage());
        ChannelOpenConfirmationMessage conf = new ChannelOpenConfirmationMessage();
        conf.setRecipientChannelId(localId);
        conf.setSenderChannelId(remoteId);
        conf.setInitialWindowSize(100);
        conf.setMaximumPacketSize(200);
        receive(ctx, conf);
    }

    /** Sends data without naming a channel and returns the peer id it went to. */
    private static int dataTarget(SshContext ctx) {
        ChannelDataMessage d = new ChannelDataMessage();
        send(ctx, d);
        return d.getRecipientChannelId().getValue();
    }

    /** Closes a channel from both sides, so it is removed. */
    private static void closeFully(SshContext ctx, int localId) {
        ChannelCloseMessage ours = new ChannelCloseMessage();
        ours.setConfigSenderChannelId(localId);
        send(ctx, ours);
        ChannelCloseMessage theirs = new ChannelCloseMessage();
        theirs.setRecipientChannelId(localId);
        receive(ctx, theirs);
    }

    @Test
    public void openingAChannelSelectsIt() {
        SshContext ctx = new SshContext();
        openAndConfirm(ctx, 50); // local 0
        openAndConfirm(ctx, 51); // local 1
        assertEquals(51, dataTarget(ctx));
    }

    @Test
    public void registeringAPeerChannelSelectsIt() {
        SshContext ctx = new SshContext();
        openAndConfirm(ctx, 50); // local 0
        receive(ctx, peerOpen(new ChannelOpenX11Message(), 70, "x11")); // local 1
        send(ctx, new ChannelOpenConfirmationMessage());
        assertEquals(70, dataTarget(ctx));
    }

    @Test
    public void selectTargetsTheChosenChannel() {
        SshContext ctx = new SshContext();
        openAndConfirm(ctx, 50); // local 0
        openAndConfirm(ctx, 51); // local 1
        ctx.getChannelManager().select(ctx.getChannels().get(0));
        assertEquals(50, dataTarget(ctx));
    }

    @Test
    public void removingTheSelectedChannelSelectsTheMostRecentRemaining() {
        SshContext ctx = new SshContext();
        openAndConfirm(ctx, 50); // local 0
        openAndConfirm(ctx, 51); // local 1
        openAndConfirm(ctx, 52); // local 2
        ctx.getChannelManager().select(ctx.getChannels().get(0));
        closeFully(ctx, 0);
        assertNull(ctx.getChannels().get(0));
        assertEquals(52, dataTarget(ctx), "most recently added remaining, not the next in order");
    }

    @Test
    public void removingAnotherChannelKeepsTheSelection() {
        SshContext ctx = new SshContext();
        openAndConfirm(ctx, 50); // local 0
        openAndConfirm(ctx, 51); // local 1
        ctx.getChannelManager().select(ctx.getChannels().get(0));
        closeFully(ctx, 1);
        assertEquals(50, dataTarget(ctx));
    }

    @Test
    public void aRemovedChannelCanStillBeSelected() {
        SshContext ctx = new SshContext();
        openAndConfirm(ctx, 50); // local 0
        openAndConfirm(ctx, 51); // local 1
        Channel dead = ctx.getChannels().get(1);
        closeFully(ctx, 1);
        ctx.getChannelManager().select(dead);
        assertEquals(51, dataTarget(ctx), "sent on the dead channel");
        assertEquals(1, ctx.getChannels().size());
    }

    @Test
    public void closingARemovedChannelLeavesANewChannelWithItsIdAlone() {
        SshContext ctx = new SshContext();
        openAndConfirm(ctx, 50); // local 0
        openAndConfirm(ctx, 51); // local 1
        Channel dead = ctx.getChannels().get(1);
        closeFully(ctx, 1);
        openAndConfirm(ctx, 52); // reuses local 1
        ctx.getChannelManager().select(dead);
        ChannelCloseMessage close = new ChannelCloseMessage();
        send(ctx, close);
        assertEquals(51, close.getRecipientChannelId().getValue());
        assertEquals(52, ctx.getChannels().get(1).getRemoteChannelId().getValue());
        assertEquals(ChannelState.OPEN, ctx.getChannels().get(1).getState());
    }

    @Test
    public void requestCanTargetAMismatchedChannelType() {
        SshContext ctx = new SshContext();
        openAndConfirm(ctx, 50); // a session channel, local 0
        receive(ctx, peerOpen(new ChannelOpenX11Message(), 60, "x11")); // local 1
        send(ctx, new ChannelOpenConfirmationMessage());
        ctx.getChannelManager().select(ctx.getChannels().get(1));
        ChannelRequestExecMessage exec = new ChannelRequestExecMessage();
        send(ctx, exec);
        assertEquals(60, exec.getRecipientChannelId().getValue());
    }

    @Test
    public void confirmingGoesThroughTheManager() {
        java.util.List<Channel> confirmed = new java.util.ArrayList<>();
        SshContext ctx = new SshContext();
        ctx.setChannelManager(
                new ChannelManager(ctx) {
                    @Override
                    public void confirmChannel(Channel channel) {
                        super.confirmChannel(channel);
                        confirmed.add(channel);
                    }
                });
        receive(ctx, peerOpen(new ChannelOpenSessionMessage(), 7, "session"));
        send(ctx, new ChannelOpenConfirmationMessage());
        assertEquals(1, confirmed.size());
        assertEquals(ChannelState.OPEN, confirmed.get(0).getState());
    }

    @Test
    public void channelsCanOnlyChangeThroughTheManager() {
        SshContext ctx = new SshContext();
        assertThrows(UnsupportedOperationException.class, () -> ctx.getChannels().remove(0));
    }
}
