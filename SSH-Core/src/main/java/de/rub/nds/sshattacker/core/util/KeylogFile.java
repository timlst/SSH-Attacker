/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.util;

import de.rub.nds.modifiablevariable.util.DataConverter;
import de.rub.nds.sshattacker.core.config.Config;
import de.rub.nds.sshattacker.core.state.SshContext;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Optional;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Writes Wireshark-compatible SSH keylog entries. Each line has the format {@code <hex cookie>
 * SHARED_SECRET <hex shared secret>}, where the cookie is the one sent in the SSH_MSG_KEXINIT of
 * the client or server. Wireshark accepts the file via the SSH protocol preference "Key log
 * filename" and looks entries up by either cookie, so one line per cookie is written.
 *
 * <p>Note that SSH decryption in Wireshark's SSH dissector is still work in progress, so a correct
 * keylog does not guarantee successful decryption. Observed with Wireshark 4.4: strict key exchange
 * (kex-strict-*) breaks decryption after the first packets, keylog lines longer than roughly 512
 * characters (e.g. the shared secret of diffie-hellman-group14 and larger groups) are truncated,
 * and ecdh-sha2-nistp* key exchanges are not decrypted. curve25519-sha256 without strict key
 * exchange is known to work. Newer Wireshark versions may lift some of these limitations.
 */
public final class KeylogFile {

    private static final Logger LOGGER = LogManager.getLogger();

    private KeylogFile() {
        super();
    }

    /**
     * Appends the shared secret of the current key exchange to the keylog file if enabled in the
     * config. Does nothing if the shared secret or both cookies are not yet known.
     *
     * @param context SSH context of the completed key exchange
     */
    public static void writeKeylog(SshContext context) {
        Config config = context.getConfig();
        if (!config.getWriteKeylogFile() || config.getKeylogFilePath() == null) {
            return;
        }
        Optional<byte[]> sharedSecret = context.getSharedSecret();
        if (sharedSecret.isEmpty()) {
            LOGGER.debug("Not writing keylog entry, shared secret is not available");
            return;
        }
        StringBuilder keylogLines = new StringBuilder();
        context.getClientCookie()
                .ifPresent(
                        cookie -> keylogLines.append(buildKeylogLine(cookie, sharedSecret.get())));
        context.getServerCookie()
                .ifPresent(
                        cookie -> keylogLines.append(buildKeylogLine(cookie, sharedSecret.get())));
        if (keylogLines.isEmpty()) {
            LOGGER.debug("Not writing keylog entry, no KEXINIT cookie is available");
            return;
        }

        Path path = Paths.get(config.getKeylogFilePath());
        try {
            Files.writeString(
                    path,
                    keylogLines.toString(),
                    StandardCharsets.US_ASCII,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND);
        } catch (IOException e) {
            LOGGER.warn("Could not write keylog file {}", path, e);
        }
    }

    private static String buildKeylogLine(byte[] cookie, byte[] secretHex) {
        return DataConverter.bytesToRawHexString(cookie)
                + " SHARED_SECRET "
                + DataConverter.bytesToRawHexString(secretHex)
                + '\n';
    }
}
