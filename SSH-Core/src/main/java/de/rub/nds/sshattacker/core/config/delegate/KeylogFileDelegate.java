/*
 * SSH-Attacker - A Modular Penetration Testing Framework for SSH
 *
 * Copyright 2014-2022 Ruhr University Bochum, Paderborn University, and Hackmanit GmbH
 *
 * Licensed under Apache License 2.0 http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.sshattacker.core.config.delegate;

import com.beust.jcommander.Parameter;
import de.rub.nds.sshattacker.core.config.Config;

public class KeylogFileDelegate extends Delegate {

    @Parameter(
            names = "-keylogfile",
            description =
                    "Append the shared secret of each key exchange to this file in a Wireshark-compatible keylog format (SSH protocol preference 'Key log filename'). Note: Wireshark's SSH decryption is work in progress; e.g. Wireshark 4.4 fails with strict kex, DH groups >= 2048 bit, and ecdh-sha2-nistp*. curve25519-sha256 without strict kex works")
    private String keylogFile;

    public String getKeylogFile() {
        return keylogFile;
    }

    public void setKeylogFile(String keylogFile) {
        this.keylogFile = keylogFile;
    }

    @Override
    public void applyDelegate(Config config) {
        if (keylogFile != null) {
            config.setWriteKeylogFile(true);
            config.setKeylogFilePath(keylogFile);
        }
    }
}
