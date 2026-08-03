package io.airvault.mobile;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

import java.net.InetAddress;

public final class RelayClientTest {
    @Test public void acceptsUserApprovedPublicSecureRelayUrls() {
        assertEquals("wss://relay.airvault.example/socket",
                RelayClient.requireSecureUrl(" wss://relay.airvault.example/socket "));
    }

    @Test public void rejectsInsecureAmbiguousAndLocalRelayUrls() {
        assertThrows(IllegalArgumentException.class, () -> RelayClient.requireSecureUrl("ws://relay.example.com"));
        assertThrows(IllegalArgumentException.class, () -> RelayClient.requireSecureUrl("wss://user@relay.example.com"));
        assertThrows(IllegalArgumentException.class, () -> RelayClient.requireSecureUrl("wss://localhost"));
        assertThrows(IllegalArgumentException.class, () -> RelayClient.requireSecureUrl("wss://relay.local"));
        assertThrows(IllegalArgumentException.class, () -> RelayClient.requireSecureUrl("wss://relay.example.com/#fragment"));
    }

    @Test public void dnsPolicyBlocksPrivateAndReservedAddresses() throws Exception {
        assertFalse(RelayClient.isPublicInternetAddress(InetAddress.getByName("127.0.0.1")));
        assertFalse(RelayClient.isPublicInternetAddress(InetAddress.getByName("10.10.0.4")));
        assertFalse(RelayClient.isPublicInternetAddress(InetAddress.getByName("169.254.169.254")));
        assertFalse(RelayClient.isPublicInternetAddress(InetAddress.getByName("100.64.0.1")));
        assertFalse(RelayClient.isPublicInternetAddress(InetAddress.getByName("::1")));
        assertFalse(RelayClient.isPublicInternetAddress(InetAddress.getByName("fc00::1")));
        assertFalse(RelayClient.isPublicInternetAddress(InetAddress.getByName("2001:db8::1")));
        assertTrue(RelayClient.isPublicInternetAddress(InetAddress.getByName("8.8.8.8")));
        assertTrue(RelayClient.isPublicInternetAddress(InetAddress.getByName("2606:4700:4700::1111")));
    }
}
