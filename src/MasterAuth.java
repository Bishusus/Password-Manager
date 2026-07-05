/**
 * A record data container designed to pass around saved master authentication details
 * (salt, verification string, iteration metrics) extracted out of the data layers.
 */
public record MasterAuth(String salt, String verifier, int iterations) {

}