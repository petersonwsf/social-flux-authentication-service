package com.socialflux.auth.config;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Material criptográfico do JWT (RS256), carregado de variáveis de ambiente:
 * <ul>
 *   <li>{@code JWT_PRIVATE_KEY_B64}: PEM PKCS#8 da chave RSA atual, em base64 de uma linha;</li>
 *   <li>{@code JWT_KEY_ID}: kid atual (padrão: thumbprint da chave);</li>
 *   <li>{@code JWT_PUBLIC_KEYS_B64}: chaves públicas anteriores (PEM em base64), separadas por vírgula,
 *       mantidas no JWKS durante a rotação.</li>
 * </ul>
 * A aplicação não sobe com configuração inválida/ausente (exceto com {@code allow-ephemeral-key}, só para desenvolvimento).
 */
@Component
public class JwtKeys {

    private static final Logger log = LoggerFactory.getLogger(JwtKeys.class);

    private final RSAKey signingKey;
    private final List<RSAKey> previousKeys;

    public JwtKeys(AuthProperties properties) {
        AuthProperties.Jwt jwt = properties.jwt();
        String privateB64 = jwt.privateKeyB64();

        if (privateB64 == null || privateB64.isBlank()) {
            if (!jwt.allowEphemeralKey()) {
                throw new IllegalStateException(
                        "JWT_PRIVATE_KEY_B64 não definida. Gere uma chave com scripts/generate-jwt-key.sh "
                                + "(ou use AUTH_ALLOW_EPHEMERAL_KEY=true apenas em desenvolvimento).");
            }
            log.warn("Usando chave RSA EFÊMERA (desenvolvimento): as sessões serão invalidadas a cada reinício.");
            this.signingKey = generateEphemeral(jwt.keyId());
        } else {
            this.signingKey = fromPrivatePem(decodeB64Text(privateB64), jwt.keyId());
        }

        List<RSAKey> previous = new ArrayList<>();
        String previousB64 = jwt.previousPublicKeysB64();
        if (previousB64 != null && !previousB64.isBlank()) {
            for (String item : previousB64.split(",")) {
                if (!item.isBlank()) {
                    previous.add(fromPublicPem(decodeB64Text(item.trim())));
                }
            }
        }
        this.previousKeys = List.copyOf(previous);
    }

    /** Chave atual de assinatura (com a parte privada). */
    public RSAKey signingKey() {
        return signingKey;
    }

    /** Conjunto público (chave atual + anteriores) servido em /.well-known/jwks.json. */
    public JWKSet publicJwkSet() {
        List<com.nimbusds.jose.jwk.JWK> keys = new ArrayList<>();
        keys.add(signingKey.toPublicJWK());
        keys.addAll(previousKeys);
        return new JWKSet(keys);
    }

    /** Conjunto usado para verificar assinaturas (chave atual + anteriores). */
    public JWKSet verificationJwkSet() {
        return publicJwkSet();
    }

    // ---------------------------------------------------------------- helpers

    private static String decodeB64Text(String value) {
        try {
            return new String(Base64.getDecoder().decode(value.replaceAll("\\s", "")), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new IllegalStateException("Valor de chave inválido: esperado base64 de um PEM.", e);
        }
    }

    private static byte[] pemBody(String pem, String type) {
        String body = pem
                .replace("-----BEGIN " + type + "-----", "")
                .replace("-----END " + type + "-----", "")
                .replaceAll("\\s", "");
        return Base64.getDecoder().decode(body);
    }

    private static RSAKey fromPrivatePem(String pem, String keyId) {
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateKey privateKey = (RSAPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(pemBody(pem, "PRIVATE KEY")));
            if (!(privateKey instanceof RSAPrivateCrtKey crt)) {
                throw new IllegalStateException("A chave privada precisa ser RSA no formato PKCS#8 (CRT).");
            }
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
            if (publicKey.getModulus().bitLength() < 2048) {
                throw new IllegalStateException("A chave RSA precisa ter pelo menos 2048 bits.");
            }
            return build(publicKey, privateKey, keyId);
        } catch (IllegalStateException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalStateException("JWT_PRIVATE_KEY_B64 inválida (esperado PEM PKCS#8 RSA em base64).", e);
        }
    }

    private static RSAKey fromPublicPem(String pem) {
        try {
            RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(pemBody(pem, "PUBLIC KEY")));
            return build(publicKey, null, null);
        } catch (Exception e) {
            throw new IllegalStateException("JWT_PUBLIC_KEYS_B64 inválida (esperado PEM de chave pública RSA em base64).", e);
        }
    }

    private static RSAKey generateEphemeral(String keyId) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            KeyPair pair = generator.generateKeyPair();
            return build((RSAPublicKey) pair.getPublic(), (RSAPrivateKey) pair.getPrivate(), keyId);
        } catch (Exception e) {
            throw new IllegalStateException("Não foi possível gerar a chave efêmera.", e);
        }
    }

    private static RSAKey build(RSAPublicKey publicKey, RSAPrivateKey privateKey, String keyId) throws Exception {
        RSAKey.Builder builder = new RSAKey.Builder(publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256);
        if (privateKey != null) {
            builder.privateKey(privateKey);
        }
        RSAKey withoutId = builder.build();
        String kid = (keyId == null || keyId.isBlank()) ? withoutId.computeThumbprint().toString() : keyId;
        return new RSAKey.Builder(withoutId).keyID(kid).build();
    }
}
