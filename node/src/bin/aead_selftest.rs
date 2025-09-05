use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use lrb_core::crypto::AeadBox;
use rand_core::{OsRng, RngCore};

fn main() {
    // 1) Ed25519: ключи + подпись/проверка
    let sk = SigningKey::generate(&mut OsRng);
    let vk = VerifyingKey::from(&sk);
    let msg = b"resonance-test-message";
    let sig = sk.sign(msg);
    assert!(vk.verify_strict(msg, &sig).is_ok(), "ed25519 verify failed");

    // 2) AEAD: XChaCha20-Poly1305, уникальный nonce внутри AeadBox
    let mut key32 = [0u8; 32];
    OsRng.fill_bytes(&mut key32);
    let aead = AeadBox::from_key(&key32);

    let aad = b"topic:external-phase|self-vk";
    let pt = "hello, Σ(t)!".as_bytes();

    let ct = aead.seal(aad, pt);
    let dec = aead.open(aad, &ct).expect("aead open failed");
    assert_eq!(dec.as_slice(), pt, "aead roundtrip mismatch");

    // 3) Негатив: порча шифротекста → ошибка
    let mut ct_bad = ct.clone();
    if let Some(last) = ct_bad.last_mut() {
        *last ^= 0xFF; // безопасно мутируем последний байт без двух заимствований
    }
    assert!(aead.open(aad, &ct_bad).is_err(), "aead must fail on tamper");

    // 4) Негатив: смена AAD → ошибка
    let aad_bad = b"topic:changed";
    assert!(
        aead.open(aad_bad, &ct).is_err(),
        "aead must fail on wrong AAD"
    );

    // 5) Подпись поверх шифротекста (seal-then-sign)
    let sig_ct = sk.sign(&ct);
    assert!(
        vk.verify_strict(&ct, &sig_ct).is_ok(),
        "sign(sealed) verify failed"
    );

    println!("OK: ed25519 + AeadBox(XChaCha20-Poly1305) self-test passed");
}
